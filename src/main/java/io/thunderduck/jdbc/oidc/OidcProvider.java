package io.thunderduck.jdbc.oidc;

import io.thunderduck.jdbc.AuthProvider;
import io.thunderduck.jdbc.ConnConfig;
import io.thunderduck.jdbc.Json;
import java.net.URI;
import java.net.URLEncoder;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Bearer tokens from the realm for {@code auth=browser}: reuses the access token while it has
 * more than 60 s left, otherwise refreshes it, and signs in again when there is no usable refresh
 * token or the realm rejects it.
 *
 * <p>Sessions are keyed by issuer, client id and API origin, so a cached sign-in is only ever sent to
 * the API host it was made for. With {@code tokenCache=file}, all providers in the JVM with the same
 * key share one lock and one in-memory token state: concurrent statements on any number of
 * connections cause a single refresh or sign-in (single flight). With {@code tokenCache=none} each
 * provider keeps its own session and memory store.
 */
public final class OidcProvider implements AuthProvider {

    static final String CLIENT_ID = "thunderduck-jdbc";
    static final String SIGN_IN_EXPIRED = "Sign-in expired — reconnect to sign in again.";
    static final String SIGN_IN_TIMED_OUT = "Sign-in was cancelled or timed out (no response within 5 minutes).";
    /** Never {@code offline_access}: sessions follow the realm's normal SSO lifetimes. */
    static final String SCOPE = "openid email profile";
    static final Duration SIGN_IN_TIMEOUT = Duration.ofMinutes(5);
    /** The Thunderduck realm's host; any issuer on it may only be used against {@link #THUNDERDUCK_API_HOST}. */
    static final String THUNDERDUCK_AUTH_HOST = "auth.thunderduck.ai";
    static final String THUNDERDUCK_API_HOST = "api.thunderduck.ai";
    static final String WRONG_HOST = "auth=browser with the Thunderduck sign-in can only connect to "
            + "api.thunderduck.ai; set issuer for other hosts";
    static final String WELL_KNOWN_PATH = "/.well-known/oauth-protected-resource";
    /** A discovery document is a few hundred bytes; anything larger is not one. */
    private static final int MAX_WELL_KNOWN_BYTES = 64 * 1024;
    /** Wall-clock budget for the discovery request and for reading its body. */
    private static final Duration DISCOVERY_BUDGET = Duration.ofSeconds(10);
    /** {@code <company>-api.<domain>}: an install's query host, whose realm is its sibling. */
    private static final Pattern BYOC_API_HOST = Pattern.compile("^([a-z0-9-]+)-api\\.(.+)$");
    private static final Pattern IP_LITERAL =
            Pattern.compile("^[0-9.]+$|^\\[[0-9a-fA-F:.]+\\]$|^[0-9a-fA-F:.]+$");
    static final String ENDPOINTS_OFF_HOST = "the sign-in server's endpoints are not on the issuer's host";
    static final String WRONG_ISSUER = "Sign-in was answered by a different sign-in server than the one "
            + "configured; not continuing.";
    static final String NEEDS_HTTPS = "auth=browser requires https (ssl=true) except for localhost";
    static final String NO_BROWSER = "auth=browser needs a desktop browser on this machine; on a server or in a "
            + "container, use an API token (auth=token)";
    private static final Duration MIN_ACCESS_LEFT = Duration.ofSeconds(60);

    /** One lock + token state; shared per store key across the JVM for {@code tokenCache=file}. */
    private static final class Session {
        Tokens tokens; // guarded by this
    }

    private static final Map<String, Session> SESSIONS = new ConcurrentHashMap<>();

    /** Supplies the realm endpoints; discovery is deferred to the first bearer() that needs them. */
    @FunctionalInterface
    interface EndpointSource {
        OidcEndpoints get() throws SQLException;
    }

    private final String storeKey;
    private final String apiBaseUrl;
    private final String issuerHost;
    private final EndpointSource endpointSource;
    private final Authenticator authenticator;
    private final TokenStore store;
    private final HttpClient http;
    private final Clock clock;

    private final Session session;
    private OidcEndpoints endpoints; // guarded by session

    /**
     * The provider for a connection: realm from {@code issuer}, cache per {@code tokenCache}.
     * Refuses, before any network call, an API host the realm's tokens must not be sent to.
     */
    public static OidcProvider forConfig(ConnConfig cfg) throws SQLException {
        // Fail closed before anything touches the network: the transport rule depends only on the
        // URL the caller wrote.
        checkApiTransport(cfg.baseUrl);
        HttpClient http = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(30)).build();
        // The managed host needs no lookup: its realm is this driver's default. Discovery only
        // matters for an interactive sign-in, so a token connection never makes the request.
        boolean managed = hostOf(parse(cfg.baseUrl)).equals(THUNDERDUCK_API_HOST);
        boolean discover = !cfg.issuerExplicit && !managed && "browser".equals(cfg.auth);
        String issuer = discover ? discoverIssuer(cfg.baseUrl, http).orElse(cfg.issuer) : cfg.issuer;
        // The issuer that governs the sign-in gets the full check either way, including one that
        // came off the wire.
        checkApiHost(issuer, cfg.baseUrl);
        Authenticator signIn = authenticatorFor(canOpenBrowser(), http, issuer);
        return create(issuer, cfg.baseUrl, () -> OidcEndpoints.discover(issuer, http), signIn,
                cfg.tokenCache, FileTokenStore.defaultFile(), http, Clock.systemUTC());
    }

    /**
     * The sign-in server an install advertises, from {@code <api>/.well-known/oauth-protected-resource}
     * (RFC 9728's {@code authorization_servers}), so a connection to any host -- an on-prem install with
     * its own domain included -- finds its realm without an {@code issuer} parameter. Empty when the server
     * does not answer, leaving the caller's default in place.
     */
    static Optional<String> discoverIssuer(String apiBaseUrl, HttpClient http) {
        URI uri;
        try {
            uri = URI.create(apiBaseUrl.replaceAll("/+$", "") + WELL_KNOWN_PATH);
        } catch (RuntimeException e) {
            return Optional.empty();
        }
        try {
            HttpResponse<InputStream> r = http.sendAsync(
                            HttpRequest.newBuilder(uri).timeout(DISCOVERY_BUDGET)
                                    .header("Accept", "application/json").GET().build(),
                            HttpResponse.BodyHandlers.ofInputStream())
                    .get(DISCOVERY_BUDGET.toMillis(), TimeUnit.MILLISECONDS);
            if (r.statusCode() != 200) {
                r.body().close();
                return Optional.empty();
            }
            // Two bounds, because either alone is escapable: at most one byte past the cap is
            // read, and the read itself runs under the same wall-clock budget -- a host that
            // trickles a byte at a time is cut off when it expires, aborting the exchange.
            byte[] body = readBounded(r.body(), MAX_WELL_KNOWN_BYTES + 1, DISCOVERY_BUDGET);
            if (body == null || body.length > MAX_WELL_KNOWN_BYTES) return Optional.empty();
            Object servers = Json.parseObject(new String(body, StandardCharsets.UTF_8))
                    .get("authorization_servers");
            if (servers instanceof List<?> list && !list.isEmpty() && list.get(0) instanceof String first
                    && plausibleIssuer(first, apiBaseUrl)) {
                return Optional.of(first);
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        } catch (Exception e) { // unreachable server, unparseable body: keep the default
            return Optional.empty();
        }
        return Optional.empty();
    }

    /**
     * Signs in through the default browser. Without one (headless, or the desktop cannot open URLs) an
     * interactive sign-in is refused, pointing at API tokens; there is no device-code fallback. The refusal
     * comes at sign-in, so the host checks still run first and a cached session keeps working.
     */
    static Authenticator authenticatorFor(boolean browserAvailable, HttpClient http, String issuer) {
        if (browserAvailable) {
            return new BrowserAuth(http, BrowserAuth::openInDesktopBrowser, SIGN_IN_TIMEOUT,
                    BrowserAuth.FIRST_PORT, BrowserAuth.LAST_PORT, issuer);
        }
        return ep -> {
            throw new SQLException(NO_BROWSER, "08001");
        };
    }

    /** True unless headless or the desktop cannot open URLs (or java.desktop is absent from the runtime). */
    static boolean canOpenBrowser() {
        try {
            return !java.awt.GraphicsEnvironment.isHeadless()
                    && java.awt.Desktop.isDesktopSupported()
                    && java.awt.Desktop.getDesktop().isSupported(java.awt.Desktop.Action.BROWSE);
        } catch (Throwable unavailable) { // e.g. NoClassDefFoundError on a jlink'd runtime
            return false;
        }
    }

    /**
     * {@code tokenCache=none}: a private memory store and a private session (nothing shared, nothing on
     * disk). {@code tokenCache=file}: the file cache and the JVM-wide session for this key.
     */
    static OidcProvider create(String issuer, String apiBaseUrl, EndpointSource endpointSource,
                               Authenticator authenticator, String tokenCache, Path cacheFile,
                               HttpClient http, Clock clock) throws SQLException {
        boolean none = "none".equals(tokenCache);
        TokenStore store = none ? new MemoryTokenStore() : new FileTokenStore(cacheFile);
        return new OidcProvider(issuer, apiBaseUrl, endpointSource, authenticator, store, http, clock, !none);
    }

    /** For tests: fixed endpoints, JVM-wide session (as tokenCache=file), no up-front host check. */
    OidcProvider(String issuer, String apiBaseUrl, OidcEndpoints ep, Authenticator authenticator,
                 TokenStore store, HttpClient http, Clock clock) throws SQLException {
        this(issuer, apiBaseUrl, () -> ep, authenticator, store, http, clock, true);
    }

    private OidcProvider(String issuer, String apiBaseUrl, EndpointSource endpointSource,
                         Authenticator authenticator, TokenStore store, HttpClient http, Clock clock,
                         boolean sharedSession) throws SQLException {
        this.storeKey = storeKey(issuer, apiBaseUrl);
        this.apiBaseUrl = apiBaseUrl;
        this.issuerHost = hostOf(parse(issuer));
        this.session = sharedSession ? SESSIONS.computeIfAbsent(storeKey, k -> new Session()) : new Session();
        this.endpointSource = endpointSource;
        this.authenticator = authenticator;
        this.store = store;
        this.http = http;
        this.clock = clock;
    }

    /** The token-store key: issuer + {@code |} + client id + {@code |} + normalized API origin. */
    static String storeKey(String issuer, String apiBaseUrl) throws SQLException {
        return issuer.replaceAll("/+$", "") + "|" + CLIENT_ID + "|" + origin(apiBaseUrl);
    }

    /**
     * Refuses API hosts the realm's tokens must not reach. An issuer on the Thunderduck auth host
     * (any path, port or case) may only be used with api.thunderduck.ai; and plain http is only
     * allowed to loopback.
     */
    static void checkApiHost(String issuer, String apiBaseUrl) throws SQLException {
        requireThunderduckApiIfRealmHost(hostOf(parse(issuer)), apiBaseUrl);
        checkApiTransport(apiBaseUrl);
    }

    /**
     * The part of the check that depends on nothing but the URL the caller wrote: https, or plain
     * http to loopback only. Runs before any request, so a cleartext host is refused without the
     * driver touching the network.
     */
    static void checkApiTransport(String apiBaseUrl) throws SQLException {
        URI api = parse(apiBaseUrl);
        String apiHost = hostOf(api);
        boolean loopback = apiHost.equals("127.0.0.1") || apiHost.equals("[::1]") || apiHost.equals("::1")
                || apiHost.equals("localhost");
        if (!"https".equals(api.getScheme().toLowerCase(Locale.ROOT)) && !loopback) {
            throw new SQLException(NEEDS_HTTPS, "28000");
        }
    }

    /**
     * True for a value that could serve as an issuer: an absolute URI with a host, https, or plain
     * http only on loopback -- the same transport rule the connection itself must satisfy. What a
     * discovery document names is untrusted input and passes through this before it is used.
     */
    static boolean plausibleIssuer(String candidate, String apiBaseUrl) {
        if (candidate == null) return false;
        URI u;
        try {
            u = new URI(candidate);
        } catch (Exception e) {
            return false;
        }
        String scheme = u.getScheme() == null ? "" : u.getScheme().toLowerCase(Locale.ROOT);
        String host = u.getHost() == null ? "" : u.getHost().toLowerCase(Locale.ROOT);
        if (host.isEmpty() || u.getRawQuery() != null || u.getRawFragment() != null
                || u.getRawUserInfo() != null) {
            return false;
        }
        URI api;
        try {
            api = parse(apiBaseUrl);
        } catch (SQLException e) {
            return false;
        }
        String apiHost = hostOf(api);
        if (isLoopbackHost(apiHost)) {
            // A loopback install is a development one: keep sign-in on loopback, in cleartext only
            // when the connection itself is cleartext.
            boolean candidateLoopback = isLoopbackHost(host);
            if (!candidateLoopback) return false;
            if ("https".equals(scheme)) return true;
            return "http".equals(scheme) && "http".equals(api.getScheme().toLowerCase(Locale.ROOT));
        }
        // Any other install: the sign-in host is the one its own naming implies, and nothing else.
        // Not a "same site" comparison -- that needs the public-suffix list, and every label
        // heuristic has a suffix it gets wrong (co.uk, github.io) or an address it collapses
        // (10.0.0.5 vs 192.168.0.5). An install that names its realm elsewhere passes `issuer=`,
        // which is checked by checkApiHost and never reaches here.
        String expected = expectedIssuerHost(apiHost);
        if (expected == null || !trimDot(host).equals(expected) || !"https".equals(scheme)) {
            return false;
        }
        return true;
    }

    /**
     * Reads at most {@code max} bytes, giving up after {@code budget}: closing the stream aborts
     * the exchange, so a slow or endless body cannot hold the caller.
     */
    private static byte[] readBounded(InputStream in, int max, Duration budget) throws Exception {
        ExecutorService pool = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "td-discovery-read");
            t.setDaemon(true);
            return t;
        });
        try {
            Future<byte[]> read = pool.submit(() -> {
                try (InputStream body = in) {
                    return body.readNBytes(max);
                }
            });
            try {
                return read.get(budget.toMillis(), TimeUnit.MILLISECONDS);
            } catch (TimeoutException e) {
                in.close();
                read.cancel(true);
                return null;
            }
        } finally {
            pool.shutdownNow();
        }
    }

    /** Numeric literal or "localhost" and actually loopback -- 127.0.0.0/8 and every IPv6 spelling. */
    static boolean isLoopbackHost(String host) {
        String h = host.endsWith(".") ? host.substring(0, host.length() - 1) : host;
        if (h.equals("localhost")) return true;
        if (!IP_LITERAL.matcher(h).matches()) return false; // a name: the same-site rule governs it
        try {
            return InetAddress.getByName(h).isLoopbackAddress();
        } catch (Exception e) {
            return true; // an unparseable literal is not something to send a sign-in to
        }
    }

    /**
     * The sign-in host an install's naming implies: {@code <company>-api.<domain>} serves queries
     * and {@code <company>-auth.<domain>} signs in. Null when the host does not follow it, which
     * leaves {@code issuer=} as the way to name a realm.
     */
    static String expectedIssuerHost(String apiHost) {
        Matcher m = BYOC_API_HOST.matcher(trimDot(apiHost));
        return m.matches() ? m.group(1) + "-auth." + m.group(2) : null;
    }

    private static String trimDot(String host) {
        String h = host.toLowerCase(Locale.ROOT);
        return h.endsWith(".") ? h.substring(0, h.length() - 1) : h;
    }


    private static boolean isLoopback(String host) {
        return isLoopbackHost(host);
    }

    /** Anything that comes from the Thunderduck realm's host may only go to api.thunderduck.ai. */
    private static void requireThunderduckApiIfRealmHost(String realmHost, String apiBaseUrl) throws SQLException {
        if (THUNDERDUCK_AUTH_HOST.equals(realmHost) && !hostOf(parse(apiBaseUrl)).equals(THUNDERDUCK_API_HOST)) {
            throw new SQLException(WRONG_HOST, "28000");
        }
    }

    /**
     * RFC 9207 issuer identification: true when {@code iss} names the configured issuer. Scheme and
     * host compare case-insensitively (host without a trailing dot), default ports are ignored, a
     * trailing slash is dropped; the path must otherwise match exactly. Unparseable values never match.
     */
    static boolean sameIssuer(String configured, String iss) {
        String a = normalizedIssuer(configured);
        return a != null && a.equals(normalizedIssuer(iss));
    }

    private static String normalizedIssuer(String issuer) {
        if (issuer == null) return null;
        URI u;
        try {
            u = new URI(issuer);
        } catch (Exception e) {
            return null;
        }
        String host = hostOf(u);
        if (u.getScheme() == null || host.isEmpty() || u.getRawQuery() != null || u.getRawFragment() != null
                || u.getRawUserInfo() != null) {
            return null;
        }
        String scheme = u.getScheme().toLowerCase(Locale.ROOT);
        int port = u.getPort();
        boolean defaultPort = port == -1 || (scheme.equals("https") && port == 443)
                || (scheme.equals("http") && port == 80);
        String path = u.getRawPath() == null ? "" : u.getRawPath().replaceAll("/+$", "");
        return scheme + "://" + host + (defaultPort ? "" : ":" + port) + path;
    }

    /** True when the issuer is on the Thunderduck auth host (any path, port or case). */
    static boolean isThunderduckIssuer(String issuer) {
        try {
            return THUNDERDUCK_AUTH_HOST.equals(hostOf(new URI(issuer)));
        } catch (Exception e) {
            return false;
        }
    }

    /** Lower-cased host without a trailing dot ("" when the URI has no host). */
    static String hostOf(URI u) {
        String h = u == null ? null : u.getHost();
        return h == null ? "" : h.toLowerCase(Locale.ROOT).replaceAll("\\.+$", "");
    }

    /**
     * The discovery document is controlled by whoever runs the issuer URL, so neither its endpoints nor
     * its {@code issuer} field are trusted: endpoints on the Thunderduck auth host bring the API-host
     * rule, and every endpoint must be on the configured issuer's host.
     */
    private void checkDiscovered(OidcEndpoints ep) throws SQLException {
        URI[] uris = {ep.authorization(), ep.token()};
        for (URI u : uris) {
            if (u != null) requireThunderduckApiIfRealmHost(hostOf(u), apiBaseUrl);
        }
        if (ep.issuer() != null) checkApiHost(ep.issuer(), apiBaseUrl);
        for (URI u : uris) {
            if (u != null && !hostOf(u).equals(issuerHost)) throw new SQLException(ENDPOINTS_OFF_HOST, "28000");
        }
    }

    /**
     * Backstop: a token the Thunderduck realm issued (by its unverified {@code iss}; the API verifies
     * signatures) may only be sent to api.thunderduck.ai, whatever the discovery said.
     */
    private void checkTokenIssuer(String accessToken) throws SQLException {
        String iss;
        try {
            String[] parts = accessToken.split("\\.");
            if (parts.length != 3) return; // not a JWT
            Object v = Json.parseObject(new String(Base64.getUrlDecoder().decode(parts[1]),
                    StandardCharsets.UTF_8)).get("iss");
            if (!(v instanceof String)) return;
            iss = (String) v;
        } catch (Exception e) {
            return; // not a decodable JWT
        }
        URI issuer;
        try {
            issuer = new URI(iss);
        } catch (Exception e) {
            return;
        }
        requireThunderduckApiIfRealmHost(hostOf(issuer), apiBaseUrl);
    }

    /** Lower-case {@code scheme://host[:port]}, default ports omitted. */
    static String origin(String url) throws SQLException {
        URI u = parse(url);
        String scheme = u.getScheme().toLowerCase(Locale.ROOT);
        int port = u.getPort();
        boolean defaultPort = port == -1 || (scheme.equals("https") && port == 443)
                || (scheme.equals("http") && port == 80);
        return scheme + "://" + u.getHost().toLowerCase(Locale.ROOT) + (defaultPort ? "" : ":" + port);
    }

    private static URI parse(String url) throws SQLException {
        try {
            URI u = new URI(url);
            if (u.getScheme() == null || u.getHost() == null || hostOf(u).isEmpty()) throw new IllegalArgumentException("no host");
            return u;
        } catch (Exception e) {
            throw new SQLException("invalid URL for sign-in: " + url, "08001", e);
        }
    }

    /** Test hook: forget every JVM-wide session. */
    static void resetSharedStateForTests() {
        SESSIONS.clear();
    }

    @Override
    public String bearer() throws SQLException {
        synchronized (session) {
            Instant now = clock.instant();
            Tokens mem = session.tokens;
            if (mem != null && mem.accessToken() != null && mem.accessExpiresAt() != null
                    && Duration.between(now, mem.accessExpiresAt()).compareTo(MIN_ACCESS_LEFT) > 0) {
                return mem.accessToken();
            }

            // Another process (or connection with its own store) may have rotated the refresh token.
            Tokens stored = store.load(storeKey).orElse(null);
            Tokens from = pickRefreshSource(mem, stored, now);
            boolean hadSession = hasRefresh(mem) || hasRefresh(stored);

            if (from != null && from.hasUsableRefresh(now)) {
                Tokens refreshed = refresh(from);
                if (refreshed != null) return adopt(keepRefreshIfAbsent(refreshed, from));
                forgetRejected(from.refreshToken());
                // A stale stored token (e.g. an unwritable cache file) must not hide a good one in memory.
                if (from != mem && hasRefresh(mem) && !mem.refreshToken().equals(from.refreshToken())
                        && mem.hasUsableRefresh(now)) {
                    refreshed = refresh(mem);
                    if (refreshed != null) return adopt(keepRefreshIfAbsent(refreshed, mem));
                    forgetRejected(mem.refreshToken());
                }
            }

            OidcEndpoints ep = endpoints();
            Tokens signedIn;
            try {
                signedIn = authenticator.signIn(ep);
            } catch (SQLException e) {
                if (hadSession) throw new SQLException(SIGN_IN_EXPIRED, "28000", e);
                throw e;
            }
            if (signedIn == null || signedIn.accessToken() == null || signedIn.accessToken().isEmpty()) {
                throw new SQLException("sign-in returned no access token", "28000");
            }
            return adopt(signedIn);
        }
    }

    @Override
    public void invalidate() {
        synchronized (session) {
            Tokens t = session.tokens;
            if (t != null) session.tokens = new Tokens(null, null, t.refreshToken(), t.refreshExpiresAt());
        }
    }

    @Override
    public boolean canRenew() {
        return true;
    }

    // ---- internals (caller holds the session lock) ----

    /** A usable stored refresh token that differs from the in-memory one wins; else memory; else store. */
    private static Tokens pickRefreshSource(Tokens mem, Tokens stored, Instant now) {
        if (stored != null && stored.hasUsableRefresh(now)
                && (!hasRefresh(mem) || !stored.refreshToken().equals(mem.refreshToken()))) {
            return stored;
        }
        return hasRefresh(mem) ? mem : stored;
    }

    private static boolean hasRefresh(Tokens t) {
        return t != null && t.refreshToken() != null && !t.refreshToken().isEmpty();
    }

    /** The realm rejected this refresh token: drop it from memory, and from the store only if still there. */
    private void forgetRejected(String rejected) {
        if (session.tokens != null && Objects.equals(session.tokens.refreshToken(), rejected)) {
            session.tokens = null;
        }
        Tokens stored = store.load(storeKey).orElse(null);
        if (stored != null && Objects.equals(stored.refreshToken(), rejected)) store.clear(storeKey);
    }

    /** Discovers once and checks the document before any of its endpoints is used. */
    private OidcEndpoints endpoints() throws SQLException {
        if (endpoints == null) {
            OidcEndpoints ep = endpointSource.get();
            checkDiscovered(ep);
            endpoints = ep;
        }
        return endpoints;
    }

    private String adopt(Tokens t) throws SQLException {
        try {
            checkTokenIssuer(t.accessToken());
        } catch (SQLException refused) {
            session.tokens = null;
            store.clear(storeKey);
            throw refused;
        }
        session.tokens = t;
        store.save(storeKey, t);
        return t.accessToken();
    }

    /** A refresh response may omit the refresh token; then the old one stays valid. */
    private static Tokens keepRefreshIfAbsent(Tokens fresh, Tokens old) {
        if (fresh.refreshToken() != null) return fresh;
        return new Tokens(fresh.accessToken(), fresh.accessExpiresAt(), old.refreshToken(), old.refreshExpiresAt());
    }

    /** Returns new tokens, or null when the realm rejects the refresh token ({@code invalid_grant}). */
    private Tokens refresh(Tokens session) throws SQLException {
        String form = "grant_type=refresh_token"
                + "&client_id=" + enc(CLIENT_ID)
                + "&refresh_token=" + enc(session.refreshToken());
        URI tokenEndpoint = endpoints().token(); // may refuse the API host; must not be wrapped
        HttpResponse<String> r;
        try {
            r = http.send(
                    HttpRequest.newBuilder(tokenEndpoint)
                            .timeout(Duration.ofSeconds(30))
                            .header("Content-Type", "application/x-www-form-urlencoded")
                            .header("Accept", "application/json")
                            .POST(HttpRequest.BodyPublishers.ofString(form, StandardCharsets.UTF_8))
                            .build(),
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new SQLException("token refresh interrupted", "08001", e);
        } catch (Exception e) {
            throw new SQLException("token refresh failed: " + e.getMessage(), "08001", e);
        }
        Map<String, Object> body = parseOrNull(r.body());
        if (r.statusCode() == 200 && body != null) return Tokens.requireAccess(body, clock);
        String error = body == null ? null : String.valueOf(body.get("error"));
        if (r.statusCode() == 400 && "invalid_grant".equals(error)) return null;
        throw new SQLException("token refresh failed (HTTP " + r.statusCode()
                + (error == null ? "" : ", " + error) + ")", "08001");
    }

    /** The JSON object of a response body, or null when it is not one. */
    static Map<String, Object> parseOrNull(String s) {
        try {
            return Json.parseObject(s);
        } catch (Exception e) {
            return null;
        }
    }

    /** Form-encodes one value; spaces as {@code %20} so it also reads right in a query string. */
    static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20");
    }

    /** POSTs a form to a realm endpoint; {@code what} names the step in error messages. */
    static HttpResponse<String> postForm(HttpClient http, URI uri, String form, String what) throws SQLException {
        try {
            return http.send(
                    HttpRequest.newBuilder(uri)
                            .timeout(Duration.ofSeconds(30))
                            .header("Content-Type", "application/x-www-form-urlencoded")
                            .header("Accept", "application/json")
                            .POST(HttpRequest.BodyPublishers.ofString(form, StandardCharsets.UTF_8))
                            .build(),
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new SQLException(what + " interrupted", "08001", e);
        } catch (Exception e) {
            throw new SQLException(what + " failed: " + e.getMessage(), "08001", e);
        }
    }
}
