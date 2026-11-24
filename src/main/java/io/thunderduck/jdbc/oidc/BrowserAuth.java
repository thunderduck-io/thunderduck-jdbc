package io.thunderduck.jdbc.oidc;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.BindException;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.function.Consumer;

/**
 * Sign-in in the user's browser: authorization code + PKCE (S256), with the code delivered to a
 * one-shot HTTP server on {@code 127.0.0.1} (the first free port in the range) at {@code /callback}.
 */
final class BrowserAuth implements Authenticator {

    static final int FIRST_PORT = 33500;
    static final int LAST_PORT = 33509;

    private static final String PAGE_OK = page("Signed in to Thunderduck",
            "Signed in. You can close this window and return to your application.");
    private static final String PAGE_FAILED = page("Thunderduck sign-in failed",
            "Sign-in did not complete. Close this window and try again from your application.");

    private final HttpClient http;
    private final Consumer<URI> opener;
    private final Duration timeout;
    private final int firstPort;
    private final int lastPort;
    private final Clock clock = Clock.systemUTC();
    private final String issuer;

    /** The callback outcome: an authorization code, or the error to fail the sign-in with. */
    private static final class Outcome {
        final String code;
        final SQLException error;
        Outcome(String code, SQLException error) {
            this.code = code;
            this.error = error;
        }
    }

    BrowserAuth(HttpClient http, Consumer<URI> opener, Duration timeout, int firstPort, int lastPort,
                String issuer) {
        this.issuer = issuer;
        this.http = http;
        this.opener = opener;
        this.timeout = timeout;
        this.firstPort = firstPort;
        this.lastPort = lastPort;
    }

    /** The issuer the connection was configured with (not the discovery document's). */
    String configuredIssuer() {
        return issuer;
    }

    /** The production opener: the user's default browser. */
    static void openInDesktopBrowser(URI uri) {
        try {
            java.awt.Desktop.getDesktop().browse(uri);
        } catch (IOException e) {
            throw new java.io.UncheckedIOException(e);
        }
    }

    @Override
    public Tokens signIn(OidcEndpoints ep) throws SQLException {
        Pkce pkce = Pkce.create();
        String state = Pkce.randomUrlSafe(32);
        CompletableFuture<Outcome> result = new CompletableFuture<>();
        HttpServer server = bindCallbackServer();
        try {
            String redirectUri = "http://127.0.0.1:" + server.getAddress().getPort() + "/callback";
            server.createContext("/callback", ex -> handleCallback(ex, state, issuer, result));
            server.start();

            URI authorize = authorizeUrl(ep.authorization(), redirectUri, state, pkce.challenge());
            try {
                opener.accept(authorize);
            } catch (RuntimeException e) {
                throw new SQLException("could not open a browser for sign-in (" + e.getMessage()
                        + "); use an API token (auth=token)", "08001", e);
            }

            Outcome outcome = await(result);
            if (outcome.error != null) throw outcome.error;
            return exchange(ep.token(), outcome.code, redirectUri, pkce.verifier());
        } finally {
            server.stop(0);
        }
    }

    private HttpServer bindCallbackServer() throws SQLException {
        InetAddress loopback;
        try {
            loopback = InetAddress.getByAddress(new byte[] {127, 0, 0, 1});
        } catch (IOException e) {
            throw new SQLException("sign-in failed: " + e.getMessage(), "08001", e);
        }
        for (int port = firstPort; port <= lastPort; port++) {
            try {
                return HttpServer.create(new InetSocketAddress(loopback, port), 0);
            } catch (BindException busy) {
                // try the next port
            } catch (IOException e) {
                throw new SQLException("sign-in failed: could not listen on 127.0.0.1:" + port + ": "
                        + e.getMessage(), "08001", e);
            }
        }
        throw new SQLException("No free local port for sign-in (" + firstPort + "–" + lastPort
                + "); close other sign-in windows or use an API token (auth=token)", "08001");
    }

    static URI authorizeUrl(URI endpoint, String redirectUri, String state, String challenge) {
        String query = "response_type=code"
                + "&client_id=" + OidcProvider.enc(OidcProvider.CLIENT_ID)
                + "&redirect_uri=" + OidcProvider.enc(redirectUri)
                + "&scope=" + OidcProvider.enc(OidcProvider.SCOPE)
                + "&state=" + OidcProvider.enc(state)
                + "&code_challenge=" + OidcProvider.enc(challenge)
                + "&code_challenge_method=S256";
        String base = endpoint.toString();
        return URI.create(base + (endpoint.getRawQuery() == null ? "?" : "&") + query);
    }

    /**
     * Answers the browser with a fixed page (no request data is echoed) and records the first
     * callback's outcome; a state mismatch, or an answer from another sign-in server (RFC 9207
     * {@code iss}), fails the sign-in without using the code.
     */
    private static void handleCallback(HttpExchange ex, String state, String issuer,
                                       CompletableFuture<Outcome> result)
            throws IOException {
        try {
            if (!"GET".equals(ex.getRequestMethod()) || !"/callback".equals(ex.getRequestURI().getPath())) {
                respond(ex, 404, PAGE_FAILED);
                return;
            }
            Map<String, String> q;
            try {
                q = query(ex.getRequestURI().getRawQuery());
            } catch (IllegalArgumentException malformed) {
                q = Map.of(); // fails the state check below
            }
            Outcome outcome = outcome(q, state, issuer);
            respond(ex, outcome.error == null ? 200 : 400, outcome.error == null ? PAGE_OK : PAGE_FAILED);
            result.complete(outcome);
        } finally {
            ex.close();
        }
    }

    /**
     * The mix-up defence (RFC 9207): a callback carrying {@code iss} must name the configured issuer,
     * and with the Thunderduck sign-in {@code iss} is required. Otherwise a custom issuer could relay
     * the browser to the Thunderduck realm and have its code redeemed at its own token endpoint.
     */
    private static Outcome outcome(Map<String, String> q, String state, String issuer) {
        String got = q.get("state");
        if (got == null || !MessageDigest.isEqual(got.getBytes(StandardCharsets.UTF_8),
                state.getBytes(StandardCharsets.UTF_8))) {
            return new Outcome(null, new SQLException(
                    "sign-in failed: the sign-in response did not match this request", "28000"));
        }
        String iss = q.get("iss");
        boolean issRequired = OidcProvider.isThunderduckIssuer(issuer);
        if ((iss == null && issRequired) || (iss != null && !OidcProvider.sameIssuer(issuer, iss))) {
            return new Outcome(null, new SQLException(OidcProvider.WRONG_ISSUER, "28000"));
        }
        String error = q.get("error");
        if ("access_denied".equals(error)) {
            return new Outcome(null, new SQLException(OidcProvider.SIGN_IN_TIMED_OUT, "28000"));
        }
        if (error != null) {
            String shown = error.matches("[A-Za-z0-9_.-]{1,64}") ? error : "unknown error";
            return new Outcome(null, new SQLException("sign-in failed: " + shown, "28000"));
        }
        String code = q.get("code");
        if (code == null || code.isEmpty()) {
            return new Outcome(null, new SQLException("sign-in failed: no authorization code", "28000"));
        }
        return new Outcome(code, null);
    }

    private Outcome await(CompletableFuture<Outcome> result) throws SQLException {
        try {
            return result.get(timeout.toMillis(), TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            throw new SQLException(OidcProvider.SIGN_IN_TIMED_OUT, "28000", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new SQLException("sign-in interrupted", "08001", e);
        } catch (ExecutionException e) {
            throw new SQLException("sign-in failed: " + e.getCause(), "08001", e.getCause());
        }
    }

    private Tokens exchange(URI tokenEndpoint, String code, String redirectUri, String verifier) throws SQLException {
        String form = "grant_type=authorization_code"
                + "&client_id=" + OidcProvider.enc(OidcProvider.CLIENT_ID)
                + "&code=" + OidcProvider.enc(code)
                + "&redirect_uri=" + OidcProvider.enc(redirectUri)
                + "&code_verifier=" + OidcProvider.enc(verifier);
        HttpResponse<String> r = OidcProvider.postForm(http, tokenEndpoint, form, "sign-in");
        Map<String, Object> body = OidcProvider.parseOrNull(r.body());
        if (r.statusCode() == 200 && body != null) return Tokens.requireAccess(body, clock);
        Object error = body == null ? null : body.get("error");
        throw new SQLException("sign-in failed (HTTP " + r.statusCode()
                + (error == null ? "" : ", " + error) + ")", "28000");
    }

    private static void respond(HttpExchange ex, int status, String html) throws IOException {
        byte[] b = html.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "text/html; charset=utf-8");
        ex.getResponseHeaders().add("Cache-Control", "no-store");
        ex.getResponseHeaders().add("Referrer-Policy", "no-referrer");
        ex.sendResponseHeaders(status, b.length);
        ex.getResponseBody().write(b);
    }

    private static Map<String, String> query(String raw) {
        Map<String, String> m = new HashMap<>();
        if (raw == null || raw.isEmpty()) return m;
        for (String kv : raw.split("&")) {
            if (kv.isEmpty()) continue;
            int eq = kv.indexOf('=');
            String k = URLDecoder.decode(eq < 0 ? kv : kv.substring(0, eq), StandardCharsets.UTF_8);
            String v = eq < 0 ? "" : URLDecoder.decode(kv.substring(eq + 1), StandardCharsets.UTF_8);
            m.putIfAbsent(k, v);
        }
        return m;
    }

    private static String page(String title, String message) {
        return "<!doctype html><html><head><meta charset=\"utf-8\"><title>" + title + "</title></head>"
                + "<body style=\"font-family:system-ui,sans-serif;margin:3rem\"><p>" + message + "</p></body></html>";
    }
}
