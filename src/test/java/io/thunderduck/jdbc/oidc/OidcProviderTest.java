package io.thunderduck.jdbc.oidc;

import static org.junit.jupiter.api.Assertions.*;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Function;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

class OidcProviderTest {

    // The stub endpoints live on 127.0.0.1, so the configured issuer must be on that host too.
    private static final String ISSUER = "http://127.0.0.1/realms/td";
    private static final String API = "https://api.thunderduck.ai";
    private static final String KEY = ISSUER + "|thunderduck-jdbc|" + API;

    private HttpServer server;
    private final List<String> tokenRequests = new CopyOnWriteArrayList<>();

    private HttpServer proxy;
    private final AtomicInteger proxiedRequests = new AtomicInteger();

    @BeforeEach
    @AfterEach
    void reset() {
        if (server != null) server.stop(0);
        if (proxy != null) proxy.stop(0);
        OidcProvider.resetSharedStateForTests();
    }

    /** A clock the test can move forward. */
    static final class MutableClock extends Clock {
        volatile Instant now = Instant.parse("2026-10-28T10:00:00Z");
        void advance(Duration d) { now = now.plus(d); }
        @Override public ZoneId getZone() { return ZoneOffset.UTC; }
        @Override public Clock withZone(ZoneId zone) { return this; }
        @Override public Instant instant() { return now; }
    }

    /** Fake sign-in: counts calls and hands out numbered tokens (or throws). */
    static final class FakeAuthenticator implements Authenticator {
        final AtomicInteger calls = new AtomicInteger();
        final MutableClock clock;
        SQLException failWith;
        FakeAuthenticator(MutableClock clock) { this.clock = clock; }
        @Override public Tokens signIn(OidcEndpoints ep) throws SQLException {
            int n = calls.incrementAndGet();
            if (failWith != null) throw failWith;
            Instant now = clock.instant();
            return new Tokens("signin-access-" + n, now.plusSeconds(300), "signin-refresh-" + n, now.plusSeconds(1800));
        }
    }

    /** The token endpoint answers each refresh POST with (status, body) chosen by the test. */
    private OidcEndpoints startTokenEndpoint(Function<Integer, Object[]> responder) throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        AtomicInteger n = new AtomicInteger();
        server.createContext("/token", ex -> {
            String body = new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
            tokenRequests.add(body);
            Object[] resp = responder.apply(n.incrementAndGet());
            byte[] b = ((String) resp[1]).getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().add("Content-Type", "application/json");
            ex.sendResponseHeaders((Integer) resp[0], b.length);
            ex.getResponseBody().write(b);
            ex.close();
        });
        server.setExecutor(Executors.newFixedThreadPool(4));
        server.start();
        String base = "http://127.0.0.1:" + server.getAddress().getPort();
        return new OidcEndpoints(URI.create(base + "/auth"), URI.create(base + "/token"));
    }

    private static Object[] refreshed(int n) {
        return new Object[] {200, "{\"access_token\":\"refreshed-access-" + n + "\",\"expires_in\":300,"
                + "\"refresh_token\":\"refreshed-refresh-" + n + "\",\"refresh_expires_in\":1800,\"token_type\":\"Bearer\"}"};
    }

    private static Object[] invalidGrant() {
        return new Object[] {400, "{\"error\":\"invalid_grant\",\"error_description\":\"Session not active\"}"};
    }

    private OidcProvider provider(OidcEndpoints ep, Authenticator a, TokenStore store, Clock clock)
            throws SQLException {
        return new OidcProvider(ISSUER, API, ep, a, store, HttpClient.newHttpClient(), clock);
    }

    @Test
    void firstUseSignsInOnce() throws Exception {
        MutableClock clock = new MutableClock();
        FakeAuthenticator a = new FakeAuthenticator(clock);
        MemoryTokenStore store = new MemoryTokenStore();
        OidcProvider p = provider(startTokenEndpoint(OidcProviderTest::refreshed), a, store, clock);

        assertEquals("signin-access-1", p.bearer());
        assertEquals("signin-access-1", p.bearer());
        assertEquals(1, a.calls.get());
        assertTrue(tokenRequests.isEmpty());
        assertEquals("signin-refresh-1", store.load(KEY).orElseThrow().refreshToken());
        assertTrue(p.canRenew());
    }

    @Test
    void validAccessTokenIsReusedWithoutNetwork() throws Exception {
        MutableClock clock = new MutableClock();
        FakeAuthenticator a = new FakeAuthenticator(clock);
        OidcProvider p = provider(startTokenEndpoint(OidcProviderTest::refreshed), a, new MemoryTokenStore(), clock);

        p.bearer();
        clock.advance(Duration.ofSeconds(239)); // 61 s left
        assertEquals("signin-access-1", p.bearer());
        assertTrue(tokenRequests.isEmpty());
        assertEquals(1, a.calls.get());
    }

    @Test
    void refreshesWhenUnder60SecondsLeft() throws Exception {
        MutableClock clock = new MutableClock();
        FakeAuthenticator a = new FakeAuthenticator(clock);
        MemoryTokenStore store = new MemoryTokenStore();
        OidcProvider p = provider(startTokenEndpoint(OidcProviderTest::refreshed), a, store, clock);

        p.bearer();
        clock.advance(Duration.ofSeconds(240)); // exactly 60 s left
        assertEquals("refreshed-access-1", p.bearer());
        assertEquals(1, tokenRequests.size());
        String body = tokenRequests.get(0);
        assertTrue(body.contains("grant_type=refresh_token"), body);
        assertTrue(body.contains("client_id=thunderduck-jdbc"), body);
        assertTrue(body.contains("refresh_token=signin-refresh-1"), body);
        assertEquals(1, a.calls.get());
        assertEquals("refreshed-refresh-1", store.load(KEY).orElseThrow().refreshToken());
    }

    @Test
    void refreshUsesStoredRefreshTokenOnNewProvider() throws Exception {
        MutableClock clock = new MutableClock();
        FakeAuthenticator a = new FakeAuthenticator(clock);
        MemoryTokenStore store = new MemoryTokenStore();
        store.save(KEY, new Tokens(null, null, "cached-refresh", clock.instant().plusSeconds(600)));
        OidcProvider p = provider(startTokenEndpoint(OidcProviderTest::refreshed), a, store, clock);

        assertEquals("refreshed-access-1", p.bearer());
        assertTrue(tokenRequests.get(0).contains("refresh_token=cached-refresh"));
        assertEquals(0, a.calls.get());
    }

    @Test
    void expiredRefreshTokenTriggersNewSignIn() throws Exception {
        MutableClock clock = new MutableClock();
        FakeAuthenticator a = new FakeAuthenticator(clock);
        MemoryTokenStore store = new MemoryTokenStore();
        store.save(KEY, new Tokens(null, null, "stale-refresh", clock.instant().minusSeconds(1)));
        OidcProvider p = provider(startTokenEndpoint(OidcProviderTest::refreshed), a, store, clock);

        assertEquals("signin-access-1", p.bearer());
        assertEquals(1, a.calls.get());
        assertTrue(tokenRequests.isEmpty(), "no refresh request with an expired refresh token");
        assertEquals("signin-refresh-1", store.load(KEY).orElseThrow().refreshToken());
    }

    @Test
    void invalidGrantOnRefreshTriggersNewSignIn() throws Exception {
        MutableClock clock = new MutableClock();
        FakeAuthenticator a = new FakeAuthenticator(clock);
        MemoryTokenStore store = new MemoryTokenStore();
        store.save(KEY, new Tokens(null, null, "revoked-refresh", clock.instant().plusSeconds(600)));
        OidcProvider p = provider(startTokenEndpoint(n -> invalidGrant()), a, store, clock);

        assertEquals("signin-access-1", p.bearer());
        assertEquals(1, tokenRequests.size());
        assertEquals(1, a.calls.get());
        assertEquals("signin-refresh-1", store.load(KEY).orElseThrow().refreshToken());
    }

    @Test
    void refreshServerErrorIsNotASignIn() throws Exception {
        MutableClock clock = new MutableClock();
        FakeAuthenticator a = new FakeAuthenticator(clock);
        MemoryTokenStore store = new MemoryTokenStore();
        store.save(KEY, new Tokens(null, null, "good-refresh", clock.instant().plusSeconds(600)));
        OidcProvider p = provider(startTokenEndpoint(n -> new Object[] {503, "{}"}), a, store, clock);

        SQLException e = assertThrows(SQLException.class, p::bearer);
        assertTrue(e.getMessage().contains("503"), e.getMessage());
        assertEquals(0, a.calls.get());
        assertEquals("good-refresh", store.load(KEY).orElseThrow().refreshToken());
    }

    @Test
    void concurrentRefreshIsSingleFlight() throws Exception {
        MutableClock clock = new MutableClock();
        FakeAuthenticator a = new FakeAuthenticator(clock);
        OidcProvider p = provider(startTokenEndpoint(n -> {
            try { Thread.sleep(150); } catch (InterruptedException ignored) { }
            return refreshed(n);
        }), a, new MemoryTokenStore(), clock);

        p.bearer();
        clock.advance(Duration.ofSeconds(280)); // 20 s left -> every caller wants a refresh

        ExecutorService pool = Executors.newFixedThreadPool(8);
        CountDownLatch go = new CountDownLatch(1);
        List<Future<String>> results = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            results.add(pool.submit(() -> { go.await(); return p.bearer(); }));
        }
        go.countDown();
        for (Future<String> f : results) assertEquals("refreshed-access-1", f.get(10, TimeUnit.SECONDS));
        pool.shutdown();
        assertEquals(1, tokenRequests.size());
        assertEquals(1, a.calls.get());
    }

    @Test
    void refreshRequestNeverAsksForOfflineAccess() throws Exception {
        MutableClock clock = new MutableClock();
        FakeAuthenticator a = new FakeAuthenticator(clock);
        OidcProvider p = provider(startTokenEndpoint(OidcProviderTest::refreshed), a, new MemoryTokenStore(), clock);

        p.bearer();
        clock.advance(Duration.ofSeconds(290));
        p.bearer();
        assertEquals(1, tokenRequests.size());
        assertFalse(tokenRequests.get(0).contains("offline_access"), tokenRequests.get(0));
        assertFalse(tokenRequests.get(0).contains("scope="), tokenRequests.get(0));
    }

    @Test
    void invalidateDropsOnlyTheAccessToken() throws Exception {
        MutableClock clock = new MutableClock();
        FakeAuthenticator a = new FakeAuthenticator(clock);
        OidcProvider p = provider(startTokenEndpoint(OidcProviderTest::refreshed), a, new MemoryTokenStore(), clock);

        p.bearer();
        p.invalidate();
        assertEquals("refreshed-access-1", p.bearer());
        assertEquals(1, a.calls.get());
        assertTrue(tokenRequests.get(0).contains("refresh_token=signin-refresh-1"));
    }

    @Test
    void failedReSignInAfterExpiryHasClearMessage() throws Exception {
        MutableClock clock = new MutableClock();
        FakeAuthenticator a = new FakeAuthenticator(clock);
        SQLException cause = new SQLException("browser closed");
        a.failWith = cause;
        MemoryTokenStore store = new MemoryTokenStore();
        store.save(KEY, new Tokens(null, null, "revoked-refresh", clock.instant().plusSeconds(600)));
        OidcProvider p = provider(startTokenEndpoint(n -> invalidGrant()), a, store, clock);

        SQLException e = assertThrows(SQLException.class, p::bearer);
        assertEquals("Sign-in expired — reconnect to sign in again.", e.getMessage());
        assertSame(cause, e.getCause());
    }

    @Test
    void firstEverSignInFailureKeepsAuthenticatorMessage() throws Exception {
        MutableClock clock = new MutableClock();
        FakeAuthenticator a = new FakeAuthenticator(clock);
        SQLException cause = new SQLException("Sign-in was cancelled or timed out (no response within 5 minutes).");
        a.failWith = cause;
        OidcProvider p = provider(startTokenEndpoint(OidcProviderTest::refreshed), a, new MemoryTokenStore(), clock);

        SQLException e = assertThrows(SQLException.class, p::bearer);
        assertSame(cause, e);
    }

    @Test
    void tokensFromResponseUsesExpiresIn() {
        MutableClock clock = new MutableClock();
        Tokens t = Tokens.fromResponse(java.util.Map.of(
                "access_token", "a", "expires_in", 300.0, "refresh_token", "r", "refresh_expires_in", 1800.0), clock);
        assertEquals("a", t.accessToken());
        assertEquals(clock.instant().plusSeconds(300), t.accessExpiresAt());
        assertEquals("r", t.refreshToken());
        assertEquals(clock.instant().plusSeconds(1800), t.refreshExpiresAt());
    }

    @Test
    void discoverReadsWellKnownConfiguration() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/realms/td/.well-known/openid-configuration", ex -> {
            byte[] b = ("{\"issuer\":\"x\",\"authorization_endpoint\":\"https://kc/auth\","
                    + "\"token_endpoint\":\"https://kc/token\"}").getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(200, b.length);
            ex.getResponseBody().write(b);
            ex.close();
        });
        server.start();
        OidcEndpoints ep = OidcEndpoints.discover(
                "http://127.0.0.1:" + server.getAddress().getPort() + "/realms/td/", HttpClient.newHttpClient());
        assertEquals(URI.create("https://kc/auth"), ep.authorization());
        assertEquals(URI.create("https://kc/token"), ep.token());
        assertEquals("x", ep.issuer());
    }

    @Test
    void storeKeyIsIssuerClientIdAndApiOrigin() throws Exception {
        assertEquals(KEY, OidcProvider.storeKey(ISSUER, API));
        assertEquals(KEY, OidcProvider.storeKey(ISSUER + "/", "HTTPS://API.Thunderduck.ai:443/"));
        assertEquals(ISSUER + "|thunderduck-jdbc|http://localhost:8080",
                OidcProvider.storeKey(ISSUER, "http://localhost:8080"));
        assertEquals(ISSUER + "|thunderduck-jdbc|http://127.0.0.1",
                OidcProvider.storeKey(ISSUER, "http://127.0.0.1:80"));
        assertNotEquals(KEY, OidcProvider.storeKey(ISSUER, "https://evil.example"));
        assertEquals(Optional.empty(), new MemoryTokenStore().load(KEY));
    }

    @Test
    void differentApiHostsDoNotShareACachedSession() throws Exception {
        MutableClock clock = new MutableClock();
        FakeAuthenticator a = new FakeAuthenticator(clock);
        MemoryTokenStore store = new MemoryTokenStore();
        store.save(KEY, new Tokens(null, null, "api-host-refresh", clock.instant().plusSeconds(600)));
        OidcEndpoints ep = startTokenEndpoint(OidcProviderTest::refreshed);
        OidcProvider other = new OidcProvider(ISSUER, "https://evil.example", ep, a, store,
                HttpClient.newHttpClient(), clock);

        assertEquals("signin-access-1", other.bearer());
        assertTrue(tokenRequests.isEmpty(), "the other host's cached refresh token must not be used");
        assertEquals("api-host-refresh", store.load(KEY).orElseThrow().refreshToken());
    }

    private static final String DEFAULT_ISSUER = "https://auth.thunderduck.ai/realms/thunderduck";
    private static final String HOST_MSG = "auth=browser with the Thunderduck sign-in can only connect to "
            + "api.thunderduck.ai; set issuer for other hosts";
    private static final String HTTPS_MSG = "auth=browser requires https (ssl=true) except for localhost";

    private static void rejects(String issuer, String api, String message) {
        SQLException e = assertThrows(SQLException.class, () -> OidcProvider.checkApiHost(issuer, api), api);
        assertEquals(message, e.getMessage());
    }

    @Test
    void thunderduckSignInOnlyServesApiThunderduckAi() throws Exception {
        OidcProvider.checkApiHost(DEFAULT_ISSUER, "https://api.thunderduck.ai");
        OidcProvider.checkApiHost(DEFAULT_ISSUER, "https://API.THUNDERDUCK.AI:443");
        OidcProvider.checkApiHost(DEFAULT_ISSUER, "https://api.thunderduck.ai.");
        rejects(DEFAULT_ISSUER, "https://trust.thunderduck.ai", HOST_MSG);
        rejects(DEFAULT_ISSUER, "https://console.thunderduck.ai", HOST_MSG);
        rejects(DEFAULT_ISSUER, "https://thunderduck.ai", HOST_MSG);
        rejects(DEFAULT_ISSUER, "https://eu.api.thunderduck.ai", HOST_MSG);
        rejects(DEFAULT_ISSUER, "https://evil.example", HOST_MSG);
        rejects(DEFAULT_ISSUER, "https://thunderduck.ai.evil.com", HOST_MSG);
        rejects(DEFAULT_ISSUER, "https://evilthunderduck.ai", HOST_MSG);
        rejects(DEFAULT_ISSUER, "http://127.0.0.1:8080", HOST_MSG);
    }

    @Test
    void anyIssuerOnTheThunderduckAuthHostGetsTheApiHostRule() {
        for (String issuer : List.of(
                "https://auth.thunderduck.ai/realms/thunderduck/.",
                "https://auth.thunderduck.ai/realms/x/../thunderduck",
                "https://auth.thunderduck.ai//realms/thunderduck",
                "HTTPS://AUTH.THUNDERDUCK.AI/realms/thunderduck",
                "https://Auth.Thunderduck.ai/realms/Thunderduck",
                "https://auth.thunderduck.ai./realms/thunderduck",
                "https://auth.thunderduck.ai:443/realms/thunderduck",
                "https://auth.thunderduck.ai:8443/realms/other",
                "https://auth.thunderduck.ai")) {
            rejects(issuer, "https://evil.example", HOST_MSG);
        }
    }

    @Test
    void discoveredThunderduckIssuerAppliesTheApiHostRuleBeforeAnyTokenRequest() throws Exception {
        MutableClock clock = new MutableClock();
        FakeAuthenticator a = new FakeAuthenticator(clock);
        OidcEndpoints stub = startTokenEndpoint(OidcProviderTest::refreshed);
        OidcEndpoints reportsThunderduck = new OidcEndpoints(stub.authorization(), stub.token(),
                "https://auth.thunderduck.ai/realms/thunderduck");
        String customIssuer = "http://127.0.0.1/realms/custom";
        String evil = "https://evil.example";
        MemoryTokenStore store = new MemoryTokenStore();
        store.save(OidcProvider.storeKey(customIssuer, evil),
                new Tokens(null, null, "cached-refresh", clock.instant().plusSeconds(600)));
        OidcProvider p = new OidcProvider(customIssuer, evil, reportsThunderduck, a, store,
                HttpClient.newHttpClient(), clock);

        SQLException e = assertThrows(SQLException.class, p::bearer);
        assertEquals(HOST_MSG, e.getMessage());
        assertTrue(tokenRequests.isEmpty());
        assertEquals(0, a.calls.get());
    }

    @Test
    void storedTokenRejectedFallsBackToTheInMemoryRefreshToken() throws Exception {
        MutableClock clock = new MutableClock();
        FakeAuthenticator a = new FakeAuthenticator(clock);
        // An unwritable cache: always returns the same stale entry, ignores writes.
        TokenStore stale = new TokenStore() {
            @Override public Optional<Tokens> load(String key) {
                return Optional.of(new Tokens(null, null, "stale-stored", clock.instant().plusSeconds(3600)));
            }
            @Override public void save(String key, Tokens t) { }
            @Override public void clear(String key) { }
        };
        OidcProvider p = provider(startTokenEndpoint(n -> {
            String last = tokenRequests.get(tokenRequests.size() - 1);
            return last.contains("refresh_token=stale-stored") ? invalidGrant() : refreshed(n);
        }), a, stale, clock);

        assertEquals("signin-access-1", p.bearer()); // stale rejected, nothing in memory yet -> sign in
        clock.advance(Duration.ofSeconds(290));
        assertEquals("refreshed-access-3", p.bearer());
        assertEquals(1, a.calls.get());
        assertEquals(3, tokenRequests.size());
        assertTrue(tokenRequests.get(2).contains("refresh_token=signin-refresh-1"), tokenRequests.get(2));
    }

    @Test
    void tokenCacheNoneNeverSharesASession(@org.junit.jupiter.api.io.TempDir java.nio.file.Path tmp)
            throws Exception {
        MutableClock clock = new MutableClock();
        FakeAuthenticator a = new FakeAuthenticator(clock);
        OidcEndpoints ep = startTokenEndpoint(OidcProviderTest::refreshed);
        java.nio.file.Path cache = tmp.resolve("credentials.json");
        OidcProvider.create(ISSUER, API, () -> ep, a, "none", cache, HttpClient.newHttpClient(), clock).bearer();
        OidcProvider.create(ISSUER, API, () -> ep, a, "none", cache, HttpClient.newHttpClient(), clock).bearer();
        assertEquals(2, a.calls.get());
        assertFalse(java.nio.file.Files.exists(cache));
    }

    @Test
    void tokenCacheFileSharesTheSessionPerKey(@org.junit.jupiter.api.io.TempDir java.nio.file.Path tmp)
            throws Exception {
        MutableClock clock = new MutableClock();
        FakeAuthenticator a = new FakeAuthenticator(clock);
        OidcEndpoints ep = startTokenEndpoint(OidcProviderTest::refreshed);
        java.nio.file.Path cache = tmp.resolve("credentials.json");
        OidcProvider.create(ISSUER, API, () -> ep, a, "file", cache, HttpClient.newHttpClient(), clock).bearer();
        assertEquals("signin-access-1",
                OidcProvider.create(ISSUER, API, () -> ep, a, "file", cache, HttpClient.newHttpClient(), clock)
                        .bearer());
        assertEquals(1, a.calls.get());
        assertTrue(tokenRequests.isEmpty());
    }

    @Test
    void plainHttpOnlyForLoopback() throws Exception {
        String custom = "https://kc.example/realms/x";
        OidcProvider.checkApiHost(custom, "http://localhost:8080");
        OidcProvider.checkApiHost(custom, "http://127.0.0.1:9");
        OidcProvider.checkApiHost(custom, "http://[::1]:9");
        OidcProvider.checkApiHost(custom, "https://evil.example");
        rejects(custom, "http://evil.example", HTTPS_MSG);
        rejects(custom, "http://10.0.0.5:8080", HTTPS_MSG);
        rejects(DEFAULT_ISSUER, "http://api.thunderduck.ai", HTTPS_MSG);
    }

    @Test
    void twoProvidersForTheSameKeyRefreshOnce() throws Exception {
        MutableClock clock = new MutableClock();
        FakeAuthenticator a1 = new FakeAuthenticator(clock);
        FakeAuthenticator a2 = new FakeAuthenticator(clock);
        MemoryTokenStore store = new MemoryTokenStore();
        OidcEndpoints ep = startTokenEndpoint(n -> {
            try { Thread.sleep(150); } catch (InterruptedException ignored) { }
            return refreshed(n);
        });
        OidcProvider p1 = provider(ep, a1, store, clock);
        OidcProvider p2 = provider(ep, a2, store, clock);

        p1.bearer();
        clock.advance(Duration.ofSeconds(280));
        assertEquals(List.of("refreshed-access-1"), runConcurrently(p1, p2));
        assertEquals(1, tokenRequests.size());
        assertEquals(1, a1.calls.get() + a2.calls.get());
    }

    @Test
    void twoProvidersWithAnEmptyCacheSignInOnce() throws Exception {
        MutableClock clock = new MutableClock();
        Authenticator slow = new Authenticator() {
            final AtomicInteger n = new AtomicInteger();
            @Override public Tokens signIn(OidcEndpoints ep) {
                try { Thread.sleep(150); } catch (InterruptedException ignored) { }
                int i = n.incrementAndGet();
                return new Tokens("signin-access-" + i, clock.instant().plusSeconds(300), "r" + i, null);
            }
        };
        AtomicInteger signIns = new AtomicInteger();
        Authenticator a1 = ep -> { signIns.incrementAndGet(); return slow.signIn(ep); };
        Authenticator a2 = ep -> { signIns.incrementAndGet(); return slow.signIn(ep); };
        MemoryTokenStore store = new MemoryTokenStore();
        OidcEndpoints ep = startTokenEndpoint(OidcProviderTest::refreshed);
        OidcProvider p1 = provider(ep, a1, store, clock);
        OidcProvider p2 = provider(ep, a2, store, clock);

        assertEquals(List.of("signin-access-1"), runConcurrently(p1, p2));
        assertEquals(1, signIns.get());
        assertTrue(tokenRequests.isEmpty());
    }

    /** 8 threads, 4 per provider, released together; returns the distinct bearers seen. */
    private static List<String> runConcurrently(OidcProvider p1, OidcProvider p2) throws Exception {
        ExecutorService pool = Executors.newFixedThreadPool(8);
        CountDownLatch go = new CountDownLatch(1);
        List<Future<String>> results = new ArrayList<>();
        for (int i = 0; i < 8; i++) {
            OidcProvider p = i % 2 == 0 ? p1 : p2;
            results.add(pool.submit(() -> { go.await(); return p.bearer(); }));
        }
        go.countDown();
        List<String> seen = new ArrayList<>();
        for (Future<String> f : results) {
            String b = f.get(10, TimeUnit.SECONDS);
            if (!seen.contains(b)) seen.add(b);
        }
        pool.shutdown();
        return seen;
    }

    @Test
    void prefersARefreshTokenAnotherProcessStored() throws Exception {
        MutableClock clock = new MutableClock();
        FakeAuthenticator a = new FakeAuthenticator(clock);
        MemoryTokenStore store = new MemoryTokenStore();
        OidcProvider p = provider(startTokenEndpoint(OidcProviderTest::refreshed), a, store, clock);

        p.bearer(); // memory holds signin-refresh-1
        store.save(KEY, new Tokens(null, null, "other-process-refresh", clock.instant().plusSeconds(1200)));
        clock.advance(Duration.ofSeconds(290));
        assertEquals("refreshed-access-1", p.bearer());
        assertTrue(tokenRequests.get(0).contains("refresh_token=other-process-refresh"), tokenRequests.get(0));
    }

    @Test
    void invalidGrantClearsTheStoreOnlyIfItStillHoldsTheRejectedToken() throws Exception {
        MutableClock clock = new MutableClock();
        FakeAuthenticator a = new FakeAuthenticator(clock);
        a.failWith = new SQLException("cancelled");
        MemoryTokenStore store = new MemoryTokenStore();
        store.save(KEY, new Tokens(null, null, "old-refresh", clock.instant().plusSeconds(600)));
        OidcProvider p = provider(startTokenEndpoint(n -> {
            // Another process rotates the cached token while our refresh is in flight.
            store.save(KEY, new Tokens(null, null, "rotated-refresh", clock.instant().plusSeconds(600)));
            return invalidGrant();
        }), a, store, clock);

        assertThrows(SQLException.class, p::bearer);
        assertEquals("rotated-refresh", store.load(KEY).orElseThrow().refreshToken());
    }

    @Test
    void invalidGrantClearsTheRejectedStoredToken() throws Exception {
        MutableClock clock = new MutableClock();
        FakeAuthenticator a = new FakeAuthenticator(clock);
        a.failWith = new SQLException("cancelled");
        MemoryTokenStore store = new MemoryTokenStore();
        store.save(KEY, new Tokens(null, null, "old-refresh", clock.instant().plusSeconds(600)));
        OidcProvider p = provider(startTokenEndpoint(n -> invalidGrant()), a, store, clock);

        assertThrows(SQLException.class, p::bearer);
        assertTrue(store.load(KEY).isEmpty());
    }

    @Test
    void resetHookForgetsSharedSessions() throws Exception {
        MutableClock clock = new MutableClock();
        FakeAuthenticator a = new FakeAuthenticator(clock);
        OidcEndpoints ep = startTokenEndpoint(OidcProviderTest::refreshed);
        provider(ep, a, new MemoryTokenStore(), clock).bearer();
        OidcProvider.resetSharedStateForTests();
        provider(ep, a, new MemoryTokenStore(), clock).bearer();
        assertEquals(2, a.calls.get());
    }

    // ---- endpoints are bound to the issuer host; Thunderduck tokens only reach api.thunderduck.ai ----

    private static final String ENDPOINTS_MSG = "the sign-in server's endpoints are not on the issuer's host";

    /**
     * An HttpClient whose every request goes to a local counting proxy, so endpoints on real host names
     * (e.g. auth.thunderduck.ai) are never contacted for real.
     */
    private HttpClient proxiedClient() throws Exception {
        proxy = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        proxy.createContext("/", ex -> { proxiedRequests.incrementAndGet(); ex.sendResponseHeaders(500, -1); ex.close(); });
        proxy.start();
        return HttpClient.newBuilder().proxy(ProxySelector.of(proxy.getAddress())).build();
    }

    private static OidcEndpoints endpointsOn(String origin, String docIssuer) {
        String base = origin + "/realms/thunderduck/protocol/openid-connect";
        return new OidcEndpoints(URI.create(base + "/auth"), URI.create(base + "/token"), docIssuer);
    }

    private void assertRefusedBeforeAnyRequest(String issuer, String api, OidcEndpoints ep, String message)
            throws Exception {
        MutableClock clock = new MutableClock();
        FakeAuthenticator a = new FakeAuthenticator(clock);
        MemoryTokenStore store = new MemoryTokenStore();
        store.save(OidcProvider.storeKey(issuer, api),
                new Tokens(null, null, "cached-refresh", clock.instant().plusSeconds(600)));
        OidcProvider p = new OidcProvider(issuer, api, ep, a, store, proxiedClient(), clock);

        SQLException e = assertThrows(SQLException.class, p::bearer);
        assertEquals(message, e.getMessage());
        assertEquals(0, proxiedRequests.get(), "no token request");
        assertEquals(0, a.calls.get(), "no sign-in");
    }

    @Test
    void discoveryWithoutIssuerButThunderduckEndpointsIsRefused() throws Exception {
        assertRefusedBeforeAnyRequest("https://sso.evil.example/realms/x", "https://evil.example",
                endpointsOn("http://auth.thunderduck.ai:8080", null), HOST_MSG);
    }

    @Test
    void discoveryWithACustomIssuerButThunderduckEndpointsIsRefused() throws Exception {
        assertRefusedBeforeAnyRequest("https://sso.evil.example/realms/x", "https://evil.example",
                endpointsOn("http://AUTH.THUNDERDUCK.AI.:8080", "https://sso.evil.example/realms/x"), HOST_MSG);
    }

    @Test
    void endpointsOffTheIssuerHostAreRefused() throws Exception {
        assertRefusedBeforeAnyRequest("https://sso.example/realms/x", "https://api.example",
                endpointsOn("http://other.example:8080", "https://sso.example/realms/x"), ENDPOINTS_MSG);
        OidcEndpoints tokenElsewhere = new OidcEndpoints(URI.create("https://sso.example/auth"),
                URI.create("https://other.example/token"));
        proxy.stop(0);
        assertRefusedBeforeAnyRequest("https://sso.example/realms/x", "https://api.example", tokenElsewhere,
                ENDPOINTS_MSG);
    }

    @Test
    void endpointsOnTheIssuerHostAreAccepted() throws Exception {
        MutableClock clock = new MutableClock();
        FakeAuthenticator a = new FakeAuthenticator(clock);
        OidcProvider p = new OidcProvider("https://SSO.example./realms/x", "https://api.example",
                endpointsOn("https://sso.example:8443", null), a, new MemoryTokenStore(), proxiedClient(), clock);
        assertEquals("signin-access-1", p.bearer());
    }

    private static String jwt(String iss) {
        Base64.Encoder b64 = Base64.getUrlEncoder().withoutPadding();
        String header = b64.encodeToString("{\"alg\":\"RS256\"}".getBytes(StandardCharsets.UTF_8));
        String payload = b64.encodeToString(("{\"iss\":\"" + iss + "\",\"azp\":\"thunderduck-jdbc\"}")
                .getBytes(StandardCharsets.UTF_8));
        return header + "." + payload + ".c2ln";
    }

    @Test
    void signedInThunderduckTokenForAnotherApiHostIsRefusedAndNotStored() throws Exception {
        MutableClock clock = new MutableClock();
        String thunderduckToken = jwt("https://auth.thunderduck.ai/realms/thunderduck");
        Authenticator a = ep -> new Tokens(thunderduckToken, clock.instant().plusSeconds(300), "td-refresh",
                clock.instant().plusSeconds(1800));
        MemoryTokenStore store = new MemoryTokenStore();
        String api = "https://evil.example";
        OidcProvider p = new OidcProvider(ISSUER, api, startTokenEndpoint(OidcProviderTest::refreshed), a, store,
                HttpClient.newHttpClient(), clock);

        SQLException e = assertThrows(SQLException.class, p::bearer);
        assertEquals(HOST_MSG, e.getMessage());
        assertTrue(store.load(OidcProvider.storeKey(ISSUER, api)).isEmpty());
        // Nothing kept in memory either: the next call does not hand out the token.
        assertThrows(SQLException.class, p::bearer);
    }

    @Test
    void refreshedThunderduckTokenForAnotherApiHostIsRefusedAndDiscarded() throws Exception {
        MutableClock clock = new MutableClock();
        FakeAuthenticator a = new FakeAuthenticator(clock);
        String thunderduckToken = jwt("https://auth.thunderduck.ai/realms/thunderduck");
        MemoryTokenStore store = new MemoryTokenStore();
        String api = "https://evil.example";
        String key = OidcProvider.storeKey(ISSUER, api);
        store.save(key, new Tokens(null, null, "cached-refresh", clock.instant().plusSeconds(600)));
        OidcProvider p = new OidcProvider(ISSUER, api, startTokenEndpoint(n -> new Object[] {200,
                "{\"access_token\":\"" + thunderduckToken + "\",\"expires_in\":300,\"refresh_token\":\"r2\"}"}),
                a, store, HttpClient.newHttpClient(), clock);

        SQLException e = assertThrows(SQLException.class, p::bearer);
        assertEquals(HOST_MSG, e.getMessage());
        assertTrue(store.load(key).isEmpty());
        assertEquals(0, a.calls.get());
    }

    @Test
    void customRealmTokenIsAcceptedForItsApiHost() throws Exception {
        MutableClock clock = new MutableClock();
        String customToken = jwt("http://127.0.0.1/realms/td");
        Authenticator a = ep -> new Tokens(customToken, clock.instant().plusSeconds(300), "r", null);
        OidcProvider p = new OidcProvider(ISSUER, "https://api.example",
                startTokenEndpoint(OidcProviderTest::refreshed), a, new MemoryTokenStore(),
                HttpClient.newHttpClient(), clock);
        assertEquals(customToken, p.bearer());
    }

    @Test
    void browserSignInNeedsADesktopBrowser() throws Exception {
        HttpClient h = HttpClient.newHttpClient();
        String iss = "https://auth.example/realms/td";
        Authenticator browser = OidcProvider.authenticatorFor(true, h, iss);
        assertInstanceOf(BrowserAuth.class, browser);
        assertEquals(iss, ((BrowserAuth) browser).configuredIssuer());
        // Headless, or no way to open a browser: an interactive sign-in is refused, pointing at API tokens
        // (no device-code fallback). Refused at sign-in, so host checks and cached tokens still apply first.
        Authenticator headless = OidcProvider.authenticatorFor(false, h, iss);
        SQLException e = assertThrows(SQLException.class,
                () -> headless.signIn(new OidcEndpoints(URI.create(iss + "/auth"), URI.create(iss + "/token"))));
        assertEquals("auth=browser needs a desktop browser on this machine; on a server or in a container, use an API token (auth=token)", e.getMessage());
        assertEquals("08001", e.getSQLState());
    }

    @Test
    void testsRunHeadlessSoNoRealBrowserCanOpen() {
        assertFalse(OidcProvider.canOpenBrowser());
    }
}
