package io.thunderduck.jdbc;

import static org.junit.jupiter.api.Assertions.*;

import java.sql.DriverPropertyInfo;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Properties;
import org.junit.jupiter.api.Test;

class ConnConfigAuthTest {

    private static final String BASE = "jdbc:thunderduck://api.thunderduck.ai/";

    @Test
    void defaultAuthIsToken() throws Exception {
        ConnConfig c = ConnConfig.parse(BASE + "?token=t", null);
        assertEquals("token", c.auth);
        assertEquals("file", c.tokenCache);
        assertEquals("https://auth.thunderduck.ai/realms/thunderduck", c.issuer);
    }

    @Test
    void byocApiHostDefaultsTheIssuerToItsAuthHost() throws Exception {
        // A BYOC install serves the realm beside the API, so browser sign-in
        // works without an issuer parameter there.
        ConnConfig c = ConnConfig.parse("jdbc:thunderduck://exampleco-api.thunderduck.ai/?auth=browser", null);
        assertEquals("https://exampleco-auth.thunderduck.ai/realms/thunderduck", c.issuer);
    }

    @Test
    void managedApiHostKeepsTheManagedRealm() throws Exception {
        assertEquals("https://auth.thunderduck.ai/realms/thunderduck",
                ConnConfig.parse(BASE + "?auth=browser", null).issuer);
        // A host that is not <prefix>-api.<domain> is not guessed at.
        assertEquals("https://auth.thunderduck.ai/realms/thunderduck",
                ConnConfig.parse("jdbc:thunderduck://db.example.com/?auth=browser", null).issuer);
    }

    @Test
    void explicitIssuerWinsOverTheDerivedOne() throws Exception {
        ConnConfig c = ConnConfig.parse(
                "jdbc:thunderduck://exampleco-api.thunderduck.ai/?auth=browser&issuer=https%3A%2F%2Flogin.example.com%2Frealms%2Fx",
                null);
        assertEquals("https://login.example.com/realms/x", c.issuer);
    }

    @Test
    void browserAuthNeedsNoToken() throws Exception {
        ConnConfig c = ConnConfig.parse(BASE + "?auth=browser", null);
        assertEquals("browser", c.auth);
        assertNull(c.token);
    }

    @Test
    void tokenAuthWithoutTokenThrowsExistingMessage() {
        SQLException e = assertThrows(SQLException.class, () -> ConnConfig.parse(BASE + "?auth=token", null));
        assertEquals("thunderduck JDBC requires an API token (URL ?token=… or the password property)",
                e.getMessage());
    }

    @Test
    void unknownAuthThrows() {
        SQLException e = assertThrows(SQLException.class, () -> ConnConfig.parse(BASE + "?auth=bogus", null));
        assertEquals("unknown auth value: bogus (use token or browser)", e.getMessage());
    }

    @Test
    void deviceSignInIsNotSupported() {
        SQLException e = assertThrows(SQLException.class, () -> ConnConfig.parse(BASE + "?auth=device", null));
        assertEquals("unknown auth value: device (use token or browser)", e.getMessage());
    }

    @Test
    void tokenCacheNoneParsesAndUnknownThrows() throws Exception {
        assertEquals("none", ConnConfig.parse(BASE + "?token=t&tokenCache=none", null).tokenCache);
        assertThrows(SQLException.class, () -> ConnConfig.parse(BASE + "?token=t&tokenCache=x", null));
    }

    @Test
    void issuerOverride() throws Exception {
        Properties p = new Properties();
        p.setProperty("issuer", "https://kc.example/realms/x");
        p.setProperty("auth", "browser");
        assertEquals("https://kc.example/realms/x", ConnConfig.parse(BASE, p).issuer);
    }

    /** A stub server that only counts requests to any path. */
    private static com.sun.net.httpserver.HttpServer countingServer(java.util.concurrent.atomic.AtomicInteger hits)
            throws Exception {
        com.sun.net.httpserver.HttpServer s =
                com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress("127.0.0.1", 0), 0);
        s.createContext("/", ex -> { hits.incrementAndGet(); ex.sendResponseHeaders(500, -1); ex.close(); });
        s.start();
        return s;
    }

    @Test
    void defaultIssuerRefusesNonThunderduckApiHostBeforeAnyRequest() throws Exception {
        java.util.concurrent.atomic.AtomicInteger hits = new java.util.concurrent.atomic.AtomicInteger();
        com.sun.net.httpserver.HttpServer api = countingServer(hits);
        try {
            SQLException e = assertThrows(SQLException.class, () -> new ThunderduckDriver().connect(
                    "jdbc:thunderduck://127.0.0.1:" + api.getAddress().getPort()
                            + "/?ssl=false&auth=browser&tokenCache=none", null));
            assertEquals("auth=browser with the Thunderduck sign-in can only connect to api.thunderduck.ai; "
                    + "set issuer for other hosts", e.getMessage());
            assertThrows(SQLException.class,
                    () -> new ThunderduckDriver().connect("jdbc:thunderduck://evil.example/?auth=browser", null));
            // One unauthenticated GET: discovery asks the host the connection names
            // (/.well-known/oauth-protected-resource) where its realm is. Nothing is
            // sent -- no token, no credentials -- and the refusal stands when it does
            // not answer with a realm of its own.
            assertEquals(1, hits.get());
        } finally {
            api.stop(0);
        }
    }

    @Test
    void aCleartextHostIsRefusedBeforeDiscoveryToo() throws Exception {
        // The transport rule runs before discovery, so an http host that is not loopback never
        // gets asked anything.
        java.util.concurrent.atomic.AtomicInteger hits = new java.util.concurrent.atomic.AtomicInteger();
        com.sun.net.httpserver.HttpServer api = countingServer(hits);
        try {
            assertThrows(SQLException.class, () -> new ThunderduckDriver().connect(
                    "jdbc:thunderduck://example.invalid:" + api.getAddress().getPort()
                            + "/?ssl=false&auth=browser&tokenCache=none", null));
            assertEquals(0, hits.get());
        } finally {
            api.stop(0);
        }
    }

    @Test
    void plainHttpToANonLoopbackHostIsRefusedBeforeAnyRequest() throws Exception {
        java.util.concurrent.atomic.AtomicInteger hits = new java.util.concurrent.atomic.AtomicInteger();
        com.sun.net.httpserver.HttpServer kc = countingServer(hits);
        try {
            String issuer = "http://127.0.0.1:" + kc.getAddress().getPort() + "/realms/td";
            SQLException e = assertThrows(SQLException.class, () -> new ThunderduckDriver().connect(
                    "jdbc:thunderduck://api.example.com/?ssl=false&auth=browser&tokenCache=none&issuer=" + issuer,
                    null));
            assertEquals("auth=browser requires https (ssl=true) except for localhost", e.getMessage());
            assertEquals(0, hits.get());
        } finally {
            kc.stop(0);
        }
    }

    @Test
    void discoveryReportingTheThunderduckIssuerAppliesTheApiHostRule() throws Exception {
        com.sun.net.httpserver.HttpServer kc =
                com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress("127.0.0.1", 0), 0);
        java.util.concurrent.atomic.AtomicInteger tokenCalls = new java.util.concurrent.atomic.AtomicInteger();
        kc.createContext("/realms/td/.well-known/openid-configuration", ex -> {
            String base = "http://127.0.0.1:" + kc.getAddress().getPort() + "/realms/td/protocol/openid-connect";
            byte[] b = ("{\"issuer\":\"https://auth.thunderduck.ai/realms/thunderduck\","
                    + "\"authorization_endpoint\":\"" + base + "/auth\",\"token_endpoint\":\"" + base + "/token\"}")
                    .getBytes(java.nio.charset.StandardCharsets.UTF_8);
            ex.sendResponseHeaders(200, b.length);
            ex.getResponseBody().write(b);
            ex.close();
        });
        kc.createContext("/realms/td/protocol", ex -> { tokenCalls.incrementAndGet(); ex.sendResponseHeaders(500, -1); ex.close(); });
        kc.start();
        try {
            String issuer = "http://127.0.0.1:" + kc.getAddress().getPort() + "/realms/td";
            // Sign-in happens at connect, so connecting is refused before any sign-in or token request.
            SQLException e = assertThrows(SQLException.class, () -> new ThunderduckDriver().connect(
                    "jdbc:thunderduck://127.0.0.1:1/?ssl=false&auth=browser&tokenCache=none&issuer=" + issuer, null));
            assertEquals("auth=browser with the Thunderduck sign-in can only connect to api.thunderduck.ai; "
                    + "set issuer for other hosts", e.getMessage());
            assertEquals(0, tokenCalls.get());
        } finally {
            kc.stop(0);
        }
    }

    /** Counts sign-ins and hands out numbered tokens. */
    static final class CountingSignIn implements io.thunderduck.jdbc.oidc.Authenticator {
        final java.util.concurrent.atomic.AtomicInteger calls = new java.util.concurrent.atomic.AtomicInteger();
        @Override public io.thunderduck.jdbc.oidc.Tokens signIn(io.thunderduck.jdbc.oidc.OidcEndpoints ep) {
            int n = calls.incrementAndGet();
            java.time.Instant now = java.time.Instant.now();
            return new io.thunderduck.jdbc.oidc.Tokens("access-" + n, now.plusSeconds(300), "refresh-" + n,
                    now.plusSeconds(1800));
        }
    }

    @Test
    void connectingSignsInAndASecondFileCachedConnectionReusesIt(@org.junit.jupiter.api.io.TempDir java.nio.file.Path tmp)
            throws Exception {
        io.thunderduck.jdbc.oidc.OidcTestSupport.resetSharedState();
        try {
            CountingSignIn signIn = new CountingSignIn();
            java.nio.file.Path cache = tmp.resolve("credentials.json");
            ThunderduckConnection.OidcFactory factory = cfg -> io.thunderduck.jdbc.oidc.OidcTestSupport.provider(
                    cfg, signIn, cache, java.time.Clock.systemUTC());
            String url = "jdbc:thunderduck://127.0.0.1:1/?ssl=false&auth=browser&issuer=http://127.0.0.1/realms/td";

            new ThunderduckConnection(ConnConfig.parse(url, null), factory);
            assertEquals(1, signIn.calls.get()); // during connect, before any query

            new ThunderduckConnection(ConnConfig.parse(url, null), factory);
            assertEquals(1, signIn.calls.get()); // tokenCache=file: the JVM-wide session is reused
            assertTrue(java.nio.file.Files.readString(cache).contains("refresh-1"));
        } finally {
            io.thunderduck.jdbc.oidc.OidcTestSupport.resetSharedState();
        }
    }

    @Test
    void connectingWithTokenCacheNoneSignsInEachTime() throws Exception {
        CountingSignIn signIn = new CountingSignIn();
        ThunderduckConnection.OidcFactory factory = cfg -> io.thunderduck.jdbc.oidc.OidcTestSupport.provider(
                cfg, signIn, java.nio.file.Path.of("unused"), java.time.Clock.systemUTC());
        String url = "jdbc:thunderduck://127.0.0.1:1/?ssl=false&auth=browser&tokenCache=none"
                + "&issuer=http://127.0.0.1/realms/td";
        new ThunderduckConnection(ConnConfig.parse(url, null), factory);
        new ThunderduckConnection(ConnConfig.parse(url, null), factory);
        assertEquals(2, signIn.calls.get());
    }

    @Test
    void failedSignInFailsTheConnect() throws Exception {
        ThunderduckConnection.OidcFactory factory = cfg -> io.thunderduck.jdbc.oidc.OidcTestSupport.provider(cfg,
                ep -> { throw new SQLException("Sign-in was cancelled or timed out (no response within 5 minutes).", "28000"); },
                java.nio.file.Path.of("unused"), java.time.Clock.systemUTC());
        String url = "jdbc:thunderduck://127.0.0.1:1/?ssl=false&auth=browser&tokenCache=none"
                + "&issuer=http://127.0.0.1/realms/td";
        SQLException e = assertThrows(SQLException.class,
                () -> new ThunderduckConnection(ConnConfig.parse(url, null), factory));
        assertEquals("Sign-in was cancelled or timed out (no response within 5 minutes).", e.getMessage());
    }

    @Test
    void driverAdvertisesAuthChoices() {
        DriverPropertyInfo[] infos = new ThunderduckDriver().getPropertyInfo(BASE, new Properties());
        DriverPropertyInfo auth = Arrays.stream(infos).filter(i -> i.name.equals("auth")).findFirst().orElseThrow();
        assertArrayEquals(new String[] {"token", "browser"}, auth.choices);
        DriverPropertyInfo token = Arrays.stream(infos).filter(i -> i.name.equals("token")).findFirst().orElseThrow();
        assertFalse(token.required);
    }
}
