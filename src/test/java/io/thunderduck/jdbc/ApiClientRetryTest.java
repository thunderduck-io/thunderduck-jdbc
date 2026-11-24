package io.thunderduck.jdbc;

import static org.junit.jupiter.api.Assertions.*;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

class ApiClientRetryTest {

    private HttpServer server;

    @AfterEach
    void stop() {
        if (server != null) server.stop(0);
    }

    static final class CountingProvider implements AuthProvider {
        final AtomicInteger bearers = new AtomicInteger();
        final AtomicInteger invalidations = new AtomicInteger();
        @Override public String bearer() { return "tok" + bearers.incrementAndGet(); }
        @Override public void invalidate() { invalidations.incrementAndGet(); }
        @Override public boolean canRenew() { return true; }
    }

    private ApiClient start(java.util.function.IntUnaryOperator statusForCall, AtomicInteger calls,
                            java.util.List<String> seenAuth, AuthProvider p) throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/queries", ex -> {
            seenAuth.add(ex.getRequestHeaders().getFirst("Authorization"));
            int status = statusForCall.applyAsInt(calls.incrementAndGet());
            byte[] b = Json.write(Map.of("id", "e1")).getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(status, b.length);
            ex.getResponseBody().write(b);
            ex.close();
        });
        server.start();
        return new ApiClient("http://127.0.0.1:" + server.getAddress().getPort(), p, 5, 5000);
    }

    @Test
    void retriesOnceAfter401WithFreshBearer() throws Exception {
        CountingProvider p = new CountingProvider();
        java.util.List<String> seen = new java.util.concurrent.CopyOnWriteArrayList<>();
        ApiClient c = start(n -> n == 1 ? 401 : 201, new AtomicInteger(), seen, p);
        assertEquals("e1", c.submitQuery("select 1"));
        assertEquals(1, p.invalidations.get());
        assertEquals(2, p.bearers.get());
        assertEquals(java.util.List.of("Bearer tok1", "Bearer tok2"), seen);
    }

    @Test
    void secondConsecutive401Fails() throws Exception {
        CountingProvider p = new CountingProvider();
        AtomicInteger calls = new AtomicInteger();
        ApiClient c = start(n -> 401, calls, new java.util.concurrent.CopyOnWriteArrayList<>(), p);
        SQLException e = assertThrows(SQLException.class, () -> c.submitQuery("select 1"));
        assertEquals("28000", e.getSQLState());
        assertEquals("authentication failed", e.getMessage());
        assertEquals(2, calls.get());
        assertEquals(1, p.invalidations.get());
    }

    @Test
    void successCallsBearerOnce() throws Exception {
        CountingProvider p = new CountingProvider();
        ApiClient c = start(n -> 201, new AtomicInteger(), new java.util.concurrent.CopyOnWriteArrayList<>(), p);
        c.submitQuery("select 1");
        assertEquals(1, p.bearers.get());
        assertEquals(0, p.invalidations.get());
    }

    @Test
    void staticTokenIs401OnceWithCheckTokenMessage() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        ApiClient c = start(n -> 401, calls, new java.util.concurrent.CopyOnWriteArrayList<>(),
                new StaticTokenProvider("tdk_x"));
        SQLException e = assertThrows(SQLException.class, () -> c.submitQuery("select 1"));
        assertEquals("28000", e.getSQLState());
        assertEquals("authentication failed (check token)", e.getMessage());
        assertEquals(1, calls.get());
    }

    // ---- redirects ----

    private HttpServer other;

    @AfterEach
    void stopOther() {
        if (other != null) other.stop(0);
    }

    private static void reply(com.sun.net.httpserver.HttpExchange ex, int status, String location, String body)
            throws java.io.IOException {
        if (location != null) ex.getResponseHeaders().add("Location", location);
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.sendResponseHeaders(status, b.length == 0 ? -1 : b.length);
        if (b.length > 0) ex.getResponseBody().write(b);
        ex.close();
    }

    @Test
    void sameOriginRedirectIsFollowedWithBearerMethodAndBody() throws Exception {
        java.util.List<String> seen = new java.util.concurrent.CopyOnWriteArrayList<>();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/queries", ex -> reply(ex, 307, "/v2/queries", ""));
        server.createContext("/v2/queries", ex -> {
            seen.add(ex.getRequestMethod() + " " + ex.getRequestHeaders().getFirst("Authorization") + " "
                    + new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            reply(ex, 201, null, Json.write(Map.of("id", "e1")));
        });
        server.start();
        ApiClient c = new ApiClient("http://127.0.0.1:" + server.getAddress().getPort(),
                new CountingProvider(), 5, 5000);
        assertEquals("e1", c.submitQuery("select 1"));
        assertEquals(1, seen.size());
        assertTrue(seen.get(0).startsWith("POST Bearer tok1 {"), seen.get(0));
        assertTrue(seen.get(0).contains("select 1"), seen.get(0));
    }

    @Test
    void crossOriginRedirectIsRefusedAndTheOtherHostSeesNothing() throws Exception {
        AtomicInteger otherHits = new AtomicInteger();
        other = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        other.createContext("/", ex -> { otherHits.incrementAndGet(); reply(ex, 201, null, "{\"id\":\"x\"}"); });
        other.start();
        int otherPort = other.getAddress().getPort();

        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/queries", ex -> reply(ex, 302, "http://localhost:" + otherPort + "/steal", ""));
        server.createContext("/executions", ex -> reply(ex, 308, "http://127.0.0.1:" + otherPort + "/steal", ""));
        server.start();
        ApiClient c = new ApiClient("http://127.0.0.1:" + server.getAddress().getPort(),
                new CountingProvider(), 5, 5000);

        SQLException e = assertThrows(SQLException.class, () -> c.submitQuery("select 1"));
        assertEquals("refusing redirect to another host: localhost", e.getMessage());
        SQLException e2 = assertThrows(SQLException.class, () -> c.awaitExecution("e1", 5000));
        assertEquals("refusing redirect to another host: 127.0.0.1", e2.getMessage());
        assertEquals(0, otherHits.get());
    }

    @Test
    void redirectLoopStopsAfterThreeHops() throws Exception {
        AtomicInteger hits = new AtomicInteger();
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/queries", ex -> { hits.incrementAndGet(); reply(ex, 302, "/queries", ""); });
        server.start();
        ApiClient c = new ApiClient("http://127.0.0.1:" + server.getAddress().getPort(),
                new CountingProvider(), 5, 5000);
        assertThrows(SQLException.class, () -> c.submitQuery("select 1"));
        assertEquals(4, hits.get());
    }

    // ---- account state ----

    private ApiClient replying(int status, String body, AtomicInteger calls, AuthProvider p) throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/", ex -> { calls.incrementAndGet(); reply(ex, status, null, body); });
        server.start();
        return new ApiClient("http://127.0.0.1:" + server.getAddress().getPort(), p, 5, 5000);
    }

    @Test
    void suspendedUserMessage() throws Exception {
        AtomicInteger calls = new AtomicInteger();
        CountingProvider p = new CountingProvider();
        ApiClient c = replying(401, "{\"detail\":\"user no longer active\"}", calls, p);
        SQLException e = assertThrows(SQLException.class, () -> c.submitQuery("select 1"));
        assertEquals("Your Thunderduck account is suspended.", e.getMessage());
        assertEquals("28000", e.getSQLState());
        // Suspension is final: no token renewal and no retry.
        assertEquals(1, calls.get());
        assertEquals(0, p.invalidations.get());
    }

    @Test
    void suspendedUserMessageForStaticToken() throws Exception {
        ApiClient c = replying(401, "{\"detail\":\"user no longer active\"}", new AtomicInteger(),
                new StaticTokenProvider("tdk_x"));
        SQLException e = assertThrows(SQLException.class, () -> c.submitQuery("select 1"));
        assertEquals("Your Thunderduck account is suspended.", e.getMessage());
    }

    @Test
    void unknownUserMessage() throws Exception {
        String body = "{\"detail\":\"no thunderduck user for this identity; sign in to the console once\"}";
        String expected = "This account has no Thunderduck access yet — sign in to the console once at "
                + "https://console.thunderduck.ai, then try again.";
        AtomicInteger calls = new AtomicInteger();
        ApiClient c = replying(404, body, calls, new CountingProvider());
        SQLException e = assertThrows(SQLException.class, () -> c.submitQuery("select 1"));
        assertEquals(expected, e.getMessage());
        assertEquals("28000", e.getSQLState());
        // Also while polling, where a plain 404 means "keep polling".
        SQLException e2 = assertThrows(SQLException.class, () -> c.awaitExecution("e1", 5000));
        assertEquals(expected, e2.getMessage());
        assertEquals(2, calls.get());
    }

    @Test
    void otherNotFoundStaysAsBefore() throws Exception {
        ApiClient c = replying(404, "{\"detail\":\"Not Found\"}", new AtomicInteger(), new CountingProvider());
        assertNull(c.fetchResultPage("e1", 10, 0));
    }
}
