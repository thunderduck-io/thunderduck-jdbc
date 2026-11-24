package io.thunderduck.jdbc;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * End-to-end tests of the store-then-fetch query flow: submit -> poll
 * {@code GET /executions/{id}} to a terminal status -> page the stored result
 * via {@code GET /executions/{id}/result}. Exercised through the public JDBC
 * surface (DriverManager -> Statement -> ResultSet) against a tiny in-process
 * HTTP stub standing in for the thunderduck API, since the driver has zero runtime
 * dependencies and this needs no more than the JDK's own HttpServer.
 */
class ThunderduckQueryFlowTest {

    private HttpServer server;

    @AfterEach
    void stopServer() {
        if (server != null) server.stop(0);
    }

    private String jdbcUrl() {
        int port = server.getAddress().getPort();
        return "jdbc:thunderduck://127.0.0.1:" + port + "/?token=t&ssl=false&poll_ms=5&timeout_ms=5000";
    }

    private static void respond(HttpExchange ex, int status, String body) throws IOException {
        byte[] b = body.getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().add("Content-Type", "application/json");
        ex.sendResponseHeaders(status, b.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(b);
        }
    }

    private static Map<String, String> queryParams(HttpExchange ex) {
        Map<String, String> m = new HashMap<>();
        String q = ex.getRequestURI().getQuery();
        if (q == null) return m;
        for (String kv : q.split("&")) {
            int i = kv.indexOf('=');
            if (i >= 0) m.put(kv.substring(0, i), kv.substring(i + 1));
        }
        return m;
    }

    private HttpServer newServer() throws IOException {
        HttpServer s = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        s.setExecutor(null);
        return s;
    }

    // ---- happy path: paginated result across multiple pages ----
    @Test
    void executesAndPagesTheStoredResult() throws Exception {
        server = newServer();
        AtomicInteger statusPolls = new AtomicInteger();

        server.createContext("/queries", ex -> respond(ex, 201, Json.write(Map.of("id", "exec-1"))));

        // Report "running" twice before "success" — proves the driver actually
        // waits for a terminal status instead of returning on the first 200
        // (the bug: the old poll loop treated any 200 as done).
        // HttpServer dispatches to the longest matching context prefix, so
        // GET /executions/exec-1/result is served by the more specific
        // context registered below rather than this one.
        server.createContext("/executions/exec-1", ex -> {
            String status = statusPolls.incrementAndGet() <= 2 ? "running" : "success";
            respond(ex, 200, Json.write(Map.of("uuid", "exec-1", "status", status)));
        });

        List<String> columns = List.of("id", "name");
        List<String> types = List.of("INTEGER", "VARCHAR");
        List<List<Object>> allRows = List.of(
                List.of(1.0, "a"), List.of(2.0, "b"), List.of(3.0, "c"), List.of(4.0, "d"), List.of(5.0, "e"));
        server.createContext("/executions/exec-1/result", ex -> {
            Map<String, String> p = queryParams(ex);
            int limit = Integer.parseInt(p.get("limit"));
            int offset = Integer.parseInt(p.get("offset"));
            int end = Math.min(offset + limit, allRows.size());
            List<List<Object>> page = offset >= allRows.size() ? List.of() : allRows.subList(offset, end);
            Map<String, Object> body = new HashMap<>();
            body.put("columns", columns);
            body.put("column_types", types);
            body.put("rows", page);
            body.put("total", (double) allRows.size());
            respond(ex, 200, Json.write(body));
        });
        server.start();

        try (Connection conn = DriverManager.getConnection(jdbcUrl());
             Statement st = conn.createStatement()) {
            st.setFetchSize(2); // force multiple /result pages over 5 rows
            try (ResultSet rs = st.executeQuery("select id, name from t")) {
                assertEquals(2, rs.getMetaData().getColumnCount());
                assertEquals(java.sql.Types.INTEGER, rs.getMetaData().getColumnType(1));
                assertEquals(java.sql.Types.VARCHAR, rs.getMetaData().getColumnType(2));

                int count = 0;
                while (rs.next()) {
                    count++;
                    assertEquals(count, rs.getInt(1));
                }
                assertEquals(5, count);
                assertFalse(rs.next());
            }
        }
        assertTrue(statusPolls.get() >= 3, "must poll past the non-terminal 'running' statuses");
    }

    // ---- error status -> SQLException(error_message) ----
    @Test
    void errorStatusThrowsWithServerMessage() throws Exception {
        server = newServer();
        server.createContext("/queries", ex -> respond(ex, 201, Json.write(Map.of("id", "exec-err"))));
        server.createContext("/executions/exec-err", ex -> respond(ex, 200,
                Json.write(Map.of("uuid", "exec-err", "status", "error", "error_message", "syntax error near X"))));
        server.start();

        try (Connection conn = DriverManager.getConnection(jdbcUrl());
             Statement st = conn.createStatement()) {
            SQLException ex = assertThrows(SQLException.class, () -> st.executeQuery("select 1"));
            assertTrue(ex.getMessage().contains("syntax error near X"), ex.getMessage());
        }
    }

    // ---- cancelled status -> SQLException ----
    @Test
    void cancelledStatusThrows() throws Exception {
        server = newServer();
        server.createContext("/queries", ex -> respond(ex, 201, Json.write(Map.of("id", "exec-cancel"))));
        server.createContext("/executions/exec-cancel", ex -> respond(ex, 200,
                Json.write(Map.of("uuid", "exec-cancel", "status", "cancelled"))));
        server.start();

        try (Connection conn = DriverManager.getConnection(jdbcUrl());
             Statement st = conn.createStatement()) {
            SQLException ex = assertThrows(SQLException.class, () -> st.executeQuery("select 1"));
            assertTrue(ex.getMessage().toLowerCase().contains("cancel"), ex.getMessage());
        }
    }

    // ---- expired stored result (409) -> a clear SQLException, not empty rows ----
    @Test
    void expiredResultThrowsInsteadOfEmptyRows() throws Exception {
        server = newServer();
        server.createContext("/queries", ex -> respond(ex, 201, Json.write(Map.of("id", "exec-exp"))));
        server.createContext("/executions/exec-exp",
                ex -> respond(ex, 200, Json.write(Map.of("uuid", "exec-exp", "status", "success"))));
        server.createContext("/executions/exec-exp/result", ex -> respond(ex, 409,
                Json.write(Map.of("detail", "result expired (removed from scratch storage); re-run the query"))));
        server.start();

        try (Connection conn = DriverManager.getConnection(jdbcUrl());
             Statement st = conn.createStatement()) {
            SQLException ex = assertThrows(SQLException.class, () -> st.executeQuery("select 1"));
            String msg = ex.getMessage().toLowerCase();
            assertTrue(msg.contains("expired") && msg.contains("re-run"), ex.getMessage());
        }
    }
}
