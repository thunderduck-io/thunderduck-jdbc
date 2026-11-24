package io.thunderduck.jdbc;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.time.Duration;
import java.util.List;
import java.util.Map;

/** Talks to the thunderduck REST API over HTTPS with a Bearer token. */
final class ApiClient {

    private final String baseUrl; // e.g. https://api.thunderduck.ai
    private final AuthProvider auth;
    private final HttpClient http;
    private final long pollIntervalMs;
    private final long queryTimeoutMs;

    private static final int MAX_REDIRECTS = 3;

    // The API reports details for a signed-in identity it will not serve, and what the user is told.
    static final String UNKNOWN_USER_DETAIL = "no thunderduck user for this identity; sign in to the console once";
    static final String INACTIVE_USER_DETAIL = "user no longer active";
    static final String NO_ACCESS = "This account has no Thunderduck access yet — sign in to the console once at "
            + "https://console.thunderduck.ai, then try again.";
    static final String SUSPENDED = "Your Thunderduck account is suspended.";

    ApiClient(String baseUrl, AuthProvider auth, long pollIntervalMs, long queryTimeoutMs) {
        this.baseUrl = baseUrl.replaceAll("/+$", "");
        this.auth = auth;
        this.pollIntervalMs = pollIntervalMs;
        this.queryTimeoutMs = queryTimeoutMs;
        this.http = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(30))
                // Redirects are followed by hand, same origin only, so the bearer never leaves the API host.
                .followRedirects(HttpClient.Redirect.NEVER)
                .build();
    }

    // ---- result holders ----
    static final class Execution {
        String uuid;
        String status;        // success | error
        String errorMessage;
        String resultLocation;
        Long resultRowCount;
    }

    static final class ResultPage {
        List<String> columns;
        List<String> columnTypes;
        List<List<Object>> rows;
        long total;
    }

    // ---- operations ----

    /** Submit SQL as a query job; returns the execution id. */
    String submitQuery(String sql) throws SQLException {
        Map<String, Object> body = Map.of("sql", sql);
        HttpResponse<String> r = send("POST", "/queries", Json.write(body));
        if (r.statusCode() != 201 && r.statusCode() != 200) {
            throw new SQLException("submit failed (HTTP " + r.statusCode() + "): " + detail(r.body()));
        }
        Map<String, Object> m = Json.parseObject(r.body());
        Object id = m.get("id");
        if (id == null) throw new SQLException("no execution id in submit response");
        return id.toString();
    }

    /** Poll {@code GET /executions/{id}} until it reaches a terminal status
     *  (success / error / cancelled); the row is inserted as "running" at
     *  submit time and upserted to a terminal status by the DuckDB job, so a
     *  200 with status "running" (or a 404, defensively, in case this races
     *  the insert) both mean "keep polling" rather than "done".
     *
     *  {@code timeoutMsOverride}, when &gt; 0, is used as the overall
     *  deadline instead of the connection's configured default — this lets a
     *  caller honor {@link java.sql.Statement#setQueryTimeout(int)}.
     *
     *  Throws on "error" (with the server's error_message), "cancelled", or
     *  timeout. Returns only once status is "success". */
    @SuppressWarnings("unchecked")
    Execution awaitExecution(String id, long timeoutMsOverride) throws SQLException {
        long timeout = timeoutMsOverride > 0 ? timeoutMsOverride : queryTimeoutMs;
        long deadline = System.currentTimeMillis() + timeout;
        while (true) {
            HttpResponse<String> r = send("GET", "/executions/" + enc(id), null);
            if (r.statusCode() == 200) {
                Map<String, Object> m = Json.parseObject(r.body());
                Execution e = new Execution();
                e.uuid = str(m.get("uuid"));
                e.status = str(m.get("status"));
                e.errorMessage = str(m.get("error_message"));
                e.resultLocation = str(m.get("result_location"));
                Object rc = m.get("result_row_count");
                e.resultRowCount = rc == null ? null : (long) Double.parseDouble(rc.toString());
                if ("success".equalsIgnoreCase(e.status)) {
                    return e;
                }
                if ("error".equalsIgnoreCase(e.status)) {
                    throw new SQLException("query failed: "
                            + (e.errorMessage == null ? "(no message)" : e.errorMessage));
                }
                if ("cancelled".equalsIgnoreCase(e.status)) {
                    throw new SQLException("query was cancelled");
                }
                // else "running" (or any other non-terminal status) — keep polling.
            } else if (r.statusCode() != 404) {
                throw new SQLException("poll failed (HTTP " + r.statusCode() + "): " + detail(r.body()));
            }
            if (System.currentTimeMillis() > deadline) {
                throw new SQLException("query timed out after " + timeout + " ms");
            }
            sleep(pollIntervalMs);
        }
    }

    /** Fetch one page of an execution's result set. Returns {@code null} when
     *  the execution has no stored result at all (404 — a non-SELECT query).
     *  Throws a clear {@link SQLException} on 409: the run itself succeeded,
     *  but its stored result has since expired — re-running the query is the
     *  only way to read it, so this must not come back as an empty/null page. */
    @SuppressWarnings("unchecked")
    ResultPage fetchResultPage(String id, int limit, long offset) throws SQLException {
        HttpResponse<String> r = send("GET",
                "/executions/" + enc(id) + "/result?limit=" + limit + "&offset=" + offset, null);
        if (r.statusCode() == 404) return null; // no stored result (non-SELECT)
        if (r.statusCode() == 409) {
            throw new SQLException("result expired; re-run the query (" + detail(r.body()) + ")");
        }
        if (r.statusCode() != 200) {
            throw new SQLException("result fetch failed (HTTP " + r.statusCode() + "): " + detail(r.body()));
        }
        Map<String, Object> m = Json.parseObject(r.body());
        ResultPage p = new ResultPage();
        p.columns = (List<String>) (List<?>) m.get("columns");
        p.columnTypes = (List<String>) (List<?>) m.getOrDefault("column_types", List.of());
        p.rows = (List<List<Object>>) (List<?>) m.get("rows");
        Object tot = m.get("total");
        p.total = tot == null ? (p.rows == null ? 0 : p.rows.size()) : (long) Double.parseDouble(tot.toString());
        return p;
    }

    /** The company's catalog schema tree (for DatabaseMetaData). */
    @SuppressWarnings("unchecked")
    Map<String, Object> fetchSchema() throws SQLException {
        HttpResponse<String> r = send("GET", "/catalog/schema", null);
        if (r.statusCode() != 200) {
            throw new SQLException("schema fetch failed (HTTP " + r.statusCode() + ")");
        }
        return Json.parseObject(r.body());
    }

    // ---- http plumbing ----
    private HttpResponse<String> send(String method, String path, String body) throws SQLException {
        HttpResponse<String> r = checkAccount(sendOnce(method, path, body));
        if (r.statusCode() != 401) return r;
        if (!auth.canRenew()) throw new SQLException("authentication failed (check token)", "28000");
        // The bearer was rejected: let the provider drop/refresh it, retry once.
        auth.invalidate();
        r = checkAccount(sendOnce(method, path, body));
        if (r.statusCode() == 401) throw new SQLException("authentication failed", "28000");
        return r;
    }

    /** Turns "this identity has no usable Thunderduck account" answers into the user-facing messages. */
    private static HttpResponse<String> checkAccount(HttpResponse<String> r) throws SQLException {
        int status = r.statusCode();
        if (status != 401 && status != 404) return r;
        String detail = detail(r.body());
        if (status == 404 && UNKNOWN_USER_DETAIL.equals(detail)) throw new SQLException(NO_ACCESS, "28000");
        if (status == 401 && INACTIVE_USER_DETAIL.equals(detail)) throw new SQLException(SUSPENDED, "28000");
        return r;
    }

    private HttpResponse<String> sendOnce(String method, String path, String body) throws SQLException {
        String bearer = auth.bearer();
        URI uri = URI.create(baseUrl + path);
        for (int hop = 0; ; hop++) {
            HttpResponse<String> r = exchange(uri, method, body, bearer);
            int status = r.statusCode();
            if (status != 301 && status != 302 && status != 303 && status != 307 && status != 308) return r;
            String location = r.headers().firstValue("Location").orElse(null);
            if (location == null) return r;
            if (hop == MAX_REDIRECTS) {
                throw new SQLException("too many redirects for " + method + " " + path);
            }
            URI next;
            try {
                next = uri.resolve(location);
            } catch (IllegalArgumentException e) {
                throw new SQLException("bad redirect location: " + location, e);
            }
            if (!sameOrigin(uri, next)) {
                throw new SQLException("refusing redirect to another host: "
                        + (next.getHost() == null ? location : next.getHost()));
            }
            if (status != 307 && status != 308) { // 301/302/303 continue as GET without a body
                method = "GET";
                body = null;
            }
            uri = next;
        }
    }

    private HttpResponse<String> exchange(URI uri, String method, String body, String bearer) throws SQLException {
        try {
            HttpRequest.Builder b = HttpRequest.newBuilder()
                    .uri(uri)
                    .timeout(Duration.ofSeconds(60))
                    .header("Authorization", "Bearer " + bearer)
                    .header("Accept", "application/json");
            if (body != null) {
                b.header("Content-Type", "application/json")
                        .method(method, HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8));
            } else {
                b.method(method, HttpRequest.BodyPublishers.noBody());
            }
            return http.send(b.build(), HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (Exception e) {
            String target = uri.getRawPath() + (uri.getRawQuery() == null ? "" : "?" + uri.getRawQuery());
            throw new SQLException("HTTP " + method + " " + target + " failed: " + e.getMessage(), e);
        }
    }

    /** Same scheme, host and (effective) port. */
    private static boolean sameOrigin(URI a, URI b) {
        return a.getScheme() != null && a.getScheme().equalsIgnoreCase(b.getScheme())
                && a.getHost() != null && a.getHost().equalsIgnoreCase(b.getHost())
                && port(a) == port(b);
    }

    private static int port(URI u) {
        if (u.getPort() != -1) return u.getPort();
        return "https".equalsIgnoreCase(u.getScheme()) ? 443 : "http".equalsIgnoreCase(u.getScheme()) ? 80 : -1;
    }

    private static String detail(String body) {
        if (body == null || body.isEmpty()) return "";
        try {
            Object d = Json.parseObject(body).get("detail");
            if (d != null) return d.toString();
        } catch (Exception ignored) { /* not json */ }
        return body.length() > 300 ? body.substring(0, 300) : body;
    }

    private static String enc(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8);
    }

    private static String str(Object o) { return o == null ? null : o.toString(); }

    private static void sleep(long ms) throws SQLException {
        try {
            Thread.sleep(ms);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new SQLException("interrupted while waiting for query", e);
        }
    }
}
