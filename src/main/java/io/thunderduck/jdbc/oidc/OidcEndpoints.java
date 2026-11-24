package io.thunderduck.jdbc.oidc;

import io.thunderduck.jdbc.Json;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.time.Duration;
import java.util.Map;

/**
 * The realm endpoints the driver uses. {@code issuer} is the discovery document's own {@code issuer} (null when not discovered).
 */
public record OidcEndpoints(URI authorization, URI token, String issuer) {

    public OidcEndpoints(URI authorization, URI token) {
        this(authorization, token, null);
    }

    /** Reads {@code <issuer>/.well-known/openid-configuration}. */
    public static OidcEndpoints discover(String issuer, HttpClient http) throws SQLException {
        String url = issuer.replaceAll("/+$", "") + "/.well-known/openid-configuration";
        Map<String, Object> doc;
        try {
            HttpResponse<String> r = http.send(
                    HttpRequest.newBuilder(URI.create(url))
                            .timeout(Duration.ofSeconds(30))
                            .header("Accept", "application/json")
                            .GET().build(),
                    HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            if (r.statusCode() != 200) {
                throw new SQLException("sign-in discovery failed for " + issuer + " (HTTP " + r.statusCode() + ")", "08001");
            }
            doc = Json.parseObject(r.body());
        } catch (SQLException e) {
            throw e;
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new SQLException("sign-in discovery interrupted", "08001", e);
        } catch (Exception e) {
            throw new SQLException("sign-in discovery failed for " + issuer + ": " + e.getMessage(), "08001", e);
        }
        return new OidcEndpoints(
                required(doc, "authorization_endpoint", issuer),
                required(doc, "token_endpoint", issuer),
                doc.get("issuer") instanceof String ? (String) doc.get("issuer") : null);
    }

    private static URI required(Map<String, Object> doc, String field, String issuer) throws SQLException {
        URI u = optional(doc, field);
        if (u == null) throw new SQLException("sign-in discovery for " + issuer + " has no " + field, "08001");
        return u;
    }

    private static URI optional(Map<String, Object> doc, String field) throws SQLException {
        Object v = doc.get(field);
        if (!(v instanceof String) || ((String) v).isEmpty()) return null;
        try {
            return URI.create((String) v);
        } catch (IllegalArgumentException e) {
            throw new SQLException("sign-in discovery returned a bad " + field, "08001", e);
        }
    }
}
