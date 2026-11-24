package io.thunderduck.jdbc.oidc;

import java.sql.SQLException;
import java.time.Clock;
import java.time.Instant;
import java.util.Map;

/**
 * Tokens from the realm's token endpoint. Any field may be null: a cached entry has no access token,
 * and a null {@code refreshExpiresAt} means the server gave no refresh expiry.
 */
public record Tokens(String accessToken, Instant accessExpiresAt, String refreshToken, Instant refreshExpiresAt) {

    /** Builds tokens from a token-endpoint JSON response, using {@code expires_in} / {@code refresh_expires_in}. */
    public static Tokens fromResponse(Map<String, Object> json, Clock clock) {
        Instant now = clock.instant();
        return new Tokens(
                str(json.get("access_token")),
                expiry(now, json.get("expires_in")),
                str(json.get("refresh_token")),
                expiry(now, json.get("refresh_expires_in")));
    }

    /** Like {@link #fromResponse} but fails when the response carries no access token. */
    static Tokens requireAccess(Map<String, Object> json, Clock clock) throws SQLException {
        Tokens t = fromResponse(json, clock);
        if (t.accessToken() == null || t.accessToken().isEmpty()) {
            throw new SQLException("token response had no access_token", "28000");
        }
        return t;
    }

    /** True when a refresh token exists and has not passed its expiry. */
    boolean hasUsableRefresh(Instant now) {
        return refreshToken != null && !refreshToken.isEmpty()
                && (refreshExpiresAt == null || now.isBefore(refreshExpiresAt));
    }

    private static Instant expiry(Instant now, Object seconds) {
        if (!(seconds instanceof Number)) return null;
        long s = ((Number) seconds).longValue();
        // Keycloak sends refresh_expires_in = 0 for tokens without their own expiry.
        return s > 0 ? now.plusSeconds(s) : null;
    }

    private static String str(Object o) {
        return o instanceof String ? (String) o : null;
    }
}
