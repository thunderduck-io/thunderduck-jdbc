package io.thunderduck.jdbc;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Parsed connection settings from the JDBC URL + properties. */
public final class ConnConfig {

    static final String DEFAULT_ISSUER = "https://auth.thunderduck.ai/realms/thunderduck";

    /**
     * A BYOC install serves the realm beside the API: {@code <company>-api.<domain>} for queries and
     * {@code <company>-auth.<domain>} for sign-in. Used to default the issuer from the host the
     * connection names, so browser sign-in needs no {@code issuer} parameter on those installs.
     */
    private static final Pattern BYOC_API_HOST = Pattern.compile("^([a-z0-9-]+)-api\\.(.+)$");
    private static final String REALM_PATH = "/realms/thunderduck";

    // Public so the io.thunderduck.jdbc.oidc package can read its settings.
    public final String baseUrl;      // https://host[:port]
    public final String token;        // null unless auth == "token"
    public final String auth;         // token | browser
    public final String tokenCache;   // file | none
    public final String issuer;
    /** True when the caller named the issuer; false when it was defaulted (discovery may replace it). */
    public final boolean issuerExplicit;
    public final long pollMs;
    public final long timeoutMs;

    private ConnConfig(String baseUrl, String token, String auth, String tokenCache, String issuer,
                       boolean issuerExplicit, long pollMs, long timeoutMs) {
        this.baseUrl = baseUrl;
        this.token = token;
        this.auth = auth;
        this.tokenCache = tokenCache;
        this.issuer = issuer;
        this.issuerExplicit = issuerExplicit;
        this.pollMs = pollMs;
        this.timeoutMs = timeoutMs;
    }

    static ConnConfig parse(String url, Properties info) throws SQLException {
        // Strip the JDBC prefix, leaving //host[:port]/[?query]
        String rest = url.substring(ThunderduckDriver.PREFIX.length());
        if (rest.startsWith("//")) rest = rest.substring(2);

        String hostPort;
        String query = "";
        int q = rest.indexOf('?');
        if (q >= 0) {
            query = rest.substring(q + 1);
            rest = rest.substring(0, q);
        }
        int slash = rest.indexOf('/');
        hostPort = slash >= 0 ? rest.substring(0, slash) : rest;
        if (hostPort.isEmpty()) throw new SQLException("thunderduck JDBC URL is missing a host");

        Map<String, String> params = parseQuery(query);
        Properties p = info == null ? new Properties() : info;

        boolean tls = !"false".equalsIgnoreCase(first(params.get("ssl"), p.getProperty("ssl"), "true"));
        String scheme = tls ? "https://" : "http://";
        String baseUrl = scheme + hostPort;

        String auth = first(params.get("auth"), p.getProperty("auth"), "token");
        if (!auth.equals("token") && !auth.equals("browser")) {
            throw new SQLException("unknown auth value: " + auth + " (use token or browser)");
        }
        String tokenCache = first(params.get("tokenCache"), p.getProperty("tokenCache"), "file");
        if (!tokenCache.equals("file") && !tokenCache.equals("none")) {
            throw new SQLException("unknown tokenCache value: " + tokenCache + " (use file or none)");
        }
        String issuer = first(params.get("issuer"), p.getProperty("issuer"));
        boolean issuerExplicit = issuer != null;
        if (issuer == null) issuer = defaultIssuer(baseUrl);

        String token = first(params.get("token"), p.getProperty("token"), p.getProperty("password"), null);
        if (auth.equals("token") && (token == null || token.isBlank())) {
            throw new SQLException("thunderduck JDBC requires an API token (URL ?token=… or the password property)");
        }

        long pollMs = parseLong(first(params.get("poll_ms"), p.getProperty("poll_ms"), "1000"));
        long timeoutMs = parseLong(first(params.get("timeout_ms"), p.getProperty("timeout_ms"), "300000"));

        return new ConnConfig(baseUrl, token, auth, tokenCache, issuer, issuerExplicit, pollMs, timeoutMs);
    }

    private static Map<String, String> parseQuery(String query) {
        Map<String, String> m = new HashMap<>();
        if (query == null || query.isEmpty()) return m;
        for (String kv : query.split("&")) {
            if (kv.isEmpty()) continue;
            int eq = kv.indexOf('=');
            if (eq < 0) {
                m.put(dec(kv), "");
            } else {
                m.put(dec(kv.substring(0, eq)), dec(kv.substring(eq + 1)));
            }
        }
        return m;
    }

    private static String dec(String s) {
        return URLDecoder.decode(s, StandardCharsets.UTF_8);
    }

    /**
     * The sign-in server for {@code baseUrl}: an install's API host
     * ({@code <company>-api.<domain>}) implies its auth host
     * ({@code <company>-auth.<domain>}); anything else -- the managed cloud's
     * {@code api.thunderduck.ai} included -- keeps the managed realm.
     */
    static String defaultIssuer(String baseUrl) {
        try {
            String host = URI.create(baseUrl).getHost();
            if (host != null) {
                Matcher m = BYOC_API_HOST.matcher(host.toLowerCase(Locale.ROOT));
                if (m.matches()) {
                    return "https://" + m.group(1) + "-auth." + m.group(2) + REALM_PATH;
                }
            }
        } catch (RuntimeException ignored) {
            // Unparseable host: fall through to the managed realm.
        }
        return DEFAULT_ISSUER;
    }

    private static String first(String... vals) {
        for (String v : vals) {
            if (v != null && !v.isBlank()) return v;
        }
        return null;
    }

    private static long parseLong(String s) {
        try {
            return Long.parseLong(s.trim());
        } catch (Exception e) {
            return 0L;
        }
    }
}
