package io.thunderduck.jdbc.oidc;

import io.thunderduck.jdbc.ConnConfig;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.file.Path;
import java.sql.SQLException;
import java.time.Clock;

/** Test-only access to OidcProvider's seams from other packages. */
public final class OidcTestSupport {

    private OidcTestSupport() { }

    /**
     * The provider forConfig would build for {@code cfg} (same host check, same cache semantics), but
     * with fixed endpoints on the issuer's host, the given sign-in and the given cache file.
     */
    public static OidcProvider provider(ConnConfig cfg, Authenticator signIn, Path cacheFile, Clock clock)
            throws SQLException {
        OidcProvider.checkApiHost(cfg.issuer, cfg.baseUrl);
        URI realm = URI.create(cfg.issuer.replaceAll("/+$", "") + "/protocol/openid-connect");
        OidcEndpoints ep = new OidcEndpoints(URI.create(realm + "/auth"), URI.create(realm + "/token"));
        return OidcProvider.create(cfg.issuer, cfg.baseUrl, () -> ep, signIn, cfg.tokenCache, cacheFile,
                HttpClient.newHttpClient(), clock);
    }

    public static void resetSharedState() {
        OidcProvider.resetSharedStateForTests();
    }
}
