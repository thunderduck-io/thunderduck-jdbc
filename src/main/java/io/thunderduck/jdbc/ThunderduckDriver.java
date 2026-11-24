package io.thunderduck.jdbc;

import java.sql.Connection;
import java.sql.Driver;
import java.sql.DriverManager;
import java.sql.DriverPropertyInfo;
import java.sql.SQLException;
import java.util.Properties;
import java.util.logging.Logger;

/**
 * JDBC driver for thunderduck.
 *
 * URL:  jdbc:thunderduck://api.thunderduck.ai[:443]/[?token=tdk_...&amp;poll_ms=1000&amp;timeout_ms=300000]
 * The token may also be passed as the JDBC "password" (or "token") property.
 */
public final class ThunderduckDriver implements Driver {

    static final String PREFIX = "jdbc:thunderduck:";
    static final int MAJOR = 0;
    static final int MINOR = 2;

    static {
        try {
            DriverManager.registerDriver(new ThunderduckDriver());
        } catch (SQLException e) {
            throw new RuntimeException("failed to register thunderduck JDBC driver", e);
        }
    }

    @Override
    public boolean acceptsURL(String url) {
        return url != null && url.startsWith(PREFIX);
    }

    @Override
    public Connection connect(String url, Properties info) throws SQLException {
        if (!acceptsURL(url)) return null; // per JDBC contract: not our URL
        ConnConfig cfg = ConnConfig.parse(url, info);
        return new ThunderduckConnection(cfg);
    }

    @Override
    public DriverPropertyInfo[] getPropertyInfo(String url, Properties info) {
        DriverPropertyInfo token = new DriverPropertyInfo("token", info == null ? null : info.getProperty("token"));
        token.description = "thunderduck API token (tdk_...). May also be the password property.";
        token.required = false; // only needed when auth=token
        DriverPropertyInfo auth = new DriverPropertyInfo("auth", info == null ? null : info.getProperty("auth"));
        auth.description = "Authentication: token (API token, default) or browser sign-in.";
        auth.choices = new String[] {"token", "browser"};
        auth.required = false;
        DriverPropertyInfo cache = new DriverPropertyInfo("tokenCache", info == null ? null : info.getProperty("tokenCache"));
        cache.description = "Cache sign-in tokens in ~/.thunderduck/credentials.json (file, default) or not (none).";
        cache.choices = new String[] {"file", "none"};
        cache.required = false;
        return new DriverPropertyInfo[] { token, auth, cache };
    }

    @Override
    public int getMajorVersion() { return MAJOR; }

    @Override
    public int getMinorVersion() { return MINOR; }

    @Override
    public boolean jdbcCompliant() { return false; }

    @Override
    public Logger getParentLogger() {
        return Logger.getLogger("io.thunderduck.jdbc");
    }
}
