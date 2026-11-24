package io.thunderduck.jdbc;

import io.thunderduck.jdbc.oidc.OidcProvider;
import java.sql.Array;
import java.sql.Blob;
import java.sql.CallableStatement;
import java.sql.Clob;
import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.NClob;
import java.sql.PreparedStatement;
import java.sql.SQLClientInfoException;
import java.sql.SQLException;
import java.sql.SQLWarning;
import java.sql.SQLXML;
import java.sql.Savepoint;
import java.sql.Statement;
import java.sql.Struct;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.Executor;

/** A thunderduck JDBC connection: a thin, read-only handle over the REST API. */
final class ThunderduckConnection implements Connection {

    private final ApiClient api;
    private final String url;
    private boolean closed;
    private volatile String currentCatalog;
    private volatile String currentSchema;
    private boolean defaultCatalogResolved; // guarded by this

    /** Builds the sign-in provider for {@code auth=browser}; a seam for tests. */
    @FunctionalInterface
    interface OidcFactory {
        AuthProvider create(ConnConfig cfg) throws SQLException;
    }

    ThunderduckConnection(ConnConfig cfg) throws SQLException {
        this(cfg, OidcProvider::forConfig);
    }

    ThunderduckConnection(ConnConfig cfg, OidcFactory oidc) throws SQLException {
        AuthProvider auth;
        if (cfg.auth.equals("token")) {
            auth = new StaticTokenProvider(cfg.token);
        } else {
            auth = oidc.create(cfg); // browser
            // Sign in now, so the browser opens while connecting, not on the first query.
            auth.bearer();
        }
        this.api = new ApiClient(cfg.baseUrl, auth, cfg.pollMs, cfg.timeoutMs);
        this.url = cfg.baseUrl;
    }

    ApiClient api() { return api; }
    String url() { return url; }

    @Override public Statement createStatement() throws SQLException { ensureOpen(); return new ThunderduckStatement(this, api); }
    @Override public Statement createStatement(int t, int c) throws SQLException { return createStatement(); }
    @Override public Statement createStatement(int t, int c, int h) throws SQLException { return createStatement(); }

    @Override public PreparedStatement prepareStatement(String sql) throws SQLException {
        ensureOpen();
        return new ThunderduckPreparedStatement(this, api, sql);
    }
    @Override public PreparedStatement prepareStatement(String sql, int t, int c) throws SQLException { return prepareStatement(sql); }
    @Override public PreparedStatement prepareStatement(String sql, int t, int c, int h) throws SQLException { return prepareStatement(sql); }
    @Override public PreparedStatement prepareStatement(String sql, int agk) throws SQLException { return prepareStatement(sql); }
    @Override public PreparedStatement prepareStatement(String sql, int[] ci) throws SQLException { return prepareStatement(sql); }
    @Override public PreparedStatement prepareStatement(String sql, String[] cn) throws SQLException { return prepareStatement(sql); }
    @Override public CallableStatement prepareCall(String sql) throws SQLException { throw Err.nyi("prepareCall"); }
    @Override public CallableStatement prepareCall(String sql, int t, int c) throws SQLException { throw Err.nyi("prepareCall"); }
    @Override public CallableStatement prepareCall(String sql, int t, int c, int h) throws SQLException { throw Err.nyi("prepareCall"); }

    @Override public DatabaseMetaData getMetaData() {
        return new ThunderduckDatabaseMetaData(this, api, url);
    }

    @Override public String nativeSQL(String sql) { return sql; }
    @Override public void setAutoCommit(boolean b) { }
    @Override public boolean getAutoCommit() { return true; }
    @Override public void commit() { }
    @Override public void rollback() { }
    @Override public void rollback(Savepoint s) throws SQLException { throw Err.nyi("rollback(savepoint)"); }
    @Override public void close() { closed = true; }
    @Override public boolean isClosed() { return closed; }
    @Override public void setReadOnly(boolean b) { }
    @Override public boolean isReadOnly() { return true; }
    // Remembered, not sent anywhere: statements name catalog.schema.table themselves. Tools such as
    // DataGrip switch the catalog and read it back before introspecting each one, and treat a
    // connection whose getCatalog() ignores setCatalog() as unable to see other catalogs.
    @Override public synchronized void setCatalog(String c) { currentCatalog = c; defaultCatalogResolved = true; }

    /**
     * Starts as the first catalog (alphabetically, as getCatalogs lists them), looked up once on first
     * use: with no current catalog, DataGrip adds a nameless "current database" beside the real ones.
     * Null only if the catalog list cannot be fetched.
     */
    @Override public synchronized String getCatalog() {
        if (!defaultCatalogResolved) {
            defaultCatalogResolved = true;
            try {
                java.util.TreeSet<String> names = new java.util.TreeSet<>();
                Object cats = api.fetchSchema().get("catalogs");
                if (cats instanceof java.util.List) {
                    for (Object c : (java.util.List<?>) cats) {
                        Object n = c instanceof java.util.Map ? ((java.util.Map<?, ?>) c).get("name") : null;
                        if (n instanceof String && !((String) n).isEmpty()) names.add((String) n);
                    }
                }
                if (!names.isEmpty()) currentCatalog = names.first();
            } catch (SQLException unavailable) {
                // no current catalog
            }
        }
        return currentCatalog;
    }
    @Override public void setSchema(String s) { currentSchema = s; }
    @Override public String getSchema() { return currentSchema; }
    @Override public void setTransactionIsolation(int level) { }
    @Override public int getTransactionIsolation() { return TRANSACTION_NONE; }
    @Override public SQLWarning getWarnings() { return null; }
    @Override public void clearWarnings() { }
    @Override public Map<String, Class<?>> getTypeMap() { return Map.of(); }
    @Override public void setTypeMap(Map<String, Class<?>> map) { }
    @Override public void setHoldability(int h) { }
    @Override public int getHoldability() { return java.sql.ResultSet.CLOSE_CURSORS_AT_COMMIT; }
    @Override public Savepoint setSavepoint() throws SQLException { throw Err.nyi("setSavepoint"); }
    @Override public Savepoint setSavepoint(String name) throws SQLException { throw Err.nyi("setSavepoint"); }
    @Override public void releaseSavepoint(Savepoint s) throws SQLException { throw Err.nyi("releaseSavepoint"); }

    @Override public Clob createClob() throws SQLException { throw Err.nyi("createClob"); }
    @Override public Blob createBlob() throws SQLException { throw Err.nyi("createBlob"); }
    @Override public NClob createNClob() throws SQLException { throw Err.nyi("createNClob"); }
    @Override public SQLXML createSQLXML() throws SQLException { throw Err.nyi("createSQLXML"); }
    @Override public Array createArrayOf(String t, Object[] e) throws SQLException { throw Err.nyi("createArrayOf"); }
    @Override public Struct createStruct(String t, Object[] a) throws SQLException { throw Err.nyi("createStruct"); }

    @Override public boolean isValid(int timeout) { return !closed; }
    @Override public void setClientInfo(String n, String v) throws SQLClientInfoException { }
    @Override public void setClientInfo(Properties p) throws SQLClientInfoException { }
    @Override public String getClientInfo(String name) { return null; }
    @Override public Properties getClientInfo() { return new Properties(); }
    @Override public void abort(Executor e) { closed = true; }
    @Override public void setNetworkTimeout(Executor e, int ms) { }
    @Override public int getNetworkTimeout() { return 0; }

    @Override public <T> T unwrap(Class<T> iface) throws SQLException {
        if (iface.isInstance(this)) return iface.cast(this);
        throw new SQLException("not a wrapper for " + iface);
    }
    @Override public boolean isWrapperFor(Class<?> iface) { return iface.isInstance(this); }

    private void ensureOpen() throws SQLException {
        if (closed) throw new SQLException("connection is closed");
    }
}
