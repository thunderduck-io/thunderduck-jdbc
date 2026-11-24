package io.thunderduck.jdbc;

import java.io.InputStream;
import java.io.Reader;
import java.math.BigDecimal;
import java.net.URL;
import java.sql.Array;
import java.sql.Blob;
import java.sql.Clob;
import java.sql.Date;
import java.sql.NClob;
import java.sql.ParameterMetaData;
import java.sql.PreparedStatement;
import java.sql.Ref;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.RowId;
import java.sql.SQLException;
import java.sql.SQLXML;
import java.sql.Time;
import java.sql.Timestamp;
import java.util.HashMap;
import java.util.Map;

/** PreparedStatement with client-side parameter substitution (the REST API takes
 *  a plain SQL string). Read-oriented; batch/stream/LOB params are unsupported. */
final class ThunderduckPreparedStatement extends ThunderduckStatement implements PreparedStatement {

    private final String sql;
    private final Map<Integer, Object> params = new HashMap<>();

    ThunderduckPreparedStatement(ThunderduckConnection connection, ApiClient api, String sql) {
        super(connection, api);
        this.sql = sql;
    }

    /** Substitute ? placeholders (outside string literals) with SQL literals. */
    private String bound() throws SQLException {
        StringBuilder sb = new StringBuilder();
        boolean inStr = false;
        int p = 1;
        for (int i = 0; i < sql.length(); i++) {
            char ch = sql.charAt(i);
            if (ch == '\'') inStr = !inStr;
            if (ch == '?' && !inStr) {
                if (!params.containsKey(p)) throw new SQLException("missing binding for parameter " + p);
                sb.append(literal(params.get(p++)));
            } else {
                sb.append(ch);
            }
        }
        return sb.toString();
    }

    private static String literal(Object v) {
        if (v == null) return "NULL";
        if (v instanceof Number) return v.toString();
        if (v instanceof Boolean) return ((Boolean) v) ? "TRUE" : "FALSE";
        // strings, dates, times, timestamps, uuids → quoted, single quotes doubled
        return "'" + v.toString().replace("'", "''") + "'";
    }

    @Override public ResultSet executeQuery() throws SQLException { return run(bound()); }
    @Override public int executeUpdate() throws SQLException { run(bound()); return 0; }
    @Override public boolean execute() throws SQLException { run(bound()); return current.getMetaData().getColumnCount() > 0; }
    @Override public void clearParameters() { params.clear(); }
    @Override public ResultSetMetaData getMetaData() { return current == null ? null : current.getMetaData(); }
    @Override public ParameterMetaData getParameterMetaData() throws SQLException { throw Err.nyi("getParameterMetaData"); }
    @Override public void addBatch() throws SQLException { throw Err.nyi("addBatch"); }

    // ---- scalar setters (stored, substituted at execute) ----
    @Override public void setNull(int i, int t) { params.put(i, null); }
    @Override public void setNull(int i, int t, String n) { params.put(i, null); }
    @Override public void setBoolean(int i, boolean x) { params.put(i, x); }
    @Override public void setByte(int i, byte x) { params.put(i, x); }
    @Override public void setShort(int i, short x) { params.put(i, x); }
    @Override public void setInt(int i, int x) { params.put(i, x); }
    @Override public void setLong(int i, long x) { params.put(i, x); }
    @Override public void setFloat(int i, float x) { params.put(i, x); }
    @Override public void setDouble(int i, double x) { params.put(i, x); }
    @Override public void setBigDecimal(int i, BigDecimal x) { params.put(i, x); }
    @Override public void setString(int i, String x) { params.put(i, x); }
    @Override public void setDate(int i, Date x) { params.put(i, x); }
    @Override public void setDate(int i, Date x, java.util.Calendar c) { params.put(i, x); }
    @Override public void setTime(int i, Time x) { params.put(i, x); }
    @Override public void setTime(int i, Time x, java.util.Calendar c) { params.put(i, x); }
    @Override public void setTimestamp(int i, Timestamp x) { params.put(i, x); }
    @Override public void setTimestamp(int i, Timestamp x, java.util.Calendar c) { params.put(i, x); }
    @Override public void setObject(int i, Object x) { params.put(i, x); }
    @Override public void setObject(int i, Object x, int t) { params.put(i, x); }
    @Override public void setObject(int i, Object x, int t, int s) { params.put(i, x); }
    @Override public void setURL(int i, URL x) { params.put(i, x == null ? null : x.toString()); }
    @Override public void setNString(int i, String x) { params.put(i, x); }
    @Override public void setRowId(int i, RowId x) { params.put(i, x == null ? null : x.toString()); }

    // ---- binary / stream / LOB params: unsupported ----
    @Override public void setBytes(int i, byte[] x) throws SQLException { throw Err.nyi("setBytes"); }
    @Override public void setAsciiStream(int i, InputStream x, int l) throws SQLException { throw Err.nyi("setAsciiStream"); }
    @Override public void setUnicodeStream(int i, InputStream x, int l) throws SQLException { throw Err.nyi("setUnicodeStream"); }
    @Override public void setBinaryStream(int i, InputStream x, int l) throws SQLException { throw Err.nyi("setBinaryStream"); }
    @Override public void setCharacterStream(int i, Reader x, int l) throws SQLException { throw Err.nyi("setCharacterStream"); }
    @Override public void setAsciiStream(int i, InputStream x, long l) throws SQLException { throw Err.nyi("setAsciiStream"); }
    @Override public void setBinaryStream(int i, InputStream x, long l) throws SQLException { throw Err.nyi("setBinaryStream"); }
    @Override public void setCharacterStream(int i, Reader x, long l) throws SQLException { throw Err.nyi("setCharacterStream"); }
    @Override public void setAsciiStream(int i, InputStream x) throws SQLException { throw Err.nyi("setAsciiStream"); }
    @Override public void setBinaryStream(int i, InputStream x) throws SQLException { throw Err.nyi("setBinaryStream"); }
    @Override public void setCharacterStream(int i, Reader x) throws SQLException { throw Err.nyi("setCharacterStream"); }
    @Override public void setNCharacterStream(int i, Reader x, long l) throws SQLException { throw Err.nyi("setNCharacterStream"); }
    @Override public void setNCharacterStream(int i, Reader x) throws SQLException { throw Err.nyi("setNCharacterStream"); }
    @Override public void setRef(int i, Ref x) throws SQLException { throw Err.nyi("setRef"); }
    @Override public void setBlob(int i, Blob x) throws SQLException { throw Err.nyi("setBlob"); }
    @Override public void setBlob(int i, InputStream x, long l) throws SQLException { throw Err.nyi("setBlob"); }
    @Override public void setBlob(int i, InputStream x) throws SQLException { throw Err.nyi("setBlob"); }
    @Override public void setClob(int i, Clob x) throws SQLException { throw Err.nyi("setClob"); }
    @Override public void setClob(int i, Reader x, long l) throws SQLException { throw Err.nyi("setClob"); }
    @Override public void setClob(int i, Reader x) throws SQLException { throw Err.nyi("setClob"); }
    @Override public void setNClob(int i, NClob x) throws SQLException { throw Err.nyi("setNClob"); }
    @Override public void setNClob(int i, Reader x, long l) throws SQLException { throw Err.nyi("setNClob"); }
    @Override public void setNClob(int i, Reader x) throws SQLException { throw Err.nyi("setNClob"); }
    @Override public void setArray(int i, Array x) throws SQLException { throw Err.nyi("setArray"); }
    @Override public void setSQLXML(int i, SQLXML x) throws SQLException { throw Err.nyi("setSQLXML"); }

    // executeQuery(String) etc. on a PreparedStatement are illegal per JDBC.
    @Override public ResultSet executeQuery(String s) throws SQLException { throw new SQLException("use executeQuery() on a PreparedStatement"); }
    @Override public int executeUpdate(String s) throws SQLException { throw new SQLException("use executeUpdate() on a PreparedStatement"); }
    @Override public boolean execute(String s) throws SQLException { throw new SQLException("use execute() on a PreparedStatement"); }
}
