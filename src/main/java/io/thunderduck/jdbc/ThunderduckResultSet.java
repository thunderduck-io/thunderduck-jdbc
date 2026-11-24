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
import java.sql.Ref;
import java.sql.ResultSet;
import java.sql.ResultSetMetaData;
import java.sql.RowId;
import java.sql.SQLException;
import java.sql.SQLWarning;
import java.sql.SQLXML;
import java.sql.Statement;
import java.sql.Time;
import java.sql.Timestamp;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.OffsetDateTime;
import java.util.Calendar;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;

/** Forward-only, read-only ResultSet backed by paginated REST fetches. */
final class ThunderduckResultSet implements ResultSet {

    private final ApiClient api;
    private final String execId;
    private final ThunderduckStatement statement;
    private final int pageSize;
    private final List<String> columns;
    private final List<String> types;
    private final long total;

    private List<List<Object>> pageRows;
    private long pageOffset;   // absolute offset of pageRows[0]
    private int idxInPage = -1;
    private boolean closed;
    private boolean lastWasNull;

    /** An in-memory result set (all rows present, no API paging) — used for
     *  DatabaseMetaData results. */
    static ThunderduckResultSet inMemory(List<String> cols, List<String> types, List<List<Object>> rows) {
        ApiClient.ResultPage p = new ApiClient.ResultPage();
        p.columns = cols;
        p.columnTypes = types;
        p.rows = rows;
        p.total = rows.size();
        return new ThunderduckResultSet(null, null, null, 1000, p);
    }

    ThunderduckResultSet(ApiClient api, String execId, ThunderduckStatement statement,
                         int pageSize, ApiClient.ResultPage first) {
        this.api = api;
        this.execId = execId;
        this.statement = statement;
        this.pageSize = pageSize <= 0 ? 1000 : pageSize;
        this.columns = first.columns == null ? List.of() : first.columns;
        this.types = first.columnTypes;
        this.total = first.total;
        this.pageRows = first.rows == null ? List.of() : first.rows;
        this.pageOffset = 0;
    }

    // ---- navigation ----
    @Override
    public boolean next() throws SQLException {
        if (closed) throw new SQLException("result set is closed");
        idxInPage++;
        if (idxInPage < pageRows.size()) return true;
        long consumed = pageOffset + pageRows.size();
        if (consumed >= total) return false;
        ApiClient.ResultPage p = api.fetchResultPage(execId, pageSize, consumed);
        if (p == null || p.rows == null || p.rows.isEmpty()) return false;
        pageRows = p.rows;
        pageOffset = consumed;
        idxInPage = 0;
        return true;
    }

    @Override public void close() { closed = true; }
    @Override public boolean isClosed() { return closed; }
    @Override public boolean wasNull() { return lastWasNull; }

    private Object raw(int col) throws SQLException {
        if (closed) throw new SQLException("result set is closed");
        if (idxInPage < 0 || idxInPage >= pageRows.size()) {
            throw new SQLException("no current row (call next() first)");
        }
        List<Object> row = pageRows.get(idxInPage);
        if (col < 1 || col > columns.size()) throw new SQLException("invalid column index " + col);
        Object v = row.get(col - 1);
        lastWasNull = (v == null);
        return v;
    }

    @Override
    public int findColumn(String label) throws SQLException {
        for (int i = 0; i < columns.size(); i++) {
            if (columns.get(i).equalsIgnoreCase(label)) return i + 1;
        }
        throw new SQLException("no such column: " + label);
    }

    // ---- typed getters by index ----
    @Override public String getString(int c) throws SQLException { Object v = raw(c); return v == null ? null : v.toString(); }
    @Override public boolean getBoolean(int c) throws SQLException {
        Object v = raw(c);
        if (v == null) return false;
        if (v instanceof Boolean) return (Boolean) v;
        String s = v.toString().trim();
        return s.equals("1") || s.equalsIgnoreCase("true") || s.equalsIgnoreCase("t");
    }
    @Override public byte getByte(int c) throws SQLException { return (byte) getLong(c); }
    @Override public short getShort(int c) throws SQLException { return (short) getLong(c); }
    @Override public int getInt(int c) throws SQLException { return (int) getLong(c); }
    @Override public long getLong(int c) throws SQLException {
        Object v = raw(c);
        if (v == null) return 0L;
        if (v instanceof Number) return ((Number) v).longValue();
        return (long) Double.parseDouble(v.toString().trim());
    }
    @Override public float getFloat(int c) throws SQLException { return (float) getDouble(c); }
    @Override public double getDouble(int c) throws SQLException {
        Object v = raw(c);
        if (v == null) return 0d;
        if (v instanceof Number) return ((Number) v).doubleValue();
        return Double.parseDouble(v.toString().trim());
    }
    @Override public BigDecimal getBigDecimal(int c) throws SQLException {
        Object v = raw(c);
        return v == null ? null : new BigDecimal(v.toString().trim());
    }
    @Override public byte[] getBytes(int c) throws SQLException {
        Object v = raw(c);
        if (v == null) return null;
        try { return HexFormat.of().parseHex(v.toString()); }
        catch (RuntimeException e) { return v.toString().getBytes(); }
    }
    @Override public Date getDate(int c) throws SQLException {
        String s = getString(c);
        if (s == null) return null;
        try { return Date.valueOf(LocalDate.parse(s.substring(0, 10))); }
        catch (RuntimeException e) { throw new SQLException("cannot parse DATE: " + s); }
    }
    @Override public Time getTime(int c) throws SQLException {
        String s = getString(c);
        if (s == null) return null;
        try {
            String t = s.contains("T") ? s.substring(s.indexOf('T') + 1) : s;
            return Time.valueOf(LocalTime.parse(t.replaceAll("[Zz].*$", "").replaceAll("[+-]\\d\\d:?\\d\\d$", "")));
        } catch (RuntimeException e) { throw new SQLException("cannot parse TIME: " + s); }
    }
    @Override public Timestamp getTimestamp(int c) throws SQLException {
        String s = getString(c);
        if (s == null) return null;
        try { return Timestamp.from(OffsetDateTime.parse(s).toInstant()); }
        catch (RuntimeException e1) {
            try { return Timestamp.valueOf(LocalDateTime.parse(s)); }
            catch (RuntimeException e2) { throw new SQLException("cannot parse TIMESTAMP: " + s); }
        }
    }
    @Override public Object getObject(int c) throws SQLException { return raw(c); }

    // ---- typed getters by label ----
    @Override public String getString(String l) throws SQLException { return getString(findColumn(l)); }
    @Override public boolean getBoolean(String l) throws SQLException { return getBoolean(findColumn(l)); }
    @Override public byte getByte(String l) throws SQLException { return getByte(findColumn(l)); }
    @Override public short getShort(String l) throws SQLException { return getShort(findColumn(l)); }
    @Override public int getInt(String l) throws SQLException { return getInt(findColumn(l)); }
    @Override public long getLong(String l) throws SQLException { return getLong(findColumn(l)); }
    @Override public float getFloat(String l) throws SQLException { return getFloat(findColumn(l)); }
    @Override public double getDouble(String l) throws SQLException { return getDouble(findColumn(l)); }
    @Override public BigDecimal getBigDecimal(String l) throws SQLException { return getBigDecimal(findColumn(l)); }
    @Override public byte[] getBytes(String l) throws SQLException { return getBytes(findColumn(l)); }
    @Override public Date getDate(String l) throws SQLException { return getDate(findColumn(l)); }
    @Override public Time getTime(String l) throws SQLException { return getTime(findColumn(l)); }
    @Override public Timestamp getTimestamp(String l) throws SQLException { return getTimestamp(findColumn(l)); }
    @Override public Object getObject(String l) throws SQLException { return getObject(findColumn(l)); }

    @Override public ResultSetMetaData getMetaData() { return new ThunderduckResultSetMetaData(columns, types); }
    @Override public Statement getStatement() { return statement; }
    @Override public int getType() { return TYPE_FORWARD_ONLY; }
    @Override public int getConcurrency() { return CONCUR_READ_ONLY; }
    @Override public int getFetchDirection() { return FETCH_FORWARD; }
    @Override public void setFetchDirection(int d) { }
    @Override public int getFetchSize() { return pageSize; }
    @Override public void setFetchSize(int rows) { }
    @Override public int getHoldability() { return CLOSE_CURSORS_AT_COMMIT; }
    @Override public SQLWarning getWarnings() { return null; }
    @Override public void clearWarnings() { }
    @Override public String getCursorName() throws SQLException { throw Err.nyi("getCursorName"); }

    // position helpers (forward-only, best-effort)
    @Override public boolean isBeforeFirst() { return idxInPage < 0 && pageOffset == 0; }
    @Override public boolean isAfterLast() { return false; }
    @Override public boolean isFirst() { return pageOffset == 0 && idxInPage == 0; }
    @Override public boolean isLast() { return false; }
    @Override public int getRow() {
        return idxInPage < 0 ? 0 : (int) (pageOffset + idxInPage + 1);
    }

    @Override public <T> T unwrap(Class<T> iface) throws SQLException {
        if (iface.isInstance(this)) return iface.cast(this);
        throw new SQLException("not a wrapper for " + iface);
    }
    @Override public boolean isWrapperFor(Class<?> iface) { return iface.isInstance(this); }

    // ---- everything below is unsupported (read-only, forward-only) ----
    @Override public BigDecimal getBigDecimal(int c, int scale) throws SQLException { return getBigDecimal(c); }
    @Override public BigDecimal getBigDecimal(String l, int scale) throws SQLException { return getBigDecimal(l); }
    @Override public InputStream getAsciiStream(int c) throws SQLException { throw Err.nyi("getAsciiStream"); }
    @Override public InputStream getUnicodeStream(int c) throws SQLException { throw Err.nyi("getUnicodeStream"); }
    @Override public InputStream getBinaryStream(int c) throws SQLException { throw Err.nyi("getBinaryStream"); }
    @Override public InputStream getAsciiStream(String l) throws SQLException { throw Err.nyi("getAsciiStream"); }
    @Override public InputStream getUnicodeStream(String l) throws SQLException { throw Err.nyi("getUnicodeStream"); }
    @Override public InputStream getBinaryStream(String l) throws SQLException { throw Err.nyi("getBinaryStream"); }
    @Override public Reader getCharacterStream(int c) throws SQLException { throw Err.nyi("getCharacterStream"); }
    @Override public Reader getCharacterStream(String l) throws SQLException { throw Err.nyi("getCharacterStream"); }
    @Override public Object getObject(int c, Map<String, Class<?>> m) throws SQLException { return getObject(c); }
    @Override public Object getObject(String l, Map<String, Class<?>> m) throws SQLException { return getObject(l); }
    @Override public <T> T getObject(int c, Class<T> type) throws SQLException { return type.cast(getObject(c)); }
    @Override public <T> T getObject(String l, Class<T> type) throws SQLException { return type.cast(getObject(l)); }
    @Override public Ref getRef(int c) throws SQLException { throw Err.nyi("getRef"); }
    @Override public Ref getRef(String l) throws SQLException { throw Err.nyi("getRef"); }
    @Override public Blob getBlob(int c) throws SQLException { throw Err.nyi("getBlob"); }
    @Override public Blob getBlob(String l) throws SQLException { throw Err.nyi("getBlob"); }
    @Override public Clob getClob(int c) throws SQLException { throw Err.nyi("getClob"); }
    @Override public Clob getClob(String l) throws SQLException { throw Err.nyi("getClob"); }
    @Override public Array getArray(int c) throws SQLException { throw Err.nyi("getArray"); }
    @Override public Array getArray(String l) throws SQLException { throw Err.nyi("getArray"); }
    @Override public Date getDate(int c, Calendar cal) throws SQLException { return getDate(c); }
    @Override public Date getDate(String l, Calendar cal) throws SQLException { return getDate(l); }
    @Override public Time getTime(int c, Calendar cal) throws SQLException { return getTime(c); }
    @Override public Time getTime(String l, Calendar cal) throws SQLException { return getTime(l); }
    @Override public Timestamp getTimestamp(int c, Calendar cal) throws SQLException { return getTimestamp(c); }
    @Override public Timestamp getTimestamp(String l, Calendar cal) throws SQLException { return getTimestamp(l); }
    @Override public URL getURL(int c) throws SQLException { throw Err.nyi("getURL"); }
    @Override public URL getURL(String l) throws SQLException { throw Err.nyi("getURL"); }
    @Override public RowId getRowId(int c) throws SQLException { throw Err.nyi("getRowId"); }
    @Override public RowId getRowId(String l) throws SQLException { throw Err.nyi("getRowId"); }
    @Override public NClob getNClob(int c) throws SQLException { throw Err.nyi("getNClob"); }
    @Override public NClob getNClob(String l) throws SQLException { throw Err.nyi("getNClob"); }
    @Override public SQLXML getSQLXML(int c) throws SQLException { throw Err.nyi("getSQLXML"); }
    @Override public SQLXML getSQLXML(String l) throws SQLException { throw Err.nyi("getSQLXML"); }
    @Override public String getNString(int c) throws SQLException { return getString(c); }
    @Override public String getNString(String l) throws SQLException { return getString(l); }
    @Override public Reader getNCharacterStream(int c) throws SQLException { throw Err.nyi("getNCharacterStream"); }
    @Override public Reader getNCharacterStream(String l) throws SQLException { throw Err.nyi("getNCharacterStream"); }

    @Override public boolean absolute(int row) throws SQLException { throw Err.nyi("absolute"); }
    @Override public boolean relative(int rows) throws SQLException { throw Err.nyi("relative"); }
    @Override public boolean previous() throws SQLException { throw Err.nyi("previous"); }
    @Override public void beforeFirst() throws SQLException { throw Err.nyi("beforeFirst"); }
    @Override public void afterLast() throws SQLException { throw Err.nyi("afterLast"); }
    @Override public boolean first() throws SQLException { throw Err.nyi("first"); }
    @Override public boolean last() throws SQLException { throw Err.nyi("last"); }

    @Override public boolean rowUpdated() throws SQLException { return false; }
    @Override public boolean rowInserted() throws SQLException { return false; }
    @Override public boolean rowDeleted() throws SQLException { return false; }
    @Override public void insertRow() throws SQLException { throw Err.nyi("insertRow"); }
    @Override public void updateRow() throws SQLException { throw Err.nyi("updateRow"); }
    @Override public void deleteRow() throws SQLException { throw Err.nyi("deleteRow"); }
    @Override public void refreshRow() throws SQLException { throw Err.nyi("refreshRow"); }
    @Override public void cancelRowUpdates() throws SQLException { throw Err.nyi("cancelRowUpdates"); }
    @Override public void moveToInsertRow() throws SQLException { throw Err.nyi("moveToInsertRow"); }
    @Override public void moveToCurrentRow() throws SQLException { throw Err.nyi("moveToCurrentRow"); }

    // update* — all unsupported
    @Override public void updateNull(int c) throws SQLException { throw Err.nyi("updateNull"); }
    @Override public void updateBoolean(int c, boolean x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateByte(int c, byte x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateShort(int c, short x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateInt(int c, int x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateLong(int c, long x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateFloat(int c, float x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateDouble(int c, double x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateBigDecimal(int c, BigDecimal x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateString(int c, String x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateBytes(int c, byte[] x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateDate(int c, Date x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateTime(int c, Time x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateTimestamp(int c, Timestamp x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateAsciiStream(int c, InputStream x, int l) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateBinaryStream(int c, InputStream x, int l) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateCharacterStream(int c, Reader x, int l) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateObject(int c, Object x, int scale) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateObject(int c, Object x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateNull(String l) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateBoolean(String l, boolean x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateByte(String l, byte x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateShort(String l, short x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateInt(String l, int x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateLong(String l, long x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateFloat(String l, float x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateDouble(String l, double x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateBigDecimal(String l, BigDecimal x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateString(String l, String x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateBytes(String l, byte[] x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateDate(String l, Date x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateTime(String l, Time x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateTimestamp(String l, Timestamp x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateAsciiStream(String l, InputStream x, int len) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateBinaryStream(String l, InputStream x, int len) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateCharacterStream(String l, Reader x, int len) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateObject(String l, Object x, int scale) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateObject(String l, Object x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateRef(int c, Ref x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateRef(String l, Ref x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateBlob(int c, Blob x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateBlob(String l, Blob x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateBlob(int c, InputStream x, long len) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateBlob(String l, InputStream x, long len) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateBlob(int c, InputStream x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateBlob(String l, InputStream x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateClob(int c, Clob x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateClob(String l, Clob x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateClob(int c, Reader x, long len) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateClob(String l, Reader x, long len) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateClob(int c, Reader x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateClob(String l, Reader x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateArray(int c, Array x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateArray(String l, Array x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateRowId(int c, RowId x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateRowId(String l, RowId x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateNString(int c, String x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateNString(String l, String x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateNClob(int c, NClob x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateNClob(String l, NClob x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateNClob(int c, Reader x, long len) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateNClob(String l, Reader x, long len) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateNClob(int c, Reader x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateNClob(String l, Reader x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateSQLXML(int c, SQLXML x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateSQLXML(String l, SQLXML x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateNCharacterStream(int c, Reader x, long len) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateNCharacterStream(String l, Reader x, long len) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateNCharacterStream(int c, Reader x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateNCharacterStream(String l, Reader x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateAsciiStream(int c, InputStream x, long len) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateBinaryStream(int c, InputStream x, long len) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateCharacterStream(int c, Reader x, long len) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateAsciiStream(String l, InputStream x, long len) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateBinaryStream(String l, InputStream x, long len) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateCharacterStream(String l, Reader x, long len) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateAsciiStream(int c, InputStream x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateBinaryStream(int c, InputStream x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateCharacterStream(int c, Reader x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateAsciiStream(String l, InputStream x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateBinaryStream(String l, InputStream x) throws SQLException { throw Err.nyi("update"); }
    @Override public void updateCharacterStream(String l, Reader x) throws SQLException { throw Err.nyi("update"); }
}
