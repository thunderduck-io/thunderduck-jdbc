package io.thunderduck.jdbc;

import java.sql.ResultSetMetaData;
import java.sql.SQLException;
import java.sql.Types;
import java.util.List;

final class ThunderduckResultSetMetaData implements ResultSetMetaData {

    private final List<String> names;
    private final List<String> types;

    ThunderduckResultSetMetaData(List<String> names, List<String> types) {
        this.names = names;
        this.types = types;
    }

    private String typeName(int col) {
        return (types != null && col <= types.size() && types.get(col - 1) != null)
                ? types.get(col - 1) : "VARCHAR";
    }

    @Override public int getColumnCount() { return names == null ? 0 : names.size(); }
    @Override public String getColumnName(int column) { return names.get(column - 1); }
    @Override public String getColumnLabel(int column) { return names.get(column - 1); }
    @Override public int getColumnType(int column) { return TdTypes.sqlType(typeName(column)); }
    @Override public String getColumnTypeName(int column) { return typeName(column); }

    @Override public String getColumnClassName(int column) {
        switch (getColumnType(column)) {
            case Types.BOOLEAN: return "java.lang.Boolean";
            case Types.TINYINT: case Types.SMALLINT: case Types.INTEGER: return "java.lang.Integer";
            case Types.BIGINT: return "java.lang.Long";
            case Types.REAL: return "java.lang.Float";
            case Types.DOUBLE: return "java.lang.Double";
            case Types.DECIMAL: case Types.NUMERIC: return "java.math.BigDecimal";
            case Types.DATE: return "java.sql.Date";
            case Types.TIME: return "java.sql.Time";
            case Types.TIMESTAMP: case Types.TIMESTAMP_WITH_TIMEZONE: return "java.sql.Timestamp";
            case Types.VARBINARY: return "[B";
            default: return "java.lang.String";
        }
    }

    @Override public boolean isSigned(int column) {
        int t = getColumnType(column);
        return t == Types.TINYINT || t == Types.SMALLINT || t == Types.INTEGER || t == Types.BIGINT
                || t == Types.REAL || t == Types.DOUBLE || t == Types.DECIMAL || t == Types.NUMERIC;
    }

    @Override public int isNullable(int column) { return columnNullableUnknown; }
    @Override public boolean isCaseSensitive(int column) { return true; }
    @Override public boolean isSearchable(int column) { return true; }
    @Override public boolean isCurrency(int column) { return false; }
    @Override public boolean isAutoIncrement(int column) { return false; }
    @Override public boolean isReadOnly(int column) { return true; }
    @Override public boolean isWritable(int column) { return false; }
    @Override public boolean isDefinitelyWritable(int column) { return false; }
    @Override public int getPrecision(int column) { return 0; }
    @Override public int getScale(int column) { return 0; }
    @Override public int getColumnDisplaySize(int column) { return 0; }
    @Override public String getSchemaName(int column) { return ""; }
    @Override public String getTableName(int column) { return ""; }
    @Override public String getCatalogName(int column) { return ""; }

    @Override public <T> T unwrap(Class<T> iface) throws SQLException {
        if (iface.isInstance(this)) return iface.cast(this);
        throw new SQLException("not a wrapper for " + iface);
    }
    @Override public boolean isWrapperFor(Class<?> iface) { return iface.isInstance(this); }
}
