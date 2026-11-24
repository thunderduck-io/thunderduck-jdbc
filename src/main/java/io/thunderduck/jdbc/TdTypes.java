package io.thunderduck.jdbc;

import java.sql.Types;

/** Maps DuckDB/thunderduck column type strings to java.sql.Types. */
final class TdTypes {

    private TdTypes() {}

    static int sqlType(String duckType) {
        if (duckType == null) return Types.VARCHAR;
        String t = duckType.trim().toUpperCase();
        // Strip parameters, e.g. DECIMAL(18,6) -> DECIMAL.
        int paren = t.indexOf('(');
        if (paren >= 0) t = t.substring(0, paren).trim();

        switch (t) {
            case "BOOLEAN": case "BOOL": return Types.BOOLEAN;
            case "TINYINT": case "INT1": return Types.TINYINT;
            case "SMALLINT": case "INT2": case "SHORT": return Types.SMALLINT;
            case "INTEGER": case "INT": case "INT4": return Types.INTEGER;
            case "BIGINT": case "INT8": case "LONG": case "HUGEINT": return Types.BIGINT;
            case "FLOAT": case "REAL": case "FLOAT4": return Types.REAL;
            case "DOUBLE": case "FLOAT8": return Types.DOUBLE;
            case "DECIMAL": case "NUMERIC": return Types.DECIMAL;
            case "DATE": return Types.DATE;
            case "TIME": case "TIME WITH TIME ZONE": return Types.TIME;
            case "TIMESTAMP": case "DATETIME": return Types.TIMESTAMP;
            case "TIMESTAMP WITH TIME ZONE": case "TIMESTAMPTZ": return Types.TIMESTAMP_WITH_TIMEZONE;
            case "BLOB": case "BYTEA": case "BINARY": return Types.VARBINARY;
            case "UUID": return Types.OTHER;
            case "JSON": return Types.VARCHAR;
            default:
                if (t.startsWith("STRUCT") || t.startsWith("MAP") || t.endsWith("[]")
                        || t.startsWith("LIST") || t.startsWith("ARRAY")) {
                    return Types.OTHER;
                }
                // VARCHAR, TEXT, CHAR, ENUM, and anything unknown → string.
                return Types.VARCHAR;
        }
    }
}
