package io.thunderduck.jdbc;

import java.sql.Connection;
import java.sql.DatabaseMetaData;
import java.sql.ResultSet;
import java.sql.RowIdLifetime;
import java.sql.SQLException;
import java.sql.Types;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.TreeSet;

/** Schema browsing over /catalog/schema, plus JDBC capability flags. */
final class ThunderduckDatabaseMetaData implements DatabaseMetaData {

    private final ThunderduckConnection connection;
    private final ApiClient api;
    private final String url;
    private Map<String, Object> schemaCache;

    ThunderduckDatabaseMetaData(ThunderduckConnection connection, ApiClient api, String url) {
        this.connection = connection;
        this.api = api;
        this.url = url;
    }

    // ---- flattened catalog rows: {catalog, schema(null for nessie), table, kind, columns} ----
    @SuppressWarnings("unchecked")
    private List<Map<String, Object>> tableEntries() throws SQLException {
        if (schemaCache == null) schemaCache = api.fetchSchema();
        List<Map<String, Object>> out = new ArrayList<>();
        List<Object> catalogs = (List<Object>) schemaCache.getOrDefault("catalogs", List.of());
        for (Object co : catalogs) {
            Map<String, Object> cat = (Map<String, Object>) co;
            String catName = str(cat.get("name"));
            List<Object> tables = (List<Object>) cat.get("tables");
            if (tables != null) {
                for (Object t : tables) addEntry(out, catName, null, (Map<String, Object>) t);
            }
            List<Object> namespaces = (List<Object>) cat.get("namespaces");
            if (namespaces != null) {
                for (Object nso : namespaces) {
                    Map<String, Object> ns = (Map<String, Object>) nso;
                    String schema = str(ns.get("name"));
                    List<Object> nts = (List<Object>) ns.getOrDefault("tables", List.of());
                    for (Object t : nts) addEntry(out, catName, schema, (Map<String, Object>) t);
                }
            }
        }
        return out;
    }

    private void addEntry(List<Map<String, Object>> out, String cat, String schema, Map<String, Object> t) {
        Map<String, Object> e = new java.util.HashMap<>();
        e.put("catalog", cat);
        e.put("schema", schema);
        e.put("table", str(t.get("name")));
        String kind = str(t.get("kind"));
        e.put("kind", "view".equalsIgnoreCase(kind) ? "VIEW" : "TABLE");
        e.put("columns", t.get("columns"));
        out.add(e);
    }

    /** JDBC: a null catalog drops the criterion; {@code ""} means objects without a catalog. */
    static boolean catalogMatches(String catalog, String value) {
        if (catalog == null) return true;
        if (catalog.isEmpty()) return value == null || value.isEmpty();
        return catalog.equals(value);
    }

    /** JDBC: a null schema pattern drops the criterion; {@code ""} means objects without a schema. */
    static boolean schemaMatches(String schemaPattern, String value) {
        if (schemaPattern == null) return true;
        if (schemaPattern.isEmpty()) return value == null || value.isEmpty();
        return like(schemaPattern, value == null ? "" : value);
    }

    /**
     * A JDBC name pattern: {@code %} is any run, {@code _} any one character, and the search-string
     * escape (a backslash, see {@link #getSearchStringEscape}) makes the next character literal.
     * DBeaver and DataGrip escape every {@code _} of a real schema name when listing its tables, so
     * the escaped form must match the name. Everything else is literal, never a regex.
     */
    static boolean like(String pattern, String value) {
        if (pattern == null || pattern.equals("%")) return true;
        if (value == null) return false;
        StringBuilder re = new StringBuilder("(?is)");
        for (int i = 0; i < pattern.length(); i++) {
            char c = pattern.charAt(i);
            if (c == '\\' && i + 1 < pattern.length()) {
                re.append(java.util.regex.Pattern.quote(String.valueOf(pattern.charAt(++i))));
            } else if (c == '%') {
                re.append(".*");
            } else if (c == '_') {
                re.append('.');
            } else {
                re.append(java.util.regex.Pattern.quote(String.valueOf(c)));
            }
        }
        return value.matches(re.toString());
    }

    // ---- browsing ----
    @Override
    public ResultSet getCatalogs() throws SQLException {
        TreeSet<String> names = new TreeSet<>();
        for (Map<String, Object> e : tableEntries()) names.add((String) e.get("catalog"));
        List<List<Object>> rows = new ArrayList<>();
        for (String n : names) rows.add(List.of(n));
        return ThunderduckResultSet.inMemory(List.of("TABLE_CAT"), List.of("VARCHAR"), rows);
    }

    @Override public ResultSet getSchemas() throws SQLException { return getSchemas(null, null); }

    @Override
    public ResultSet getSchemas(String catalog, String schemaPattern) throws SQLException {
        TreeSet<String> seen = new TreeSet<>();
        List<List<Object>> rows = new ArrayList<>();
        for (Map<String, Object> e : tableEntries()) {
            String schema = (String) e.get("schema");
            String cat = (String) e.get("catalog");
            if (schema == null) continue;
            if (!catalogMatches(catalog, cat)) continue;
            if (!like(schemaPattern, schema)) continue;
            String key = cat + "." + schema;
            if (seen.add(key)) rows.add(rowOf(schema, cat));
        }
        return ThunderduckResultSet.inMemory(
                List.of("TABLE_SCHEM", "TABLE_CATALOG"), List.of("VARCHAR", "VARCHAR"), rows);
    }

    private static List<Object> rowOf(Object... vals) {
        List<Object> l = new ArrayList<>();
        for (Object v : vals) l.add(v);
        return l;
    }

    @Override
    public ResultSet getTables(String catalog, String schemaPattern, String tableNamePattern,
                               String[] types) throws SQLException {
        List<String> cols = List.of("TABLE_CAT", "TABLE_SCHEM", "TABLE_NAME", "TABLE_TYPE",
                "REMARKS", "TYPE_CAT", "TYPE_SCHEM", "TYPE_NAME",
                "SELF_REFERENCING_COL_NAME", "REF_GENERATION");
        List<List<Object>> rows = new ArrayList<>();
        for (Map<String, Object> e : tableEntries()) {
            String cat = (String) e.get("catalog");
            String schema = (String) e.get("schema");
            String table = (String) e.get("table");
            String kind = (String) e.get("kind");
            if (!catalogMatches(catalog, cat)) continue;
            if (!schemaMatches(schemaPattern, schema)) continue;
            if (!like(tableNamePattern, table)) continue;
            if (types != null && types.length > 0) {
                boolean match = false;
                for (String ty : types) if (ty != null && ty.equalsIgnoreCase(kind)) match = true;
                if (!match) continue;
            }
            rows.add(rowOf(cat, schema, table, kind, null, null, null, null, null, null));
        }
        List<String> types2 = new ArrayList<>();
        for (int i = 0; i < cols.size(); i++) types2.add("VARCHAR");
        return ThunderduckResultSet.inMemory(cols, types2, rows);
    }

    @Override
    @SuppressWarnings("unchecked")
    public ResultSet getColumns(String catalog, String schemaPattern, String tableNamePattern,
                                String columnNamePattern) throws SQLException {
        List<String> cols = List.of("TABLE_CAT", "TABLE_SCHEM", "TABLE_NAME", "COLUMN_NAME",
                "DATA_TYPE", "TYPE_NAME", "COLUMN_SIZE", "BUFFER_LENGTH", "DECIMAL_DIGITS",
                "NUM_PREC_RADIX", "NULLABLE", "REMARKS", "COLUMN_DEF", "SQL_DATA_TYPE",
                "SQL_DATETIME_SUB", "CHAR_OCTET_LENGTH", "ORDINAL_POSITION", "IS_NULLABLE",
                "SCOPE_CATALOG", "SCOPE_SCHEMA", "SCOPE_TABLE", "SOURCE_DATA_TYPE",
                "IS_AUTOINCREMENT", "IS_GENERATEDCOLUMN");
        List<List<Object>> rows = new ArrayList<>();
        for (Map<String, Object> e : tableEntries()) {
            String cat = (String) e.get("catalog");
            String schema = (String) e.get("schema");
            String table = (String) e.get("table");
            if (!catalogMatches(catalog, cat)) continue;
            if (!schemaMatches(schemaPattern, schema)) continue;
            if (!like(tableNamePattern, table)) continue;
            List<Object> columns = (List<Object>) e.get("columns");
            if (columns == null) continue;
            int ordinal = 0;
            for (Object co : columns) {
                ordinal++;
                Map<String, Object> col = (Map<String, Object>) co;
                String name = str(col.get("name"));
                String type = str(col.get("type"));
                if (!like(columnNamePattern, name)) continue;
                rows.add(rowOf(cat, schema, table, name,
                        TdTypes.sqlType(type), type, 0, 0, 0, 10, columnNullableUnknown,
                        null, null, 0, 0, 0, ordinal, "", null, null, null, null, "NO", "NO"));
            }
        }
        List<String> types = new ArrayList<>();
        for (int i = 0; i < cols.size(); i++) types.add(i == 4 || i == 16 ? "INTEGER" : "VARCHAR");
        return ThunderduckResultSet.inMemory(cols, types, rows);
    }

    @Override
    public ResultSet getTableTypes() throws SQLException {
        List<List<Object>> rows = List.of(List.of((Object) "TABLE"), List.of((Object) "VIEW"));
        return ThunderduckResultSet.inMemory(List.of("TABLE_TYPE"), List.of("VARCHAR"), rows);
    }

    private ResultSet empty(String... cols) {
        List<String> c = List.of(cols);
        List<String> t = new ArrayList<>();
        for (int i = 0; i < c.size(); i++) t.add("VARCHAR");
        return ThunderduckResultSet.inMemory(c, t, new ArrayList<>());
    }

    // ---- empty result sets for metadata we don't model ----
    @Override public ResultSet getTypeInfo() { return empty("TYPE_NAME", "DATA_TYPE"); }
    @Override public ResultSet getProcedures(String c, String s, String p) { return empty("PROCEDURE_CAT", "PROCEDURE_SCHEM", "PROCEDURE_NAME"); }
    @Override public ResultSet getProcedureColumns(String c, String s, String p, String col) { return empty("PROCEDURE_CAT", "COLUMN_NAME"); }
    @Override public ResultSet getFunctions(String c, String s, String p) { return empty("FUNCTION_CAT", "FUNCTION_SCHEM", "FUNCTION_NAME"); }
    @Override public ResultSet getFunctionColumns(String c, String s, String p, String col) { return empty("FUNCTION_CAT", "COLUMN_NAME"); }
    @Override public ResultSet getColumnPrivileges(String c, String s, String t, String col) { return empty("TABLE_CAT", "COLUMN_NAME", "GRANTEE", "PRIVILEGE"); }
    @Override public ResultSet getTablePrivileges(String c, String s, String t) { return empty("TABLE_CAT", "TABLE_NAME", "GRANTEE", "PRIVILEGE"); }
    @Override public ResultSet getBestRowIdentifier(String c, String s, String t, int sc, boolean n) { return empty("SCOPE", "COLUMN_NAME"); }
    @Override public ResultSet getVersionColumns(String c, String s, String t) { return empty("SCOPE", "COLUMN_NAME"); }
    @Override public ResultSet getPrimaryKeys(String c, String s, String t) { return empty("TABLE_CAT", "TABLE_SCHEM", "TABLE_NAME", "COLUMN_NAME", "KEY_SEQ", "PK_NAME"); }
    @Override public ResultSet getImportedKeys(String c, String s, String t) { return empty("PKTABLE_CAT", "FKTABLE_NAME", "FKCOLUMN_NAME"); }
    @Override public ResultSet getExportedKeys(String c, String s, String t) { return empty("PKTABLE_CAT", "FKTABLE_NAME", "FKCOLUMN_NAME"); }
    @Override public ResultSet getCrossReference(String pc, String ps, String pt, String fc, String fs, String ft) { return empty("PKTABLE_CAT", "FKTABLE_NAME"); }
    @Override public ResultSet getIndexInfo(String c, String s, String t, boolean u, boolean a) { return empty("TABLE_CAT", "TABLE_NAME", "INDEX_NAME", "COLUMN_NAME"); }
    @Override public ResultSet getUDTs(String c, String s, String tn, int[] ty) { return empty("TYPE_CAT", "TYPE_NAME"); }
    @Override public ResultSet getSuperTypes(String c, String s, String tn) { return empty("TYPE_CAT", "TYPE_NAME"); }
    @Override public ResultSet getSuperTables(String c, String s, String tn) { return empty("TABLE_CAT", "TABLE_NAME"); }
    @Override public ResultSet getAttributes(String c, String s, String tn, String ap) { return empty("TYPE_CAT", "ATTR_NAME"); }
    @Override public ResultSet getClientInfoProperties() { return empty("NAME", "MAX_LEN", "DEFAULT_VALUE", "DESCRIPTION"); }
    @Override public ResultSet getPseudoColumns(String c, String s, String t, String col) { return empty("TABLE_CAT", "COLUMN_NAME"); }

    // ---- identity / versions ----
    @Override public Connection getConnection() { return connection; }
    @Override public String getURL() { return "jdbc:thunderduck://" + url.replaceFirst("^https?://", ""); }
    @Override public String getUserName() { return ""; }
    @Override public String getDriverName() { return "thunderduck JDBC driver"; }
    @Override public String getDriverVersion() { return "0.2.1"; }
    @Override public int getDriverMajorVersion() { return ThunderduckDriver.MAJOR; }
    @Override public int getDriverMinorVersion() { return ThunderduckDriver.MINOR; }
    @Override public String getDatabaseProductName() { return "thunderduck"; }
    @Override public String getDatabaseProductVersion() { return "0.1.0"; }
    @Override public int getDatabaseMajorVersion() { return 0; }
    @Override public int getDatabaseMinorVersion() { return 1; }
    @Override public int getJDBCMajorVersion() { return 4; }
    @Override public int getJDBCMinorVersion() { return 2; }
    @Override public int getDefaultTransactionIsolation() { return Connection.TRANSACTION_NONE; }
    @Override public int getSQLStateType() { return sqlStateSQL; }
    @Override public RowIdLifetime getRowIdLifetime() { return RowIdLifetime.ROWID_UNSUPPORTED; }

    // ---- product identifiers / behaviour ----
    @Override public boolean isReadOnly() { return true; }
    @Override public boolean allProceduresAreCallable() { return false; }
    @Override public boolean allTablesAreSelectable() { return true; }
    @Override public boolean nullsAreSortedHigh() { return false; }
    @Override public boolean nullsAreSortedLow() { return true; }
    @Override public boolean nullsAreSortedAtStart() { return false; }
    @Override public boolean nullsAreSortedAtEnd() { return false; }
    @Override public boolean usesLocalFiles() { return false; }
    @Override public boolean usesLocalFilePerTable() { return false; }
    @Override public boolean supportsMixedCaseIdentifiers() { return false; }
    @Override public boolean storesUpperCaseIdentifiers() { return false; }
    @Override public boolean storesLowerCaseIdentifiers() { return false; }
    @Override public boolean storesMixedCaseIdentifiers() { return true; }
    @Override public boolean supportsMixedCaseQuotedIdentifiers() { return true; }
    @Override public boolean storesUpperCaseQuotedIdentifiers() { return false; }
    @Override public boolean storesLowerCaseQuotedIdentifiers() { return false; }
    @Override public boolean storesMixedCaseQuotedIdentifiers() { return true; }
    @Override public String getIdentifierQuoteString() { return "\""; }
    @Override public String getSQLKeywords() { return ""; }
    @Override public String getNumericFunctions() { return ""; }
    @Override public String getStringFunctions() { return ""; }
    @Override public String getSystemFunctions() { return ""; }
    @Override public String getTimeDateFunctions() { return ""; }
    @Override public String getSearchStringEscape() { return "\\"; }
    @Override public String getExtraNameCharacters() { return ""; }
    @Override public String getSchemaTerm() { return "schema"; }
    @Override public String getProcedureTerm() { return "procedure"; }
    @Override public String getCatalogTerm() { return "catalog"; }
    @Override public boolean isCatalogAtStart() { return true; }
    @Override public String getCatalogSeparator() { return "."; }

    // ---- support flags (read-only analytics engine) ----
    @Override public boolean supportsAlterTableWithAddColumn() { return false; }
    @Override public boolean supportsAlterTableWithDropColumn() { return false; }
    @Override public boolean supportsColumnAliasing() { return true; }
    @Override public boolean nullPlusNonNullIsNull() { return true; }
    @Override public boolean supportsConvert() { return true; }
    @Override public boolean supportsConvert(int from, int to) { return false; }
    @Override public boolean supportsTableCorrelationNames() { return true; }
    @Override public boolean supportsDifferentTableCorrelationNames() { return false; }
    @Override public boolean supportsExpressionsInOrderBy() { return true; }
    @Override public boolean supportsOrderByUnrelated() { return true; }
    @Override public boolean supportsGroupBy() { return true; }
    @Override public boolean supportsGroupByUnrelated() { return true; }
    @Override public boolean supportsGroupByBeyondSelect() { return true; }
    @Override public boolean supportsLikeEscapeClause() { return true; }
    @Override public boolean supportsMultipleResultSets() { return false; }
    @Override public boolean supportsMultipleTransactions() { return false; }
    @Override public boolean supportsNonNullableColumns() { return true; }
    @Override public boolean supportsMinimumSQLGrammar() { return true; }
    @Override public boolean supportsCoreSQLGrammar() { return true; }
    @Override public boolean supportsExtendedSQLGrammar() { return false; }
    @Override public boolean supportsANSI92EntryLevelSQL() { return true; }
    @Override public boolean supportsANSI92IntermediateSQL() { return false; }
    @Override public boolean supportsANSI92FullSQL() { return false; }
    @Override public boolean supportsIntegrityEnhancementFacility() { return false; }
    @Override public boolean supportsOuterJoins() { return true; }
    @Override public boolean supportsFullOuterJoins() { return true; }
    @Override public boolean supportsLimitedOuterJoins() { return true; }
    @Override public boolean supportsSchemasInDataManipulation() { return true; }
    @Override public boolean supportsSchemasInProcedureCalls() { return false; }
    @Override public boolean supportsSchemasInTableDefinitions() { return false; }
    @Override public boolean supportsSchemasInIndexDefinitions() { return false; }
    @Override public boolean supportsSchemasInPrivilegeDefinitions() { return false; }
    @Override public boolean supportsCatalogsInDataManipulation() { return true; }
    @Override public boolean supportsCatalogsInProcedureCalls() { return false; }
    @Override public boolean supportsCatalogsInTableDefinitions() { return false; }
    @Override public boolean supportsCatalogsInIndexDefinitions() { return false; }
    @Override public boolean supportsCatalogsInPrivilegeDefinitions() { return false; }
    @Override public boolean supportsPositionedDelete() { return false; }
    @Override public boolean supportsPositionedUpdate() { return false; }
    @Override public boolean supportsSelectForUpdate() { return false; }
    @Override public boolean supportsStoredProcedures() { return false; }
    @Override public boolean supportsSubqueriesInComparisons() { return true; }
    @Override public boolean supportsSubqueriesInExists() { return true; }
    @Override public boolean supportsSubqueriesInIns() { return true; }
    @Override public boolean supportsSubqueriesInQuantifieds() { return true; }
    @Override public boolean supportsCorrelatedSubqueries() { return true; }
    @Override public boolean supportsUnion() { return true; }
    @Override public boolean supportsUnionAll() { return true; }
    @Override public boolean supportsOpenCursorsAcrossCommit() { return false; }
    @Override public boolean supportsOpenCursorsAcrossRollback() { return false; }
    @Override public boolean supportsOpenStatementsAcrossCommit() { return true; }
    @Override public boolean supportsOpenStatementsAcrossRollback() { return true; }
    @Override public boolean supportsStoredFunctionsUsingCallSyntax() { return false; }

    @Override public int getMaxBinaryLiteralLength() { return 0; }
    @Override public int getMaxCharLiteralLength() { return 0; }
    @Override public int getMaxColumnNameLength() { return 0; }
    @Override public int getMaxColumnsInGroupBy() { return 0; }
    @Override public int getMaxColumnsInIndex() { return 0; }
    @Override public int getMaxColumnsInOrderBy() { return 0; }
    @Override public int getMaxColumnsInSelect() { return 0; }
    @Override public int getMaxColumnsInTable() { return 0; }
    @Override public int getMaxConnections() { return 0; }
    @Override public int getMaxCursorNameLength() { return 0; }
    @Override public int getMaxIndexLength() { return 0; }
    @Override public int getMaxSchemaNameLength() { return 0; }
    @Override public int getMaxProcedureNameLength() { return 0; }
    @Override public int getMaxCatalogNameLength() { return 0; }
    @Override public int getMaxRowSize() { return 0; }
    @Override public boolean doesMaxRowSizeIncludeBlobs() { return false; }
    @Override public int getMaxStatementLength() { return 0; }
    @Override public int getMaxStatements() { return 0; }
    @Override public int getMaxTableNameLength() { return 0; }
    @Override public int getMaxTablesInSelect() { return 0; }
    @Override public int getMaxUserNameLength() { return 0; }

    @Override public boolean supportsTransactions() { return false; }
    @Override public boolean supportsTransactionIsolationLevel(int level) { return level == Connection.TRANSACTION_NONE; }
    @Override public boolean supportsDataDefinitionAndDataManipulationTransactions() { return false; }
    @Override public boolean supportsDataManipulationTransactionsOnly() { return false; }
    @Override public boolean dataDefinitionCausesTransactionCommit() { return false; }
    @Override public boolean dataDefinitionIgnoredInTransactions() { return false; }

    @Override public boolean supportsResultSetType(int type) { return type == ResultSet.TYPE_FORWARD_ONLY; }
    @Override public boolean supportsResultSetConcurrency(int type, int concurrency) {
        return type == ResultSet.TYPE_FORWARD_ONLY && concurrency == ResultSet.CONCUR_READ_ONLY;
    }
    @Override public boolean ownUpdatesAreVisible(int type) { return false; }
    @Override public boolean ownDeletesAreVisible(int type) { return false; }
    @Override public boolean ownInsertsAreVisible(int type) { return false; }
    @Override public boolean othersUpdatesAreVisible(int type) { return false; }
    @Override public boolean othersDeletesAreVisible(int type) { return false; }
    @Override public boolean othersInsertsAreVisible(int type) { return false; }
    @Override public boolean updatesAreDetected(int type) { return false; }
    @Override public boolean deletesAreDetected(int type) { return false; }
    @Override public boolean insertsAreDetected(int type) { return false; }
    @Override public boolean supportsBatchUpdates() { return false; }
    @Override public boolean supportsSavepoints() { return false; }
    @Override public boolean supportsNamedParameters() { return false; }
    @Override public boolean supportsMultipleOpenResults() { return false; }
    @Override public boolean supportsGetGeneratedKeys() { return false; }
    @Override public boolean supportsResultSetHoldability(int h) { return h == ResultSet.CLOSE_CURSORS_AT_COMMIT; }
    @Override public int getResultSetHoldability() { return ResultSet.CLOSE_CURSORS_AT_COMMIT; }
    @Override public boolean locatorsUpdateCopy() { return false; }
    @Override public boolean supportsStatementPooling() { return false; }
    @Override public boolean autoCommitFailureClosesAllResultSets() { return false; }
    @Override public boolean generatedKeyAlwaysReturned() { return false; }

    @Override public <T> T unwrap(Class<T> iface) throws SQLException {
        if (iface.isInstance(this)) return iface.cast(this);
        throw new SQLException("not a wrapper for " + iface);
    }
    @Override public boolean isWrapperFor(Class<?> iface) { return iface.isInstance(this); }

    private static String str(Object o) { return o == null ? null : o.toString(); }
}
