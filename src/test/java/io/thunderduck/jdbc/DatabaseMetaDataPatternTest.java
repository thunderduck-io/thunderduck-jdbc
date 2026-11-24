package io.thunderduck.jdbc;

import static org.junit.jupiter.api.Assertions.*;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

/** JDBC name patterns: `%` and `_` are wildcards, and the search-string escape (`\`) makes them literal. */
class DatabaseMetaDataPatternTest {

    private HttpServer server;
    private ThunderduckDatabaseMetaData md;

    @BeforeEach
    void start() throws Exception {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/catalog/schema", ex -> {
            byte[] b = ("{\"catalogs\":[{\"name\":\"sales_pg\",\"namespaces\":["
                    + "{\"name\":\"demo_sales\",\"tables\":[{\"name\":\"order_items\",\"kind\":\"table\",\"columns\":[]}]},"
                    + "{\"name\":\"demoxsales\",\"tables\":[{\"name\":\"other\",\"kind\":\"table\",\"columns\":[]}]},"
                    + "{\"name\":\"a.b$(c)\",\"tables\":[{\"name\":\"t\",\"kind\":\"view\",\"columns\":[]}]}"
                    + "]}]}").getBytes(StandardCharsets.UTF_8);
            ex.sendResponseHeaders(200, b.length);
            ex.getResponseBody().write(b);
            ex.close();
        });
        server.start();
        ApiClient api = new ApiClient("http://127.0.0.1:" + server.getAddress().getPort(),
                new StaticTokenProvider("t"), 1000, 30000);
        md = new ThunderduckDatabaseMetaData(null, api, "jdbc:thunderduck://127.0.0.1/");
    }

    @AfterEach
    void stop() {
        server.stop(0);
    }

    private static List<String> col(ResultSet rs, String name) throws Exception {
        List<String> out = new ArrayList<>();
        while (rs.next()) out.add(rs.getString(name));
        return out;
    }

    @Test
    void escapedUnderscoreInSchemaPatternMatchesOnlyTheLiteralName() throws Exception {
        // DBeaver/DataGrip escape `_` with getSearchStringEscape() when listing a schema's tables.
        assertEquals(List.of("order_items"),
                col(md.getTables("sales_pg", "demo\\_sales", "%", null), "TABLE_NAME"));
    }

    @Test
    void unescapedUnderscoreIsAWildcard() throws Exception {
        assertEquals(List.of("order_items", "other"),
                col(md.getTables("sales_pg", "demo_sales", null, null), "TABLE_NAME"));
    }

    @Test
    void escapedTableAndColumnPatternsAndRegexCharactersAreLiteral() throws Exception {
        assertEquals(List.of("order_items"),
                col(md.getTables(null, "demo\\_sales", "order\\_items", new String[] {"TABLE"}), "TABLE_NAME"));
        assertEquals(List.of("t"), col(md.getTables(null, "a.b$(c)", "%", null), "TABLE_NAME"));
        assertEquals(List.of("demo_sales"), col(md.getSchemas("sales_pg", "demo\\_sales"), "TABLE_SCHEM"));
    }

    @Test
    void emptyCatalogOrSchemaMeansNoneNotAny() throws Exception {
        // JDBC: "" retrieves objects WITHOUT a catalog/schema; null drops the criterion. DataGrip
        // calls getSchemas("", "%"), and answering with every schema invents a catalog-less copy.
        assertEquals(List.of(), col(md.getSchemas("", "%"), "TABLE_SCHEM"));
        assertEquals(List.of(), col(md.getTables("", null, "%", null), "TABLE_NAME"));
        assertEquals(List.of(), col(md.getTables("sales_pg", "", "%", null), "TABLE_NAME"));
        assertEquals(List.of(), col(md.getColumns("sales_pg", "", "%", "%"), "COLUMN_NAME"));
        assertEquals(3, col(md.getSchemas(null, "%"), "TABLE_SCHEM").size());
    }
}
