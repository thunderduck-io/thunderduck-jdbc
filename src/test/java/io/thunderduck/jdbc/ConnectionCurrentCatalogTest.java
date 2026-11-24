package io.thunderduck.jdbc;

import static org.junit.jupiter.api.Assertions.*;

import org.junit.jupiter.api.Test;

/**
 * DataGrip switches the connection to each catalog (setCatalog, then getCatalog to confirm) before
 * introspecting it. A connection that ignores setCatalog looks unswitchable, and DataGrip then loads
 * only the first catalog's tables.
 */
class ConnectionCurrentCatalogTest {

    private com.sun.net.httpserver.HttpServer server;

    @org.junit.jupiter.api.AfterEach
    void stop() {
        if (server != null) server.stop(0);
    }

    /** A connection to a stub API whose /catalog/schema lists the given catalogs (or fails with 500). */
    private ThunderduckConnection connect(java.util.concurrent.atomic.AtomicInteger calls, String... catalogs)
            throws Exception {
        server = com.sun.net.httpserver.HttpServer.create(new java.net.InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/catalog/schema", ex -> {
            calls.incrementAndGet();
            StringBuilder b = new StringBuilder("{\"catalogs\":[");
            for (int i = 0; i < catalogs.length; i++) {
                b.append(i > 0 ? "," : "").append("{\"name\":\"").append(catalogs[i]).append("\",\"namespaces\":[]}");
            }
            byte[] body = b.append("]}").toString().getBytes(java.nio.charset.StandardCharsets.UTF_8);
            ex.sendResponseHeaders(catalogs.length == 0 ? 500 : 200, catalogs.length == 0 ? -1 : body.length);
            if (catalogs.length > 0) ex.getResponseBody().write(body);
            ex.close();
        });
        server.start();
        return new ThunderduckConnection(ConnConfig.parse(
                "jdbc:thunderduck://127.0.0.1:" + server.getAddress().getPort() + "/?ssl=false&token=t", null));
    }

    @Test
    void startsInTheFirstCatalogSoToolsNeverInventAnUnnamedOne() throws Exception {
        // With no current catalog, DataGrip adds a nameless "current database" next to the real ones.
        java.util.concurrent.atomic.AtomicInteger calls = new java.util.concurrent.atomic.AtomicInteger();
        ThunderduckConnection c = connect(calls, "demo_alpha", "demo_beta", "demo_gamma");
        assertEquals("demo_alpha", c.getCatalog());
        assertEquals("demo_alpha", c.getCatalog());
        assertEquals(1, calls.get(), "fetched once, on first use");
    }

    @Test
    void noCatalogWhenTheListCannotBeFetched() throws Exception {
        ThunderduckConnection c = connect(new java.util.concurrent.atomic.AtomicInteger());
        assertNull(c.getCatalog());
    }

    @Test
    void currentCatalogAndSchemaAreRemembered() throws Exception {
        ThunderduckConnection c = new ThunderduckConnection(
                ConnConfig.parse("jdbc:thunderduck://127.0.0.1:1/?ssl=false&token=t", null));
        assertNull(c.getSchema());
        c.setCatalog("demo_catalog");
        c.setSchema("analytics_123456789");
        assertEquals("demo_catalog", c.getCatalog());
        assertEquals("analytics_123456789", c.getSchema());
        c.setCatalog("thunder_duck_demo");
        assertEquals("thunder_duck_demo", c.getCatalog());
    }
}
