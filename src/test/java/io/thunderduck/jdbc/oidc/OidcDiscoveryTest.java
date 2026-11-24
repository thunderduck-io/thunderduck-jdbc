package io.thunderduck.jdbc.oidc;

import static org.junit.jupiter.api.Assertions.*;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import org.junit.jupiter.api.Test;

/** How the driver finds an install's realm when the host does not name it. */
class OidcDiscoveryTest {

    private static HttpServer serve(String body, int status) throws Exception {
        HttpServer s = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        s.createContext("/.well-known/oauth-protected-resource", ex -> {
            byte[] b = body.getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().add("Content-Type", "application/json");
            ex.sendResponseHeaders(status, b.length);
            ex.getResponseBody().write(b);
            ex.close();
        });
        s.start();
        return s;
    }

    @Test
    void readsTheAdvertisedRealm() throws Exception {
        HttpServer s = serve("{\"resource\":\"http://127.0.0.1\","
                + "\"authorization_servers\":[\"http://localhost:8080/realms/thunderduck\"]}", 200);
        try {
            String base = "http://127.0.0.1:" + s.getAddress().getPort();
            assertEquals(Optional.of("http://localhost:8080/realms/thunderduck"),
                    OidcProvider.discoverIssuer(base, HttpClient.newHttpClient()));
        } finally {
            s.stop(0);
        }
    }

    @Test
    void anAdvertisedCleartextOrRelativeIssuerIsRefused() throws Exception {
        for (String bad : new String[] {
                "http://login.acme.internal/realms/thunderduck", // cleartext off loopback
                "/realms/thunderduck",                            // relative
                "login.acme.internal",                            // no scheme
                "https://user:pw@login.acme.internal/realms/thunderduck"}) {
            HttpServer s = serve("{\"authorization_servers\":[\"" + bad + "\"]}", 200);
            try {
                String base = "http://127.0.0.1:" + s.getAddress().getPort();
                assertEquals(Optional.empty(),
                        OidcProvider.discoverIssuer(base, HttpClient.newHttpClient()), bad);
            } finally {
                s.stop(0);
            }
        }
    }

    @Test
    void plausibleIssuerMatchesTheConnectionsTransportRule() {
        String remote = "https://exampleco-api.thunderduck.ai";
        String local = "http://localhost:18000";
        assertTrue(OidcProvider.plausibleIssuer(
                "https://exampleco-auth.thunderduck.ai/realms/thunderduck", remote));
        // A loopback sign-in server is only plausible from a loopback connection, whatever its
        // scheme -- otherwise a remote install's document could aim sign-in at a local service.
        assertFalse(OidcProvider.plausibleIssuer("https://localhost:8443/realms/thunderduck", remote));
        assertFalse(OidcProvider.plausibleIssuer("http://login.acme.internal/realms/thunderduck", remote));
        assertFalse(OidcProvider.plausibleIssuer("https:///realms/thunderduck", remote));
        assertFalse(OidcProvider.plausibleIssuer("https://x/realms/r?next=1", remote));
        assertFalse(OidcProvider.plausibleIssuer(null, remote));

        // Plain http is only for a connection that is itself plain http to loopback: a remote
        // host cannot point the sign-in at a local service through its discovery document.
        assertTrue(OidcProvider.plausibleIssuer("http://localhost:8080/realms/thunderduck", local));
        assertFalse(OidcProvider.plausibleIssuer("http://localhost:8080/realms/thunderduck", remote));
        assertFalse(OidcProvider.plausibleIssuer("http://10.0.0.5:8080/realms/thunderduck", local));
    }

    @Test
    void loopbackIsDecidedByAddressNotBySpelling() {
        assertTrue(OidcProvider.isLoopbackHost("127.0.0.1"));
        assertTrue(OidcProvider.isLoopbackHost("127.0.0.2"));      // any of 127/8
        assertTrue(OidcProvider.isLoopbackHost("localhost"));
        assertTrue(OidcProvider.isLoopbackHost("localhost."));     // trailing dot
        assertTrue(OidcProvider.isLoopbackHost("[::1]"));
        assertTrue(OidcProvider.isLoopbackHost("0:0:0:0:0:0:0:1"));
        assertFalse(OidcProvider.isLoopbackHost("10.0.0.5"));
        assertFalse(OidcProvider.isLoopbackHost("td.acme.internal"));
    }

    @Test
    void aRemoteConnectionOnlyAcceptsItsOwnSignInHost() {
        String remote = "https://exampleco-api.thunderduck.ai";
        assertTrue(OidcProvider.plausibleIssuer(
                "https://exampleco-auth.thunderduck.ai/realms/thunderduck", remote));
        // Names that resolve or alias to loopback, and other sites, are out of scope.
        for (String bad : new String[] {
                "https://127.0.0.2:8443/realms/thunderduck",
                "https://[::ffff:127.0.0.1]:8443/realms/thunderduck",
                "https://localtest.me:8443/realms/thunderduck",
                "https://evil.example.com/realms/thunderduck",
                "http://login.example.com/realms/thunderduck"}) {
            assertFalse(OidcProvider.plausibleIssuer(bad, remote), bad);
        }
    }

    @Test
    void anOnPremInstallUsingTheSameNamingIsDiscovered() {
        String onprem = "https://acme-api.internal.example.co.uk";
        assertTrue(OidcProvider.plausibleIssuer(
                "https://acme-auth.internal.example.co.uk/realms/thunderduck", onprem));
        assertFalse(OidcProvider.plausibleIssuer(
                "https://login.internal.example.co.uk/realms/thunderduck", onprem));
    }

    @Test
    void onlyTheHostTheNamingImpliesIsAccepted() {
        assertEquals("exampleco-auth.thunderduck.ai",
                OidcProvider.expectedIssuerHost("exampleco-api.thunderduck.ai"));
        assertEquals("acme-auth.example.co.uk", OidcProvider.expectedIssuerHost("acme-api.example.co.uk"));
        assertNull(OidcProvider.expectedIssuerHost("thunderduck.acme.internal")); // no convention: issuer=
        assertNull(OidcProvider.expectedIssuerHost("10.0.0.5"));

        String api = "https://exampleco-api.thunderduck.ai";
        assertTrue(OidcProvider.plausibleIssuer(
                "https://exampleco-auth.thunderduck.ai/realms/thunderduck", api));
        // Siblings, shared-suffix names and other addresses are all out of scope now.
        for (String bad : new String[] {
                "https://other.thunderduck.ai/realms/thunderduck",
                "https://exampleco-auth.thunderduck.ai.evil.com/realms/thunderduck",
                "https://exampleco-auth.thunderduck.io/realms/thunderduck",
                "https://evil.co.uk/realms/thunderduck"}) {
            assertFalse(OidcProvider.plausibleIssuer(bad, api), bad);
        }
    }

    @Test
    void aBodyOverTheCapIsRejectedWhileReading() throws Exception {
        String big = "{\"authorization_servers\":[\"https://login.acme.internal/realms/thunderduck\"],\"pad\":\""
                + "x".repeat(70 * 1024) + "\"}";
        HttpServer s = serve(big, 200);
        try {
            String base = "http://127.0.0.1:" + s.getAddress().getPort();
            assertEquals(Optional.empty(), OidcProvider.discoverIssuer(base, HttpClient.newHttpClient()));
        } finally {
            s.stop(0);
        }
    }

    @Test
    void emptyWhenTheHostDoesNotAdvertiseOne() throws Exception {
        HttpServer s = serve("{\"error\":\"not found\"}", 404);
        try {
            String base = "http://127.0.0.1:" + s.getAddress().getPort();
            assertEquals(Optional.empty(), OidcProvider.discoverIssuer(base, HttpClient.newHttpClient()));
        } finally {
            s.stop(0);
        }
    }

    @Test
    void emptyWhenTheBodyCarriesNoServers() throws Exception {
        HttpServer s = serve("{\"resource\":\"x\",\"authorization_servers\":[]}", 200);
        try {
            String base = "http://127.0.0.1:" + s.getAddress().getPort();
            assertEquals(Optional.empty(), OidcProvider.discoverIssuer(base, HttpClient.newHttpClient()));
        } finally {
            s.stop(0);
        }
    }
}
