package io.thunderduck.jdbc.oidc;

import static org.junit.jupiter.api.Assertions.*;

import com.sun.net.httpserver.HttpServer;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.URI;
import java.net.URLDecoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.sql.SQLException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.function.Consumer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

/** The "browser" is a test opener that reads the authorize URL and calls the loopback callback itself. */
class BrowserAuthTest {

    private static final String TOKENS = "{\"access_token\":\"acc\",\"expires_in\":300,"
            + "\"refresh_token\":\"ref\",\"refresh_expires_in\":1800,\"token_type\":\"Bearer\"}";

    private HttpServer realm;
    private final List<String> tokenRequests = new CopyOnWriteArrayList<>();
    private final List<ServerSocket> occupied = new ArrayList<>();
    private final HttpClient http = HttpClient.newHttpClient();

    @AfterEach
    void stop() throws Exception {
        if (realm != null) realm.stop(0);
        for (ServerSocket s : occupied) s.close();
    }

    private OidcEndpoints startRealm() throws Exception {
        realm = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        realm.createContext("/token", ex -> {
            tokenRequests.add(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.UTF_8));
            byte[] b = TOKENS.getBytes(StandardCharsets.UTF_8);
            ex.getResponseHeaders().add("Content-Type", "application/json");
            ex.sendResponseHeaders(200, b.length);
            ex.getResponseBody().write(b);
            ex.close();
        });
        realm.start();
        String base = "http://127.0.0.1:" + realm.getAddress().getPort();
        return new OidcEndpoints(URI.create(base + "/auth"), URI.create(base + "/token"), null);
    }

    static Map<String, String> query(String rawQuery) {
        Map<String, String> m = new HashMap<>();
        for (String kv : rawQuery.split("&")) {
            int eq = kv.indexOf('=');
            m.put(URLDecoder.decode(kv.substring(0, eq), StandardCharsets.UTF_8),
                    URLDecoder.decode(kv.substring(eq + 1), StandardCharsets.UTF_8));
        }
        return m;
    }

    private static final String ISSUER = "https://auth.example/realms/td";
    private static final String TD_ISSUER = "https://auth.thunderduck.ai/realms/thunderduck";
    private static final String MIX_UP = "Sign-in was answered by a different sign-in server than the one "
            + "configured; not continuing.";

    /**
     * Plays the browser: records the authorize URL, then hits the callback with code + the given state
     * (null: the request's own; {@link #NO_STATE}: none) and, when set, an {@code iss} parameter.
     */
    private final class FakeBrowser implements Consumer<URI> {
        static final String NO_STATE = "\0none";
        final String stateOverride;
        final String iss;
        volatile URI authorizeUrl;
        volatile HttpResponse<String> callbackResponse;

        FakeBrowser(String stateOverride) { this(stateOverride, null); }

        FakeBrowser(String stateOverride, String iss) {
            this.stateOverride = stateOverride;
            this.iss = iss;
        }

        @Override public void accept(URI u) {
            authorizeUrl = u;
            Map<String, String> q = query(u.getRawQuery());
            String state = stateOverride != null ? stateOverride : q.get("state");
            String params = "code=the-code" + (NO_STATE.equals(state) ? "" : "&state=" + state) + "&session_state=x"
                    + (iss == null ? "" : "&iss=" + OidcProvider.enc(iss));
            URI cb = URI.create(q.get("redirect_uri") + "?" + params);
            try {
                callbackResponse = http.send(HttpRequest.newBuilder(cb).GET().build(),
                        HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }

    private BrowserAuth auth(Consumer<URI> opener, Duration timeout) {
        return auth(opener, timeout, ISSUER);
    }

    private BrowserAuth auth(Consumer<URI> opener, Duration timeout, String issuer) {
        return new BrowserAuth(http, opener, timeout, 33500, 33509, issuer);
    }

    private void occupy(int port) throws Exception {
        ServerSocket s = new ServerSocket();
        s.bind(new InetSocketAddress(InetAddress.getByName("127.0.0.1"), port));
        occupied.add(s);
    }

    @Test
    void signInExchangesCodeWithVerifier() throws Exception {
        OidcEndpoints ep = startRealm();
        FakeBrowser browser = new FakeBrowser(null);
        Tokens t = auth(browser, Duration.ofSeconds(10)).signIn(ep);

        assertEquals("acc", t.accessToken());
        assertEquals("ref", t.refreshToken());

        URI a = browser.authorizeUrl;
        assertEquals(ep.authorization().getPath(), a.getPath());
        Map<String, String> q = query(a.getRawQuery());
        assertEquals("code", q.get("response_type"));
        assertEquals("thunderduck-jdbc", q.get("client_id"));
        assertEquals("S256", q.get("code_challenge_method"));
        assertEquals("openid email profile", q.get("scope"));
        assertFalse(a.toString().contains("offline_access"));
        assertNotNull(q.get("state"));
        assertTrue(q.get("state").length() >= 16);
        assertTrue(q.get("redirect_uri").matches("http://127\\.0\\.0\\.1:335(0[0-9])/callback"), q.get("redirect_uri"));

        assertEquals(1, tokenRequests.size());
        Map<String, String> form = query(tokenRequests.get(0));
        assertEquals("authorization_code", form.get("grant_type"));
        assertEquals("the-code", form.get("code"));
        assertEquals("thunderduck-jdbc", form.get("client_id"));
        assertEquals(q.get("redirect_uri"), form.get("redirect_uri"));
        byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(form.get("code_verifier").getBytes(StandardCharsets.US_ASCII));
        assertEquals(q.get("code_challenge"), Base64.getUrlEncoder().withoutPadding().encodeToString(digest));
    }

    @Test
    void callbackWithWrongStateIsRejected() throws Exception {
        OidcEndpoints ep = startRealm();
        FakeBrowser browser = new FakeBrowser("not-the-state");
        assertThrows(SQLException.class, () -> auth(browser, Duration.ofSeconds(10)).signIn(ep));
        assertTrue(tokenRequests.isEmpty());
        assertNotEquals(200, browser.callbackResponse.statusCode());
        assertFalse(browser.callbackResponse.body().contains("not-the-state"));
    }

    @Test
    void bindsFirstFreePortInRange() throws Exception {
        occupy(33500);
        OidcEndpoints ep = startRealm();
        FakeBrowser browser = new FakeBrowser(null);
        auth(browser, Duration.ofSeconds(10)).signIn(ep);
        assertEquals("http://127.0.0.1:33501/callback", query(browser.authorizeUrl.getRawQuery()).get("redirect_uri"));
    }

    @Test
    void allPortsBusyFailsWithMessage() throws Exception {
        for (int p = 33500; p <= 33509; p++) occupy(p);
        OidcEndpoints ep = startRealm();
        FakeBrowser browser = new FakeBrowser(null);
        SQLException e = assertThrows(SQLException.class, () -> auth(browser, Duration.ofSeconds(10)).signIn(ep));
        assertEquals("No free local port for sign-in (33500–33509); close other sign-in windows or use an API token (auth=token)",
                e.getMessage());
        assertNull(browser.authorizeUrl);
    }

    @Test
    void timesOutWithMessage() throws Exception {
        OidcEndpoints ep = startRealm();
        SQLException e = assertThrows(SQLException.class,
                () -> auth(u -> { }, Duration.ofMillis(200)).signIn(ep));
        assertEquals("Sign-in was cancelled or timed out (no response within 5 minutes).", e.getMessage());
        assertTrue(tokenRequests.isEmpty());
    }

    @Test
    void callbackPageSaysSignedIn() throws Exception {
        OidcEndpoints ep = startRealm();
        FakeBrowser browser = new FakeBrowser(null);
        auth(browser, Duration.ofSeconds(10)).signIn(ep);
        assertEquals(200, browser.callbackResponse.statusCode());
        assertTrue(browser.callbackResponse.body().contains("Signed in"), browser.callbackResponse.body());
        assertFalse(browser.callbackResponse.body().contains("the-code"));
    }

    @Test
    void deniedConsentIsCancelled() throws Exception {
        OidcEndpoints ep = startRealm();
        Consumer<URI> denying = u -> {
            Map<String, String> q = query(u.getRawQuery());
            URI cb = URI.create(q.get("redirect_uri") + "?error=access_denied&state=" + q.get("state"));
            try {
                http.send(HttpRequest.newBuilder(cb).GET().build(), HttpResponse.BodyHandlers.ofString());
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        };
        SQLException e = assertThrows(SQLException.class, () -> auth(denying, Duration.ofSeconds(10)).signIn(ep));
        assertEquals("Sign-in was cancelled or timed out (no response within 5 minutes).", e.getMessage());
        assertTrue(tokenRequests.isEmpty());
    }

    @Test
    void callbackPortIsReleasedAfterSignIn() throws Exception {
        OidcEndpoints ep = startRealm();
        FakeBrowser browser = new FakeBrowser(null);
        auth(browser, Duration.ofSeconds(10)).signIn(ep);
        int port = URI.create(query(browser.authorizeUrl.getRawQuery()).get("redirect_uri")).getPort();
        // The port is free again once sign-in returns.
        occupy(port);
    }

    @Test
    void callbackWithoutStateIsRejected() throws Exception {
        OidcEndpoints ep = startRealm();
        FakeBrowser browser = new FakeBrowser(FakeBrowser.NO_STATE);
        assertThrows(SQLException.class, () -> auth(browser, Duration.ofSeconds(10)).signIn(ep));
        assertTrue(tokenRequests.isEmpty());
        assertNotEquals(200, browser.callbackResponse.statusCode());
    }

    @Test
    void callbackFromAnotherIssuerIsRefusedBeforeTheTokenRequest() throws Exception {
        OidcEndpoints ep = startRealm();
        FakeBrowser browser = new FakeBrowser(null, TD_ISSUER);
        SQLException e = assertThrows(SQLException.class,
                () -> auth(browser, Duration.ofSeconds(10), "https://evil.example/realms/x").signIn(ep));
        assertEquals(MIX_UP, e.getMessage());
        assertTrue(tokenRequests.isEmpty());
        assertNotEquals(200, browser.callbackResponse.statusCode());
    }

    @Test
    void thunderduckIssuerRequiresIss() throws Exception {
        OidcEndpoints ep = startRealm();
        FakeBrowser browser = new FakeBrowser(null, null);
        SQLException e = assertThrows(SQLException.class,
                () -> auth(browser, Duration.ofSeconds(10), TD_ISSUER).signIn(ep));
        assertEquals(MIX_UP, e.getMessage());
        assertTrue(tokenRequests.isEmpty());
    }

    @Test
    void thunderduckIssuerWithMatchingIssSucceeds() throws Exception {
        OidcEndpoints ep = startRealm();
        FakeBrowser browser = new FakeBrowser(null, TD_ISSUER);
        Tokens t = auth(browser, Duration.ofSeconds(10), "HTTPS://Auth.Thunderduck.AI./realms/thunderduck/").signIn(ep);
        assertEquals("acc", t.accessToken());
        assertEquals(1, tokenRequests.size());
    }

    @Test
    void matchingIssOnCustomIssuerSucceeds() throws Exception {
        OidcEndpoints ep = startRealm();
        FakeBrowser browser = new FakeBrowser(null, ISSUER + "/");
        assertEquals("acc", auth(browser, Duration.ofSeconds(10)).signIn(ep).accessToken());
        assertEquals(1, tokenRequests.size());
    }

    @Test
    void issWithAnotherPathIsRefused() throws Exception {
        OidcEndpoints ep = startRealm();
        FakeBrowser browser = new FakeBrowser(null, "https://auth.example/realms/other");
        SQLException e = assertThrows(SQLException.class, () -> auth(browser, Duration.ofSeconds(10)).signIn(ep));
        assertEquals(MIX_UP, e.getMessage());
        assertTrue(tokenRequests.isEmpty());
    }
}
