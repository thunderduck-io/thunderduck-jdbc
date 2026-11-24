package io.thunderduck.jdbc.oidc;

import static org.junit.jupiter.api.Assertions.*;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import org.junit.jupiter.api.Test;

class PkceTest {

    @Test
    void challengeIsBase64UrlSha256OfVerifierWithoutPadding() throws Exception {
        Pkce p = Pkce.create();
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(p.verifier().getBytes(StandardCharsets.US_ASCII));
        assertEquals(Base64.getUrlEncoder().withoutPadding().encodeToString(digest), p.challenge());
        assertFalse(p.challenge().contains("="));
    }

    @Test
    void verifierIsUnreservedAndOfLegalLength() {
        Pkce p = Pkce.create();
        assertTrue(p.verifier().length() >= 43 && p.verifier().length() <= 128, p.verifier());
        assertTrue(p.verifier().matches("[A-Za-z0-9\\-._~]+"), p.verifier());
        assertNotEquals(p.verifier(), Pkce.create().verifier());
    }
}
