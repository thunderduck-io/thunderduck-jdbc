package io.thunderduck.jdbc.oidc;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

/** A PKCE pair (RFC 7636, S256): a random 43-char verifier and its SHA-256 challenge. */
final class Pkce {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final String verifier;
    private final String challenge;

    private Pkce(String verifier, String challenge) {
        this.verifier = verifier;
        this.challenge = challenge;
    }

    static Pkce create() {
        String verifier = randomUrlSafe(32); // 43 chars of [A-Za-z0-9_-]
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
            return new Pkce(verifier, Base64.getUrlEncoder().withoutPadding().encodeToString(digest));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is unavailable", e); // every JDK has it
        }
    }

    /** {@code bytes} random bytes, base64url without padding. */
    static String randomUrlSafe(int bytes) {
        byte[] b = new byte[bytes];
        RANDOM.nextBytes(b);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
    }

    String verifier() {
        return verifier;
    }

    String challenge() {
        return challenge;
    }
}
