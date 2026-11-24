package io.thunderduck.jdbc.oidc;

import static org.junit.jupiter.api.Assertions.*;
import static org.junit.jupiter.api.Assumptions.assumeTrue;

import java.nio.charset.StandardCharsets;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

class FileTokenStoreTest {

    private static final String KEY = "https://kc.test/realms/td|thunderduck-jdbc";
    private static final Instant REFRESH_EXP = Instant.parse("2026-10-28T12:00:00Z");

    @TempDir
    Path tmp;

    private Path file() {
        return tmp.resolve(".thunderduck").resolve("credentials.json");
    }

    private static boolean posix() {
        return FileSystems.getDefault().supportedFileAttributeViews().contains("posix");
    }

    @Test
    void roundTripKeepsRefreshTokenAndExpiry() {
        new FileTokenStore(file()).save(KEY, new Tokens("acc", Instant.now(), "ref", REFRESH_EXP));

        Tokens t = new FileTokenStore(file()).load(KEY).orElseThrow();
        assertEquals("ref", t.refreshToken());
        assertEquals(REFRESH_EXP, t.refreshExpiresAt());
        assertNull(t.accessToken());
        assertNull(t.accessExpiresAt());
    }

    @Test
    void keysAreIndependentAndClearRemovesOne() {
        FileTokenStore s = new FileTokenStore(file());
        s.save(KEY, new Tokens(null, null, "a", REFRESH_EXP));
        s.save("other|thunderduck-jdbc", new Tokens(null, null, "b", null));
        s.clear(KEY);
        assertTrue(s.load(KEY).isEmpty());
        Tokens other = s.load("other|thunderduck-jdbc").orElseThrow();
        assertEquals("b", other.refreshToken());
        assertNull(other.refreshExpiresAt());
    }

    @Test
    void accessTokenIsNotWritten() throws Exception {
        new FileTokenStore(file()).save(KEY, new Tokens("secret-access-token", Instant.now(), "ref", REFRESH_EXP));
        String json = Files.readString(file(), StandardCharsets.UTF_8);
        assertFalse(json.contains("secret-access-token"), json);
        assertFalse(json.contains("access"), json);
        assertTrue(json.contains("refresh_token"), json);
        assertTrue(json.contains("refresh_expires_at"), json);
    }

    @Test
    void fileIsOwnerOnlyOnPosix() throws Exception {
        assumeTrue(posix());
        new FileTokenStore(file()).save(KEY, new Tokens(null, null, "ref", REFRESH_EXP));
        assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(file())));
        assertEquals("rwx------", PosixFilePermissions.toString(Files.getPosixFilePermissions(file().getParent())));
    }

    @Test
    void widePermissionsOnExistingFileAreTightenedOnSave() throws Exception {
        assumeTrue(posix());
        Files.createDirectories(file().getParent());
        Files.writeString(file(), "{}");
        Files.setPosixFilePermissions(file(), PosixFilePermissions.fromString("rw-r--r--"));
        new FileTokenStore(file()).save(KEY, new Tokens(null, null, "ref", REFRESH_EXP));
        assertEquals("rw-------", PosixFilePermissions.toString(Files.getPosixFilePermissions(file())));
    }

    @Test
    void missingFileLoadsEmpty() {
        assertTrue(new FileTokenStore(file()).load(KEY).isEmpty());
    }

    @Test
    void corruptFileLoadsEmptyAndSaveRecovers() throws Exception {
        Files.createDirectories(file().getParent());
        Files.writeString(file(), "{not json");
        FileTokenStore s = new FileTokenStore(file());
        assertTrue(s.load(KEY).isEmpty());
        s.save(KEY, new Tokens(null, null, "ref", REFRESH_EXP));
        assertEquals("ref", s.load(KEY).orElseThrow().refreshToken());
    }

    @Test
    void wrongShapeLoadsEmpty() throws Exception {
        Files.createDirectories(file().getParent());
        Files.writeString(file(), "{\"" + KEY + "\": {\"refresh_token\": 5, \"refresh_expires_at\": \"nope\"}}");
        assertTrue(new FileTokenStore(file()).load(KEY).isEmpty());
        Files.writeString(file(), "[1,2]");
        assertTrue(new FileTokenStore(file()).load(KEY).isEmpty());
    }

    @Test
    void unreadableFileLoadsEmpty() throws Exception {
        assumeTrue(posix());
        new FileTokenStore(file()).save(KEY, new Tokens(null, null, "ref", REFRESH_EXP));
        Files.setPosixFilePermissions(file(), PosixFilePermissions.fromString("---------"));
        assumeTrue(!Files.isReadable(file()), "running as a user that can read anything (root)");
        assertTrue(new FileTokenStore(file()).load(KEY).isEmpty());
    }

    @Test
    void defaultFileIsUnderHomeDotThunderduck() {
        assertEquals(Path.of(System.getProperty("user.home"), ".thunderduck", "credentials.json"),
                FileTokenStore.defaultFile());
    }
}
