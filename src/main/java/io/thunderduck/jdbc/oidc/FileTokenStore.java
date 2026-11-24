package io.thunderduck.jdbc.oidc;

import io.thunderduck.jdbc.Json;
import java.io.File;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.attribute.FileAttribute;
import java.nio.file.attribute.PosixFilePermissions;
import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Refresh-token cache in a JSON file: {@code {"<key>": {"refresh_token": ..., "refresh_expires_at": ...}}}.
 * The access token is never written. The directory and file are owner-only where POSIX permissions exist.
 * The cache is best effort: an unreadable or corrupt file loads as empty, and a failed write is ignored
 * (the connection keeps its tokens in memory and signs in again next time).
 */
public final class FileTokenStore implements TokenStore {

    private static final String REFRESH_TOKEN = "refresh_token";
    private static final String REFRESH_EXPIRES_AT = "refresh_expires_at";

    private final Path file;

    public FileTokenStore(Path file) {
        this.file = file.toAbsolutePath();
    }

    /** {@code ~/.thunderduck/credentials.json}. */
    public static Path defaultFile() {
        return Path.of(System.getProperty("user.home"), ".thunderduck", "credentials.json");
    }

    @Override
    public Optional<Tokens> load(String key) {
        try {
            Object entry = read().get(key);
            if (!(entry instanceof Map)) return Optional.empty();
            Map<?, ?> m = (Map<?, ?>) entry;
            Object rt = m.get(REFRESH_TOKEN);
            Object exp = m.get(REFRESH_EXPIRES_AT);
            if (!(rt instanceof String) || ((String) rt).isEmpty()) return Optional.empty();
            if (exp != null && !(exp instanceof String)) return Optional.empty();
            Instant expiresAt = exp == null ? null : Instant.parse((String) exp);
            return Optional.of(new Tokens(null, null, (String) rt, expiresAt));
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    @Override
    public synchronized void save(String key, Tokens t) {
        if (t.refreshToken() == null || t.refreshToken().isEmpty()) {
            clear(key);
            return;
        }
        Map<String, Object> root = readOrEmpty();
        Map<String, Object> entry = new LinkedHashMap<>();
        entry.put(REFRESH_TOKEN, t.refreshToken());
        entry.put(REFRESH_EXPIRES_AT, t.refreshExpiresAt() == null ? null : t.refreshExpiresAt().toString());
        root.put(key, entry);
        write(root);
    }

    @Override
    public synchronized void clear(String key) {
        if (!Files.exists(file)) return;
        Map<String, Object> root = readOrEmpty();
        if (root.remove(key) != null) write(root);
    }

    private Map<String, Object> read() throws IOException {
        if (!Files.isRegularFile(file)) return new LinkedHashMap<>();
        return Json.parseObject(Files.readString(file, StandardCharsets.UTF_8));
    }

    private Map<String, Object> readOrEmpty() {
        try {
            Map<String, Object> m = read();
            return m == null ? new LinkedHashMap<>() : new LinkedHashMap<>(m);
        } catch (Exception e) {
            return new LinkedHashMap<>(); // corrupt: start over
        }
    }

    private void write(Map<String, Object> root) {
        boolean posix = FileSystems.getDefault().supportedFileAttributeViews().contains("posix");
        Path dir = file.getParent();
        Path tmp = null;
        try {
            if (!Files.isDirectory(dir)) {
                if (posix) {
                    Files.createDirectories(dir, perms("rwx------"));
                } else {
                    Files.createDirectories(dir);
                }
            }
            // Write a fresh owner-only file and move it over the old one, so the cache is never
            // half-written and never readable by others even if the old file was.
            tmp = posix
                    ? Files.createTempFile(dir, ".credentials", ".tmp", perms("rw-------"))
                    : Files.createTempFile(dir, ".credentials", ".tmp");
            if (!posix) ownerOnly(tmp.toFile());
            Files.writeString(tmp, Json.write(root), StandardCharsets.UTF_8);
            try {
                Files.move(tmp, file, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException e) {
                Files.move(tmp, file, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException | RuntimeException e) {
            // Best effort: tokens stay in memory for this connection.
        } finally {
            if (tmp != null) {
                try {
                    Files.deleteIfExists(tmp);
                } catch (IOException ignored) {
                    // nothing more to do
                }
            }
        }
    }

    private static FileAttribute<?> perms(String spec) {
        return PosixFilePermissions.asFileAttribute(PosixFilePermissions.fromString(spec));
    }

    private static void ownerOnly(File f) {
        f.setReadable(false, false);
        f.setReadable(true, true);
        f.setWritable(false, false);
        f.setWritable(true, true);
    }
}
