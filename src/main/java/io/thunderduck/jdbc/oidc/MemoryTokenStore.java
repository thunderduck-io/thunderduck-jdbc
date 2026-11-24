package io.thunderduck.jdbc.oidc;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/** In-process store for {@code tokenCache=none}: nothing touches the disk. */
public final class MemoryTokenStore implements TokenStore {

    private final Map<String, Tokens> tokens = new ConcurrentHashMap<>();

    @Override
    public Optional<Tokens> load(String key) {
        return Optional.ofNullable(tokens.get(key));
    }

    @Override
    public void save(String key, Tokens t) {
        tokens.put(key, t);
    }

    @Override
    public void clear(String key) {
        tokens.remove(key);
    }
}
