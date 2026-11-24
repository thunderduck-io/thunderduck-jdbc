package io.thunderduck.jdbc.oidc;

import java.util.Optional;

/** Keeps refresh tokens between connections. Key = issuer + {@code |} + client id. */
public interface TokenStore {
    Optional<Tokens> load(String key);

    void save(String key, Tokens t);

    void clear(String key);
}
