package io.thunderduck.jdbc.oidc;

import java.sql.SQLException;

/** An interactive (browser) sign-in that yields fresh tokens. */
public interface Authenticator {
    Tokens signIn(OidcEndpoints ep) throws SQLException;
}
