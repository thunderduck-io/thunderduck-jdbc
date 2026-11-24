package io.thunderduck.jdbc;

import java.sql.SQLException;

/** Supplies the Bearer credential for each API request. */
public interface AuthProvider {

    /** The current bearer token; may refresh or sign in as needed. */
    String bearer() throws SQLException;

    /** Called after the server rejected the last bearer (HTTP 401). */
    void invalidate();

    /** Whether a fresh bearer can be obtained after invalidate(); if false, a 401 is final. */
    boolean canRenew();
}
