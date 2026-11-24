package io.thunderduck.jdbc;

import java.sql.SQLFeatureNotSupportedException;

/** Shared "not supported" helper for the many JDBC interface methods the
 *  thunderduck driver doesn't implement (it's a read-only, forward-only bridge
 *  over the REST API). */
final class Err {
    private Err() {}

    static SQLFeatureNotSupportedException nyi(String feature) {
        return new SQLFeatureNotSupportedException(feature + " is not supported by the thunderduck JDBC driver");
    }
}
