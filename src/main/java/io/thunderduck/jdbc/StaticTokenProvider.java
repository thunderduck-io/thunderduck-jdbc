package io.thunderduck.jdbc;

/** A fixed API token (tdk_...); nothing to refresh, so invalidation is a no-op. */
final class StaticTokenProvider implements AuthProvider {

    private final String token;

    StaticTokenProvider(String token) {
        this.token = token;
    }

    @Override
    public String bearer() {
        return token;
    }

    @Override
    public void invalidate() {
        // a static token cannot be renewed
    }

    @Override
    public boolean canRenew() {
        return false;
    }
}
