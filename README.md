# thunderduck JDBC driver

A JDBC driver that lets SQL/BI tools query thunderduck. Each query runs as a
thunderduck DuckDB Job via the REST API; results come back as a JDBC `ResultSet`.
Zero runtime dependencies (JDK `HttpClient` + a tiny JSON parser).

[Source on GitHub](https://github.com/thunderduck-io/thunderduck-jdbc) ·
[Documentation](https://docs.thunderduck.ai/clients/jdbc) ·
[Maven Central](https://central.sonatype.com/artifact/io.thunderduck/thunderduck-jdbc/overview)

## Build

```bash
mvn -q -DskipTests package
# → target/thunderduck-jdbc-<version>.jar
```

(No Maven? It's pure JDK — `javac -d out $(find src/main/java -name '*.java')` then
`jar cf thunderduck-jdbc.jar -C out . -C src/main/resources .`.)

## Connect

- **Driver class:** `io.thunderduck.jdbc.ThunderduckDriver` (auto-registers)
- **URL:** `jdbc:thunderduck://api.thunderduck.ai/?token=<TOKEN>`
  - Or pass the token as the JDBC **password** property (leave the URL token off).
  - Optional params: `poll_ms` (default 1000), `timeout_ms` (default 300000), `ssl=false`.
- **Sign in with your account (0.2.0+):** `jdbc:thunderduck://api.thunderduck.ai/?auth=browser`
  opens your browser at connect time (desktop only; servers, containers and CI use API
  tokens). Values: `auth` = `token` (default) | `browser`; `tokenCache` =
  `file` (default; refresh token in `~/.thunderduck/credentials.json`, owner-only) | `none`
  (nothing on disk); `issuer` — the sign-in server. Defaulted from the host you connect to: the driver asks it (`/.well-known/oauth-protected-resource`)
  which sign-in server it belongs to. It accepts exactly the host your naming implies —
  `<company>-api.<domain>` → `<company>-auth.<domain>` — and nothing else; an install that names
  its realm differently passes `issuer=`, which always overrides. Loopback sign-in is accepted
  only from a loopback connection.
  Browser callback uses `127.0.0.1` ports 33500–33509. Queries show as "JDBC" in Query
  History. Use API tokens for servers and CI. Full guide: https://docs.thunderduck.ai/clients/jdbc
- **Token:** create one in the console under **API Tokens** (a `tdk_…` value; shown once).

### DBeaver / DataGrip
Add the jar from `target/` (`thunderduck-jdbc-<version>.jar`) as a new driver (class `io.thunderduck.jdbc.ThunderduckDriver`,
URL template `jdbc:thunderduck://{host}/`), then connect with your `tdk_…` token as the password.

### Java
```java
Class.forName("io.thunderduck.jdbc.ThunderduckDriver"); // or rely on ServiceLoader
var url = "jdbc:thunderduck://api.thunderduck.ai/?token=" + token;
try (var c = DriverManager.getConnection(url);
     var st = c.createStatement();
     var rs = st.executeQuery("SELECT * FROM tndr_postgres_demo.ecommerce.orders LIMIT 100")) {
    while (rs.next()) System.out.println(rs.getBigDecimal("total_amount"));
}
```

Query using `catalog.schema.table` (e.g. `tndr_postgres_demo.ecommerce.orders`,
`tndr_glue_demo.iris`) — the same names shown in the Studio catalog explorer.

## License

Apache-2.0. See [LICENSE](LICENSE).

This repository is a mirror of Thunderduck's internal source; see
[CONTRIBUTING.md](CONTRIBUTING.md) for how issues and pull requests are handled,
and [SECURITY.md](SECURITY.md) to report a vulnerability.

## Behaviour & limits (v1)

- **Read-only, forward-only.** `TYPE_FORWARD_ONLY` / `CONCUR_READ_ONLY`.
- **Latency:** each query is a fresh Job, so expect a few seconds before the first
  row — fine for analytics/BI, not for tight interactive loops. Results paginate
  automatically as you iterate the `ResultSet`.
- **Typed metadata:** `ResultSetMetaData` reflects real column types.
- **Schema browsing works.** `DatabaseMetaData.getCatalogs/getSchemas/getTables/getColumns`
  are implemented on top of the catalog API, and `PreparedStatement` is available.
- **Not implemented** (throw `SQLFeatureNotSupportedException`): batches, updates,
  and `Statement.cancel()` (a no-op — use the console to cancel a run, or the
  `thunderduck-sqlalchemy` Python driver, which does support cancellation).
