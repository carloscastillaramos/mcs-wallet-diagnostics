package pe.gob.mtc.wallet.diagnostics.integration;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

/** Test optativo contra PostgreSQL 16 real: Flyway, RANGE/HASH y deduplicacion. */
@EnabledIfEnvironmentVariable(named = "WALLET_PG_IT", matches = "true")
class PostgresIntegrationTest {
    private static String env(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) throw new IllegalStateException("Falta " + name);
        return value;
    }

    @Test
    void flywayAndGlobalIdempotencyAcrossMonths() throws Exception {
        String url = env("WALLET_PG_JDBC_URL");
        String user = env("WALLET_PG_USER");
        String password = env("WALLET_PG_PASSWORD");

        Flyway flyway = Flyway.configure()
                .dataSource(url, user, password)
                .defaultSchema("wallet_diagnostics")
                .schemas("wallet_diagnostics")
                .createSchemas(false)
                .table("flyway_schema_history")
                .locations("classpath:db/migration")
                .load();
        flyway.migrate();
        flyway.validate();

        try (Connection connection = DriverManager.getConnection(url, user, password)) {
            assertEquals(1, scalarLong(connection, "SELECT count(*) FROM pg_partitioned_table "
                    + "WHERE partrelid='wallet_diagnostics.mcs_diag_event'::regclass"));
            assertEquals(1, scalarLong(connection, "SELECT count(*) FROM pg_partitioned_table "
                    + "WHERE partrelid='wallet_diagnostics.mcs_diag_event_registry'::regclass"));
            assertEquals(16, scalarLong(connection, "SELECT count(*) FROM pg_inherits "
                    + "WHERE inhparent='wallet_diagnostics.mcs_diag_event_registry'::regclass"));
            assertTrue(scalarLong(connection, "SELECT count(*) FROM pg_inherits "
                    + "WHERE inhparent='wallet_diagnostics.mcs_diag_event'::regclass") >= 2);

            String device = UUID.randomUUID().toString();
            String nonce = "n-" + UUID.randomUUID();
            assertEquals(1, reserveNonce(connection, device, nonce));
            assertEquals(0, reserveNonce(connection, device, nonce));

            String event = UUID.randomUUID().toString();
            String hash = "a".repeat(64);
            OffsetDateTime now = OffsetDateTime.now(ZoneOffset.UTC);
            OffsetDateTime nextMonth = now.withDayOfMonth(1).plusMonths(1);

            connection.setAutoCommit(false);
            try {
                assertEquals(1, reserveEventId(connection, device, event, hash, now));
                assertEquals(1, insertEvent(connection, device, event, hash, now));
                connection.commit();
            } catch (Exception e) {
                connection.rollback();
                throw e;
            }

            // Simular reenvio en otro mes: NO debe duplicarse el identificador global.
            assertEquals(0, reserveEventId(connection, device, event, hash, nextMonth));
            String otherEvent = UUID.randomUUID().toString();
            try {
                assertEquals(1, reserveEventId(connection, device, otherEvent, hash, nextMonth));
                assertEquals(1, insertEvent(connection, device, otherEvent, hash, nextMonth));
                connection.commit();
            } catch (Exception e) {
                connection.rollback();
                throw e;
            }
            assertEquals(2, countForDevice(connection, device));
            connection.rollback();
            connection.setAutoCommit(true);

            // Limpieza de datos sinteticos de la prueba (en un entorno local aislado).
            try (PreparedStatement p1 = connection.prepareStatement(
                    "DELETE FROM wallet_diagnostics.mcs_diag_event WHERE device_id=?");
                 PreparedStatement p2 = connection.prepareStatement(
                         "DELETE FROM wallet_diagnostics.mcs_diag_event_registry WHERE device_id=?");
                 PreparedStatement p3 = connection.prepareStatement(
                         "DELETE FROM wallet_diagnostics.mcs_diag_nonce WHERE device_id=?")) {
                for (PreparedStatement p : new PreparedStatement[]{p1,p2,p3}) {
                    p.setString(1, device);
                    p.executeUpdate();
                }
            }
        }
    }

    private static int reserveNonce(Connection c, String device, String nonce) throws Exception {
        try (PreparedStatement p = c.prepareStatement(
                "INSERT INTO wallet_diagnostics.mcs_diag_nonce(device_id,nonce_value,received_at) "
                        + "VALUES(?,?,CURRENT_TIMESTAMP) ON CONFLICT (device_id,nonce_value) DO NOTHING")) {
            p.setString(1, device);
            p.setString(2, nonce);
            return p.executeUpdate();
        }
    }

    private static int reserveEventId(Connection c, String device, String event, String hash,
                                      OffsetDateTime time) throws Exception {
        try (PreparedStatement p = c.prepareStatement(
                "INSERT INTO wallet_diagnostics.mcs_diag_event_registry "
                        + "(device_id,event_id,payload_sha256,first_seen_at) VALUES(?,?,?,?) "
                        + "ON CONFLICT (device_id,event_id) DO NOTHING")) {
            p.setString(1, device);
            p.setString(2, event);
            p.setString(3, hash);
            p.setObject(4, time);
            return p.executeUpdate();
        }
    }

    private static int insertEvent(Connection c, String device, String event, String hash,
                                   OffsetDateTime time) throws Exception {
        try (PreparedStatement p = c.prepareStatement(
                "INSERT INTO wallet_diagnostics.mcs_diag_event "
                        + "(device_id,event_id,occurred_at,received_at,event_type,component,severity,"
                        + "error_code,platform,app_version,duration_ms,attributes_json,payload_sha256) "
                        + "VALUES (?,?,?,?,'TEST_EVENT','WALLET','INFO','TEST','ANDROID','0.3.0',"
                        + "10,CAST(? AS jsonb),?)")) {
            p.setString(1, device);
            p.setString(2, event);
            p.setObject(3, time);
            p.setObject(4, time);
            p.setString(5, "{\"test\":true}");
            p.setString(6, hash);
            return p.executeUpdate();
        }
    }

    private static long countForDevice(Connection c, String device) throws Exception {
        try (PreparedStatement p = c.prepareStatement(
                "SELECT count(*) FROM wallet_diagnostics.mcs_diag_event WHERE device_id=?")) {
            p.setString(1, device);
            try (ResultSet rs = p.executeQuery()) {
                assertTrue(rs.next());
                return rs.getLong(1);
            }
        }
    }

    private static long scalarLong(Connection c, String sql) throws Exception {
        try (PreparedStatement p = c.prepareStatement(sql);
             ResultSet rs = p.executeQuery()) {
            assertTrue(rs.next());
            return rs.getLong(1);
        }
    }
}
