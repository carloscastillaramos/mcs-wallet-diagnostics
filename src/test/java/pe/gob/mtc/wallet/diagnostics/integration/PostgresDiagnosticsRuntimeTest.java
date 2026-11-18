package pe.gob.mtc.wallet.diagnostics.integration;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.jdbc.AutoConfigureTestDatabase;
import org.springframework.boot.test.autoconfigure.jdbc.JdbcTest;
import org.springframework.context.annotation.Import;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.PlatformTransactionManager;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionTemplate;
import pe.gob.mtc.wallet.diagnostics.domain.DiagnosticEvent;
import pe.gob.mtc.wallet.diagnostics.domain.DiagnosticsException;
import pe.gob.mtc.wallet.diagnostics.domain.StoredDiagnosticEvent;
import pe.gob.mtc.wallet.diagnostics.infrastructure.PostgresDiagnosticsRepository;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Ejercita el repositorio Spring JDBC REAL de Diagnostics y su transaccionalidad.
 * Su ejecución es optativa, y solo se permite en PostgreSQL local desechable.
 */
@JdbcTest(properties = {"spring.flyway.enabled=true", "spring.datasource.hikari.maximum-pool-size=8"})
@Import(PostgresDiagnosticsRepository.class)
@AutoConfigureTestDatabase(replace = AutoConfigureTestDatabase.Replace.NONE)
@EnabledIfEnvironmentVariable(named = "WALLET_PG_DEEP_IT", matches = "true")
@Transactional(propagation = Propagation.NOT_SUPPORTED)
class PostgresDiagnosticsRuntimeTest {
    @DynamicPropertySource
    static void postgres(DynamicPropertyRegistry registry) {
        String url = required("WALLET_PG_JDBC_URL");
        if (!(url.startsWith("jdbc:postgresql://127.0.0.1:55432/")
                || url.startsWith("jdbc:postgresql://localhost:55432/"))) {
            throw new IllegalStateException("Solo se admite la base PostgreSQL de pruebas en localhost:55432");
        }
        registry.add("spring.datasource.url", () -> url);
        registry.add("spring.datasource.username", () -> required("WALLET_PG_USER"));
        registry.add("spring.datasource.password", () -> required("WALLET_PG_PASSWORD"));
    }

    private static String required(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) throw new IllegalStateException("Falta " + name);
        return value;
    }

    @Autowired private PostgresDiagnosticsRepository repository;
    @Autowired private JdbcTemplate jdbc;
    @Autowired private PlatformTransactionManager transactionManager;
    private TransactionTemplate tx;
    private String deviceId;

    @BeforeEach
    void setUp() {
        deviceId = UUID.randomUUID().toString();
        tx = new TransactionTemplate(transactionManager);
    }

    @AfterEach
    void cleanSyntheticRows() {
        jdbc.update("DELETE FROM wallet_diagnostics.mcs_diag_event WHERE device_id=?", deviceId);
        jdbc.update("DELETE FROM wallet_diagnostics.mcs_diag_event_registry WHERE device_id=?", deviceId);
        jdbc.update("DELETE FROM wallet_diagnostics.mcs_diag_nonce WHERE device_id=?", deviceId);
        jdbc.update("DELETE FROM wallet_diagnostics.mcs_diag_admin_audit WHERE device_id=?", deviceId);
        jdbc.update("DELETE FROM wallet_diagnostics.mcs_diag_device WHERE device_id=?", deviceId);
    }

    @Test
    void registerRevokeAndReplayProtectionExecuteOnRealPostgreSql() {
        String keyId = "key-" + UUID.randomUUID();
        tx.executeWithoutResult(status -> repository.registerDevice(deviceId, keyId,
                "ANDROID", "dGVzdC1rZXk=", "local-integration-test"));
        assertEquals("dGVzdC1rZXk=", repository.activeDeviceKey(deviceId, keyId).orElseThrow());
        assertEquals(Boolean.TRUE, tx.execute(status -> repository.reserveNonce(deviceId, "nonce-integration-123")));
        assertEquals(Boolean.FALSE, tx.execute(status -> repository.reserveNonce(deviceId, "nonce-integration-123")));
        jdbc.update("INSERT INTO wallet_diagnostics.mcs_diag_nonce(device_id,nonce_value,received_at) "
                + "VALUES(?,?,CURRENT_TIMESTAMP - INTERVAL '3 days')", deviceId, "expired-test-nonce");
        assertTrue(tx.execute(status -> repository.purgeOldNonces()) >= 1);
        assertEquals(0L, jdbc.queryForObject("SELECT count(*) FROM wallet_diagnostics.mcs_diag_nonce "
                + "WHERE device_id=? AND nonce_value=?", Long.class, deviceId, "expired-test-nonce").longValue());
        assertEquals(Boolean.TRUE, tx.execute(status -> repository.revokeDevice(deviceId, keyId, "local-integration-test")));
        assertTrue(repository.activeDeviceKey(deviceId, keyId).isEmpty());
        assertEquals(Boolean.FALSE, tx.execute(status -> repository.revokeDevice(deviceId, keyId, "local-integration-test")));
    }

    @Test
    void eventIdempotencyIsGlobalAcrossMonthlyPartitions() {
        UUID eventId = UUID.randomUUID();
        Instant now = Instant.now();
        Instant nextMonth = OffsetDateTime.now(ZoneOffset.UTC).withDayOfMonth(1)
                .plusMonths(1).toInstant();
        String hash = "a".repeat(64);
        StoredDiagnosticEvent current = event(eventId, now, hash);
        StoredDiagnosticEvent replay = event(eventId, nextMonth, hash);

        assertEquals(Boolean.TRUE, tx.execute(status -> repository.insertEvent(deviceId, current)));
        assertEquals(Boolean.FALSE, tx.execute(status -> repository.insertEvent(deviceId, replay)));
        DiagnosticsException conflict = assertThrows(DiagnosticsException.class,
                () -> tx.execute(status -> repository.insertEvent(deviceId,
                        event(eventId, nextMonth, "b".repeat(64)))));
        assertEquals("CONFLICTING_EVENT_ID", conflict.code());
        UUID secondId = UUID.randomUUID();
        assertEquals(Boolean.TRUE, tx.execute(status -> repository.insertEvent(deviceId,
                event(secondId, nextMonth, hash))));
        assertEquals(2L, eventCount());
        String partition = jdbc.queryForObject(
                "SELECT tableoid::regclass::text FROM wallet_diagnostics.mcs_diag_event "
                        + "WHERE device_id=? AND event_id=?",
                String.class, deviceId, secondId.toString());
        assertNotNull(partition);
        assertTrue(partition.contains("mcs_diag_event_"));
    }

    @Test
    void registryReservationIsRolledBackIfMonthlyPartitionRejectsEvent() {
        UUID eventId = UUID.randomUUID();
        String hash = "c".repeat(64);
        // Fuera del horizonte inicial de particiones: la escritura del evento falla.
        Instant outOfHorizon = Instant.now().plusSeconds(86400L * 365 * 10);
        assertThrows(RuntimeException.class, () -> tx.execute(status ->
                repository.insertEvent(deviceId, event(eventId, outOfHorizon, hash))));
        Long reserved = jdbc.queryForObject(
                "SELECT count(*) FROM wallet_diagnostics.mcs_diag_event_registry "
                        + "WHERE device_id=? AND event_id=?",
                Long.class, deviceId, eventId.toString());
        assertNotNull(reserved);
        assertEquals(0L, reserved.longValue(),
                "No debe quedar idempotencia reservada si la inserción del evento hizo rollback");
        assertEquals(Boolean.TRUE, tx.execute(status -> repository.insertEvent(deviceId,
                event(eventId, Instant.now(), hash))));
        assertEquals(1L, eventCount());
    }

    @Test
    void simultaneousReplaysDoNotDuplicateAnEvent() throws Exception {
        UUID eventId = UUID.randomUUID();
        StoredDiagnosticEvent payload = event(eventId, Instant.now(), "d".repeat(64));
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService workers = Executors.newFixedThreadPool(2);
        try {
            Future<Boolean> first = workers.submit(() -> {
                await(start);
                return tx.execute(status -> repository.insertEvent(deviceId, payload));
            });
            Future<Boolean> second = workers.submit(() -> {
                await(start);
                return tx.execute(status -> repository.insertEvent(deviceId, payload));
            });
            start.countDown();
            int accepted = (Boolean.TRUE.equals(first.get(15, TimeUnit.SECONDS)) ? 1 : 0)
                    + (Boolean.TRUE.equals(second.get(15, TimeUnit.SECONDS)) ? 1 : 0);
            assertEquals(1, accepted, "Solo debe insertarse una copia del evento");
            assertEquals(1L, eventCount());
        } finally {
            start.countDown();
            workers.shutdownNow();
            assertTrue(workers.awaitTermination(10, TimeUnit.SECONDS));
        }
    }

    private long eventCount() {
        return jdbc.queryForObject("SELECT count(*) FROM wallet_diagnostics.mcs_diag_event "
                + "WHERE device_id=?", Long.class, deviceId);
    }

    private static StoredDiagnosticEvent event(UUID eventId, Instant receivedAt, String hash) {
        DiagnosticEvent event = new DiagnosticEvent(eventId, receivedAt,
                "DOWNLOAD_ERROR", "WALLET", "ERROR", "NETWORK_TIMEOUT",
                "ANDROID", "0.3.0", 75L, Map.of("NETWORK_STATE", "ONLINE"));
        return new StoredDiagnosticEvent(event, "{\"NETWORK_STATE\":\"ONLINE\"}", hash, receivedAt);
    }

    private static void await(CountDownLatch latch) {
        try {
            if (!latch.await(10, TimeUnit.SECONDS)) throw new IllegalStateException("Timeout en test concurrente");
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrumpido", e);
        }
    }
}
