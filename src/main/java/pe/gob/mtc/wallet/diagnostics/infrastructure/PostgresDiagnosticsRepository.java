package pe.gob.mtc.wallet.diagnostics.infrastructure;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import pe.gob.mtc.wallet.diagnostics.application.port.DiagnosticsRepository;
import pe.gob.mtc.wallet.diagnostics.domain.DiagnosticsException;
import pe.gob.mtc.wallet.diagnostics.domain.StoredDiagnosticEvent;

import java.sql.Timestamp;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * PostgreSQL adapter. No exception-driven conflict handling: ON CONFLICT is
 * atomic and works under Spring's existing @Transactional ingest boundary.
 */
@Repository
public class PostgresDiagnosticsRepository implements DiagnosticsRepository {
    private final JdbcTemplate jdbc;

    public PostgresDiagnosticsRepository(JdbcTemplate jdbc) { this.jdbc = jdbc; }

    @Override
    public Optional<String> activeDeviceKey(String deviceId, String keyId) {
        return jdbc.query(
                "SELECT public_key_spki_b64 FROM wallet_diagnostics.mcs_diag_device "
                        + "WHERE device_id=? AND key_id=? AND active=true AND revoked_at IS NULL",
                rs -> rs.next() ? Optional.of(rs.getString(1)) : Optional.empty(), deviceId, keyId);
    }

    @Override
    public boolean reserveNonce(String deviceId, String nonce) {
        int inserted = jdbc.update(
                "INSERT INTO wallet_diagnostics.mcs_diag_nonce(device_id,nonce_value,received_at) "
                        + "VALUES(?,?,CURRENT_TIMESTAMP) ON CONFLICT (device_id,nonce_value) DO NOTHING",
                deviceId, nonce);
        return inserted == 1;
    }

    @Override
    public boolean insertEvent(String deviceId, StoredDiagnosticEvent stored) {
        var event = stored.event();
        String eventId = event.eventId().toString();
        // The registry guarantees global uniqueness across date partitions.
        // The two inserts MUST remain in the caller's single DB transaction.
        int reserved = jdbc.update(
                "INSERT INTO wallet_diagnostics.mcs_diag_event_registry"
                        + "(device_id,event_id,payload_sha256,first_seen_at) "
                        + "VALUES(?,?,?,?) ON CONFLICT (device_id,event_id) DO NOTHING",
                deviceId, eventId, stored.payloadHash(), Timestamp.from(stored.receivedAt()));
        if (reserved == 0) {
            List<String> originalHashes = jdbc.query(
                    "SELECT payload_sha256 FROM wallet_diagnostics.mcs_diag_event_registry "
                            + "WHERE device_id=? AND event_id=?",
                    (rs, row) -> rs.getString(1).trim(), deviceId, eventId);
            if (originalHashes.size() != 1 || !originalHashes.get(0).equals(stored.payloadHash())) {
                throw DiagnosticsException.conflict();
            }
            return false;
        }

        jdbc.update("INSERT INTO wallet_diagnostics.mcs_diag_event("
                        + "device_id,event_id,occurred_at,received_at,event_type,component,"
                        + "severity,error_code,platform,app_version,duration_ms,attributes_json,payload_sha256)"
                        + " VALUES(?,?,?,?,?,?,?,?,?,?,?,CAST(? AS jsonb),?)",
                deviceId, eventId, Timestamp.from(event.occurredAt()),
                Timestamp.from(stored.receivedAt()), event.eventType(), event.component(),
                event.severity(), event.code(), event.platform(), event.appVersion(), event.durationMs(),
                stored.attributesJson(), stored.payloadHash());
        return true;
    }

    @Override
    public void registerDevice(String deviceId, String keyId, String platform, String publicKeyBase64, String actor) {
        // Administrator cannot resurrect a key already revoked by Provider.
        // Same transaction-scoped lock as ProviderDeviceSyncRepository.
        jdbc.queryForObject("SELECT pg_advisory_xact_lock(hashtextextended(?,0))", Object.class,
                "mcs_diag_sync:" + deviceId + ":" + keyId);
        int inserted = jdbc.update(
                "INSERT INTO wallet_diagnostics.mcs_diag_device("
                        + "device_id,key_id,platform,public_key_spki_b64,active,created_at) "
                        + "SELECT ?,?,?,?,true,CURRENT_TIMESTAMP WHERE NOT EXISTS ("
                        + "SELECT 1 FROM wallet_diagnostics.mcs_diag_device_tombstone "
                        + "WHERE device_id=? AND key_id=?) "
                        + "ON CONFLICT (device_id,key_id) DO NOTHING",
                deviceId, keyId, platform, publicKeyBase64,deviceId,keyId);
        if (inserted != 1) throw DiagnosticsException.conflict();
        audit("DEVICE_REGISTERED", actor, deviceId, keyId);
    }

    @Override
    public boolean revokeDevice(String deviceId, String keyId, String actor) {
        jdbc.queryForObject("SELECT pg_advisory_xact_lock(hashtextextended(?,0))", Object.class,
                "mcs_diag_sync:" + deviceId + ":" + keyId);
        int changed = jdbc.update("UPDATE wallet_diagnostics.mcs_diag_device "
                        + "SET active=false,revoked_at=CURRENT_TIMESTAMP "
                        + "WHERE device_id=? AND key_id=? AND active=true",
                deviceId, keyId);
        if (changed > 0) {
            jdbc.update("INSERT INTO wallet_diagnostics.mcs_diag_device_tombstone "
                    + "(device_id,key_id,actor_id) VALUES(?,?,?) ON CONFLICT DO NOTHING",
                    deviceId,keyId,actor);
            audit("DEVICE_REVOKED", actor, deviceId, keyId);
        }
        return changed > 0;
    }

    private void audit(String action, String actor, String deviceId, String keyId) {
        jdbc.update("INSERT INTO wallet_diagnostics.mcs_diag_admin_audit("
                        + "action,actor_id,device_id,key_id,created_at) VALUES(?,?,?,?,CURRENT_TIMESTAMP)",
                action, actor, deviceId, keyId);
    }

    @Override
    public List<Map<String, Object>> findEvents(String deviceId, String code, int offset, int limit) {
        StringBuilder sql = new StringBuilder("SELECT device_id AS \"DEVICE_ID\",event_id AS \"EVENT_ID\","
                + "occurred_at AS \"OCCURRED_AT\",received_at AS \"RECEIVED_AT\","
                + "event_type AS \"EVENT_TYPE\",component AS \"COMPONENT\","
                + "severity AS \"SEVERITY\",error_code AS \"ERROR_CODE\","
                + "platform AS \"PLATFORM\",app_version AS \"APP_VERSION\","
                + "duration_ms AS \"DURATION_MS\",attributes_json::text AS \"ATTRIBUTES_JSON\" "
                + "FROM wallet_diagnostics.mcs_diag_event WHERE 1=1");
        List<Object> params = new ArrayList<>();
        if (deviceId != null && !deviceId.isBlank()) {
            sql.append(" AND device_id=?"); params.add(deviceId);
        }
        if (code != null && !code.isBlank()) {
            sql.append(" AND error_code=?"); params.add(code);
        }
        // Preserve the existing API contract; use seek pagination in a future API revision.
        sql.append(" ORDER BY received_at DESC,event_id DESC LIMIT ? OFFSET ?");
        params.add(limit); params.add(offset);
        return jdbc.queryForList(sql.toString(), params.toArray());
    }

    @Override
    public List<Map<String, Object>> summarizeLastHours(int hours) {
        Instant since = Instant.now().minus(hours, ChronoUnit.HOURS);
        return jdbc.queryForList(
                "SELECT component AS \"COMPONENT\",severity AS \"SEVERITY\","
                        + "COUNT(*) AS \"TOTAL\",MAX(received_at) AS \"LAST_SEEN\" "
                        + "FROM wallet_diagnostics.mcs_diag_event WHERE received_at >= ? "
                        + "GROUP BY component,severity ORDER BY COUNT(*) DESC",
                Timestamp.from(since));
    }

    @Override
    public int purgeOldNonces() {
        return jdbc.update("WITH expired AS (SELECT device_id,nonce_value "
                + "FROM wallet_diagnostics.mcs_diag_nonce "
                + "WHERE received_at < CURRENT_TIMESTAMP - INTERVAL '1 day' "
                + "ORDER BY received_at LIMIT 2000 FOR UPDATE SKIP LOCKED) "
                + "DELETE FROM wallet_diagnostics.mcs_diag_nonce n USING expired e "
                + "WHERE n.device_id=e.device_id AND n.nonce_value=e.nonce_value");
    }
}
