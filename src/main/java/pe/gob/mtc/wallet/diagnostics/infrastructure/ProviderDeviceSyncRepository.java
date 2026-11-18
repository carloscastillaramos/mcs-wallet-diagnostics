package pe.gob.mtc.wallet.diagnostics.infrastructure;

import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.transaction.annotation.Transactional;
import pe.gob.mtc.wallet.diagnostics.domain.DiagnosticsException;

import java.util.List;

/** Idempotent sync with revocation tombstones, serialized per (device,key). */
@Repository
public class ProviderDeviceSyncRepository {
    private final JdbcTemplate jdbc;
    public ProviderDeviceSyncRepository(JdbcTemplate jdbc) { this.jdbc=jdbc; }

    private void serial(String deviceId,String keyId) {
        // Identical input always acquires same transaction-scoped lock.
        jdbc.queryForObject("SELECT pg_advisory_xact_lock(hashtextextended(?,0))",Object.class,
                "mcs_diag_sync:"+deviceId+":"+keyId);
    }

    @Transactional
    public void register(String deviceId,String keyId,String platform,String spki,String actor) {
        serial(deviceId,keyId);
        if(jdbc.queryForObject("SELECT EXISTS (SELECT 1 FROM wallet_diagnostics.mcs_diag_device_tombstone "
                +"WHERE device_id=? AND key_id=?)",Boolean.class,deviceId,keyId)) return;
        int inserted=jdbc.update("INSERT INTO wallet_diagnostics.mcs_diag_device "
                +"(device_id,key_id,platform,public_key_spki_b64,active,created_at) "
                +"VALUES(?,?,?,?,true,CURRENT_TIMESTAMP) ON CONFLICT (device_id,key_id) DO NOTHING",
                deviceId,keyId,platform,spki);
        if(inserted==1) {
            audit("DEVICE_REGISTERED",actor,deviceId,keyId);
            return;
        }
        List<Boolean> exact=jdbc.query("SELECT (platform=? AND public_key_spki_b64=? AND active=true AND revoked_at IS NULL) "
                +"FROM wallet_diagnostics.mcs_diag_device WHERE device_id=? AND key_id=?",
                (rs,row)->rs.getBoolean(1),platform,spki,deviceId,keyId);
        if(exact.size()!=1 || !exact.get(0)) throw DiagnosticsException.conflict();
    }

    @Transactional
    public void revoke(String deviceId,String keyId,String actor) {
        serial(deviceId,keyId);
        int inserted=jdbc.update("INSERT INTO wallet_diagnostics.mcs_diag_device_tombstone "
                +"(device_id,key_id,actor_id) VALUES(?,?,?) ON CONFLICT DO NOTHING",
                deviceId,keyId,actor);
        jdbc.update("UPDATE wallet_diagnostics.mcs_diag_device SET active=false,revoked_at=COALESCE(revoked_at,CURRENT_TIMESTAMP) "
                +"WHERE device_id=? AND key_id=? AND active=true",deviceId,keyId);
        if(inserted==1) audit("DEVICE_REVOKED",actor,deviceId,keyId);
    }

    private void audit(String action,String actor,String deviceId,String keyId) {
        jdbc.update("INSERT INTO wallet_diagnostics.mcs_diag_admin_audit "
                +"(action,actor_id,device_id,key_id,created_at) VALUES(?,?,?,?,CURRENT_TIMESTAMP)",
                action,actor,deviceId,keyId);
    }
}
