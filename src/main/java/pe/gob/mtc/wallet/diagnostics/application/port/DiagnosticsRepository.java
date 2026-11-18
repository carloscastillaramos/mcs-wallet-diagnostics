package pe.gob.mtc.wallet.diagnostics.application.port;

import pe.gob.mtc.wallet.diagnostics.domain.StoredDiagnosticEvent;

import java.util.List;
import java.util.Map;
import java.util.Optional;

public interface DiagnosticsRepository {
    Optional<String> activeDeviceKey(String deviceId, String keyId);
    boolean reserveNonce(String deviceId, String nonce);
    boolean insertEvent(String deviceId, StoredDiagnosticEvent event);
    void registerDevice(String deviceId, String keyId, String platform, String publicKeyBase64, String actor);
    boolean revokeDevice(String deviceId, String keyId, String actor);
    List<Map<String, Object>> findEvents(String deviceId, String code, int offset, int limit);
    List<Map<String, Object>> summarizeLastHours(int hours);
    int purgeOldNonces();
}
