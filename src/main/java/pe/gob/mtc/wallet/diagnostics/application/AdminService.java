package pe.gob.mtc.wallet.diagnostics.application;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pe.gob.mtc.wallet.diagnostics.application.port.DiagnosticsRepository;
import pe.gob.mtc.wallet.diagnostics.domain.DiagnosticsException;
import pe.gob.mtc.wallet.diagnostics.security.DeviceRequestAuthenticator;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@Service
public class AdminService {
    private final DiagnosticsRepository repository;

    public AdminService(DiagnosticsRepository repository) { this.repository = repository; }

    @Transactional
    public void register(UUID deviceId, String keyId, String platform, String publicKeyBase64, String actor) {
        String normalized = DeviceRequestAuthenticator.normalizeAndValidatePublicKey(publicKeyBase64);
        repository.registerDevice(deviceId.toString(), keyId, platform, normalized, actor);
    }

    @Transactional
    public boolean revoke(UUID deviceId, String keyId, String actor) {
        return repository.revokeDevice(deviceId.toString(), keyId, actor);
    }

    @Transactional(readOnly = true)
    public List<Map<String, Object>> list(String deviceId, String code, int page, int size) {
        if (page < 0 || page > 10000 || size < 1 || size > 100
                || (deviceId != null && !deviceId.isBlank() && !validUuid(deviceId))
                || (code != null && !code.isBlank() && !code.matches("[A-Z][A-Z0-9_.-]{2,63}"))) {
            throw DiagnosticsException.invalid();
        }
        return repository.findEvents(deviceId, code, page * size, size);
    }

    @Transactional(readOnly = true)
    public List<Map<String, Object>> summary(int hours) {
        if (hours < 1 || hours > 168) throw DiagnosticsException.invalid();
        return repository.summarizeLastHours(hours);
    }

    private boolean validUuid(String text) {
        try { return UUID.fromString(text).toString().equalsIgnoreCase(text); }
        catch (IllegalArgumentException invalid) { return false; }
    }
}
