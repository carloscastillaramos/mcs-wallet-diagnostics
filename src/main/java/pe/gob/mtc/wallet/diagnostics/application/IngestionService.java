package pe.gob.mtc.wallet.diagnostics.application;

import com.fasterxml.jackson.core.JsonProcessingException;
import java.io.IOException;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.Validator;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import pe.gob.mtc.wallet.diagnostics.application.port.DiagnosticsRepository;
import pe.gob.mtc.wallet.diagnostics.config.DiagnosticsProperties;
import pe.gob.mtc.wallet.diagnostics.domain.DiagnosticBatch;
import pe.gob.mtc.wallet.diagnostics.domain.DiagnosticEvent;
import pe.gob.mtc.wallet.diagnostics.domain.DeviceIdentity;
import pe.gob.mtc.wallet.diagnostics.domain.DiagnosticsException;
import pe.gob.mtc.wallet.diagnostics.domain.StoredDiagnosticEvent;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;
import java.util.TreeMap;
import java.util.UUID;

@Service
public class IngestionService {
    // No se aceptan textos libres, DNI, QR, tokens, credenciales o stacktraces.
    private static final Map<String, Set<String>> ATTRIBUTES = Map.of(
            "NETWORK_STATE", Set.of("ONLINE", "OFFLINE", "UNKNOWN"),
            "LICENSE_CLASS", Set.of("A", "B", "ESPECIAL", "UNKNOWN"),
            "CREDENTIAL_FORMAT", Set.of("MSO_MDOC", "SD_JWT", "LDP_VC", "CWT", "UNKNOWN"),
            "DEVICE_POSTURE", Set.of("CLEAN", "ROOTED", "EMULATOR", "DEBUGGER", "UNKNOWN"),
            "FLOW_STAGE", Set.of("AUTH", "TOKEN", "OFFER", "REQUEST", "DOWNLOAD", "STORE", "PRESENT", "UNKNOWN")
    );
    private static final Set<String> COMPONENTS = Set.of(
            "WALLET", "CERTIFY", "MIMOTO", "VERIFY", "NETWORK", "SECURITY", "SSOIUGO");
    private final DiagnosticsRepository repository;
    private final ObjectMapper mapper;
    private final Validator validator;
    private final DiagnosticsProperties properties;
    private final Clock clock;

    public IngestionService(DiagnosticsRepository repository, ObjectMapper mapper, Validator validator,
                            DiagnosticsProperties properties) {
        this(repository, mapper, validator, properties, Clock.systemUTC());
    }

    IngestionService(DiagnosticsRepository repository, ObjectMapper mapper, Validator validator,
                     DiagnosticsProperties properties, Clock clock) {
        this.repository = repository;
        this.mapper = mapper;
        this.validator = validator;
        this.properties = properties;
        this.clock = clock;
    }

    @Transactional
    public IngestResult accept(DeviceIdentity device, String nonce, byte[] json) {
        long startedAt = System.nanoTime();
        DiagnosticBatch batch;
        try {
            batch = mapper.readValue(json, DiagnosticBatch.class);
        } catch (IOException invalid) {
            throw DiagnosticsException.invalid();
        }
        if (batch == null || !validator.validate(batch).isEmpty()
                || batch.events().size() > properties.maximumEventsPerBatch()) {
            throw DiagnosticsException.invalid();
        }
        Instant now = clock.instant();
        for (DiagnosticEvent event : batch.events()) validateEvent(event, now);

        // La PK (device_id, nonce) coordina los pods y vence tras 24 h.
        // En un reintento de Wallet se debe generar un nonce y una firma nuevos.
        if (!repository.reserveNonce(device.deviceId(), nonce)) throw DiagnosticsException.replay();
        int accepted = 0;
        int duplicates = 0;
        for (DiagnosticEvent event : batch.events()) {
            Map<String, String> canonicalAttrs = event.attributes() == null
                    ? Map.of() : new TreeMap<>(event.attributes());
            DiagnosticEvent canonical = new DiagnosticEvent(
                    event.eventId(), event.occurredAt(), event.eventType(), event.component(),
                    event.severity(), event.code(), event.platform(), event.appVersion(),
                    event.durationMs(), canonicalAttrs);
            StoredDiagnosticEvent stored = new StoredDiagnosticEvent(
                    canonical, encode(canonicalAttrs), hash(encode(canonical)), now);
            if (repository.insertEvent(device.deviceId(), stored)) accepted++;
            else duplicates++;
        }
        return new IngestResult(UUID.randomUUID(), accepted, duplicates,
                UUID.randomUUID(), now, (System.nanoTime() - startedAt) / 1_000_000);
    }

    private void validateEvent(DiagnosticEvent event, Instant now) {
        if (!COMPONENTS.contains(event.component())
                || event.occurredAt().isAfter(now.plusSeconds(properties.maximumClockSkewSeconds()))
                || event.occurredAt().isBefore(now.minusSeconds(properties.maximumEventAgeDays() * 86400))) {
            throw DiagnosticsException.invalid();
        }
        if (event.attributes() == null) return;
        for (var entry : event.attributes().entrySet()) {
            Set<String> allowed = ATTRIBUTES.get(entry.getKey());
            if (allowed == null || !allowed.contains(entry.getValue())) {
                throw DiagnosticsException.invalid();
            }
        }
    }

    private String encode(Object value) {
        try {
            return mapper.writeValueAsString(value);
        } catch (JsonProcessingException e) {
            throw DiagnosticsException.invalid();
        }
    }

    private String hash(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException impossible) {
            throw new IllegalStateException("SHA-256 no disponible", impossible);
        }
    }

    @Scheduled(fixedDelayString = "${MCS_NONCE_CLEANUP_INTERVAL_MS:3600000}")
    public void cleanupNonces() {
        try {
            // Cap the work per run; multiple pods coordinate with SKIP LOCKED.
            for (int batch = 0; batch < 100; batch++) {
                if (repository.purgeOldNonces() < 2000) break;
            }
        } catch (RuntimeException unavailable) {
            // Best effort: la limpieza no interfiere con la recepción.
        }
    }

    public record IngestResult(UUID batchId, int accepted, int duplicates,
                               UUID trackingId, Instant timestamp, long executionTimeMs) {}
}
