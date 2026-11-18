package pe.gob.mtc.wallet.diagnostics.api;

import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import pe.gob.mtc.wallet.diagnostics.application.IngestionService;
import pe.gob.mtc.wallet.diagnostics.config.DiagnosticsProperties;
import pe.gob.mtc.wallet.diagnostics.domain.DiagnosticsException;
import pe.gob.mtc.wallet.diagnostics.security.DeviceRequestAuthenticator;
import pe.gob.mtc.wallet.diagnostics.security.JweEnvelopeService;

import java.io.IOException;

@RestController
@RequestMapping("/api/v1/diagnostics")
public class DiagnosticsController {
    private static final Logger log = LoggerFactory.getLogger(DiagnosticsController.class);
    private final IngestionService service;
    private final DeviceRequestAuthenticator authenticator;
    private final JweEnvelopeService envelopeService;
    private final DiagnosticsProperties properties;

    public DiagnosticsController(IngestionService service, DeviceRequestAuthenticator authenticator,
                                 JweEnvelopeService envelopeService,
                                 DiagnosticsProperties properties) {
        this.service = service;
        this.authenticator = authenticator;
        this.envelopeService = envelopeService;
        this.properties = properties;
    }

    @PostMapping(path = "/batches", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<IngestionService.IngestResult> receive(
            HttpServletRequest request,
            @RequestHeader(value = "X-MCS-Device-ID", required = false) String deviceId,
            @RequestHeader(value = "X-MCS-Key-ID", required = false) String keyId,
            @RequestHeader(value = "X-MCS-Timestamp", required = false) String timestamp,
            @RequestHeader(value = "X-MCS-Nonce", required = false) String nonce,
            @RequestHeader(value = "X-MCS-Signature", required = false) String signature) throws IOException {
        // Lectura acotada incluso cuando se transmite con Transfer-Encoding: chunked.
        byte[] body = request.getInputStream().readNBytes(properties.maximumBodyBytes() + 1);
        if (body.length > properties.maximumBodyBytes()) throw DiagnosticsException.tooLarge();
        var device = authenticator.authenticate(deviceId, keyId, timestamp, nonce, signature, body);
        // La firma cubre el sobre JWE exacto, no el JSON descifrado.
        // Todo fallo de descifrado es rechazado; no existe ruta legacy en claro.
        byte[] plaintext = envelopeService.decryptSignedEnvelope(body);
        var result = service.accept(device, nonce, plaintext);
        // Solo metadatos agregados; jamás dispositivo, IP, payload, firma o encabezados.
        log.info("DIAGNOSTIC_BATCH_ACCEPTED trackingId={} accepted={} duplicates={} executionTimeMs={}",
                result.trackingId(), result.accepted(), result.duplicates(), result.executionTimeMs());
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(result);
    }
}
