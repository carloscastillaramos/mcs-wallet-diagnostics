package pe.gob.mtc.wallet.diagnostics.domain;

import java.time.Instant;

public record StoredDiagnosticEvent(
        DiagnosticEvent event, String attributesJson, String payloadHash, Instant receivedAt) {
}
