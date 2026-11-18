package pe.gob.mtc.wallet.diagnostics.domain;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

public record DiagnosticEvent(
        @NotNull UUID eventId,
        @NotNull Instant occurredAt,
        @NotBlank @Pattern(regexp = "[A-Z][A-Z0-9_]{2,47}") String eventType,
        @NotBlank @Pattern(regexp = "[A-Z][A-Z0-9_]{2,47}") String component,
        @NotBlank @Pattern(regexp = "INFO|WARN|ERROR|CRITICAL") String severity,
        @NotBlank @Pattern(regexp = "[A-Z][A-Z0-9_.-]{2,63}") String code,
        @NotBlank @Pattern(regexp = "ANDROID|IOS") String platform,
        @NotBlank @Pattern(regexp = "[0-9A-Za-z._-]{1,32}") String appVersion,
        @Min(0) @Max(86400000) Long durationMs,
        @Size(max = 10) Map<String, @NotNull @Size(max = 48) String> attributes) {
}
