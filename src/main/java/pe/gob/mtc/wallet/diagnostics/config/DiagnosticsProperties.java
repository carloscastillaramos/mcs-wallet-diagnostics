package pe.gob.mtc.wallet.diagnostics.config;

import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "mcs.diagnostics")
public record DiagnosticsProperties(
        @Min(1024) @Max(1048576) int maximumBodyBytes,
        @Min(1) @Max(200) int maximumEventsPerBatch,
        @Min(30) @Max(900) long maximumClockSkewSeconds,
        @Min(1) @Max(30) long maximumEventAgeDays) {
}
