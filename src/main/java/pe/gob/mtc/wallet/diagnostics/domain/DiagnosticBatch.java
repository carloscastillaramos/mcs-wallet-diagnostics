package pe.gob.mtc.wallet.diagnostics.domain;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotEmpty;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

import java.util.List;

public record DiagnosticBatch(
        @NotNull @NotEmpty @Size(max = 200) List<@NotNull @Valid DiagnosticEvent> events) {
}
