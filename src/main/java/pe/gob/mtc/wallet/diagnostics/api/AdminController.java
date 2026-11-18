package pe.gob.mtc.wallet.diagnostics.api;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import pe.gob.mtc.wallet.diagnostics.application.AdminService;

import java.util.List;
import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/admin")
public class AdminController {
    private final AdminService service;

    public AdminController(AdminService service) { this.service = service; }

    @PreAuthorize("hasAuthority('SCOPE_diagnostics.admin')")
    @PostMapping("/devices")
    public ResponseEntity<Void> register(@Valid @RequestBody Registration request,
                                         @AuthenticationPrincipal Jwt actor) {
        service.register(request.deviceId(), request.keyId(), request.platform(),
                request.publicKeySpkiBase64(), actor.getSubject());
        return ResponseEntity.status(HttpStatus.CREATED).build();
    }

    @PreAuthorize("hasAuthority('SCOPE_diagnostics.admin')")
    @PostMapping("/devices/{deviceId}/keys/{keyId}/revoke")
    public ResponseEntity<Void> revoke(@PathVariable UUID deviceId, @PathVariable String keyId,
                                       @AuthenticationPrincipal Jwt actor) {
        return service.revoke(deviceId, keyId, actor.getSubject())
                ? ResponseEntity.noContent().build()
                : ResponseEntity.notFound().build();
    }

    @PreAuthorize("hasAnyAuthority('SCOPE_diagnostics.read','SCOPE_diagnostics.admin')")
    @GetMapping("/events")
    public List<Map<String, Object>> events(
            @RequestParam(required = false) String deviceId,
            @RequestParam(required = false) String code,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "50") int size) {
        return service.list(deviceId, code, page, size);
    }

    @PreAuthorize("hasAnyAuthority('SCOPE_diagnostics.read','SCOPE_diagnostics.admin')")
    @GetMapping("/summary")
    public List<Map<String, Object>> summary(@RequestParam(defaultValue = "24") int hours) {
        return service.summary(hours);
    }

    public record Registration(
            @NotNull UUID deviceId,
            @NotBlank @Pattern(regexp = "[A-Za-z0-9_-]{1,64}") String keyId,
            @NotBlank @Pattern(regexp = "ANDROID|IOS") String platform,
            @NotBlank @Size(min = 80, max = 2048) String publicKeySpkiBase64) {}
}
