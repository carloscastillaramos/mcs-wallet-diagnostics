package pe.gob.mtc.wallet.diagnostics.api;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.*;
import pe.gob.mtc.wallet.diagnostics.infrastructure.ProviderDeviceSyncRepository;
import pe.gob.mtc.wallet.diagnostics.security.DeviceRequestAuthenticator;

import java.util.UUID;

/** Only the authorized service identity of Wallet Provider may invoke these routes. */
@RestController
@RequestMapping("/api/v1/internal/devices")
public class ProviderSyncController {
    private final ProviderDeviceSyncRepository repository;
    public ProviderSyncController(ProviderDeviceSyncRepository repository) { this.repository=repository; }

    public record RegisterRequest(
            @NotBlank @Pattern(regexp="ANDROID|IOS") String platform,
            @NotBlank @Size(min=80,max=2048) String publicKeySpkiBase64) {}

    @PreAuthorize("hasAuthority('SCOPE_diagnostics.device.sync') and @providerServiceIdentity.allowed(authentication)")
    @PutMapping("/{deviceId}/keys/{keyId}")
    public ResponseEntity<Void> register(@PathVariable UUID deviceId,@PathVariable String keyId,
            @Valid @RequestBody RegisterRequest request,@AuthenticationPrincipal Jwt principal) {
        validateKeyId(keyId);
        String spki=DeviceRequestAuthenticator.normalizeAndValidatePublicKey(request.publicKeySpkiBase64());
        repository.register(deviceId.toString(),keyId,request.platform(),spki,principal.getSubject());
        return ResponseEntity.noContent().build();
    }

    @PreAuthorize("hasAuthority('SCOPE_diagnostics.device.sync') and @providerServiceIdentity.allowed(authentication)")
    @DeleteMapping("/{deviceId}/keys/{keyId}")
    public ResponseEntity<Void> revoke(@PathVariable UUID deviceId,@PathVariable String keyId,
            @AuthenticationPrincipal Jwt principal) {
        validateKeyId(keyId);
        repository.revoke(deviceId.toString(),keyId,principal.getSubject());
        return ResponseEntity.noContent().build();
    }

    private void validateKeyId(String id) {
        if(!id.matches("[A-Za-z0-9_-]{1,64}"))
            throw new IllegalArgumentException("Invalid key identifier");
    }
}
