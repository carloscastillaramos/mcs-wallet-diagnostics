package pe.gob.mtc.wallet.diagnostics.api;

import org.springframework.http.CacheControl;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import pe.gob.mtc.wallet.diagnostics.security.EncryptionKeyRing;

import java.util.Map;

/**
 * Solo publica JWK RSA con componentes (n, e); nunca expone parámetros privados.
 * Se debe consumir únicamente por HTTPS con cadena TLS validada por la Wallet.
 */
@RestController
@RequestMapping("/api/v1/diagnostics")
public class EncryptionKeyController {
    private final EncryptionKeyRing keys;

    public EncryptionKeyController(EncryptionKeyRing keys) {
        this.keys = keys;
    }

    @GetMapping(path = "/keys", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, Object>> keys() {
        return ResponseEntity.ok().cacheControl(CacheControl.noCache())
                .body(keys.publicJwks());
    }
}
