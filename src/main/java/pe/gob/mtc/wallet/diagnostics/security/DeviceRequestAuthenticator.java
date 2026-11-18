package pe.gob.mtc.wallet.diagnostics.security;

import org.springframework.stereotype.Component;
import pe.gob.mtc.wallet.diagnostics.application.port.DiagnosticsRepository;
import pe.gob.mtc.wallet.diagnostics.config.DiagnosticsProperties;
import pe.gob.mtc.wallet.diagnostics.domain.DeviceIdentity;
import pe.gob.mtc.wallet.diagnostics.domain.DiagnosticsException;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.AlgorithmParameters;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Clock;
import java.util.Base64;
import java.util.HexFormat;
import java.util.UUID;

@Component
public class DeviceRequestAuthenticator {
    public static final String SIGNED_PATH = "/api/v1/diagnostics/batches";
    private final DiagnosticsRepository repository;
    private final DiagnosticsProperties properties;
    private final Clock clock;

    public DeviceRequestAuthenticator(DiagnosticsRepository repository, DiagnosticsProperties properties) {
        this(repository, properties, Clock.systemUTC());
    }

    DeviceRequestAuthenticator(DiagnosticsRepository repository, DiagnosticsProperties properties, Clock clock) {
        this.repository = repository;
        this.properties = properties;
        this.clock = clock;
    }

    public DeviceIdentity authenticate(String deviceId, String keyId, String timestamp,
                                       String nonce, String signatureBase64Url, byte[] body) {
        if (deviceId == null || keyId == null || timestamp == null || nonce == null
                || signatureBase64Url == null) throw DiagnosticsException.unauthorized();
        try {
            String normalizedDeviceId = UUID.fromString(deviceId).toString();
            if (!normalizedDeviceId.equals(deviceId)) throw DiagnosticsException.unauthorized();
            if (!keyId.matches("[A-Za-z0-9_-]{1,64}")
                    || !nonce.matches("[A-Za-z0-9_-]{16,96}")
                    || signatureBase64Url.length() > 512) throw DiagnosticsException.unauthorized();
            long sentSeconds = Long.parseLong(timestamp);
            if (Math.abs(Math.subtractExact(clock.instant().getEpochSecond(), sentSeconds))
                    > properties.maximumClockSkewSeconds()) throw DiagnosticsException.unauthorized();

            String publicKeyBase64 = repository.activeDeviceKey(deviceId, keyId)
                    .orElseThrow(DiagnosticsException::unauthorized);
            var key = KeyFactory.getInstance("EC").generatePublic(
                    new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyBase64)));
            if (!(key instanceof ECPublicKey ec) || !isP256(ec)) {
                throw DiagnosticsException.unauthorized();
            }
            String bodyHash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(body));
            String signed = "MCS-DIAG-V1\nPOST\n" + SIGNED_PATH + "\n"
                    + deviceId + "\n" + keyId + "\n" + timestamp + "\n" + nonce + "\n" + bodyHash;
            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(key);
            verifier.update(signed.getBytes(StandardCharsets.UTF_8));
            if (!verifier.verify(Base64.getUrlDecoder().decode(signatureBase64Url))) {
                throw DiagnosticsException.unauthorized();
            }
            return new DeviceIdentity(deviceId, keyId);
        } catch (DiagnosticsException known) {
            throw known;
        } catch (Exception invalid) {
            throw DiagnosticsException.unauthorized();
        }
    }

    public static String normalizeAndValidatePublicKey(String base64) {
        try {
            if (base64 == null || base64.length() > 2048) throw DiagnosticsException.invalid();
            byte[] encoded = Base64.getDecoder().decode(base64);
            var key = KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(encoded));
            if (!(key instanceof ECPublicKey ec) || !isP256(ec)) {
                throw DiagnosticsException.invalid();
            }
            return Base64.getEncoder().encodeToString(key.getEncoded());
        } catch (DiagnosticsException known) {
            throw known;
        } catch (Exception e) {
            throw DiagnosticsException.invalid();
        }
    }

    private static boolean isP256(ECPublicKey key) throws Exception {
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec expected = parameters.getParameterSpec(ECParameterSpec.class);
        ECParameterSpec actual = key.getParams();
        return actual.getCurve().equals(expected.getCurve())
                && actual.getGenerator().equals(expected.getGenerator())
                && actual.getOrder().equals(expected.getOrder())
                && actual.getCofactor() == expected.getCofactor();
    }
}
