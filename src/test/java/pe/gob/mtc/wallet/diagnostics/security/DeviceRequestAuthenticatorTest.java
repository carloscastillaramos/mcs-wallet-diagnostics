package pe.gob.mtc.wallet.diagnostics.security;

import org.junit.jupiter.api.Test;
import pe.gob.mtc.wallet.diagnostics.application.port.DiagnosticsRepository;
import pe.gob.mtc.wallet.diagnostics.config.DiagnosticsProperties;
import pe.gob.mtc.wallet.diagnostics.domain.DiagnosticsException;

import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.HexFormat;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class DeviceRequestAuthenticatorTest {
    private static final String DEVICE = "22f4303c-9c70-469c-a0d2-c78147e21bfa";
    private static final String KEY = "wallet-01";
    private static final String NONCE = "DgL10mLsI9t6u-6rxe34GA";
    private static final Instant NOW = Instant.parse("2026-11-06T02:00:00Z");
    private static final DiagnosticsProperties PROPS = new DiagnosticsProperties(65536, 50, 300, 8);

    @Test
    void acceptsSignedRegisteredDevice() throws Exception {
        var keys = generateKeyPair();
        var repo = mock(DiagnosticsRepository.class);
        when(repo.activeDeviceKey(DEVICE, KEY))
                .thenReturn(Optional.of(Base64.getEncoder().encodeToString(keys.getPublic().getEncoded())));
        byte[] body = "{\"events\":[]}".getBytes(StandardCharsets.UTF_8);
        String timestamp = Long.toString(NOW.getEpochSecond());
        String signature = sign(keys, body, timestamp, NONCE);
        var auth = new DeviceRequestAuthenticator(repo, PROPS, Clock.fixed(NOW, ZoneOffset.UTC));

        var identity = auth.authenticate(DEVICE, KEY, timestamp, NONCE, signature, body);
        assertEquals(DEVICE, identity.deviceId());
        assertEquals(KEY, identity.keyId());
    }

    @Test
    void rejectsModifiedBody() throws Exception {
        var keys = generateKeyPair();
        var repo = mock(DiagnosticsRepository.class);
        when(repo.activeDeviceKey(DEVICE, KEY))
                .thenReturn(Optional.of(Base64.getEncoder().encodeToString(keys.getPublic().getEncoded())));
        String timestamp = Long.toString(NOW.getEpochSecond());
        byte[] original = "{\"events\":[]}".getBytes(StandardCharsets.UTF_8);
        String signature = sign(keys, original, timestamp, NONCE);
        var auth = new DeviceRequestAuthenticator(repo, PROPS, Clock.fixed(NOW, ZoneOffset.UTC));

        assertThrows(DiagnosticsException.class, () -> auth.authenticate(
                DEVICE, KEY, timestamp, NONCE, signature,
                "{\"events\":[1]}".getBytes(StandardCharsets.UTF_8)));
    }

    @Test
    void rejectsStaleTimestampBeforeDatabaseLookup() {
        var repo = mock(DiagnosticsRepository.class);
        var auth = new DeviceRequestAuthenticator(repo, PROPS, Clock.fixed(NOW, ZoneOffset.UTC));
        assertThrows(DiagnosticsException.class,
                () -> auth.authenticate(DEVICE, KEY, "1700000000", NONCE, "invalid", new byte[0]));
        verifyNoInteractions(repo);
    }

    @Test
    void rejectsUnregisteredKey() {
        var repo = mock(DiagnosticsRepository.class);
        when(repo.activeDeviceKey(DEVICE, KEY)).thenReturn(Optional.empty());
        var auth = new DeviceRequestAuthenticator(repo, PROPS, Clock.fixed(NOW, ZoneOffset.UTC));
        assertEquals("UNAUTHORIZED_DEVICE", assertThrows(DiagnosticsException.class,
                () -> auth.authenticate(DEVICE, KEY, Long.toString(NOW.getEpochSecond()),
                        NONCE, "aaaa", new byte[0])).code());
    }

    private java.security.KeyPair generateKeyPair() throws Exception {
        var generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    private String sign(java.security.KeyPair keys, byte[] body, String timestamp, String nonce) throws Exception {
        String digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(body));
        String canonical = "MCS-DIAG-V1\nPOST\n" + DeviceRequestAuthenticator.SIGNED_PATH
                + "\n" + DEVICE + "\n" + KEY + "\n" + timestamp + "\n" + nonce + "\n" + digest;
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(keys.getPrivate());
        signer.update(canonical.getBytes(StandardCharsets.UTF_8));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(signer.sign());
    }
}
