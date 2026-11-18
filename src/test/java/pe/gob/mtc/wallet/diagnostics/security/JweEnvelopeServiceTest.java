package pe.gob.mtc.wallet.diagnostics.security;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEHeader;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.RSAEncrypter;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import pe.gob.mtc.wallet.diagnostics.application.port.DiagnosticsRepository;
import pe.gob.mtc.wallet.diagnostics.config.DiagnosticsProperties;
import pe.gob.mtc.wallet.diagnostics.domain.DiagnosticsException;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;
import java.util.HexFormat;

import static org.mockito.Mockito.*;

import static org.junit.jupiter.api.Assertions.*;

class JweEnvelopeServiceTest {
    @TempDir Path dir;

    @Test
    void decryptsStandardCompactJweWithActivePublicKey() throws Exception {
        KeyPair pair = rsa();
        EncryptionKeyRing ring = ring(pair, "mcs-2026-11");
        var crypto = new JweEnvelopeService(ring, new ObjectMapper(), 65536);
        String plaintext = "{\"events\":[{\"eventType\":\"DOWNLOAD_ERROR\"}]}";
        String compact = encrypt(pair, "mcs-2026-11", plaintext);

        byte[] clear = crypto.decryptSignedEnvelope(wrapper(compact));

        assertEquals(plaintext, new String(clear, StandardCharsets.UTF_8));
        String jwks = new ObjectMapper().writeValueAsString(ring.publicJwks());
        assertTrue(jwks.contains("\"kid\":\"mcs-2026-11\""));
        assertTrue(jwks.contains("\"activeKid\":\"mcs-2026-11\""));
        assertFalse(jwks.contains("\"d\":"));
        assertFalse(jwks.contains("\"p\":"));
        assertFalse(jwks.contains("\"q\":"));
    }

    @Test
    void rejectsCleartextLegacyAndUnknownKid() throws Exception {
        KeyPair pair = rsa();
        var crypto = new JweEnvelopeService(ring(pair, "mcs-2026-11"),
                new ObjectMapper(), 65536);
        assertThrows(DiagnosticsException.class,
                () -> crypto.decryptSignedEnvelope("{\"events\":[]}".getBytes(StandardCharsets.UTF_8)));
        assertThrows(DiagnosticsException.class,
                () -> crypto.decryptSignedEnvelope(wrapper(encrypt(pair, "unknown", "{}"))));
    }

    @Test
    void rejectsModifiedCiphertextAndExcessivePlaintext() throws Exception {
        KeyPair pair = rsa();
        var ring = ring(pair, "mcs-2026-11");
        String compact = encrypt(pair, "mcs-2026-11", "{\"events\":[]}");
        String[] pieces = compact.split("\\.", -1);
        pieces[3] = (pieces[3].charAt(0) == 'A' ? "B" : "A") + pieces[3].substring(1);
        var crypto = new JweEnvelopeService(ring, new ObjectMapper(), 65536);
        assertThrows(DiagnosticsException.class,
                () -> crypto.decryptSignedEnvelope(wrapper(String.join(".", pieces))));

        var smallLimit = new JweEnvelopeService(ring, new ObjectMapper(), 1024);
        assertThrows(DiagnosticsException.class, () -> smallLimit.decryptSignedEnvelope(
                wrapper(encrypt(pair, "mcs-2026-11", "A".repeat(1025)))));
    }

    @Test
    void verifiesDeviceSignatureOverEncryptedBodyBeforeDecrypting() throws Exception {
        var server = rsa();
        var ecdsaGenerator = KeyPairGenerator.getInstance("EC");
        ecdsaGenerator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair wallet = ecdsaGenerator.generateKeyPair();
        var repo = mock(DiagnosticsRepository.class);
        String device = "22f4303c-9c70-469c-a0d2-c78147e21bfa";
        String key = "wallet-01";
        String nonce = "DgL10mLsI9t6u-6rxe34GA";
        Instant now = Instant.parse("2026-11-06T02:00:00Z");
        String timestamp = Long.toString(now.getEpochSecond());
        when(repo.activeDeviceKey(device, key)).thenReturn(
                java.util.Optional.of(Base64.getEncoder().encodeToString(wallet.getPublic().getEncoded())));
        var authenticator = new DeviceRequestAuthenticator(repo,
                new DiagnosticsProperties(131072, 50, 300, 8), Clock.fixed(now, ZoneOffset.UTC));
        byte[] signedBody = wrapper(encrypt(server, "mcs-2026-11", "{\"events\":[]}"));
        String hash = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(signedBody));
        String canonical = "MCS-DIAG-V1\nPOST\n" + DeviceRequestAuthenticator.SIGNED_PATH
                + "\n" + device + "\n" + key + "\n" + timestamp + "\n" + nonce + "\n" + hash;
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(wallet.getPrivate());
        signer.update(canonical.getBytes(StandardCharsets.UTF_8));
        String sig = Base64.getUrlEncoder().withoutPadding().encodeToString(signer.sign());

        assertEquals(device, authenticator.authenticate(device, key, timestamp, nonce, sig, signedBody).deviceId());
        assertEquals("{\"events\":[]}", new String(
                new JweEnvelopeService(ring(server, "mcs-2026-11"), new ObjectMapper(), 65536)
                        .decryptSignedEnvelope(signedBody), StandardCharsets.UTF_8));
        byte[] altered = signedBody.clone();
        altered[altered.length - 2] = altered[altered.length - 2] == 'A' ? (byte) 'B' : (byte) 'A';
        assertThrows(DiagnosticsException.class, () ->
                authenticator.authenticate(device, key, timestamp, nonce, sig, altered));
    }

    private EncryptionKeyRing ring(KeyPair pair, String kid) throws Exception {
        String encoded = Base64.getMimeEncoder(64, new byte[]{'\n'})
                .encodeToString(pair.getPrivate().getEncoded());
        Files.writeString(dir.resolve(kid + ".pem"),
                "-----BEGIN PRIVATE KEY-----\n" + encoded + "\n-----END PRIVATE KEY-----\n");
        return new EncryptionKeyRing(dir.toString(), kid);
    }

    private KeyPair rsa() throws Exception {
        var generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(3072);
        return generator.generateKeyPair();
    }

    private String encrypt(KeyPair pair, String kid, String payload) throws Exception {
        var header = new JWEHeader.Builder(JWEAlgorithm.RSA_OAEP_256, EncryptionMethod.A256GCM)
                .keyID(kid)
                .type(new JOSEObjectType(JweEnvelopeService.TYPE))
                .build();
        var jwe = new JWEObject(header, new Payload(payload));
        jwe.encrypt(new RSAEncrypter((RSAPublicKey) pair.getPublic()));
        return jwe.serialize();
    }

    private byte[] wrapper(String compact) {
        return ("{\"jwe\":\"" + compact + "\"}").getBytes(StandardCharsets.UTF_8);
    }
}
