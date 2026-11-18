package pe.gob.mtc.wallet.diagnostics.security;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.crypto.RSADecrypter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import pe.gob.mtc.wallet.diagnostics.domain.DiagnosticsException;

import java.nio.charset.StandardCharsets;

/**
 * Capa JWE RFC 7516 independiente de la firma ECDSA de cada instalación.
 * La firma se comprueba ANTES de invocar este descifrador.
 */
@Service
public class JweEnvelopeService {
    public static final String TYPE = "mcs-diag+jwe";
    private final EncryptionKeyRing keys;
    private final ObjectMapper mapper;
    private final int maxDecryptedBytes;

    public JweEnvelopeService(EncryptionKeyRing keys, ObjectMapper mapper,
                              @Value("${MCS_MAX_DECRYPTED_BYTES:65536}") int maxDecryptedBytes) {
        if (maxDecryptedBytes < 1024 || maxDecryptedBytes > 1048576) {
            throw new IllegalArgumentException("MCS_MAX_DECRYPTED_BYTES fuera de rango");
        }
        this.keys = keys;
        this.mapper = mapper;
        this.maxDecryptedBytes = maxDecryptedBytes;
    }

    public byte[] decryptSignedEnvelope(byte[] signedBody) {
        try {
            JsonNode envelope = mapper.readTree(signedBody);
            // El contrato impide payloads alternativos o campos no firmados.
            if (envelope == null || !envelope.isObject() || envelope.size() != 1
                    || !envelope.has("jwe") || !envelope.path("jwe").isTextual()) {
                throw DiagnosticsException.invalid();
            }
            String compact = envelope.path("jwe").asText();
            if (compact.length() < 60 || compact.length() > 180000
                    || compact.chars().filter(c -> c == '.').count() != 4) {
                throw DiagnosticsException.invalid();
            }
            JWEObject jwe = JWEObject.parse(compact);
            var header = jwe.getHeader();
            if (!JWEAlgorithm.RSA_OAEP_256.equals(header.getAlgorithm())
                    || !EncryptionMethod.A256GCM.equals(header.getEncryptionMethod())
                    || header.getCompressionAlgorithm() != null
                    || (header.getCriticalParams() != null && !header.getCriticalParams().isEmpty())
                    || header.getJWK() != null
                    || !new JOSEObjectType(TYPE).equals(header.getType())) {
                throw DiagnosticsException.invalid();
            }
            String kid = header.getKeyID();
            if (kid == null || !kid.matches("[A-Za-z0-9_-]{1,64}")) {
                throw DiagnosticsException.invalid();
            }
            var privateKey = keys.privateKey(kid)
                    .orElseThrow(DiagnosticsException::invalid);
            jwe.decrypt(new RSADecrypter(privateKey));
            byte[] cleartext = jwe.getPayload().toBytes();
            if (cleartext == null || cleartext.length > maxDecryptedBytes) {
                throw DiagnosticsException.invalid();
            }
            // Este byte[] solo existe en memoria para validación y persistencia.
            return cleartext;
        } catch (DiagnosticsException invalid) {
            throw invalid;
        } catch (Exception invalid) {
            // Un mensaje uniforme evita revelar si falló el KID o la autenticación GCM.
            throw DiagnosticsException.invalid();
        }
    }
}
