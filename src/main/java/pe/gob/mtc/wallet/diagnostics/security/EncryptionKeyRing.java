package pe.gob.mtc.wallet.diagnostics.security;

import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Llaves privadas RSA del receptor, cargadas al inicio desde un Secret montado
 * de solo lectura. Nunca se entregan al cliente ni se registran en logs.
 *
 * Para cambiar la llave activa se monta el nuevo Secret en TODAS las réplicas
 * y se reinician los pods. Las llaves anteriores permanecen para descifrar
 * lotes preparados durante una desconexión (por lo menos la ventana offline).
 */
@Component
public class EncryptionKeyRing {
    private final String activeKid;
    private final Map<String, RSAPrivateCrtKey> privateKeys;
    private final List<Map<String, Object>> publishedKeys;

    public EncryptionKeyRing(
            @Value("${MCS_ENCRYPTION_KEYS_DIRECTORY:}") String directory,
            @Value("${MCS_ENCRYPTION_ACTIVE_KID:}") String activeKid) {
        if (directory == null || directory.isBlank()
                || activeKid == null || !activeKid.matches("[A-Za-z0-9_-]{1,64}")) {
            throw new IllegalStateException("No se configuraron las llaves JWE institucionales");
        }
        Path keyDir = Path.of(directory);
        if (!Files.isDirectory(keyDir)) {
            throw new IllegalStateException("No existe el directorio de llaves JWE");
        }
        try {
            Map<String, RSAPrivateCrtKey> loaded = new LinkedHashMap<>();
            List<Map<String, Object>> jwks = new ArrayList<>();
            try (var files = Files.list(keyDir)) {
                for (Path file : files.filter(f -> f.getFileName().toString().endsWith(".pem"))
                        .sorted().toList()) {
                    String filename = file.getFileName().toString();
                    String kid = filename.substring(0, filename.length() - 4);
                    if (!kid.matches("[A-Za-z0-9_-]{1,64}") || !Files.isRegularFile(file)) {
                        throw new IllegalStateException("Nombre de archivo de llave JWE no válido");
                    }
                    RSAPrivateCrtKey privateKey = loadPkcs8Pem(file);
                    if (privateKey.getModulus().bitLength() < 3072) {
                        throw new IllegalStateException("La llave RSA debe tener al menos 3072 bits");
                    }
                    RSAPublicKey publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA")
                            .generatePublic(new RSAPublicKeySpec(
                                    privateKey.getModulus(), privateKey.getPublicExponent()));
                    loaded.put(kid, privateKey);
                    RSAKey jwk = new RSAKey.Builder(publicKey)
                            .keyID(kid)
                            .keyUse(KeyUse.ENCRYPTION)
                            .algorithm(JWEAlgorithm.RSA_OAEP_256)
                            .build();
                    jwks.add(jwk.toPublicJWK().toJSONObject());
                }
            }
            if (!loaded.containsKey(activeKid)) {
                throw new IllegalStateException("El identificador de llave activa no existe");
            }
            this.activeKid = activeKid;
            this.privateKeys = Collections.unmodifiableMap(loaded);
            this.publishedKeys = List.copyOf(jwks);
        } catch (IOException | java.security.GeneralSecurityException invalid) {
            // No incluir paths, claves ni contenido PEM en mensajes de arranque.
            throw new IllegalStateException("No se pueden cargar las llaves JWE", invalid);
        }
    }

    public String activeKid() {
        return activeKid;
    }

    public Optional<RSAPrivateCrtKey> privateKey(String kid) {
        return Optional.ofNullable(privateKeys.get(kid));
    }

    public Map<String, Object> publicJwks() {
        return Map.of("keys", publishedKeys, "activeKid", activeKid);
    }

    private static RSAPrivateCrtKey loadPkcs8Pem(Path file)
            throws IOException, java.security.GeneralSecurityException {
        String text = Files.readString(file, StandardCharsets.US_ASCII);
        if (!text.contains("-----BEGIN PRIVATE KEY-----")
                || !text.contains("-----END PRIVATE KEY-----")) {
            throw new IllegalStateException("Se requiere PEM PKCS#8 sin contraseña");
        }
        String encoded = text.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s+", "");
        byte[] der = Base64.getDecoder().decode(encoded);
        var key = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
        if (!(key instanceof RSAPrivateCrtKey rsa)) {
            throw new IllegalStateException("La llave JWE no es RSA CRT");
        }
        return rsa;
    }
}
