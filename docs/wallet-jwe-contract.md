# Contrato de criptografía entre INJI Wallet y mcs-wallet-diagnostics

## Dos parejas de llaves, nunca compartidas como privadas

| Uso | Clave privada | Clave pública |
| --- | --- | --- |
| Identidad y firma ECDSA P-256 | Wallet (Keystore / Secure Enclave) | PostgreSQL MCS_DIAG_DEVICE; registrada tras enrolamiento seguro |
| Cifrado JWE RSA ≥3072 bits | MTC, montada como Secret de solo lectura en cada pod | GET /api/v1/diagnostics/keys; JWKS por HTTPS |
| HTTPS/TLS | Certificado/llave TLS del Ingress MTC | Certificado validado por Wallet |

La llave privada de la Wallet **nunca sale del móvil**. La llave privada RSA
del servidor **nunca sale del ámbito de infraestructura MTC**. Solo se
distribuyen sus llaves públicas. ECDSA garantiza origen e integridad; JWE
aporta confidencialidad; TLS evita manipulación del canal y autentica
el dominio receptor.

## Protocolo obligatorio de ingesta, versión 2

1. La Wallet conserva eventos saneados en su MMKV cifrado. La integración
   de este cliente aún no forma parte de los archivos entregados.
2. Al conectarse, consulta por **HTTPS validado**
   `GET /api/v1/diagnostics/keys`. Del campo `activeKid` selecciona
   el JWK público de tipo RSA que lleva ese `kid`. No aceptar material
   de origen distinto del endpoint institucional esperado.
3. Se construye el JSON de evento ya definido (máximo 50 eventos, máximo
   65536 bytes de UTF-8 claro, sin PII ni mensajes libres).
4. La Wallet genera un JWE **compacto RFC 7516** usando:
   - Cabecera protegida: `{"alg":"RSA-OAEP-256","enc":"A256GCM","kid":"<activeKid>","typ":"mcs-diag+jwe"}`.
   - Clave AES-256 aleatoria efímera por lote, administrada internamente
     por la biblioteca JOSE.
   - La clave AES se protege con la llave pública RSA del microservicio.
   - Un IV AES-GCM nuevo por lote y etiqueta de autenticidad GCM.
   - Sin compresión `zip`. No usar `RSA1_5`, `RSA-OAEP` simple o AES-CBC.
5. El cuerpo HTTP UTF-8 exacto es `{"jwe":"<cinco-segmentos-JWE>"}`,
   con `Content-Type: application/json`. No incluir el JSON de eventos
   original fuera del JWE.
6. **Después de cifrar**, la Wallet calcula SHA-256 sobre los bytes exactos
   del cuerpo HTTP y firma con su clave privada ECDSA P-256 el mensaje
   canónico `MCS-DIAG-V1\nPOST\n/api/v1/diagnostics/batches\n<deviceId>\n<keyId>\n<timestamp>\n<nonce>\n<sha256HexBody>`.
   El formato de firma es DER / SHA256withECDSA, codificado Base64URL
   sin padding. Encabezados X-MCS-* conservan el contrato anterior.
7. El receptor verifica primero ECDSA, dispositivo activo, timestamp
   y luego descifra JWE con la llave RSA privada identificada por el KID.
   Nunca admite JSON claro como alternativa.
8. Valida tipos, atributos y límites del lote; registra nonce y
   eventos en PostgreSQL en una transacción. Responde **202 solo tras COMMIT**.
9. Solo entonces la Wallet elimina de MMKV los eventos confirmados.
   Ante fallos de red/5xx/timeout mantiene la cola local, falla
   silenciosamente y reintenta al recuperar conectividad, con nuevo
   nonce y nueva firma. Conserva los eventId para deduplicación.

## Rotación del par RSA del servidor

El Secret `mcs-wallet-diagnostics-jwe` proporciona:

- `active-kid`: identificador de la llave activa.
- `mcs-2026-11.pem`: PEM PKCS#8 privado (nombre ilustrativo).
- Llaves privadas anteriores `<kid>.pem` durante el período de
  solapamiento. No guardar estas llaves en Git o en imágenes Docker.

Todos los pods deben recibir el mismo conjunto de llaves y el mismo
`active-kid`. Se recomienda rotación con despliegue coordinado y una
ventana de coexistencia. La Wallet volverá a obtener JWKS al reconectarse
antes de cifrar la cola. Un cambio de KID **no requiere cambiar la llave
privada ECDSA del dispositivo**.

## Seguridad pendiente de homologación

- El servidor carga PEM PKCS#8 en la memoria de cada pod. Para producción
  con exigencia HSM, reemplazar `EncryptionKeyRing` por proveedor
  criptográfico institucional PKCS#11/KMS que no exporte privadas.
- El enrolamiento de una nueva Wallet y la atestación de dispositivo
  (Play Integrity / App Attest) no están integrados.
- El cliente Android/iOS y su puente criptográfico React Native no forman
  parte de este proyecto: faltan generar/parchar esos fuentes y probar
  interoperabilidad real.
- La clave de servidor obtenida por `GET /keys` hereda la confianza del
  certificado TLS. Evaluar pinning o firma institucional del JWKS según
  política y ciclo de renovación de certificados.
- PostgreSQL debe gestionar cifrado en reposo de RDS y respaldo cifrado. El JWE se descifra
  en memoria antes de la escritura PostgreSQL.
- Rechazar solicitud si no se puede obtener llave válida o cifrar;
  conservar la cola, sin afectar el flujo funcional de la Wallet.

Ver secuencia en `wallet-key-exchange.mmd`.
