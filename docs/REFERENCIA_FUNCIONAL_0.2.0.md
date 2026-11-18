> DOCUMENTO HISTÓRICO Oracle 0.2.0 — no usar su configuración para AWS/PostgreSQL.

# mcs-wallet-diagnostics

Microservicio MTC de recepción de diagnósticos técnicos de INJI Wallet.

## Estado de la entrega

Versión 0.2.0: fuentes iniciales, persistencia **directa en Oracle 19c**,
autenticación ECDSA de instalaciones registradas, **cifrado JWE
RSA-OAEP-256/A256GCM obligatorio**, idempotencia entre réplicas, API
administrativa JWT para futura interfaz, pruebas unitarias, imagen Docker y
manifiestos Kubernetes. No contiene claves, contraseñas, tokens ni endpoints
institucionales reales.

**No se ha desplegado en el MTC ni probado contra su Oracle.**
La adaptación del cliente móvil es un trabajo separado: el almacenamiento MMKV
cifrado actual **no tiene todavía** transmisión, confirmación ni reintentos.
El microservicio no modifica la Wallet ni puede garantizar por sí solo el
comportamiento silencioso de la aplicación móvil.

## Arquitectura

1. La Wallet conserva los eventos filtrados en su cola local cifrada.
2. Al recuperar la conexión, la Wallet obtiene por HTTPS la **llave pública
   RSA** del receptor: `GET /api/v1/diagnostics/keys`. Cifra el lote
   en formato JWE con clave AES-256-GCM efímera, protegida con RSA-OAEP-256.
3. El cliente móvil, una vez enrolado, **firma los bytes del sobre cifrado**
   con otra llave privada, ECDSA P-256, no exportable de esa instalación.
4. Spring Boot comprueba firma, registro activo, timestamp y nonce. Después
   descifra el JWE con su llave privada RSA y valida el esquema saneado.
5. La transacción en Oracle registra nonce y eventos con unicidad por
   dispositivo/evento. El servidor devuelve HTTP 202 después del COMMIT.
6. Un cliente que reintenta crea un **nonce nuevo y una firma nueva**, pero
   conserva los mismos eventId. Si Oracle ya registró el evento, lo cuenta
   como duplicado sin volver a persistirlo.

Las tablas y restricciones únicas de Oracle son el punto de coordinación
entre pods. Los **eventos diagnósticos** nunca se almacenan en archivos: van
directamente a Oracle. Los **logs operativos** sí admiten rotación local
por pod; no funcionan como caché ni cola de eventos. Si Oracle falla, se devuelve HTTP 503; la Wallet
deberá preservar localmente los eventos y continuar su flujo habitual.

## Configuración exclusivamente por variables de entorno

Requeridas:

| Variable | Uso |
|---|---|
| MCS_DB_URL | URL JDBC Oracle; usar TCPS/wallet Oracle si MTC lo exige |
| MCS_DB_USERNAME | Usuario DML con mínimo privilegio |
| MCS_DB_PASSWORD | Contraseña entregada mediante gestor institucional |
| MCS_ADMIN_JWT_ISSUER_URI | Emisor institucional para API administrativa |
| MCS_ADMIN_JWT_JWK_SET_URI | JWK público de verificación de administradores |
| MCS_ADMIN_JWT_AUDIENCE | Audience que debe contener el JWT administrativo |
| MCS_ENCRYPTION_KEYS_DIRECTORY | Directorio de Secret montado con archivos `<kid>.pem` PKCS#8 RSA ≥3072 bits, únicamente lectura |
| MCS_ENCRYPTION_ACTIVE_KID | Identificador de llave JWE pública activa para nuevos lotes |

Opcionales: MCS_HTTP_PORT (8080), MCS_DB_POOL_MAX_SIZE (8),
MCS_DB_POOL_MIN_IDLE (1), MCS_MAX_BODY_BYTES (131072),
MCS_MAX_DECRYPTED_BYTES (65536),
MCS_MAX_EVENTS_PER_BATCH (50), MCS_CLOCK_SKEW_SECONDS (300),
MCS_MAX_EVENT_AGE_DAYS (8), MCS_NONCE_CLEANUP_INTERVAL_MS (3600000),
MCS_ORACLE_CONNECT_TIMEOUT_MS (5000), MCS_ORACLE_READ_TIMEOUT_MS (10000)
y MCS_JDBC_QUERY_TIMEOUT (5s).

### Logs operativos rotativos (no sustituyen Oracle)

- La salida por consola permanece activa para `kubectl logs` y recolección
  institucional. Kubernetes rota esos logs por configuración de kubelet.
- Cuando `MCS_LOG_FILE` se define, Spring Boot crea también un archivo
  con rotación diaria o por tamaño, lo que ocurra primero. El patrón
  de archivos comprimidos por defecto es
  `application.log.YYYY-MM-DD.N.log.gz`.
- En `k8s/deployment.yaml` cada pod escribe en
  `/var/log/mcs-wallet-diagnostics/application.log` sobre su
  propio `emptyDir` de 128 MiB. No hay PVC compartido ni contención
  entre réplicas.
- Parámetros: `MCS_LOG_MAX_FILE_SIZE=10MB`,
  `MCS_LOG_MAX_HISTORY=7`, `MCS_LOG_TOTAL_SIZE_CAP=96MB`,
  `MCS_LOG_LEVEL=INFO` (opcional). Las trazas propias registran solo
  identificadores aleatorios de seguimiento, conteos y códigos de error; no
  escriben cuerpos, firmas, tokens, claves ni identificadores del dispositivo.
  Revisar en QA las salidas de bibliotecas y plataforma para descartar fugas.
- Los archivos del volumen efímero se pierden al eliminar el pod; la
  conservación institucional requiere un colector central y permisos
  restringidos. No habilitar DEBUG de HTTP, JDBC o seguridad en producción
  sin evaluación de privacidad. El volumen del nodo debe tener cifrado
  de disco cuando lo exija la política MTC.

Ningún dato sensible está codificado en application.yml. No se incluye un
Secret de Kubernetes con valores de ejemplo. El MTC debe crear
`mcs-wallet-diagnostics-config` y `mcs-wallet-diagnostics-jwe` mediante su
gestor de secretos autorizado, con cifrado de secretos en etcd, RBAC y
rotación. El segundo Secret debe contener `active-kid` y los archivos
`<kid>.pem`, nunca claves públicas del dispositivo.

## Instalación

1. Homologar Java 17, Maven 3.6.3+, Spring Boot 3.5.x y Oracle 19c.
2. Aprobar por DBA el SQL versionado en sql/001_schema_oracle19c.sql.
3. Crear el usuario de aplicación con permisos DML mínimos (ver comentarios SQL).
4. Definir fuente administrativa JWT independiente de SSOIUGO para el receptor.
5. Proveer variables de entorno requeridas desde el gestor institucional;
   montar el Secret RSA con la llave activa y anteriores en todos los pods.
6. Ejecutar Maven: mvn -B -ntp clean verify.
7. Construir y analizar imagen: docker build -t mcs-wallet-diagnostics:0.2.0 .
8. Firmar y publicar imagen homologada del MTC, con digest inmutable.
9. Revisar k8s/deployment.yaml, k8s/service.yaml y completar NetworkPolicies,
   certificados TLS, rutas permitidas hacia Oracle y restricciones de Ingress.
10. Validar `GET /api/v1/diagnostics/keys` con HTTPS; comprobar que
    solo publica `n`, `e`, `kid` y no factores privados RSA.
11. Enrolar un dispositivo de prueba mediante la API administrativa autorizada.
12. Validar intercambio JWE + ECDSA real desde Wallet únicamente en QA.

El SQL **no se ejecuta automáticamente en el arranque** para que la cuenta
de producción no requiera permisos de DDL. La base de datos es Oracle,
no PostgreSQL ni almacenamiento temporal en disco.

## API

**GET /api/v1/diagnostics/keys**

Devuelve el conjunto de **llaves públicas de cifrado RSA** en JWKS
(`kty=RSA`, `use=enc`, `alg=RSA-OAEP-256`, `kid`, `n`, `e`)
y el campo `activeKid` para seleccionar la llave vigente. No requiere
credenciales porque son llaves públicas, pero **debe consultarse sobre HTTPS
con certificado de servidor validado**. No exponer la llave privada.

**POST /api/v1/diagnostics/batches**

- Content-Type: application/json.
- Encabezados: X-MCS-Device-ID, X-MCS-Key-ID, X-MCS-Timestamp,
  X-MCS-Nonce, X-MCS-Signature.
- El cuerpo **debe** contener exclusivamente `{"jwe":"<compact-JWE>"}`.
  No se aceptan eventos en JSON claro ni downgrade al protocolo v0.1.1.
- JWE protegido: `alg=RSA-OAEP-256`, `enc=A256GCM`,
  `typ=mcs-diag+jwe`, `kid=<llave-activa-o-válida>`; 5 segmentos Base64URL.
  Se rechazan otros algoritmos, compresión ZIP, KID desconocido,
  contenido adulterado, etiquetas GCM inválidas o estructuras extrañas.
- Máximo 50 eventos por lote, cuerpo cifrado 128 KiB y contenido
  descifrado 64 KiB (configurables); el proxy limita igualmente el cuerpo.
- Respuesta 202: batchId, accepted, duplicates, trackingId, timestamp y executionTimeMs.
- 401: instalación, firma o timestamp no válido.
- 409: nonce repetido o eventId reutilizado con contenido distinto.
- 413: tamaño excesivo.
- 503: Oracle temporalmente indisponible.

Ejemplo ilustrativo del **JSON interno**, ANTES del cifrado (sin datos personales):

    {
      "events": [{
        "eventId": "8c53c6e7-cf3f-4693-9710-705e7d24c91e",
        "occurredAt": "2026-11-06T01:59:45Z",
        "eventType": "DOWNLOAD_ERROR",
        "component": "WALLET",
        "severity": "ERROR",
        "code": "SSOIUGO_TOKEN_TIMEOUT",
        "platform": "ANDROID",
        "appVersion": "1.0.0",
        "durationMs": 15000,
        "attributes": {
          "NETWORK_STATE": "ONLINE",
          "LICENSE_CLASS": "A"
        }
      }]
    }

El JWE compacto contiene cinco segmentos separados por puntos. Los campos
del encabezado protegido pueden verse; los eventos del ejemplo no se
transmiten legibles. El cuerpo HTTP real es:

    {"jwe":"<compact-JWE-cifrado-con-la-llave-RSA-publica-del-receptor>"}

El envío es **at least once** y la persistencia es idempotente: el cliente
puede retransmitir después de un timeout sin duplicar registros en Oracle.

### Canonicalización de la firma

El cuerpo JSON **cifrado** (`{"jwe":"..."}`) se transmite en UTF-8 sin
modificar sus bytes después de firmar. Primero cifrar, luego firmar.
Se calcula SHA-256 sobre esos bytes y se escribe en hexadecimal minúscula.
Luego se forma una cadena UTF-8 con los siguientes ocho campos unidos por LF:

    MCS-DIAG-V1
    POST
    /api/v1/diagnostics/batches
    <deviceIdUUIDCanonicoMinusculas>
    <keyId>
    <timestampUnixSeconds>
    <nonceBase64UrlAleatorio>
    <sha256HexMinusculasDelCuerpo>

La clave de instalación debe ser EC secp256r1 (P-256) y la firma Java
SHA256withECDSA codificada en **ASN.1 DER**; el encabezado
X-MCS-Signature lleva Base64URL sin padding de esos bytes DER.
No usar las firmas JOSE P1363 de 64 bytes sin convertirlas a DER.

El timestamp admite ±300 segundos por defecto. El nonce debe ser
aleatorio, único y Base64URL (16–96 caracteres). La base de datos impide
su reutilización entre pods; los nonces se conservan 24 horas.

En Android, una clave ECDSA protegida por Keystore puede firmar usando
SHA256withECDSA. Debe evaluarse KeyInfo/attestation y elegibilidad de
dispositivos con las reglas vigentes MTC. Para iOS, comprobar el formato
de firma DER de la API de Secure Enclave empleada.

### Llaves asimétricas, cifrado de transporte y cifrado en reposo

El cifrado de extremo a extremo se realiza con una clave AES **efímera por
lote**, que JWE genera internamente y encapsula bajo la llave pública RSA
del servidor. No se introduce una clave AES compartida estática en
`application.yml`. Existen llaves asimétricas de dos propósitos diferentes:

1. **Autenticidad del dispositivo (ECDSA P-256):** la Wallet debe generar
   una clave privada no exportable en Android Keystore / iOS Secure Enclave.
   La clave **privada nunca se transmite ni se configura en el servidor**.
   Un enrolamiento institucional autentica la instalación y registra
   únicamente su clave **pública** mediante la API administrativa.
   Se almacena en `MCS_DIAG_DEVICE.PUBLIC_KEY_SPKI_B64` de Oracle.
   El servidor valida la firma de cada solicitud con esta clave pública.
   **ECDSA firma; no cifra el cuerpo.** El firmante de Wallet y su
   enrolamiento automático aún no están implementados.
2. **Confidencialidad de aplicación (JWE):** el receptor MTC genera y custodia
   una pareja RSA de cifrado, distinta de la de firma de Wallet. El servidor
   publica SOLO el componente público por HTTPS; cada Wallet cifra con él.
   La llave privada RSA permanece en el Secret institucional montado
   `/run/secrets/mcs-wallet-diagnostics/jwe/<kid>.pem` y se usa para
   descifrar los lotes JWE dentro del pod. El Ingress solo observa bytes JWE
   cifrados, incluso si termina TLS. La llave privada se carga en memoria
   del proceso; el código no integra todavía KMS/HSM/PKCS#11.
3. **Confidencialidad en tránsito:** HTTPS/TLS 1.2/1.3 termina en el Ingress
   institucional. `k8s/ingress.nginx.example.yaml` referencia el Secret
   `mcs-diagnostics-tls` que debe contener el certificado TLS y su clave
   privada; estos NO se incluyen en el proyecto. La verificación de la
   identidad del servidor por Wallet es obligatoria. El tramo interno
   Ingress→pod es HTTP en el ejemplo y requiere políticas de red estrictas;
   si la clasificación de información exige cifrado interno, configurar
   TLS/mTLS hasta el servicio, ya que el manifiesto actual no lo hace.
4. **Confidencialidad en reposo:** la cola MMKV existente se cifra localmente
   en Wallet. Los diagnósticos recibidos se almacenan en Oracle como datos
   estructurados; su cifrado en disco y respaldos corresponde a Oracle
   TDE/controles DBA, que aún requieren configuración y verificación real.
   Los datos se descifran en memoria antes de persistirse y el receptor no
   implementa cifrado de columnas Oracle: TDE sigue siendo requisito.
5. **JWT administrativo:** `MCS_ADMIN_JWT_ISSUER_URI`,
   `MCS_ADMIN_JWT_JWK_SET_URI` y `MCS_ADMIN_JWT_AUDIENCE` señalan el
   emisor institucional; el receptor usa claves **públicas de verificación**
   de su JWKS. No son la clave ECDSA de la Wallet ni la clave TLS.

### Distribución y rotación de la llave RSA del servidor

- Las llaves RSA **nunca se crean en la Wallet**. El MTC las genera fuera
  del proyecto y provisiona el material privado como Secret montado y de
  solo lectura (idealmente a través de HSM/KMS institucional).
- La Wallet solicita `GET /api/v1/diagnostics/keys` en una conexión TLS
  validada, selecciona `activeKid` y toma su RSA JWK público.
- En una rotación se montan en **todos** los pods la llave nueva y las
  anteriores, se cambia `active-kid` y se actualizan las réplicas.
- La Wallet vuelve a consultar llaves antes de enviar sus eventos desde
  la cola offline. Los lotes que ya se cifraron con un KID anterior pueden
  procesarse mientras el servidor conserve esa llave privada.
- No retirar las llaves antiguas hasta que venza la ventana de reintentos
  y retención pactada; registrar fecha/versión y revocaciones. Toda
  sustitución requiere proceso de gestión y autorización institucional.
- La prueba de posesión de firma ECDSA de cada Wallet, su atestación de
  dispositivo y el aprovisionamiento automático continúan pendientes.

El protocolo de integración móvil está detallado en
`docs/wallet-jwe-contract.md` y su secuencia en
`docs/wallet-key-exchange.mmd`.

### Enrolamiento y revocación

La API administrativa usa JWT válido emitido por el sistema institucional,
con issuer, audience y scopes verificados. No depende de SSOIUGO para
recibir diagnósticos de instalaciones ya registradas.

**POST /api/v1/admin/devices** (scope diagnostics.admin):

    {
      "deviceId": "22f4303c-9c70-469c-a0d2-c78147e21bfa",
      "keyId": "wallet-01",
      "platform": "ANDROID",
      "publicKeySpkiBase64": "<clave-publica-EC-P256-X509-SPKI-Base64>"
    }

El enrolamiento NO se expone a la Wallet sin control: un sistema
institucional de provisión debe autenticar y autorizar la instalación.
El identificador debe ser aleatorio, no DNI ni número de licencia.

**POST /api/v1/admin/devices/{deviceId}/keys/{keyId}/revoke**
(scope diagnostics.admin) revoca el acceso posterior.

**GET /api/v1/admin/events?deviceId=&code=&page=0&size=50**
(scope diagnostics.read o diagnostics.admin) devuelve filas paginadas
para el futuro frontend. La API de consulta no comparte privilegios
con la API receptora.

**GET /api/v1/admin/summary?hours=24** (mismos scopes de lectura):
estadísticas agregadas por componente y severidad para un futuro dashboard.

## Privacidad y formato de eventos

No se admiten mensajes libres, stacktraces, payloads de certificados,
credenciales, PIN, QR, DNI, tokens ni datos personales. Solo metadatos
de diagnóstico predefinidos. El campo attributes acepta únicamente
NETWORK_STATE, LICENSE_CLASS, CREDENTIAL_FORMAT, DEVICE_POSTURE y
FLOW_STAGE, con valores enumerados validados. Si se necesitan nuevas
variables, agregarlas deliberadamente con evaluación de privacidad.

Debe habilitarse Oracle TDE, respaldo cifrado, políticas de acceso y
retención institucional aprobada. No se automatiza el borrado de eventos
sin dicha aprobación. El microservicio no tiene privilegios DDL.

## Endurecimiento MTC pendiente de integración

- TLS 1.2/1.3 obligatorio en el Ingress, con certificados homologados.
- Limitar el Ingress público SOLO al POST receptor y GET de llaves públicas;
  API admin vía red
  interna o VPN y/o mTLS, WAF y limitación de tasa por dispositivo/IP.
- NetworkPolicy allowlist del proxy, DNS y Oracle; plantilla default-deny
  incluida, pero NO aplicar sola sin las excepciones reales del clúster.
- Autorizar el enrolamiento con prueba de posesión y Play Integrity /
  App Attest según plataforma; estos verificadores aún NO están integrados.
- Comprobar que claves privadas de instalaciones no sean exportables y
  revocar instalaciones fraudulentas.
- Restringir logs operativos: no volcar bodies, firmas ni cabeceras.
- Firmar imagen, generar SBOM, escanear dependencias y aplicar parches.
- Verificar afinidad de DB, pool total de conexiones por réplica y
  cuotas globales de Ingress; evitar saturar Oracle.
- Preparar procedimientos de recuperación, backups y pruebas de desastre.

## QA mínimo antes de producción

1. Firma válida, firma adulterada y clave revocada.
2. Nonce repetido desde dos pods simultáneos.
3. Mismo eventId enviado con nonce nuevo: un solo registro Oracle.
4. Mismo eventId pero contenido diferente: error 409 y rollback.
5. Concurrencia de lotes y rotación de claves del dispositivo.
6. Oracle desconectado: respuesta 503; Wallet continúa sin errores visibles.
7. Reconexión: retransmisión desde cola local con nonce/firma nuevos.
8. Validez de tipos A, B y Especial, sin datos personales en eventos.
9. Ataques de tamaño excesivo, autorización y saturación de endpoints.
10. Consultas paginadas y aislamiento de privilegios de lectura/admin.
11. JWE RSA-OAEP-256/A256GCM correcto; rechazo de cuerpo legacy en claro,
    KID desconocido, algoritmo inferior, GCM adulterado y textos gigantes.
12. Rotación con KID antiguo/nuevo simultáneo entre 2+ pods, descarga de
    JWK activo en Wallet y firma ECDSA del **sobre cifrado**.
13. Secret RSA protegido con RBAC, política de lectura y cifrado de volumen,
    idealmente sustituyendo archivos PKCS#8 por un conector HSM/KMS.

Los tests unitarios incluidos contemplan firmas, timestamps, entradas
no registradas, eventos duplicados, nonces repetidos, validación de
atributos y casos JWE. **No se han ejecutado con Maven en este entorno.**
Las pruebas Oracle real/Kubernetes/Wallet tampoco pueden considerarse
realizadas por entregar las fuentes.
