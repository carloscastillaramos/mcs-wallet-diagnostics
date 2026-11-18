# mcs-wallet-diagnostics 0.3.0 — Java 21 · PostgreSQL · AWS EKS

**Estado:** fuentes migradas, pruebas Maven/E2E **pendientes de ejecutar**. Este backend no sustituye aún la integración del cliente móvil. No contiene endpoints productivos ni credenciales.

## Arquitectura criptográfica (sin cambio respecto a 0.2.0)

- El móvil retiene eventos saneados en **cola local cifrada**. El envío a Discord fue retirado en el trabajo de INJI Wallet, pero esa integración NO está cubierta por este ZIP.
- Obtiene la llave pública en `GET /api/v1/diagnostics/keys`, cifra el lote como JWE compacto (RSA-OAEP-256 / A256GCM, `typ=mcs-diag+jwe`, `kid`), firma el JSON cifrado con su clave ECDSA P-256 y llama `POST /api/v1/diagnostics/batches` sobre TLS.
- Encabezados: `X-MCS-Device-ID`, `X-MCS-Key-ID`, `X-MCS-Timestamp`, `X-MCS-Nonce`, `X-MCS-Signature`.
- Spring valida firma de dispositivo activo, timestamp y nonce; descifra JWE en memoria y valida lista blanca de eventos sin DNI, QR, tokens ni trazas libres.
- Responde HTTP 202 **después del COMMIT**. Reintento = nuevo nonce y firma, mismos `eventId`. Persistencia at least once con deduplicación global.
- JWT administrativo con scopes `diagnostics.admin` y `diagnostics.read` se conserva. El aprovisionamiento desde Wallet Provider aún NO está integrado.
- Las API son HTTP síncronas. **No hay integración SQS/Kafka/RabbitMQ en este servidor.** La cola existente es local a la app móvil; no inventar un broker AWS.

Más detalles del protocolo: `docs/wallet-jwe-contract.md` (revisado para PostgreSQL) y `docs/wallet-key-exchange.mmd`.

## Modelo PostgreSQL y millones de eventos

Migración `src/main/resources/db/migration/V1__initial.sql`, historial Flyway `wallet_diagnostics.flyway_schema_history`. Crear esquema por DBA antes de Flyway. Roles separados DDL y DML en producción.

| Tabla | Función | Escalado |
|---|---|---|
| `mcs_diag_device` | Claves públicas y revocación | Índice PK `(device_id,key_id)`, sin particiones |
| `mcs_diag_nonce` | Antirreplay de peticiones | PK y purga cada 24h; sin particiones inicialmente |
| `mcs_diag_event_registry` | Dedupe global permanente `(device_id,event_id)` | **16 particiones HASH por `device_id`**; la PK incluye clave de partición |
| `mcs_diag_event` | Eventos masivos y metadatos JSONB | RANGE mensual por `received_at` UTC; PK `(device_id,event_id,received_at)` |
| `mcs_diag_admin_audit` | Auditoría de administración | Tabla ordinaria, con índice temporal |

`PostgresDiagnosticsRepository.insertEvent()` primero reserva id/hash global en el registro por `ON CONFLICT DO NOTHING`, compara hash en duplicados y solo entonces inserta la fila particionada. Toda recepción está bajo una sola transacción `@Transactional` de `IngestionService.accept()`, incluyendo el nonce. **No separar esas operaciones en distintas transacciones.**

El hash registry no se elimina al borrar la partición histórica salvo decisión explícita que preserve la política de idempotencia. Crear particiones futuras mensualmente mediante `sql/maintenance/ensure_partitions.sql`; ya se precrean desde mes -1 a +18 al instalar. No hay partición DEFAULT: si la administración omite crear particiones la escritura falla, por eso monitorizar ventana futura.

`GET /api/v1/admin/events` mantiene `page`/`size` y `GET /api/v1/admin/summary` usa ventana temporal indexable. El endpoint de eventos no obliga filtros de fecha; **se recomienda agregar cursor y rango de fecha** tras medir volumen y acordar evolución de contrato, antes de grandes consultas históricas.

## Configuración AWS EKS

- `src/main/resources/application.yml` lee `MCS_DB_URL`, `MCS_DB_USERNAME`, `MCS_DB_PASSWORD`. TLS a RDS privado con `sslmode=verify-full&sslrootcert=/run/trust/rds/rds-global-bundle.pem`.
- Firma/JWE: `MCS_ENCRYPTION_KEYS_DIRECTORY`, `MCS_ENCRYPTION_ACTIVE_KID`; claves privadas PKCS#8 montadas desde Secret, nunca en Git.
- JWT administrativo: `MCS_ADMIN_JWT_ISSUER_URI`, `MCS_ADMIN_JWT_JWK_SET_URI`, `MCS_ADMIN_JWT_AUDIENCE`.
- Pool Hikari por pod 1–8 por defecto; opciones `MCS_DB_POOL_MAX_SIZE`/`MIN_IDLE`. El servicio es stateless.
- Java 21, Docker multi-stage construye JAR estable `target/mcs-wallet-diagnostics.jar`. Logs stdout a CloudWatch; `MCS_LOG_FILE` mantiene rotación local opcional por pod, sin almacenar cuerpos de diagnóstico.
- Manifiestos EKS: `k8s/deployment.yaml`, `service.yaml`, `serviceaccount.yaml`, `poddisruptionbudget.yaml`. Gateway Istio es **plantilla NO aplicable** hasta revisar rutas y host. Secret `mcs-wallet-diagnostics-config`, Secret `mcs-wallet-diagnostics-jwe`, ConfigMap `aws-rds-ca-bundle`.
- Mimoto/Verify participan en Istio; Certify no tenía sidecar en observación. No cambiar mTLS global ni asumir identidad de servicio en la lógica Java sin adaptación.

## Verificación / entrega

```bash
java -version
mvn -B -ntp clean verify
docker build -t mcs-wallet-diagnostics:0.3.0 .
```

**Pendiente:** CI Maven JDK21, Flyway contra PostgreSQL 16+, reintentos simultáneos, timeouts, índices/particiones, RDS/IAM/TLS, JWE móvil real, pruebas de seguridad, logging AWS, despliegue e integración E2E.

## 0.4.0 — Aprovisionamiento automático Provider

API interna `PUT/DELETE /api/v1/internal/devices/{deviceId}/keys/{keyId}` con JWT de servicio (scope `diagnostics.device.sync` y cliente permitido en `MCS_PROVIDER_SYNC_CLIENT_ID`), registro idempotente y tombstones PostgreSQL V2 para revocación irreversible. **No exponer en el gateway**. Contrato en `../mcs-wallet-provider/docs/INTEGRACION_DIAGNOSTICS_0.4.0.md`.


---

## Configuración para Infraestructura — diferencial MTC (17/11/2026)

**Alcance:** solo indicar acciones de configuración que cambian frente al despliegue anterior. **No pedir a Infraestructura que vuelva a configurar variables ya operativas y sin cambios.** Esta sección es documentación de fuentes del 17/11/2026, no una comparación certificada contra el commit efectivamente desplegado; completar esa comparación usando Git antes de poner la etiqueta definitiva «nueva» o «modificada» en los servicios existentes.

**Clasificación:** `EXISTENTE` = conocida del despliegue previo (sin acción salvo variación real); `NUEVA MTC` = incorporada funcionalmente en la implementación reciente, pendiente de contrastar con el último commit desplegado; `CAMBIO DE USO` = misma variable o configuración pero distinta forma de suministrarla; `NUEVA INSTALACIÓN` = toda variable del microservicio nuevo. No confundir parámetros de construcción Docker con variables de ejecución.

**Estado:** servicio nuevo; todas las variables siguientes son `NUEVA INSTALACIÓN` para Infraestructura. Requiere configuración inicial completa de JWE, autenticación de servicios y base de datos.

| Variable | Valor predeterminado en fuentes | Acción inicial / alcance |
|---|---|---|
| `MCS_ADMIN_JWT_AUDIENCE` | `sin valor predeterminado` | Audience autorizada |
| `MCS_ADMIN_JWT_ISSUER_URI` | `sin valor predeterminado` | Issuer del servicio de identidad |
| `MCS_ADMIN_JWT_JWK_SET_URI` | `sin valor predeterminado` | JWKS verificado del emisor |
| `MCS_CLOCK_SKEW_SECONDS` | `300` | Conservar predeterminado salvo dimensionamiento/validación del ambiente |
| `MCS_DB_PASSWORD` | `sin valor predeterminado` | Secret |
| `MCS_DB_POOL_MAX_SIZE` | `8` | Conservar predeterminado salvo dimensionamiento/validación del ambiente |
| `MCS_DB_POOL_MIN_IDLE` | `1` | Conservar predeterminado salvo dimensionamiento/validación del ambiente |
| `MCS_DB_URL` | `sin valor predeterminado` | Secret: JDBC RDS con TLS validado |
| `MCS_DB_USERNAME` | `sin valor predeterminado` | Secret/usuario técnico |
| `MCS_ENCRYPTION_ACTIVE_KID` | `sin valor predeterminado` | Kid cuya clave privada existe en directorio montado |
| `MCS_ENCRYPTION_KEYS_DIRECTORY` | `sin valor predeterminado` | Directorio de llaves privadas JWE montado, nunca Git |
| `MCS_HTTP_MAX_CONNECTIONS` | `500` | Conservar predeterminado salvo dimensionamiento/validación del ambiente |
| `MCS_HTTP_MAX_THREADS` | `80` | Conservar predeterminado salvo dimensionamiento/validación del ambiente |
| `MCS_HTTP_PORT` | `8080` | Conservar predeterminado salvo dimensionamiento/validación del ambiente |
| `MCS_JDBC_QUERY_TIMEOUT` | `5s` | Conservar predeterminado salvo dimensionamiento/validación del ambiente |
| `MCS_LOG_FILE` | `sin valor predeterminado` | Opcional. Si se usa, volumen escribible con rotación; si no, stdout |
| `MCS_LOG_LEVEL` | `INFO` | Conservar predeterminado salvo dimensionamiento/validación del ambiente |
| `MCS_LOG_MAX_FILE_SIZE` | `10MB` | Conservar predeterminado salvo dimensionamiento/validación del ambiente |
| `MCS_LOG_MAX_HISTORY` | `7` | Conservar predeterminado salvo dimensionamiento/validación del ambiente |
| `MCS_LOG_TOTAL_SIZE_CAP` | `96MB` | Conservar predeterminado salvo dimensionamiento/validación del ambiente |
| `MCS_MAX_BODY_BYTES` | `131072` | Conservar predeterminado salvo dimensionamiento/validación del ambiente |
| `MCS_MAX_DECRYPTED_BYTES` | `65536` | Conservar predeterminado salvo dimensionamiento/validación del ambiente |
| `MCS_MAX_EVENTS_PER_BATCH` | `50` | Conservar predeterminado salvo dimensionamiento/validación del ambiente |
| `MCS_MAX_EVENT_AGE_DAYS` | `8` | Conservar predeterminado salvo dimensionamiento/validación del ambiente |
| `MCS_NONCE_CLEANUP_INTERVAL_MS` | `ver código / establecer si se requiere` | Conservar predeterminado salvo dimensionamiento/validación del ambiente |
| `MCS_PROVIDER_SYNC_CLIENT_ID` | `sin valor predeterminado (si se activa sincronización)` | Client ID permitido para canal privado Provider→Diagnostics |
| `SPRING_FLYWAY_ENABLED` | `true` | Deshabilitar en pod cuando la migración corra por Job DBA |

**Dependencias de puesta en servicio:** esquema PostgreSQL, migraciones DBA autorizadas, certificados y permisos de red/Secrets, luego smoke test. `SPRING_FLYWAY_ENABLED=false` en el Deployment EKS previsto requiere ejecutar migraciones previamente; el predeterminado de la aplicación es `true`.

**Criterio de activación:** no activar controles nuevos con valores de ejemplo. Los secretos y certificados se proporcionan por los mecanismos institucionales, no mediante el repositorio. Los flags nuevos desactivados conservan el flujo anterior mientras se ejecutan pruebas E2E.

**Verificación histórica antes de la entrega:** ejecutar `git diff <commit-actualmente-desplegado> HEAD -- .` dentro de este repositorio, revisar cambios de `application.*`, Dockerfile, Helm, `*.env` y referencias de variables en el código. Marcar como `EXISTENTE` cualquier nombre que ya estuviera operativo y no haya cambiado su interpretación.
