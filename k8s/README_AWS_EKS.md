# AWS EKS — Wallet Diagnostics 0.3.0

- PostgreSQL 16+ privado en AWS RDS; `MCS_DB_URL` con `sslmode=verify-full&sslrootcert=/run/trust/rds/rds-global-bundle.pem`, usuario específico de `wallet_diagnostics`. ConfigMap CA: `aws-rds-ca-bundle` con `rds-global-bundle.pem`.
- Crear esquema `wallet_diagnostics` por DBA. Migración Flyway con rol DDL en job controlado; en servicio PRD, `SPRING_FLYWAY_ENABLED=false` y rol DML. Si se usa primer arranque en QA, el rol necesita DDL.
- Secret `mcs-wallet-diagnostics-config`: `jdbc-url`, `username`, `password`, `jwt-issuer-uri`, `jwt-jwk-set-uri`, `jwt-audience`. No desplegar sin emisor JWT confiable para administración.
- Secret `mcs-wallet-diagnostics-jwe`: `active-kid` y archivos `<kid>.pem` PKCS#8 RSA; el código cifra con clave pública expuesta en JWKS. Nunca compartir privadas ni colocar en Git.
- El sidecar Istio se inyecta en este pod, pero Certify sigue sin sidecar; no cambiar mTLS global. Tráfico público sólo para ingestión y JWKS mediante gateway existente. No exponer `/api/v1/admin/**`.
- Dos réplicas, `ClusterIP`, PodDisruptionBudget, Probes, service account dedicada sin permisos de Kubernetes API adicionales. Logs stdout a CloudWatch y opcional fichero rotativo efímero por pod.
- Particiones mensuales por `received_at` UTC; registro particionado por hash de device_id mantiene unicidad global `(device_id,event_id)`. Toda ingestión se ejecuta en **una transacción**, incluido nonce y registry; no separarla al refactorizar.
- Ejecutar `sql/maintenance/ensure_partitions.sql` mensualmente por rol DDL. Retención: **no borrar** `mcs_diag_event_registry` sin una política explícita, porque se perdería la deduplicación global de reintentos históricos.
- `mcs-wallet-provider` todavía no aprovisiona automáticamente los dispositivos de Diagnostics. Registrar/revocar en forma segura y automatizada es un pendiente E2E, no ocultarlo.

## Entrega

`mvn -B -ntp clean verify` con JDK 21. Dockerfile construye JAR estable dentro de la imagen. CI entrega imagen firmada en ECR con digest inmutable. No aplicar `istio-virtualservice.template.yaml` hasta reemplazar host y gateway aprobados. No instalar nginx Ingress nuevo: usar Istio ya presente en EKS.

## QA imprescindible

PostgreSQL real: dos pods simultáneos insertando mismo `(device_id,event_id)`, mismo hash y hash distinto; reintentos por lote; replay de nonce; fallo tras reservar en registry; TTL nonce; pruning; rotación; rollbacks. Flujo JWE + firma ECDSA sin credenciales sensibles, y validación de límites y status HTTP. Verificar JWE keys durante rotación y AWS CloudWatch.
