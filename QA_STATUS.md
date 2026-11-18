# Estado QA — PostgreSQL/AWS EKS (0.3.0)

- Fuentes adaptadas a Java 21, PostgreSQL JDBC, Flyway y particiones mensuales.
- Pruebas unitarias heredadas conservadas; ejecución Maven NO verificada en el entorno de preparación.
- **Pendiente**: `mvn -B -ntp clean verify` en CI con Java 21 y Maven.
- **Pendiente**: pruebas integradas PostgreSQL 16+ (Flyway, transacciones, conflictos concurrentes, pruning y retención).
- **Pendiente**: certificar JWE/firmas con clientes móviles y registro desde Wallet Provider.
- **Pendiente**: desplegar en AWS EKS y validar IAM, Istio, TLS, secretos y conexiones RDS.
- No se incluyen secretos, llaves ni valores de producción.
