# SentinelIAM — Enterprise RBAC & Access Governance Console

Consola empresarial de gobierno de identidades (IAM / Zero-Trust) para administrar matrices de permisos RBAC, detectar conflictos de **Segregación de Funciones (SoD / SOX)**, simular acceso efectivo RBAC + ABAC y revisar el *Blast-Radius Diff* antes de publicar políticas.

## Capacidades Empresariales

- **Matriz Interactiva Rol × Recurso × Acción:** Gestiona roles corporativos (`FinOps_Analyst`, `Treasury_Approver`, `Platform_SRE`, `SecOps_Auditor`, `Super_Admin`) sobre recursos críticos.
- **Detector de Conflictos SoD (SOX Compliance):** Identifica combinaciones tóxicas (ej. `Ledger:create` + `Ledger:approve` o `Billing:create` + `Billing:approve`) dentro de un mismo rol o por acumulación de roles en un usuario.
- **Simulador de Permiso Efectivo (RBAC + ABAC):** Evalúa contexto de ejecución (MFA verificado, entorno `prod`/`staging`, IP corporativa dentro de CIDR permitido) y entrega traza explicable `ALLOW` / `DENY`.
- **Policy Blast-Radius Diff:** Compara borrador vs política publicada antes de aplicar cambios en producción.

## Ejecución y Pruebas

```bash
npm test
python3 -m http.server 8087 --directory src
```
