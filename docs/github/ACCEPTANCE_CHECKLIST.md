# Acceptance checklist — control Git/GitHub

| Control | Estado | Evidencia |
|---|---|---|
| Repositorio identificable | DEMOSTRADO LOCALMENTE | Nombre `mvp-herramienta-evaluacion-web` |
| Historial Git real | DEMOSTRADO | 2 commits reales desde la importación |
| Baseline G24 exacto | DEMOSTRADO | SHA registrado en `docs/BASELINE_MANIFEST.md` |
| Historial retroactivo inventado | NO | Importación documentada como baseline |
| `main` controlada | PREPARADO | Rama `main` + tags |
| `develop` | PREPARADO | Rama `develop` |
| Política de commits | DEMOSTRADO | `docs/CONTRIBUTING.md` |
| PR template | PREPARADO | `.github/PULL_REQUEST_TEMPLATE/default.md` |
| README | DEMOSTRADO | `README.md` |
| Changelog | DEMOSTRADO | `CHANGELOG.md` |
| Decision log | DEMOSTRADO | `DECISIONS.md` |
| `.gitignore` | DEMOSTRADO | `.gitignore` |
| `.env.example` | DEMOSTRADO | `.env.example` |
| Dependencias | DEMOSTRADO | `requirements.txt` |
| Fixtures | DEMOSTRADO | `tests/fixtures/` |
| Evidencia G25 | CONSERVADA | `evidence/historical/` |
| Trazabilidad criterio→código→test→evidencia→release | DEMOSTRADO DOCUMENTALMENTE | `docs/traceability/` |
| CI básico | PREPARADO | `.github/workflows/ci.yml` |
| Seguridad del repositorio | DEMOSTRADO DOCUMENTALMENTE | `.gitignore`, `docs/security/SECURITY.md` |
| Seguridad de aplicación | DOCUMENTADA | `docs/security/SECURITY.md` |
| Reproducibilidad | DOCUMENTADA BAJO CONDICIONES | `docs/validation/` |
| G23 histórico | CONSERVADO | `docs/validation/FASE_10.md` |
| G24 identificable | DEMOSTRADO | SHA + tag baseline |
| G25 identificable | DEMOSTRADO DOCUMENTALMENTE | evidencias históricas |
| F10 no modificado | DEMOSTRADO DOCUMENTALMENTE | `docs/validation/FASE_10.md` |
| No claim de producción | DEMOSTRADO DOCUMENTALMENTE | README + release notes |
| No claim de 87/87 | DEMOSTRADO DOCUMENTALMENTE | README + release notes |
| No claim WCAG | DEMOSTRADO DOCUMENTALMENTE | README + security/validation docs |
| No claim de ranking/citación | DEMOSTRADO DOCUMENTALMENTE | README + validation docs |
| No secretos en archivos de configuración | REVISADO EN BASELINE | `.env.example`, `.gitignore` |
| Publicación en GitHub | PENDIENTE DE CONEXIÓN | Requiere acceso a cuenta/organización |
