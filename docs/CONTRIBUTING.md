# Guía breve de cambios

## Flujo

1. Crear una rama temporal: `feature/*`, `fix/*`, `security/*` o `test/*`.
2. Identificar el criterio/capacidad afectado cuando corresponda.
3. Realizar el cambio.
4. Ejecutar las pruebas disponibles y registrar el resultado.
5. Si el cambio corrige un defecto relevante, conservar o añadir una regresión cuando sea razonable.
6. Abrir PR con problema, cambio, criterio, evidencia, pruebas, resultado, riesgos, limitaciones e impacto en regresión.
7. Revisar.
8. Integrar en `main` solo cuando el cambio esté controlado.
9. Crear tag/release para hitos relevantes.

## Commits

Usar mensajes comprensibles, por ejemplo:

- `feat: implementa ...`
- `fix: corrige ...`
- `test: añade regresión ...`
- `security: bloquea ...`
- `docs: actualiza ...`
- `refactor: separa ...`

Evitar mensajes como `cambios`, `final`, `ahora sí` o `última versión`.

## Regla crítica

No asumir que un commit, PR o tag implica validación funcional. La validación requiere pruebas y evidencia.
