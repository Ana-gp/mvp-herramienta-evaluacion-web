# MVP — Herramienta de Evaluación Web

**PROCONSI · Vibe Coding · Git/GitHub · QA · trazabilidad**

> MVP de herramienta para evaluación web mediante señales técnicas de SEO, accesibilidad y AI Search, desarrollado mediante Vibe Coding con control de versiones, validación y trazabilidad.

![PROCONSI](docs/assets/proconsi.jpg)

## 1. Qué es

Este repositorio contiene el **baseline técnico controlado** del MVP de la Herramienta de Evaluación Web. La incorporación formal de Git/GitHub se realiza en esta etapa para gobernar el desarrollo existente y futuro.

**Importante:** este repositorio no reescribe la historia metodológica ni modifica la Matriz V1, F3.2 ni la decisión de F10.

## 2. Alcance

El artefacto ejecuta un subconjunto de capacidades del universo V1, entre ellas señales técnicas de:

- SEO: acceso/HTTP, redirects, robots, canonical, title, idioma, viewport, enlaces, contenido dinámico observable, JSON-LD y otras señales implementadas.
- Accesibilidad técnica: landmarks, texto alternativo, asociación técnica de controles y contraste, dentro del alcance realmente implementado.
- AI Search: señales técnicas/semánticas observables y readiness heurística.

El repositorio **no representa la validación completa de los 87 criterios de la Matriz V1**.

## 3. Arquitectura

La aplicación actual es un artefacto Python de servicio HTTP local. El flujo conceptual es:

**URL → acceso → análisis técnico/DOM → evidencia → criterio → resultado → diagnóstico/recomendación/limitación**

La evidencia y los resultados mantienen la distinción entre señal y resultado externo.

## 4. Instalación

Requisito: Python 3.x compatible con el entorno registrado del proyecto.

```bash
python -m venv .venv
# Linux/macOS
source .venv/bin/activate
# Windows PowerShell
# .venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
```

## 5. Ejecución

```bash
python src/app.py
```

Por defecto escucha en `127.0.0.1:8787`. El puerto puede cambiarse con `PORT`.

`ALLOW_PRIVATE_TARGETS` permanece desactivado por defecto. No debe activarse como supuesto de seguridad de producción.

## 6. Tests y validación

El repositorio conserva como **evidencia histórica** los materiales de G25 y el fixture utilizado en la regresión. No se presentan como nuevos tests ejecutados por GitHub.

- `tests/fixtures/test_fixture_G25.html`: fixture con SHA conservado.
- `evidence/historical/`: matrices y checklist de G25.
- `docs/validation/FASE_10.md`: relación entre baseline, G24 y G25.

La distinción obligatoria es:

**ESPECIFICADO ≠ IMPLEMENTADO ≠ EJECUTADO ≠ VALIDADO ≠ PRODUCCIÓN**

## 7. Estado actual

- Baseline importado: **G24**, artefacto con SHA `daaddc88ae91be787d9be44652e93d5a9540584914694fa3b63a2918007ab3ef`.
- Fixture G25: SHA `6c953b7516c2740b18c82417d79613b946579c090489320ab2e3676a3e31cdd8`.
- F10: **🟡 PASS WITH CONDITIONS**.
- Este repositorio inicia el historial Git formal; no se fabrican commits históricos.

## 8. Vibe Coding

Vibe Coding se utilizó como **metodología de desarrollo asistido**. El código generado no se consideró automáticamente correcto. El proceso incorporó especificación, supervisión humana, pruebas, corrección, regresión, trazabilidad y control de cambios.

La secuencia G23 → G24 → G25 es una evidencia clave de ese control: G23 detectó defectos, G24 corrigió y revalidó, y G25 ejecutó regresión sobre el artefacto correspondiente.

## 9. Seguridad

Los controles observados incluyen validación de destinos, bloqueo de destinos restringidos bajo el modo estricto, validación de redirecciones y controles de ejecución del navegador según las condiciones registradas.

Esto es **laboratorio/control técnico**, no certificación de seguridad de producción.

## 10. Accesibilidad

El producto evalúa señales técnicas automatizables dentro de su alcance. No debe presentarse como auditoría humana completa, conformidad WCAG ni validación mediante lector de pantalla/Braille.

## 11. AI Search

AI Search es un **dominio de evaluación**. Las señales observables del MVP no demuestran ranking, citación por ChatGPT u otros sistemas, ni rendimiento externo.

No se introduce un LLM de runtime solo para etiquetar el producto como “IA”.

## 12. Control de versiones

A partir de este baseline, el procedimiento normal es:

**branch → commit → test → PR/revisión → merge → tag/release**

Los commits deben explicar qué cambió; la documentación del cambio debe explicar por qué.

## 13. Documentación

- `CHANGELOG.md` — evolución controlada.
- `DECISIONS.md` — decisiones técnicas relevantes.
- `docs/traceability/` — relación criterio/código/prueba/evidencia.
- `docs/validation/` — relación con F10 y G25.
- `docs/security/` — controles y límites de seguridad.
- `docs/architecture/` — arquitectura real del baseline.
- `docs/CONTRIBUTING.md` — procedimiento de cambios.

## 14. Regla de gobierno

GitHub demuestra **trazabilidad, evolución, control de cambios y reproducibilidad documental**. La validación sigue dependiendo de pruebas y evidencias.

GitHub no convierte una capacidad no validada en validada y no convierte el MVP en un producto de producción por el mero hecho de estar versionado.
