# Relación entre baseline, G24, G25 y F10

## Baseline importado

El repositorio importa como estado inicial el artefacto G24 identificado por SHA:

`daaddc88ae91be787d9be44652e93d5a9540584914694fa3b63a2918007ab3ef`

El fixture de regresión asociado se identifica por SHA:

`6c953b7516c2740b18c82417d79613b946579c090489320ab2e3676a3e31cdd8`

## Historia que se conserva

```text
G23 — FAIL
   ↓ corrección
G24 — PASS WITH CONDITIONS
   ↓ regresión
G25 — PASS WITH CONDITIONS
   ↓
F10 — PASS WITH CONDITIONS
```

G23 no se elimina ni se convierte en una versión artificialmente correcta. G24 representa la corrección y revalidación de los defectos identificados. G25 representa la regresión sobre el artefacto correspondiente.

## Resultado F10

La decisión final permanece **🟡 PASS WITH CONDITIONS**.

Git/GitHub no modifica esta decisión y no transforma automáticamente evidencias históricas en nuevas validaciones.

## Ejemplos de estados G25

- SEO-02 `/redirect1`: DETECTADO.
- SEO-02 `/loop`: NO_EVALUABLE.
- SEO-09 `/dynamic`: DETECTADO.
- SEO-09 `/domdiff`: EVIDENCIA_INSUFICIENTE.
- ACC-08 `/test.html`: CORRECTO como señal técnica de contraste, no conformidad WCAG.
- SEO-26 `/jsoninvalid`: DETECTADO.
- ACC-14: NO IMPLEMENTADO.

## Regla de interpretación

**SEÑAL ≠ RESULTADO**  
**NO_EVALUABLE ≠ ERROR**  
**ESPECIFICADO ≠ IMPLEMENTADO ≠ EJECUTADO ≠ VALIDADO ≠ PRODUCCIÓN**
