# Decision Log

## D-001 — Incorporar Git/GitHub como capa transversal de control
**Fecha:** 2026-10-12  
**Contexto:** el MVP ya dispone de desarrollo y validaciones históricas, pero el control de versiones formal se consolida ahora.  
**Alternativas:** fabricar historial retroactivo; mantener archivos sin control formal; importar baseline y comenzar historial controlado.  
**Decisión:** importar el baseline G24 como estado inicial y comenzar desde este punto un historial Git real.  
**Motivo:** máxima honestidad documental y trazabilidad sin alterar F10.  
**Impacto:** las futuras evoluciones quedan asociadas a commits, pruebas, evidencias y releases.

## D-002 — No introducir un LLM de runtime por imagen de producto
**Contexto:** el dominio es AI Search, pero muchos checks requeridos son técnicos y deterministas.  
**Decisión:** mantener automatización, reglas, heurísticas y revisión humana dentro del alcance actual.  
**Motivo:** reproducibilidad y control de evidencia.  
**Limitación:** AI Search readiness no equivale a rendimiento o citación externa.

## D-003 — Mantener la abstención metodológica
**Contexto:** algunos casos no permiten una conclusión fiable.  
**Decisión:** conservar estados como `NO_EVALUABLE` y `EVIDENCIA_INSUFICIENTE` cuando corresponda.  
**Motivo:** evitar transformar ausencia de evidencia en ausencia de problema.

## D-004 — Separar laboratorio de producción
**Contexto:** existen controles de seguridad observados en entorno controlado.  
**Decisión:** documentarlos como controles bajo condiciones registradas, sin claim de seguridad de producción.  
**Motivo:** coherencia con F10.
