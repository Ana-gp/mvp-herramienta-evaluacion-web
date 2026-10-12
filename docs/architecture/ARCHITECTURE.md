# Arquitectura del baseline

## Artefacto

El baseline importado es un servicio Python autocontenido (`src/app.py`) que expone una interfaz web local y un endpoint de análisis.

## Flujo

```text
Usuario
  ↓
Interfaz web
  ↓
POST /api/analyze
  ↓
Validación de URL/destino
  ↓
Fetch + redirecciones + análisis técnico
  ↓
DOM/HTML y, cuando procede, navegador/CDP
  ↓
Evidencia
  ↓
Resultados por criterio
  ↓
Diagnóstico / recomendación / limitación
  ↓
Informe JSON / interfaz
```

## Seguridad observable

El código incluye validación de protocolo, rechazo de credenciales embebidas, resolución y bloqueo de destinos restringidos bajo configuración estricta, validación de redirecciones y límites de ejecución observados en el artefacto.

## Límite

La arquitectura descrita no constituye una certificación de seguridad de producción.
