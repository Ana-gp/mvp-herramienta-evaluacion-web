# Seguridad

## Principios

- No almacenar secretos en el repositorio.
- Tratar el contenido web como datos no confiables.
- No permitir que el contenido analizado se convierta en instrucciones del sistema.
- Mantener validación de destinos y redirecciones.
- Mantener `ALLOW_PRIVATE_TARGETS=0` por defecto.

## Controles observados en el baseline

- Solo HTTP/HTTPS.
- Rechazo de credenciales embebidas en URL.
- Resolución y bloqueo de direcciones privadas/loopback/link-local/reservadas bajo modo estricto.
- Validación por salto de redirección.
- Límites de tamaño/redirects/timeout en el flujo correspondiente.

## Alcance

Estos controles fueron evaluados bajo condiciones de laboratorio registradas. No equivalen a una auditoría de penetración ni a una certificación de seguridad de producción.

## Secretos

Nunca subir API keys, contraseñas, tokens, cookies, certificados privados, `.env` reales o datos personales. Si un secreto real entra en Git, debe considerarse comprometido y revocarse/rotarse; borrarlo del último commit no basta.
