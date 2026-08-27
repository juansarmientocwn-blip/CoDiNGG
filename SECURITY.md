# Política de seguridad

## Cómo reportar una vulnerabilidad

**No abras una issue pública** para reportar una vulnerabilidad.

Usa el canal privado de GitHub: pestaña **Security → Report a vulnerability**
(*Private vulnerability reporting*; actívalo en Settings → Code security si aún
no está encendido).

Compromiso de respuesta:

| Momento | Qué ocurre |
|---|---|
| 48 horas | Acuse de recibo |
| 7 días | Confirmación o descarte, con la valoración inicial de gravedad |
| 90 días | Publicación coordinada, o antes si ya hay parche |

Se agradece y se acredita a quien reporta, salvo que prefiera el anonimato.

## Qué entra en el alcance

- Ejecución remota de código, inyección (SQL, comandos, plantillas), deserialización insegura
- Saltos de autenticación o de autorización
- Exposición de datos personales o de credenciales
- Vulnerabilidades de la cadena de suministro: dependencias, acciones de GitHub, artefactos

## Qué no entra

- Ataques que requieren acceso físico al equipo o privilegios de administrador ya obtenidos
- Ingeniería social a personas del proyecto
- Denegación de servicio por volumen bruto de peticiones
- Hallazgos de escáneres automáticos sin un caso reproducible de explotación

## Defensas activas en este repositorio

Este repositorio ejecuta un agente de seguridad automático
(`.github/workflows/agente-seguridad.yml`) en cada push, cada pull request y a diario:

- **gitleaks** — secretos filtrados, en el código y en todo el historial de git
- **Trivy** — CVEs en dependencias, malas configuraciones y licencias
- **ClamAV** — antivirus sobre el árbol del repositorio
- **CodeQL** — análisis estático de seguridad del código fuente
- **OpenSSF Scorecard** — postura de seguridad del propio repositorio
- **Dependabot** — parches de seguridad automáticos

Los resultados van a la pestaña **Security → Code scanning**.

## Si se filtra una credencial

El orden importa y casi siempre se hace al revés:

1. **Rota la credencial primero.** Borrarla del repositorio no la invalida: desde el
   momento en que se publicó, está comprometida.
2. Revisa los registros de acceso del servicio afectado por si ya se usó.
3. Sólo entonces limpia el historial (`git filter-repo`, o BFG) y fuerza el push.
4. Avisa a quien tenga clones del repositorio: su copia local sigue conteniendo el secreto.
