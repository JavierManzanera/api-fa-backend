# Informe de Auditoría de Seguridad — `api-fa-backend`

**Fecha:** 2026-08-21
**Alcance:** Revisión estática (SAST manual) de la base de auth reutilizable (FastAPI + SQLAlchemy async + PostgreSQL/asyncpg + JWT/python-jose + passlib/bcrypt). Sin entorno con dependencias instaladas ni base de datos corriendo — no se hizo DAST/pentest dinámico. Las afirmaciones de CVE se basan en conocimiento de entrenamiento, no en consulta en vivo a NVD/OSV — deben confirmarse con `pip-audit`/`safety` sobre el árbol de dependencias resuelto una vez exista un lockfile.

---

## Hallazgos

### 1. CRÍTICO — Refresh token utilizable como access token (bypass de autenticación)
**Evidencia:** `app/api/deps.py:26-33` (`get_current_user`) decodifica el JWT y solo valida `payload.get("sub")`; nunca inspecciona el claim `"refresh": True` que `app/core/security.py:34` añade a los refresh tokens. `verify_refresh_token` (`app/core/security.py:38-53`) sí hace esa comprobación, pero ese código nunca es llamado por `get_current_user` — son dos rutas de validación completamente independientes.

**Escenario de explotación confirmado:** un atacante que obtiene un refresh token (XSS, log leak, dispositivo robado) puede enviarlo como `Authorization: Bearer <refresh_token>` contra cualquier endpoint protegido por `get_current_user`/`get_current_active_user`. Como el refresh token vive `REFRESH_TOKEN_EXPIRE_DAYS=7` días frente a los `ACCESS_TOKEN_EXPIRE_MINUTES=30` del access token, esto extiende la ventana de un token robado de 30 minutos a 7 días.

**Fix:** en `get_current_user`, rechazar el token si `payload.get("refresh") is True`. Mejor aún: usar `"type": "access"` / `"type": "refresh"` explícito en ambos tokens y validar el tipo esperado en cada punto de verificación (fail-closed).
**OWASP:** API2:2023 Broken Authentication / CWE-287.

---

### 2. CRÍTICO — Cuenta comprometible por fuerza bruta de OTP sin rate limiting
**Evidencia:** sin `slowapi`/`fastapi-limiter` en `requirements.txt`; sin middleware de throttling en `app/main.py`. OTP: `auth.py:86` `"".join(random.choices(string.digits, k=6))` → 10⁶ combinaciones, expira en 10 min. `Verification` no tiene contador de intentos ni bloqueo.

**Escenario:** `/reset-password` (`auth.py:126-155`) valida el OTP con un SELECT indexado — sin bcrypt ni operación costosa — y si coincide, cambia la contraseña en la misma request, sin pasar por `/verify-otp`. Con el email objetivo (obtenible por enumeración, ver #6) y sin rate limit, es factible cubrir una fracción significativa del espacio de 10⁶ dentro de la ventana de 10 min. Agravante: `/verify-otp` funciona como oráculo gratuito para validar guesses sin comprometerse a una nueva contraseña. **Vector de account takeover completo, no autenticado.**

**Fix:** rate limiting por IP+email en los 4 endpoints públicos; contador de intentos fallidos en `Verification` con bloqueo tras N intentos e invalidación del código; CAPTCHA en forgot-password; aumentar el espacio de OTP o reducir el TTL; considerar colapsar `/verify-otp` + `/reset-password` en un flujo de un solo intento con token de un solo uso.
**OWASP:** API4:2023 + API6:2023 / CWE-307.

---

### 3. ALTO — Sin revocación de tokens; el reset de password no invalida sesiones activas
**Evidencia:** no existe `/logout`. `/refresh` (`auth.py:158-176`) devuelve el mismo `refresh_token` recibido sin rotarlo. `reset_password` solo actualiza `hashed_password`; no hay `token_version`/`security_stamp` en `User` para invalidar tokens ya emitidos.

**Escenario:** un token robado sigue siendo válido durante toda su vida útil natural (hasta 7 días para el refresh) incluso después de que el usuario cambie su contraseña por sospecha de compromiso. Combinado con #1, un refresh token robado da acceso persistente de hasta 7 días sin forma de revocarlo.

**Fix:** endpoint `/logout` con blacklist (Redis/tabla `revoked_tokens` con TTL = exp del token) o allowlist de refresh tokens activos; rotar el refresh token en cada `/refresh` (detectar reuse como señal de robo); incrementar un `token_version` en `User` en cada reset de password y validarlo en `get_current_user`.
**OWASP:** API2:2023 / CWE-613.

---

### 4. ALTO — `SECRET_KEY` sin validación de longitud/entropía; placeholder no bloqueado
**Evidencia:** `app/core/config.py:16` `SECRET_KEY: str` sin `min_length` ni `field_validator`. `.env.example:9` `SECRET_KEY=your_secret_key_here`.

**Escenario:** si un desarrollador copia `.env.example` a `.env` sin cambiar el placeholder, la app arranca con normalidad y firma JWT con un secreto público — cualquiera puede forjar access y refresh tokens válidos (agrava #1).

**Fix:** `field_validator` en `Settings` que rechace el arranque si `len(SECRET_KEY) < 32` o coincide con placeholders conocidos; documentar generación con `secrets.token_urlsafe(64)`.
**OWASP:** API8:2023 / CWE-521, CWE-1188.

---

### 5. MEDIO — Timing side-channel / enumeración de usuarios en `/login` y `/forgot-password`
**Evidencia:** `auth.py:52` `if not user or not security.verify_password(...)` — cortocircuito de Python: si `user` es `None`, `verify_password` (bcrypt, ~100-300ms) nunca se ejecuta. Diferencia de latencia medible remotamente. `/forgot-password` tiene la misma asimetría (un SELECT si no existe el email vs. DELETE+INSERT+COMMIT si existe) pese al mensaje genérico correcto.

**Fix:** ejecutar siempre `verify_password` contra un hash bcrypt dummy precomputado cuando el usuario no existe, para igualar tiempos de respuesta.
**OWASP:** A07:2021 / CWE-208.

---

### 6. MEDIO — Enumeración de usuarios explícita en `/register`
**Evidencia:** `auth.py:26-30` responde `400 "The user with this email already exists..."` — contraste directo con el diseño correcto de `/forgot-password`.

**Fix:** si el modelo de amenaza prioriza no-enumeración, aceptar el registro devolviendo 201 igualmente y enviar un email "ya tienes cuenta" al correo existente, o documentar el trade-off como riesgo aceptado.
**OWASP:** A07:2021 / CWE-203.

---

### 7. MEDIO — Código OTP almacenado en texto plano en base de datos
**Evidencia:** `app/models/verification.py:12` sin hashing/HMAC, a diferencia de `hashed_password`.

**Escenario:** cualquier lectura no autorizada de `verifications` (backup filtrado, réplica mal configurada, insider) entrega códigos de reset válidos y listos para usar.

**Fix:** almacenar `HMAC-SHA256(code, server_pepper)`; comparar con `hmac.compare_digest`.
**OWASP:** A02:2021 / CWE-312.

---

### 8. MEDIO — Sin TLS/SSL forzado en la conexión a PostgreSQL
**Evidencia:** `app/core/config.py` construye el DSN sin `ssl`/`sslmode`; `app/core/database.py` no pasa `connect_args={"ssl": ...}`.

**Fix:** añadir `POSTGRES_SSL_MODE` y pasar `connect_args={"ssl": "require"}` (o `verify-full`), fail-closed en producción.
**OWASP:** A02:2021 / CWE-319.

---

### 9. MEDIO — Sin CORS ni cabeceras de seguridad HTTP
**Evidencia:** `app/main.py` no registra `CORSMiddleware`, `TrustedHostMiddleware`, ni cabeceras (HSTS, `X-Content-Type-Options`, `X-Frame-Options`, CSP).

**Riesgo:** al ser un template reutilizable, es probable que el siguiente proyecto añada `allow_origins=["*"]` apresuradamente. Mejor fijar el patrón correcto ahora.

**Fix:** `CORSMiddleware` con `allow_origins` parametrizado por env var (nunca `"*"` con `allow_credentials=True`); middleware de cabeceras de seguridad.
**OWASP:** A05:2021 / CWE-693.

---

### 10. MEDIO — Sin logging/auditoría de eventos de autenticación
**Evidencia:** ningún uso de `logging`; solo un `print()` de debug del OTP en claro (`auth.py:97-99`), riesgo adicional si stdout va a logs centralizados no restringidos.

**Fix:** logging estructurado (sin loguear password/OTP en claro) de login éxito/fallo, reset de password, intentos de OTP fallidos, uso de refresh token; eliminar el `print` antes de producción.
**OWASP:** A09:2021.

---

### 11. BAJO — `is_verified` es un campo sin función (dead code de diseño)
**Evidencia:** se crea en `False` en `/register` pero `login` nunca lo consulta, y no existe endpoint que lo ponga en `True` (`/verify-otp` está scopeado solo a `purpose="reset_password"`).

**Fix:** implementar el flujo `/verify-email` faltante y aplicarlo en `login`, o documentar que `is_verified` es un placeholder no funcional.
**OWASP:** A04:2021.

---

### 12. BAJO — Dependencias sin pin de versión; riesgo de cadena de suministro
**Evidencia:** todo `requirements.txt` sin versión excepto `bcrypt==3.2.2`; sin lockfile.

**`python-jose`:** CVEs históricos relevantes para JWT — CVE-2024-33663 (confusión de algoritmo con JWK no confiable) y CVE-2024-33664 (DoS por descompresión JWE maliciosa en ≤3.3.0). Esta app fija `algorithms=[ALGORITHM]`=HS256 explícito, no deriva el algoritmo del header ni consume JWKS externos, por lo que el vector de confusión de algoritmo no parece aplicar directamente tal como está el código — pero no es confirmable sin lockfile. Recomendado pinnear `python-jose>=3.4.0` o migrar a `pyjwt`.

**`bcrypt==3.2.2`:** sin CVE directo confirmado; el pin parece ser el workaround conocido de compatibilidad `passlib==1.7.x` + `bcrypt>=4.0`. Paquete de 2021 sin parches posteriores — higiene, no vulnerabilidad activa confirmada.

**Fix:** lockfile con versiones fijas y actualizadas; `pip-audit`/`safety` en CI.
**OWASP:** A06:2021 / CWE-1104, CWE-1357.

---

### 13. BAJO — `/docs`, `/redoc`, `/openapi.json` expuestos sin gate de entorno
**Evidencia:** `FastAPI(...)` sin `docs_url`/`openapi_url` condicionados por entorno.

**Fix:** deshabilitar cuando `ENVIRONMENT=production`.
**OWASP:** API9:2023.

---

### 14. BAJO — Sin separación de privilegios DB (DDL vs. DML)
**Evidencia:** `Base.metadata.create_all` en el lifespan requiere que el usuario de runtime tenga privilegios DDL — sin rol separado de migración.

**Fix:** cuando se implemente Alembic (gap ya conocido), usar rol de migración separado (DDL) y rol de runtime restringido a DML.
**OWASP:** A05:2021 / CWE-250.

---

## Puntos positivos confirmados
- Todas las queries usan SQLAlchemy ORM parametrizado — sin riesgo de inyección SQL (A03:2021 — **PASS**).
- `UserResponse` excluye `hashed_password` de las respuestas — sin fuga de hash (API3:2023 — **PASS**).
- IDs de usuario son UUID v4, no secuenciales (**PASS**).
- Validación de fuerza de password razonable (mayúscula + dígito + especial, 8-128 chars) — falta chequeo contra listas de contraseñas filtradas (ASVS 2.1.7).
- `.env` correctamente excluido de VCS; solo `.env.example` con placeholders versionado (**PASS**).
- `/forgot-password` usa mensaje de respuesta genérico (intención de diseño correcta, aunque con fuga de timing, #5).

---

## Threat model — superficie y ruta de ataque crítica

- **Superficie:** 5 endpoints públicos no autenticados (`register`, `login`, `forgot-password`, `verify-otp`, `reset-password`) + 1 semi-autenticado (`refresh`, autenticado solo por posesión del token).
- **Dato más sensible de vida corta:** `verifications.code` (OTP en claro, #7).
- **Ruta de ataque dominante (no autenticado, automatizable, sin CAPTCHA/rate limit):** enumerar email → forzar OTP → resetear password → usar refresh token robado que sobrevive el reset. Cadena de extremo a extremo de account takeover.
- Al ser un template reutilizable en múltiples proyectos, cualquier hallazgo Critical/High se replica automáticamente en todo proyecto que lo consuma.

---

## Veredicto — OWASP API Security Top 10 (2023)

| Categoría | Veredicto | Hallazgos |
|---|---|---|
| API2 Broken Authentication | **FAIL** | #1, #3, #4, #5 |
| API3 Broken Object Property Level Authorization | PASS | — |
| API4 Unrestricted Resource Consumption | **FAIL** | #2 |
| API6 Unrestricted Access to Sensitive Business Flows | **FAIL** | #2 |
| API8 Security Misconfiguration | **FAIL** | #4, #9, #13 |
| API9 Improper Inventory Management | **FAIL** (menor) | #13 |

**Veredicto global: FAIL.** No apto para producción sin remediar los hallazgos Críticos (#1, #2) y Altos (#3, #4) como mínimo.

---

## Gate 3 — Verificación OBJ-001 (2026-08-21)

**Alcance:** verificación SAST manual (evidencia archivo:línea, no confianza en el resumen de `developer`) de los hallazgos #1, #2, #4, más revisión nueva del rate limiter (`app/core/rate_limit.py`, `app/models/rate_limit.py`) introducido por esta implementación. Archivos revisados: `app/core/security.py`, `app/api/deps.py`, `app/api/v1/endpoints/auth.py`, `app/core/rate_limit.py`, `app/models/rate_limit.py`, `app/models/verification.py`, `app/core/config.py`, `app/main.py`, `.env.example`, `app/schemas/user.py`.

### Hallazgo #1 (refresh token usable como access token) — **CERRADO**

- `app/api/deps.py:28` — `get_current_user`: `if payload.get("type") != security.TOKEN_TYPE_ACCESS: raise credentials_exception`. Es fail-closed genuino: `payload.get("type")` sobre un token *sin* ese claim en absoluto devuelve `None`, y `None != "access"` es `True` → 401. Cubre tanto tokens forjados sin el claim como cualquier access token emitido por la versión anterior del código (que tampoco llevaba `type`) — estos últimos quedan invalidados de golpe, comportamiento correcto y esperado de un fix fail-closed (efecto colateral: fuerza re-login global, no es un fallo de seguridad).
- `app/core/security.py:29-34` y `:42-47` — `create_access_token`/`create_refresh_token` fijan `"type": "access"`/`"type": "refresh"` explícito en cada emisión.
- `app/core/security.py:51-65` — `verify_refresh_token` valida `type == "refresh"` y ahora lanza `401` (antes `400`) para **toda** falla de validez (tipo incorrecto, firma inválida, expirado, malformado) — una sola rama de except, sin fugas de comportamiento entre casos.
- Las dos rutas de validación (access vía `deps.get_current_user`, refresh vía `security.verify_refresh_token`) siguen siendo independientes pero ahora **ambas** exigen el `type` correcto — ya no hay bypass cruzado.

### Hallazgo #2 (OTP fuerza-bruteable) — **CERRADO**, con una nota de diseño residual (no bloqueante)

- Generación CSPRNG confirmada: `app/api/v1/endpoints/auth.py:33-36` usa `secrets.choice(string.digits)`, no `random`.
- Lockout de 5 intentos confirmado y funcional: `app/api/v1/endpoints/auth.py:39-77` (`_check_and_consume_otp`). Al llegar a `MAX_OTP_ATTEMPTS = 5` (línea 22), `verification.expires_at` se fija a `now()` (línea 73), lo que hace que la fila deje de matchear el filtro `expires_at > now()` de la consulta (líneas 58-63) en cualquier intento posterior — el lockout **sí impide** seguir probando códigos contra esa fila.
- Rate limiting verificado en los 3 endpoints correctos con los límites acordados en Gate 1: `/forgot-password` 5/min (`auth.py:142-148`), `/verify-otp` 10/min (`auth.py:207-213`), `/reset-password` 10/min (`auth.py:226-232`). Los tres llaman `rate_limit.enforce_rate_limit` **antes** de tocar el estado de `Verification`.
- **Oráculo lockout vs. expiración natural — confirmado que NO existe distinción explotable.** Ambos casos (fila no existe porque expiró a los 10 min sin más, y fila "expirada" a la fuerza por el lockout) terminan en la misma rama `if verification is None: raise generic_error` (`auth.py:67-68`), con el mismo `400` y el mismo mensaje `GENERIC_OTP_INVALID_MESSAGE`. No hay diferencia de código de estado, cuerpo de respuesta, ni cabecera entre ambos casos. (No se midió timing de la query en sí — la única diferencia potencial de temporización sería el propio índice/plan de PostgreSQL, no una rama de código distinta; se considera fuera del alcance práctico de un oráculo remoto explotable.)
- **Reseteo del contador `attempts` — solo posible vía `/forgot-password`, y ese camino está limitado.** `attempts` solo vuelve a 0 cuando se crea una fila `Verification` nueva (rotación en `/forgot-password`, `auth.py:176-190`, que además hace `DELETE` de las filas previas). Ese endpoint exige que no exista una fila creada en los últimos 60s **para ese `(email, purpose)`, viva o ya bloqueada/expirada** (`auth.py:170-173`, `existing.created_at > cooldown_cutoff` sin filtrar por estado) — el diseño documentado explícitamente cierra el gap de "pedir un OTP nuevo inmediatamente tras agotar el budget". Combinado con el rate limit de 5/min en ese mismo endpoint, el techo práctico de intentos por los 10 minutos de vida de un código es del orden de 5 intentos por cada ventana de 60s de cooldown (~50 intentos/10 min en el peor caso), no infinito — una mejora sustancial y consistente con lo aprobado en Gate 1, pero **no** matemáticamente cero; se documenta aquí como riesgo residual aceptado (ya decidido en Gate 1, no es una regresión ni un hallazgo nuevo).
- **Nota de concurrencia (no nueva, ya señalada en Fase 2 como fuera de alcance):** `_check_and_consume_otp` lee `verification.attempts`, incrementa en Python y hace `commit()` sin un `SELECT ... FOR UPDATE`/lock explícito. Bajo solicitudes verdaderamente paralelas (no solo secuenciales, que es como se probó) contra la misma fila, dos requests podrían leer el mismo valor de `attempts` antes de que cualquiera confirme, permitiendo en teoría 1-2 intentos extra más allá de 5 en una ventana de carrera muy estrecha. Severidad Baja — no revive el hallazgo original (sigue habiendo un tope acotado, no fuerza bruta ilimitada); se deja documentado como mejora futura (`SELECT FOR UPDATE` o constraint a nivel DB), no como bloqueo de este gate.

### Hallazgo #4 (SECRET_KEY sin validar) — **CERRADO**

- `app/core/config.py:37-50` — `field_validator` en `SECRET_KEY` lanza `ValueError` si `len(value) < 32` (línea 40) o si el valor (normalizado con `.strip().lower()`) está en `_SECRET_KEY_BLOCKLIST` (línea 45), que incluye explícitamente `"your_secret_key_here"` — el placeholder exacto que trae `.env.example:11`.
- Confirmado que esto **bloquea el arranque de verdad**, no solo loguea: `settings = get_settings()` se ejecuta a nivel de módulo en `config.py:68`, y `get_settings()` (línea 65-66) instancia `Settings()` directamente. Un `ValueError` dentro de un `field_validator` de Pydantic v2 se envuelve en una `ValidationError` real que se propaga en la construcción del objeto — como esto ocurre en tiempo de import de `app.core.config` (importado por casi todo el árbol de `app/`), cualquier arranque con un `SECRET_KEY` inválido revienta antes de que `uvicorn`/FastAPI sirvan una sola request.
- `.env.example:9-11` documenta correctamente el nuevo requisito (32 chars mínimo, no placeholder, comando `secrets.token_urlsafe(64)` sugerido).

### Revisión nueva — Rate limiter (`app/core/rate_limit.py`, `app/models/rate_limit.py`)

**Identificación del cliente:** clave compuesta `(scope, ip, email)` — `app/core/rate_limit.py:42-51`. Correcto en el sentido de que ata el límite tanto a la IP como al email objetivo, no solo a uno de los dos.

- **[NUEVO — MEDIO] `client_ip()` no soporta despliegue detrás de proxy/load balancer** (`app/core/rate_limit.py:65-72`): usa `request.client.host` directamente, sin leer `X-Forwarded-For`/`Forwarded`. Esto **no** es explotable como spoofing directo (la cabecera ni se lee, así que un atacante no puede inyectar una IP falsa que la app vaya a confiar), pero es un bug real de despliegue para el contexto explícito de este template ("pensado para desplegarse en cualquier proyecto", típicamente detrás de un ALB/nginx ingress/reverse proxy): en ese escenario, `request.client.host` resuelve a la IP fija del proxy para el 100% del tráfico real, colapsando la dimensión "IP" de la clave `(ip, email)` a una constante. El límite efectivo en producción se degrada a "solo por email" — el email objetivo sigue protegido (el límite no desaparece), pero se pierde el aislamiento por IP que el diseño pretendía, y usuarios legítimos detrás del mismo proxy/NAT que intenten operar sobre el mismo email compartirían accidentalmente el mismo budget.
  **Fix recomendado:** no parsear `X-Forwarded-For` a ciegas (eso sí sería spoofable por un cliente arbitrario) — usar `uvicorn --proxy-headers --forwarded-allow-ips=<IP del LB conocida>` (o `ProxyHeadersMiddleware` de Starlette) para que `request.client.host` ya venga resuelto de forma confiable solo cuando el hop inmediato es un proxy explícitamente confiado; documentar esto como requisito de despliegue en el README del template.
- **[NUEVO — BAJO] `rate_limit_hits` sin TTL ni mecanismo de limpieza** — confirmado por grep en todo el árbol del proyecto: no existe ningún job de purga, `DELETE` de mantenimiento, ni `server_default`/política de expiración sobre la tabla (`app/models/rate_limit.py:9-38`). Cada request aceptada contra los 3 endpoints inserta una fila permanente (`app/core/rate_limit.py:61`); la tabla crece sin límite durante toda la vida del despliegue. No es explotable de forma inmediata/aguda, pero es un DoS de almacenamiento a largo plazo (y eventualmente degrada el plan de la consulta `COUNT()` pese al índice compuesto). Ya anticipado como trade-off consciente en `docs/api/obj-001-design-notes.md` (sección 5, punto 4: "Postgres-table fallback... at the cost of more DB writes"), pero el diseño no incluyó una estrategia de purga — se deja como hallazgo formal para no perderlo de vista antes de que este template se replique a otros proyectos.
  **Fix recomendado:** job periódico (pg_cron, tarea de arranque, Celery beat, o simplemente un `DELETE WHERE created_at < now() - max_window` ejecutado de forma oportunista dentro de `enforce_rate_limit`) que purgue filas más antiguas que la ventana máxima usada por cualquier scope.

### Hallazgos Medio/Bajo preexistentes — ¿agravados por este cambio?

- **`GET /auth/me` (nuevo endpoint, `auth.py:80-84`):** responde con `UserResponse` (`id`, `email`, `is_active`, `is_verified`, `created_at`) — el mismo schema ya auditado como PASS por excluir `hashed_password` (ver "Puntos positivos confirmados"). No expone nada nuevo. Está protegido por `deps.get_current_active_user` (requiere access token válido tras el fix de #1), consistente con el resto de endpoints autenticados. **Sin agravación.**
- Hallazgos #3 (sin revocación), #5 (timing side-channel), #6 (enumeración en `/register`), #7 (OTP en claro), #8-#14: ninguno de los archivos tocados en esta implementación introduce cambios en su superficie — se mantienen tal como estaban, sin agravarse ni cerrarse (fuera del alcance declarado de OBJ-001). Nota: #7 (OTP en claro en `verifications.code`) sigue aplicando igual sobre la nueva columna `attempts` de la misma fila — sin cambio de riesgo, la columna nueva no almacena datos sensibles adicionales.

### Veredicto Gate 3

| Hallazgo | Veredicto | Evidencia clave |
|---|---|---|
| #1 (refresh usable as access) | **CERRADO** | `app/api/deps.py:28`, `app/core/security.py:51-65` |
| #2 (OTP fuerza-bruteable) | **CERRADO** (riesgo residual documentado, aceptado en Gate 1) | `app/api/v1/endpoints/auth.py:33-36, 39-77, 142-232` |
| #4 (SECRET_KEY sin validar) | **CERRADO** | `app/core/config.py:37-50, 65-68` |
| Rate limiter — IP keying tras proxy | **NUEVO — MEDIO** | `app/core/rate_limit.py:65-72` |
| Rate limiter — `rate_limit_hits` sin TTL | **NUEVO — BAJO** | `app/models/rate_limit.py:9-38`, `app/core/rate_limit.py:61` |

**Veredicto OWASP (delta sobre el informe original):** API2:2023 Broken Authentication pasa de **FAIL** a **PASS** en lo que respecta a #1 y #4 (persiste FAIL global por #3, aún no remediado — OBJ-002); API4/API6:2023 (OTP brute force) pasan de **FAIL** a **PASS** por #2. Se abre un nuevo punto bajo A05:2021 Security Misconfiguration (Medio) por el keying de IP del rate limiter sin soporte de proxy — no bloqueante para cerrar OBJ-001, pero debe registrarse como backlog antes de que este template se despliegue detrás de un load balancer real.

**Recomendación:** OBJ-001 puede marcarse cerrado a efectos de los hallazgos #1/#2/#4 del audit original. Los dos hallazgos nuevos del rate limiter no bloquean el gate (no reabren ninguna ruta de account takeover ya cerrada) pero deben quedar trazados en `dependency_graph.md` como items de seguimiento — el de IP-tras-proxy es candidato natural para OBJ-004 (HTTP Security Baseline) dado que ese objetivo ya toca configuración de red/despliegue, y el de purga de `rate_limit_hits` encaja en OBJ-006 (Migrations & Supply Chain Hardening) junto al resto de higiene operativa.
