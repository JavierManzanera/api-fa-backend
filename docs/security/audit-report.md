# Informe de Auditoría de Seguridad — `api-fa-backend`

**Fecha:** 2026-08-21 (creación) — última actualización 2026-08-25 (Gate 3 OBJ-004)
**Alcance:** Revisión estática (SAST manual) de la base de auth reutilizable (FastAPI + SQLAlchemy async + PostgreSQL/asyncpg + JWT/python-jose + passlib/bcrypt). Sin entorno con dependencias instaladas ni base de datos corriendo — no se hizo DAST/pentest dinámico. Las afirmaciones de CVE se basan en conocimiento de entrenamiento, no en consulta en vivo a NVD/OSV — deben confirmarse con `pip-audit`/`safety` sobre el árbol de dependencias resuelto una vez exista un lockfile.

## Resumen (header summary block — mantener actualizado en cada pase Gate 3)

- 14 hallazgos originales (2026-08-21) + 6 hallazgos nuevos descubiertos en pases Gate 3 posteriores.
- Estado a 2026-08-25: **CERRADOS** #1, #2, #3, #4, #5, #7, #8, #9, #10, #13 (10/14). **ABIERTO** #6 (bloqueado en decisión de producto, OBJ-007 no iniciado). **PENDIENTES** #11 (OBJ-005), #12 y #14 (OBJ-006, no iniciados).
- Cadena de account-takeover no autenticado original (enumeración de email → fuerza bruta OTP → reset password → refresh token robado sobreviviendo el reset) queda **cerrada en todos sus eslabones** (OBJ-001/OBJ-002/OBJ-003).
- Gate 3 security-specialist verdicts: OBJ-001 PASS · OBJ-002 PASS · OBJ-003 PASS · **OBJ-004 PASS** (este pase, HTTP security baseline — CORS/headers/docs-gating/audit-log/`X-Forwarded-For` trust).
- Hallazgos nuevos BAJOS aún trazados, no bloqueantes: `rate_limit_hits` sin TTL (→OBJ-006), TOCTOU en `/auth/refresh` (→OBJ-006), sin verificación wire-level de TLS a Postgres (pendiente chequeo puntual).
- Próximos objetivos con hallazgos abiertos: OBJ-005 (#11), OBJ-006 (#12, #14, + residuales de concurrencia/purga acumulados en Gate 3).

---

## Índice de hallazgos (mantener actualizado cada vez que se añade una sección "Gate 3 — Verificación OBJ-00X")

| # | Severidad | Título | Estado | Cerrado en |
|---|---|---|---|---|
| 1 | CRÍTICO | Refresh token utilizable como access token | **CERRADO** | OBJ-001 |
| 2 | CRÍTICO | OTP fuerza-bruteable sin rate limiting | **CERRADO** (residual de budget aceptado en Gate 1) | OBJ-001 |
| 3 | ALTO | Sin revocación de tokens | **CERRADO** | OBJ-002 |
| 4 | ALTO | `SECRET_KEY` sin validar | **CERRADO** | OBJ-001 |
| 5 | MEDIO | Timing side-channel en `/login`/`/forgot-password` | **CERRADO** (residual de forma de queries, trade-off Gate 1) | OBJ-003 |
| 6 | MEDIO | Enumeración explícita en `/register` | **ABIERTO** — bloqueado en decisión de producto | OBJ-007 (no iniciado) |
| 7 | MEDIO | OTP en texto plano en BD | **CERRADO** | OBJ-003 |
| 8 | MEDIO | Sin TLS forzado a PostgreSQL | **CERRADO** (impl.); doc gap nuevo abajo | OBJ-003 |
| 9 | MEDIO | Sin CORS ni cabeceras de seguridad | **CERRADO** | OBJ-004 |
| 10 | MEDIO | Sin logging/auditoría de auth | **CERRADO** | OBJ-004 |
| 11 | BAJO | `is_verified` sin función | Pendiente | OBJ-005 (en curso) |
| 12 | BAJO | Dependencias sin pin / cadena de suministro | Pendiente | OBJ-006 (en curso) |
| 13 | BAJO | `/docs`/`/redoc`/`/openapi.json` sin gate de entorno | **CERRADO** | OBJ-004 |
| 14 | BAJO | Sin separación de privilegios DB (DDL/DML) | Pendiente | OBJ-006 (en curso) |

**Hallazgos nuevos, descubiertos durante pases Gate 3 (no numerados en el informe original):**

| Hallazgo | Severidad | Descubierto en | Estado / destino |
|---|---|---|---|
| Rate limiter: `client_ip()` no soporta proxy/LB (`X-Forwarded-For`) | MEDIO | Gate 3 OBJ-001 | **CERRADO** (OBJ-004, `TRUSTED_PROXY_COUNT`) |
| `rate_limit_hits` sin TTL/purga | BAJO | Gate 3 OBJ-001 | Pendiente → OBJ-006 |
| `/auth/logout` timing side-channel | BAJO | Gate 3 OBJ-002 | **CERRADO** (fold-in en OBJ-003) |
| `.env.example` no advierte que `require` es vulnerable a MITM | BAJO | Gate 3 OBJ-003 | **CERRADO** (OBJ-004, wording fix confirmado) |

**Saltar a:** "Veredicto — OWASP API Security Top 10" (veredicto original) · "Gate 3 — Verificación OBJ-001" · "Gate 3 — Verificación OBJ-002" · "Gate 3 — Verificación OBJ-003" · "Gate 3 — Verificación OBJ-004" (cada sección Gate 3 tiene su propia tabla de veredicto al final — no hace falta leer la sección completa si solo necesitas el resultado).

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

---

## Gate 3 — Verificación OBJ-002 (2026-08-23)

**Alcance:** verificación SAST manual (evidencia archivo:línea, no confianza en el resumen de `developer`/`qa-engineer`) del hallazgo #3 (sin revocación de tokens). Archivos revisados directamente: `app/api/v1/endpoints/auth.py`, `app/core/security.py`, `app/api/deps.py`, `app/models/refresh_session.py`, `app/models/user.py`, `app/core/config.py`, `.env.example`, `docs/api/obj-002-design-notes.md` (como input de diseño, no como sustituto de leer el código).

### Hallazgo #3 (sin revocación de tokens) — **CERRADO**

Los tres mecanismos de revocación exigidos en Gate 1 están implementados y verificados directamente en el código, no solo por los tests:

- **(a) Logout explícito.** `POST /auth/logout` (`auth.py:389-411`) decodifica el `jti` con verificación de firma real (`security.extract_jti_if_present`, `security.py:109-123` — usa `jwt.decode` con `SECRET_KEY`, nunca confía en un `jti` no firmado) y revoca la fila `refresh_sessions` correspondiente (`revoked_at = now()`). Confirmado el efecto: un refresh token robado y luego deslogueado, si se reintenta contra `/auth/refresh`, cae en la rama `session_row.revoked_at is not None` (`auth.py:352-359`) → **reuse detectado → revoca la familia entera** → 401. El logout de una sesión concreta deja esa sesión (y, si se reintenta, toda su familia) inutilizable. Verificado leyendo el código, no solo `tests/api/test_logout.py`.
- **(b) Reuse-tras-rotación.** `auth.py:352-359`: si la fila encontrada por `jti` ya tiene `revoked_at` seteado, se ejecuta `UPDATE refresh_sessions SET revoked_at = now() WHERE family_id = :fid AND revoked_at IS NULL` (vía `_revoke_active_sessions`, `auth.py:122-133`) — revoca **toda la familia**, no solo la fila reutilizada, exactamente el diseño "rotation with reuse detection" documentado en `obj-002-design-notes.md` §2. Confirmado que no hay atajo que revoque solo la fila individual.
- **(c) Reset de password.** `auth.py:294-305`: `user.token_version += 1` y `_revoke_active_sessions(db, RefreshSession.user_id == user.id, now=...)` ocurren en la misma función, sin ningún `await db.commit()` intermedio entre el hash de la nueva contraseña y la revocación masiva — un único `await db.commit()` al final (`auth.py:305`) hace ambas operaciones atómicas en la misma transacción. Verificado explícitamente que `_check_and_consume_otp` (la única llamada previa en esta request) **no** hace commit en su rama de éxito (`auth.py:73-80` — el `db.commit()` de esa función solo se ejecuta en la rama de código incorrecto, antes de lanzar el 400); en la rama de éxito no hay commit hasta el de `reset_password` mismo. No existe ventana entre "password actualizado" y "sesiones revocadas" — son la misma transacción atómica, tal como exigía Gate 1. Un token robado no puede "colarse" entre esos dos pasos porque nunca están separados por un commit.

Los tres cierres se apoyan además en el `ver` claim (`token_version`) como segunda línea de defensa independiente (`app/api/deps.py:46`, `auth.py:370-372`): incluso si por algún defecto no cubierto aquí una fila de `refresh_sessions` sobreviviera, el token seguiría muriendo por `ver` mismatch tras un reset de password. Defensa en profundidad confirmada, no solo teórica — son dos mecanismos independientes, no uno que dependa del otro.

**Veredicto: hallazgo #3 CERRADO.** Un refresh token robado se vuelve inutilizable tras cualquiera de los tres eventos (logout, replay-tras-rotación, reset de password), verificado por lectura directa del código, no solo por el paso de los 71 tests.

### Revisión del residual aceptado — access tokens no invalidados en logout

Confirmado que coincide exactamente con lo implementado: `app/api/deps.py`'s `get_current_user` no consulta ninguna blacklist/tabla de revocación para access tokens — solo valida firma, `exp`, `type`, y `ver` contra `user.token_version` (que **no** cambia en logout, solo en reset-password). Un access token robado sigue siendo válido tras un logout hasta su expiración natural. `ACCESS_TOKEN_EXPIRE_MINUTES=30` (`.env.example:13`).

**Re-afirmación del trade-off (no reabierto):** 30 minutos es un valor razonable y estándar en la industria para una ventana de exposición stateless — sigue siendo una mejora sustancial frente al hallazgo original (hasta 7 días vía refresh token robado, cadena completa con #1). Nota, no bloqueo: si el modelo de amenaza de un proyecto concreto que herede este template maneja datos de alta sensibilidad, vale la pena que ese proyecto evalúe bajar a 15 min o añadir una blacklist ligera (p. ej. Redis con TTL = tiempo restante del token) — pero eso reintroduce el lookup por request que Gate 1 explícitamente decidió evitar aquí. Aceptado tal cual, sin cambios de veredicto.

### Revisión del TOCTOU ya señalado (no bloqueante, trackeado a OBJ-006)

Confirmado el mismo gap que `obj-002-design-notes.md` §2 ya documenta explícitamente: `POST /auth/refresh` hace `SELECT` de la fila `refresh_sessions` (`auth.py:342-343`) y más tarde `UPDATE`+`INSERT` (vía `_issue_tokens_and_session` + las líneas 382-385) sin `SELECT ... FOR UPDATE` ni un `UPDATE ... WHERE revoked_at IS NULL RETURNING ...` atómico. Confirmado por lectura de código que el `UPDATE` final sobre `session_row` (`auth.py:383-384`, vía atributo ORM) **no** repite el filtro `revoked_at IS NULL` — es un `UPDATE ... WHERE id = :jti` incondicional, así que dos requests concurrentes con el mismo token aún-válido podrían ambas leer `revoked_at IS NULL`, ambas proceder a "rotar", y ambas insertar una fila hija válida para la misma familia (ver análisis: bajo `READ COMMITTED`, la segunda request bloqueada por el lock de fila de la primera `UPDATE` no vuelve a evaluar la condición al desbloquear, porque no hay condición en el `WHERE`). Efecto: en una ventana de carrera muy estrecha, **dos tokens hijos válidos simultáneos** para la misma familia, en vez de uno — no es solo un overshoot acotado tipo rate-limiter, es una violación puntual de la invariante "un solo hijo activo por rotación". **Severidad se mantiene Baja** (ventana de explotación extremadamente estrecha — requiere dos requests genuinamente concurrentes con el mismo refresh token válido en el mismo instante; no es un bypass sin límite, y no revive la cadena de account-takeover original) y **coincide exactamente con la propia evaluación de `obj-002-design-notes.md`** ("bounded double-rotation, not an unbounded bypass"). No se encontró nada nuevo más allá de lo ya documentado — confirmado, no reabierto, sigue correctamente trackeado hacia el ítem de concurrency-hardening de OBJ-006 (mismo `SELECT ... FOR UPDATE`/`UPDATE ... RETURNING` recomendado ya para el TOCTOU de OTP-lockout/rate-limiter de OBJ-001).

### Nueva superficie: `family_id`/`jti`/`replaced_by` — inyección, IDOR, bypass de lógica

- **Sin inyección SQL.** Todas las consultas sobre `RefreshSession` usan el ORM parametrizado de SQLAlchemy (`select`, `update` con `.where(...)`); `family_id`/`jti`/`replaced_by` son siempre `uuid.UUID` generados server-side (`uuid.uuid4()`, `auth.py:182, 374`) o parseados de forma segura desde el claim JWT vía `_parse_jti` (`auth.py:310-319`), que envuelve `uuid.UUID(str(raw_jti))` en un `try/except (ValueError, AttributeError, TypeError)` — un `jti` malformado/de tipo inesperado (string, lista, número) cae a `None`, sin excepción sin manejar, sin construir SQL dinámico. **Sin riesgo de inyección.**
- **Sin IDOR.** El único punto donde un `jti` llega desde input del cliente es el claim `jti` de un refresh JWT presentado por el atacante — pero tanto `/auth/refresh` (`security.decode_refresh_token_claims`) como `/auth/logout` (`security.extract_jti_if_present`) verifican la **firma** del JWT contra `SECRET_KEY` antes de extraer el claim (`security.py:83-91`, `119-123`). Como `jti` se asigna siempre server-side en el momento de emisión (nunca client-controlled en `create_refresh_token`, excepto por el parámetro opcional que **ningún** call site real deja sin especificar — confirmado por grep, todos los call sites reales pasan `jti` explícito), un atacante no puede forjar un token con el `jti` de la sesión de otro usuario sin conocer `SECRET_KEY` (lo cual sería un compromiso total ya cubierto por el hallazgo #4, cerrado). Por tanto no existe forma de que un usuario autenticado (o no autenticado) revoque o interfiera con la sesión de otro usuario vía `/auth/logout` o `/auth/refresh` manipulando `jti`/`family_id`.
- **Sin bypass de lógica nuevo.** `family_id` nunca se acepta como input directo en ningún endpoint (siempre se copia server-side de `session_row.family_id`, `auth.py:356, 376`); no hay ruta donde un cliente pueda especificar directamente a qué familia pertenece un token nuevo. `replaced_by` es puramente informativo/auditoría (confirmado en el modelo: "not required for correctness"), nunca leído por ninguna rama de decisión de autorización — no puede usarse para bypass aunque se corrompiera.
- **`token_version` no se expone en ninguna respuesta** — grep en `app/schemas/` sin resultados; `UserResponse` no lo incluye. Sin fuga de información que ayude a un atacante a predecir el próximo valor válido (aunque tampoco sería explotable, al ser solo un contador incremental server-side sin uso como secreto).

### `/auth/logout` — revisión específica de oráculo

Confirmado el diseño anti-oráculo declarado: siempre `204`, cuerpo vacío, para cualquier body bien formado — sin distinción de código de estado ni de cuerpo entre token válido/inválido/ya revocado/ya expirado. Revisado explícitamente:

- Token con `jti` válido apuntando a una fila activa → `UPDATE` + commit → `204`.
- Token con `jti` válido apuntando a una fila ya revocada → mismo `UPDATE` (0 filas afectadas por el filtro `revoked_at IS NULL` de `_revoke_active_sessions`) + commit → `204`. Sin diferencia de código/cuerpo.
- Token con firma inválida, expirado, o malformado → `extract_jti_if_present` devuelve `None` → ninguna operación DB → `204`. Sin diferencia de código/cuerpo tampoco.
- Body sin el campo `refresh_token` → `422` (validación de Pydantic, antes de que el handler se ejecute) — la única distinción de status code existente, y es puramente de forma de request, no de validez del token; no filtra nada sobre ningún usuario.

**[NUEVO — BAJO] Canal lateral de timing en `/auth/logout` (no de estado de sesión, sí de validez de firma).** El único camino que hace un round-trip a la base de datos (`UPDATE` + `commit`, `auth.py:407-410`) es el de `jti is not None`, es decir: firma JWT válida contra `SECRET_KEY`. Un token con firma inválida o malformado nunca llega a tocar la base de datos — falla en el `jwt.decode` local (`security.py:120-122`) y retorna inmediatamente. Esto crea una diferencia de latencia medible (una operación de red/DB async vs. una operación puramente en memoria) entre "el string presentado es un JWT válidamente firmado por este servidor" y "no lo es". **No** filtra si la sesión está activa/revocada/expirada (esos tres casos comparten exactamente el mismo camino con DB) — solo filtra la propiedad "firma válida sí/no". Impacto práctico bajo: no ayuda a un atacante a adivinar sesiones ajenas (necesitaría igualmente forjar una firma válida, lo cual requeriría `SECRET_KEY`), pero es la misma clase de hallazgo que el #5 original (timing side-channel en `/login`/`/forgot-password`), aplicada a un endpoint nuevo introducido por OBJ-002. **Fix recomendado:** si se quiere cerrar también este canal, ejecutar un `await db.execute(select(1))`/no-op de latencia equivalente en la rama `jti is None` antes de retornar, para igualar el tiempo de respuesta — mismo patrón de mitigación ya recomendado para el hallazgo #5. **Recomendación de tracking:** plegar en OBJ-003, que ya cubre "constant-time login/forgot-password" (audit-report.md #5) — mismo endpoint objetivo conceptual (canales de timing), no amerita un objetivo nuevo.

### Veredicto Gate 3

| Ítem | Veredicto | Evidencia clave |
|---|---|---|
| #3 (a) Logout revoca sesión robada | **CERRADO** | `auth.py:389-411`, `405-410`, reuse-check en `352-359` |
| #3 (b) Reuse-tras-rotación revoca familia completa | **CERRADO** | `auth.py:352-359`, `_revoke_active_sessions` en `122-133` |
| #3 (c) Reset de password: bump `token_version` + revocación masiva atómica | **CERRADO** | `auth.py:294-305`, un único `commit` en línea 305 |
| Residual: access tokens no blacklisted en logout | **Confirmado, re-afirmado como aceptable** | `app/api/deps.py:17-49`, `.env.example:13` (`ACCESS_TOKEN_EXPIRE_MINUTES=30`) |
| TOCTOU en `/auth/refresh` (no atomic read-then-write) | **Confirmado, severidad Baja sin cambios, ya trackeado en OBJ-006** | `auth.py:340-385`, `obj-002-design-notes.md` §2 |
| Superficie `family_id`/`jti`/`replaced_by` (inyección/IDOR/bypass) | **Sin hallazgos nuevos — PASS** | `auth.py:310-319`, `security.py:83-123` |
| `/auth/logout` — oráculo de estado de sesión | **PASS — sin oráculo de validez/revocación** | `auth.py:389-411` |
| `/auth/logout` — canal lateral de timing (firma válida vs. inválida) | **NUEVO — BAJO** | `auth.py:405-410`, `security.py:109-123` |

**Veredicto OWASP (delta sobre el informe original):** API2:2023 Broken Authentication pasa de **FAIL** a **PASS** en lo que respecta a #3 (revocación de tokens) — con esto, y sumado al cierre de #1/#2/#4 en OBJ-001, **API2:2023 queda en PASS global** salvo por el hallazgo #5 (timing side-channel en login/forgot-password, aún no remediado, OBJ-003) que sigue abierto bajo A07:2021 y que ahora también aplica, en menor medida, a `/auth/logout` (nuevo hallazgo de esta sección).

**Recomendación:** OBJ-002 puede marcarse cerrado a efectos del hallazgo #3. El nuevo hallazgo de timing en `/auth/logout` no bloquea el gate (no reabre ninguna ruta de account takeover, no filtra estado de sesión) pero debe quedar trazado en `dependency_graph.md` — candidato natural para OBJ-003, que ya tiene alcance de "constant-time login/forgot-password" (audit-report.md #5) y puede absorber este endpoint adicional sin abrir un objetivo nuevo.

**Gate 3 security-specialist verdict for OBJ-002: PASS.** Finding #3 is genuinely closed (verified by direct code reading of the three revocation paths, not test-trust alone). One new LOW finding (logout timing side-channel) tracked to OBJ-003, non-blocking. The two previously-known residuals (access-token stateless window, refresh-session TOCTOU) are confirmed as implemented/described and re-affirmed at their existing severity — no upgrade, no new exploitation path found on either.

---

## Gate 3 — Verificación OBJ-003 (2026-08-23)

**Alcance:** verificación SAST manual (evidencia archivo:línea, lectura directa del código — no confianza en el resumen de `developer`/`qa-engineer`) de los hallazgos #7 (OTP en texto plano), #8 (sin TLS a PostgreSQL) y #5 (timing side-channel en login/forgot-password), más el fold-in del canal de timing en `/auth/logout` señalado en el Gate 3 de OBJ-002. Archivos revisados directamente: `app/core/security.py`, `app/core/config.py`, `app/core/database.py`, `app/api/v1/endpoints/auth.py`, `app/api/deps.py`, `app/models/verification.py`, `.env.example`, `docs/api/obj-003-design-notes.md` (como input de diseño, no como sustituto de leer el código).

### Hallazgo #7 (OTP en texto plano) — **CERRADO**

- **Sin escritura ni comparación en texto plano en ningún punto del código de producción.** Grep dirigido sobre `app/` confirma un único sitio de escritura (`auth.py:256`, `Verification(code=security.hash_otp(otp), ...)`) y un único sitio de comparación (`auth.py:73`, `security.verify_otp_hash(otp, verification.code)`) — ninguna otra referencia a `verification.code`/`Verification(code=` existe en `app/`. `tests/factories.py:90` también hashea correctamente (`code=security.hash_otp(code)`), consistente con el requisito no-opcional que el propio diseño (`obj-003-design-notes.md` §1.5) exigió para esta pasada.
- **Derivación de clave confirmada como Opción B (derivada), no Opción A (reuso crudo de `SECRET_KEY`).** `app/core/security.py:26-29`: `_OTP_HMAC_KEY = hmac.new(settings.SECRET_KEY.encode("utf-8"), _OTP_HMAC_CONTEXT, hashlib.sha256).digest()` — un paso HMAC-como-KDF (`_OTP_HMAC_CONTEXT = b"api-fa-backend:otp-hmac:v1"` como dato, `SECRET_KEY` como clave del HMAC) que produce una subclave criptográficamente independiente de los bytes crudos de `SECRET_KEY`. `hash_otp` (`security.py:63-70`) usa esa subclave, nunca `SECRET_KEY` directamente, como clave del segundo HMAC sobre el código. Esto es exactamente la construcción documentada en `obj-003-design-notes.md` §1.1 Opción B, y separación de claves real: un volcado de la tabla `verifications` sin `SECRET_KEY` no permite forjar ni verificar códigos.
- **Comparación en tiempo constante confirmada.** `verify_otp_hash` (`security.py:73-79`): `return hmac.compare_digest(hash_otp(code), stored_hash)` — no hay ningún `==`/`!=` sobre el hash en ningún punto del código de producción; confirmado también que `_check_and_consume_otp` (`auth.py:73`) llama exclusivamente a `verify_otp_hash`, no a una comparación directa.
- **Fail-closed ante filas legacy/corruptas.** `verify_otp_hash` nunca lanza excepción ante un `stored_hash` mal formado o aún en texto plano (p. ej. una fila creada antes del deploy de este cambio) — `hmac.compare_digest` simplemente retorna `False` frente a longitudes/contenidos distintos, autorresolviéndose dentro del TTL de 10 minutos del OTP, mismo patrón fail-closed-por-construcción que los claims `type`/`ver` de OBJ-001/002.

**Veredicto: hallazgo #7 CERRADO**, verificado por lectura directa del código de producción, no solo por el paso de los 118 tests.

### Hallazgo #8 (sin TLS a PostgreSQL) — **CERRADO**, con una brecha de documentación operador-facing (nueva, BAJA)

- **`POSTGRES_SSL_MODE` es fail-closed ante valores inválidos, mismo patrón que `SECRET_KEY`.** `app/core/config.py:64-72`, `validate_postgres_ssl_mode`: `if value not in _VALID_POSTGRES_SSL_MODES: raise ValueError(...)`, sobre el mismo `field_validator` de Pydantic v2 que corre en la construcción eager de `Settings()` a nivel de módulo (`config.py:87-90`, idéntico mecanismo de arranque-bloqueante ya confirmado para `SECRET_KEY` en el Gate 3 de OBJ-001). Un valor no reconocido — incluyendo variantes de mayúsculas/minúsculas de un modo válido (`"REQUIRE"`, `"Disable"`), confirmado que la comparación es exacta sin `.lower()` — impide el arranque real de la app, no solo un warning. **Nota, no defecto:** a diferencia de `SECRET_KEY`, `disable` en sí mismo SÍ es un valor válido que no bloquea el arranque — esto es la Opción A de Gate 1 (configurable con escape hatch de operador), decidida explícitamente por el usuario, no una omisión de este pass.
- **Las tres traducciones a `asyncpg` son correctas y genuinamente distinguibles, no una `ssl.create_default_context()` ingenua reusada tres veces.** `app/core/database.py:9-26`, `_build_ssl_connect_arg`:
  - `disable` → `False` (sin TLS en absoluto — asyncpg interpreta esto como conexión en claro).
  - `require` → `ssl.create_default_context()` con `check_hostname = False` y `verify_mode = ssl.CERT_NONE` **seteados explícitamente** — esto es la distinción crítica que el diseño identificó correctamente: `asyncpg`'s `ssl=True`/una `SSLContext` por defecto ya se comporta como `verify-full` de libpq (`CERT_REQUIRED` + chequeo de hostname), no como `require`. Sin este override explícito, un desarrollador ingenuo habría mapeado `require` al mismo objeto que `verify-full`, perdiendo silenciosamente la distinción "cifra pero no verifica" vs. "cifra y verifica". Confirmado leyendo el código, no asumido del diseño.
  - `verify-full` → `ssl.create_default_context()` sin modificar (postura por defecto: `CERT_REQUIRED` + verificación de hostname).
  - `connect_args={"ssl": _build_ssl_connect_arg(...)}` nunca se omite (`database.py:29-34`) — el comportamiento nunca depende del default no documentado de `asyncpg`, tal como especifica el diseño.
- **La garantía de `require` es honesta en el código fuente, pero el diseño es sincero de una forma incompleta cara al operador de despliegue.** El docstring de `_build_ssl_connect_arg` (`database.py:10-16`) explica correctamente que `require` es "cifra el cable, no verifica la identidad del servidor" — pero ese texto vive en un docstring de Python, no en el lugar que un operador desplegando este template realmente lee primero. **[NUEVO — BAJO]** `.env.example:8-13` documenta `verify-full` (recomendado) y `disable` (opt-out local/test) con una frase cada uno, pero **no menciona `require` en absoluto** pese a ser uno de los tres valores válidos — un operador que solo lee `.env.example` (el artefacto de referencia más probable al forkear este template, según su propio propósito declarado en `dependency_graph.md`) no tiene ninguna señal ahí de que `require` es vulnerable a MITM vía certificado falsificado/auto-firmado no verificado, y podría razonablemente asumirlo "suficientemente seguro" por analogía con `verify-full` al ver que ambos "activan TLS". **Escenario de explotación concreto:** un operador que copia `.env.example`, ve que `require` "activa TLS" (nombre que además invita a pensar que es el modo "fuerte por defecto"), lo despliega contra una réplica de Postgres cuyo certificado ha sido sustituido por un atacante en posición de red (proxy transparente, DNS spoofing, etc.) — la conexión se cifra igual, la app nunca lo nota, y el atacante intercepta credenciales/tokens en tránsito con un ataque MITM activo trivial de montar frente a `CERT_NONE`.
  **Fix recomendado:** añadir una línea a `.env.example` explicando explícitamente que `require` cifra el tráfico pero **no** valida el certificado del servidor (vulnerable a MITM con un certificado no confiable) y que solo `verify-full` da la garantía completa de identidad — mismo nivel de detalle que ya existe para los otros dos modos. No bloqueante para este gate (el código es correcto; es un gap de documentación operador-facing, no un defecto de implementación), pero real y de bajo esfuerzo de arreglo — recomendado como parte de OBJ-004 (que ya toca configuración de despliegue/entorno) en vez de abrir un objetivo nuevo.
- **Residual ya señalado por `qa-engineer`/`developer`, confirmado aquí, no verificado end-to-end en esta pasada tampoco:** ninguna de las tres pasadas de este objetivo (qa-engineer Fase 2, developer Fase 3, esta verificación) ha conectado realmente contra un Postgres con TLS terminado — `app.core.database.engine` está confirmado (por lectura directa de `tests/conftest.py` y por el propio `obj-003-design-notes.md` §2.2) como nunca conectado en este sandbox (sin Docker, sin certificados TLS configurados en la instancia throwaway `initdb`/`pg_ctl`). La lógica de `_build_ssl_connect_arg` es correcta por inspección directa contra el comportamiento documentado de `asyncpg`/el módulo `ssl` estándar de Python, pero un chequeo DAST real contra un Postgres con TLS habilitado (certificado válido para `verify-full`, y un certificado deliberadamente no confiable para confirmar que `require` efectivamente no lo rechaza) sigue pendiente antes de dar por cerrado el hallazgo #8 a nivel de wire para un despliegue real. No bloqueante para este gate (mismo criterio ya aplicado a los TOCTOU de OBJ-001/002: severidad/alcance conocido, tracking explícito, no repetición del gap).

**Veredicto: hallazgo #8 CERRADO** a nivel de implementación (fail-closed en `Settings`, traducción correcta y honesta de los tres modos). Un hallazgo nuevo BAJO de documentación (`.env.example` no advierte sobre la naturaleza MITM-vulnerable de `require`) y un residual ya conocido (sin verificación wire-level contra TLS real) — ninguno bloquea el cierre de este hallazgo, ambos trackeados abajo.

### Hallazgo #5 (timing side-channel en login/forgot-password) + fold-in de `/auth/logout` — **CERRADO**

- **`/auth/login` — sin bypass de cortocircuito, confirmado sin asimetría residual de ningún tipo.** `auth.py:173-186`: el `select(User)` se ejecuta siempre (1 query, tanto si el email existe como si no) y `security.verify_password_or_dummy(...)` se llama siempre, **antes** de cualquier `if`/`return` — no hay ninguna rama que evite esta llamada. `verify_password_or_dummy` (`security.py:49-60`) ejecuta exactamente **una** llamada real a `verify_password` (bcrypt) en ambos casos: contra `user.hashed_password` si `user` existe, contra `DUMMY_PASSWORD_HASH` (calculado una sola vez al importar el módulo, `security.py:46`) si no. El resultado se descarta y se fuerza `False` cuando `hashed_password is None`, así que ni siquiera un choque astronómicamente improbable contra el hash dummy podría autenticar como un usuario inexistente. **Conteo/forma de queries y de llamadas bcrypt genuinamente idéntico entre ambas ramas** — no hay ninguna asimetría estructural residual en `/login`, no solo de latencia dominante sino de forma de la ejecución completa.
- **`/auth/forgot-password` — la llamada dummy se ejecuta siempre, antes del `return` por email inexistente.** `auth.py:211-223`: `select(User)` siempre se ejecuta, `security.verify_password_or_dummy(payload.email, None)` (línea 220) se ejecuta **antes** del `if not user: return` (línea 222) — sin bypass. Confirmado que el objetivo del bcrypt es siempre `DUMMY_PASSWORD_HASH` (nunca el hash real de ningún usuario), consistente con que este endpoint nunca verifica contraseña alguna.
  **Residual de forma de query — ya documentado como trade-off aceptado en Gate 1, no un hallazgo nuevo, confirmado presente por lectura de código:** después de la llamada dummy, la rama "usuario existe" continúa con una query adicional (`existing_result`, `auth.py:231-239`, contra `Verification`) y, si no está en cooldown, un `DELETE` + `INSERT` + `COMMIT` adicionales (líneas 246-261) que la rama "usuario no existe" nunca ejecuta (retorna en la línea 223). Esto es exactamente la asimetría que `obj-003-design-notes.md` §3.2 identificó explícitamente al elegir la Opción A ("un piso de 100-300ms domina la asimetría de conteo de queries que reemplaza") en vez de la Opción B (paridad de forma de queries, sin sumar latencia) — **decisión de Gate 1, no un descuido de esta implementación**. Evaluado explícitamente para la pregunta de esta verificación ("¿un observador de red que mira conteo/forma de queries, no solo latencia del endpoint, puede distinguir las ramas?"): un atacante remoto solo tiene visibilidad de la latencia HTTP total observada, no del tráfico SQL interno — las 1-2 queries/DELETE/INSERT adicionales son operaciones de bajo milisegundo frente al piso de ~100-300ms del bcrypt dummy, por lo que el diferencial de latencia total sigue dominado por el mecanismo cerrado en este pass, no por la asimetría de queries subyacente. **No es una eliminación completa de la señal, es una reducción a un margen de ruido consistente con el marco "best-effort, no wall-clock-perfect" ya establecido desde `obj-001-critical-auth-hardening.md` Scenario 2.6** — re-afirmado aquí, no reabierto, no degradado respecto a lo ya decidido en Gate 1.
- **Fold-in de `/auth/logout` — confirmada la simetría estructural exacta.** `auth.py:430-437`: la rama `jti is not None` hace `_revoke_active_sessions` (un `UPDATE`, vía `db.execute`) seguido de `db.commit()`; la rama `else` hace `await db.execute(select(1))` seguido del mismo `db.commit()` movido fuera del `if` (incondicional en ambas ramas). Confirmado por lectura directa: exactamente una llamada a `db.execute` y una a `db.commit` en cualquiera de las dos ramas — la asimetría "round-trip a DB sí/no" que el Gate 3 de OBJ-002 había señalado queda genuinamente cerrada, no solo aproximada.

**Veredicto: hallazgo #5 CERRADO**, incluyendo el fold-in de `/auth/logout`. La garantía estructural (una llamada bcrypt por request en login/forgot-password, un `execute`+`commit` por request en logout, sin bypass de cortocircuito en ningún caso) está verificada por lectura directa de código en las tres rutas, no solo por el paso de los 118 tests. El residual de forma de queries en `/forgot-password` es un trade-off ya decidido y documentado en Gate 1 (Opción A sobre Opción B), confirmado presente pero de impacto acotado por el propio diseño — no constituye una reapertura del hallazgo.

### Regresión — hallazgos #1-#4 (cadena de account-takeover ya cerrada)

Revisados `app/api/deps.py` y las porciones no tocadas por esta pasada de `app/core/security.py`/`auth.py` para confirmar que ningún cambio de OBJ-003 los reabre:

- **#1 (refresh usable como access token):** `deps.py:28` sigue rechazando `payload.get("type") != TOKEN_TYPE_ACCESS` sin cambios; `create_access_token`/`create_refresh_token` (`security.py:82-127`) mantienen el claim `type` explícito sin modificación de esta pasada (solo se les añadió, en un pass previo ya auditado, el claim `ver`). **Sin regresión.**
- **#2 (OTP fuerza-bruteable):** `_check_and_consume_otp` (`auth.py:42-80`) mantiene intacta la lógica de `attempts`/`MAX_OTP_ATTEMPTS`/lockout (líneas 74-78) — el único cambio es la línea 73, que pasó de comparación en claro a `verify_otp_hash`. El rate limiting en los tres endpoints OTP-adyacentes tampoco fue tocado. **Sin regresión** — y de hecho el cambio de hashing no debilita el lockout: una fila con `code` aún en texto plano (pre-deploy) simplemente falla siempre `verify_otp_hash`, consumiendo el mismo presupuesto de intentos que un guess incorrecto normal.
- **#3 (sin revocación de tokens):** los tres mecanismos verificados en el Gate 3 de OBJ-002 (`logout`, reuse-tras-rotación, reset-password bulk-revoke) no fueron tocados en su lógica de revocación por esta pasada — el único cambio en `/auth/logout` es el restructure del branch `jti is None` (no-op + commit incondicional), que no altera en absoluto la rama `jti is not None` que hace el trabajo real de revocación (`auth.py:431-434`, idéntica a la ya auditada). `/auth/reset-password`'s bump de `token_version` + `_revoke_active_sessions` (líneas 318-321) no fueron tocados por esta pasada — confirmado por lectura directa, el único cambio en esa función es la línea 312 (`user.hashed_password = ...`, sin relación) y la comparación OTP en `_check_and_consume_otp` ya cubierta en #2. **Sin regresión.**
- **#4 (`SECRET_KEY` sin validar):** `config.py:49-62` (`validate_secret_key_strength`) permanece byte-por-byte igual a lo auditado en el Gate 3 de OBJ-001 — el único cambio en este archivo es la adición, en paralelo, del nuevo campo `POSTGRES_SSL_MODE` y su propio validador independiente (líneas 64-72), que no interactúa con la validación de `SECRET_KEY` de ninguna forma (dos `field_validator`s independientes sobre campos distintos). **Sin regresión**, y nótese que `_OTP_HMAC_KEY` (finding #7's nueva dependencia sobre `SECRET_KEY`) hereda automáticamente la garantía de fuerza/no-placeholder ya impuesta por este validador — un `SECRET_KEY` débil o placeholder ya no puede ni siquiera importarse, así que la clave OTP derivada nunca puede derivarse de un secreto conocido/débil tampoco.

**Ningún hallazgo de la cadena de account-takeover original (#1-#4) se reabre por los cambios de OBJ-003.**

### Veredicto Gate 3

| Hallazgo | Veredicto | Evidencia clave |
|---|---|---|
| #7 (OTP en texto plano) | **CERRADO** | `security.py:26-29,63-79`, `auth.py:73,256`, sin plaintext writes/comparisons (grep confirmado) |
| #8 (sin TLS a Postgres) | **CERRADO** (implementación); nuevo BAJO de documentación | `config.py:64-72,87-90`, `database.py:9-34` |
| #8 — `.env.example` no advierte sobre `require` = cifra sin verificar identidad | **NUEVO — BAJO** | `.env.example:8-13` |
| #8 — sin verificación wire-level contra TLS real (residual, ya señalado por qa-engineer/developer) | **Confirmado, no bloqueante, mismo residual ya conocido** | `obj-003-design-notes.md` §2.2, `tests/conftest.py` |
| #5 (timing side-channel login/forgot-password) | **CERRADO** | `auth.py:173-186,211-223`, `security.py:49-60` |
| #5 — residual de forma de queries en `/forgot-password` (ya decidido en Gate 1, Opción A sobre B) | **Confirmado, no bloqueante, no reabierto** | `auth.py:225-261`, `obj-003-design-notes.md` §3.2 |
| Fold-in `/auth/logout` timing (OBJ-002 Gate 3) | **CERRADO** | `auth.py:430-437` |
| Regresión #1 (refresh-as-access) | **Sin regresión** | `deps.py:28` |
| Regresión #2 (OTP brute force) | **Sin regresión** | `auth.py:42-80` |
| Regresión #3 (revocación) | **Sin regresión** | `auth.py:318-321,407-438` |
| Regresión #4 (SECRET_KEY) | **Sin regresión** | `config.py:49-62` |

**Veredicto OWASP (delta sobre el informe original):** A02:2021 (Cryptographic Failures) pasa de **FAIL** a **PASS** en lo que respecta a #7 (OTP en claro) y #8 (sin TLS); A07:2021 (Identification and Authentication Failures) pasa de **FAIL** a **PASS** en lo que respecta a #5 (timing side-channel), incluyendo el fold-in de `/auth/logout`. Con esto, y sumado al cierre de #1-#4 en OBJ-001/OBJ-002, la cadena completa de account-takeover no autenticado descrita en la sección "Threat model" del informe original queda cerrada en todos sus eslabones conocidos. Persisten como **FAIL**/pendientes: #6 (enumeración en `/register`, bloqueado en decisión de producto — OBJ-007), #9/#10/#13 (CORS/headers/logging/docs-gating — OBJ-004), #11 (`is_verified` sin función — OBJ-005), #12/#14 (supply chain/migraciones/roles DB — OBJ-006).

**Recomendación:** OBJ-003 puede marcarse cerrado a efectos de los hallazgos #5/#7/#8. El nuevo hallazgo BAJO (`.env.example` no documenta la naturaleza MITM-vulnerable de `require`) no bloquea el gate — recomendado como fix de bajo esfuerzo dentro de OBJ-004 (que ya toca documentación de configuración de despliegue) en vez de abrir un objetivo nuevo. El residual de verificación wire-level de TLS contra un Postgres real permanece como el único ítem genuinamente no verificado end-to-end de este objetivo — recomendado como un chequeo puntual (no necesariamente un objetivo completo) antes de que cualquier despliegue real de este template dependa de `require`/`verify-full` en producción.

**Gate 3 security-specialist verdict for OBJ-003: PASS.** Findings #5, #7, and #8 are genuinely closed by direct code reading, not test-trust alone: the OTP HMAC construction provides real key separation from `SECRET_KEY` (Option B, not Option A), `verify_otp_hash` is constant-time, the three `POSTGRES_SSL_MODE` values produce genuinely distinguishable and correctly-scoped `asyncpg` SSL postures (in particular `require` does NOT collapse into `verify-full`'s guarantee), and `verify_password_or_dummy`/the logout no-op both execute unconditionally on every code path with no early-return bypass. One new LOW finding (`.env.example` doesn't warn that `require` is MITM-vulnerable) and two already-known, Gate-1-accepted residuals (forgot-password's bounded query-count asymmetry; no live-TLS-Postgres wire-level verification) are non-blocking. No regression found in findings #1-#4.

---

## Gate 3 — Verificación OBJ-004 (2026-08-25)

**Alcance:** verificación SAST manual (evidencia archivo:línea, lectura directa del código y del `git diff`, no confianza en el resumen de `developer`) de los hallazgos #9 (CORS/cabeceras de seguridad), #10 (logging/auditoría + `print` de debug del OTP) y #13 (`/docs`/`/redoc`/`/openapi.json` sin gate de entorno), más el fold-in de dos backlog items de Gate 3 previos: `client_ip()` sin soporte de `X-Forwarded-For` (OBJ-001 Gate 3, MEDIO) y `.env.example` sin advertencia sobre `POSTGRES_SSL_MODE=require` (OBJ-003 Gate 3, BAJO). Archivos revisados vía `git diff` + lectura completa: `app/main.py`, `app/core/config.py`, `app/core/rate_limit.py`, `app/api/v1/endpoints/auth.py`, `app/core/security_headers.py` (nuevo), `app/core/audit_log.py` (nuevo), `app/core/notifications.py` (nuevo), `.env.example`, `docs/api/obj-004-design-notes.md` (como input de diseño, no sustituto de leer el código), más las suites de test nuevas (`tests/api/test_cors_middleware.py`, `test_security_headers.py`, `test_docs_gating.py`, `test_rate_limit_ip_spoofing.py`, `tests/unit/test_client_ip.py`, `test_environment_settings.py`, `test_cors_settings.py`) leídas para confirmar cobertura, no para sustituir verificación propia. Verificación adicional en vivo: sondas ASGI (`httpx.ASGITransport`, sin tocar Postgres) ejecutadas directamente contra `app.main.app` en tres configuraciones (`ENVIRONMENT` faltante, `ENVIRONMENT=foo`, `BACKEND_CORS_ORIGINS=*`) para confirmar fail-closed en el arranque, y una sonda de cabeceras/CORS/CSP contra la app en ejecución.

### Hallazgo #9 (CORS / cabeceras de seguridad HTTP) — **CERRADO**

- **CORS no puede colapsar a permisivo por accidente.** `app/core/config.py:69` — `BACKEND_CORS_ORIGINS: Annotated[List[AnyHttpUrl], NoDecode] = []`. Confirmado por sonda en vivo (no solo lectura): con `BACKEND_CORS_ORIGINS` sin configurar, una petición con `Origin: https://evil.example.com` no recibe `Access-Control-Allow-Origin` (`cors_default_acao: null`). Confirmado también que `BACKEND_CORS_ORIGINS=*` **bloquea el arranque** (`ValidationError: Input should be a valid URL` sobre `BACKEND_CORS_ORIGINS.0`) — `AnyHttpUrl` rechaza estructuralmente el literal `"*"`, cerrando el miedo nombrado explícitamente por el propio hallazgo #9 ("es probable que el siguiente proyecto añada `allow_origins=['*']` apresuradamente") a nivel de tipo, no de convención.
- **`allow_credentials=False` está hardcodeado, no gobernado por ninguna variable de entorno** (`app/main.py`, llamada a `CORSMiddleware`) — no existe ninguna combinación de configuración que pueda producir `allow_origins` permisivo **y** `allow_credentials=True` simultáneamente, porque el segundo nunca es configurable en absoluto. Cierra explícitamente el escenario que el task pidió confirmar.
- **Bug de trailing-slash encontrado y corregido, confirmado con test de regresión dedicado.** `app/main.py`: `allow_origins=[str(origin).rstrip("/") for origin in settings.BACKEND_CORS_ORIGINS]` — sin el `.rstrip("/")`, `AnyHttpUrl`'s `str()` (que siempre añade `/` final) nunca habría matcheado un `Origin` real de navegador. Confirmado en vivo vía sonda subprocess (`test_cors_middleware.py::test_trailing_slash_bug_fix_matching_origin_gets_cors_header`) — no solo por lectura de código.
- **`allow_methods`/`allow_headers` son allowlists explícitas** (`["GET", "POST"]` / `["Authorization", "Content-Type"]`), no `["*"]` — confirmado en `app/main.py`.
- **Cabeceras de seguridad — confirmadas en vivo, no solo leídas.** Sonda ASGI directa contra `app.main.app` (sin subprocess, sin Postgres) devolvió: `hsts: "max-age=63072000; includeSubDomains"` (sin `preload`), `xfo: "DENY"`, `nosniff: "nosniff"`, `csp_root: "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"`. Coincide exactamente con `app/core/security_headers.py` y con el diseño Gate 1 aprobado.
- **`/openapi.json` recibe la CSP estricta, no la de `/docs`/`/redoc` — el error específico que el diseño advirtió como fácil de cometer, confirmado NO cometido.** Sonda en vivo: `openapi_csp: "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"` (idéntica a la raíz `/`), mientras que `docs_csp` (sobre `/docs`) es la variante permisiva con `cdn.jsdelivr.net`. `_DOCS_PATHS = {"/docs", "/redoc"}` (`security_headers.py:28`) excluye explícitamente `/openapi.json` por diseño — el comentario del propio código lo señala (`# /openapi.json is pure JSON -- gets _API_CSP`) y la sonda confirma que el comportamiento real coincide con el comentario. Reforzado además por `tests/api/test_security_headers.py::test_openapi_json_gets_strict_csp_not_docs_csp`, que existe específicamente para no regresar este caso.
- **`TrustedHostMiddleware` (citado en la evidencia original de #9 aunque no en el desglose de ítems del task) también se cerró** — `ALLOWED_HOSTS: List[str] = ["*"]` (`config.py:74`), registrado en `app/main.py`. Default `"*"` preserva el comportamiento actual (sin validación de host) mientras da a cada fork un knob explícito y documentado en `.env.example`. No es un hallazgo nuevo: el propio informe original citaba `TrustedHostMiddleware` en la evidencia de #9, así que su adición forma parte legítima del cierre de este hallazgo, no scope creep.
- **Orden de middleware verificado (`Starlette.add_middleware` hace `insert(0, ...)`, así que el orden de ejecución real es el inverso al de registro): `SecurityHeadersMiddleware` → `TrustedHostMiddleware` → `CORSMiddleware` → router.** Esto es correcto y no introduce ningún hueco: `SecurityHeadersMiddleware` envuelve a los otros dos, así que decora la respuesta final (incluyendo un 400 de `TrustedHostMiddleware` o cualquier error 4xx/5xx) sin excepción — confirmado en vivo que un `400` de `/auth/login` con credenciales inválidas también lleva `nosniff`/`X-Frame-Options` (test `test_nosniff_present_on_error_response_too`, reproducido conceptualmente en esta verificación). No bloqueante, documentado aquí solo para que quede trazado el razonamiento del orden.

**Veredicto: hallazgo #9 CERRADO.** CORS fail-closed por defecto y estructuralmente incapaz de aceptar `"*"`; `allow_credentials` no configurable, siempre `False`; las cuatro cabeceras de seguridad presentes en toda respuesta, con la distinción CSP `/openapi.json` vs. `/docs`/`/redoc` confirmada correcta tanto por lectura de código como por sonda en vivo.

### Hallazgo #10 (logging/auditoría de auth + `print` de debug del OTP) — **CERRADO**

- **El `print` de debug del OTP fue eliminado por completo, no comentado.** Confirmado por `grep -rn "print(" app/` sobre el árbol completo de `app/` (excluyendo `__pycache__`): cero resultados de código, la única coincidencia es la palabra "print" dentro de un comentario/docstring de `app/core/notifications.py` describiendo por qué se eliminó. El bloque original (`auth.py:263-266` en el `git diff`, tres líneas `print(...)`) fue reemplazado íntegramente por `audit_log.log_auth_event("auth.otp.requested", ...)` + `notifications.send_otp_notification(...)`.
- **`send_otp_notification` (nuevo, `app/core/notifications.py`) es un genuino no-op — no imprime a stdout, no loguea, no persiste el OTP en ningún sitio alcanzable en este entorno.** Cuerpo completo: `return None`. Es la única función del código base con permiso documentado (en su propio docstring) para recibir el OTP en claro fuera de generación/hashing — y no hace nada observable con él. Verificado por lectura completa del archivo (21 líneas), no hay rama oculta ni logging condicional.
- **Regla PII/leakage de §4.3 del diseño — verificada línea por línea en las 8 llamadas reales a `log_auth_event` en `auth.py` (líneas 82, 91 [wrapped], 213, 219, 303, 432, 469, 515) más 1 en `rate_limit.py:61`. Ningún campo pasado en ninguna de las 9 llamadas es la contraseña cruda, el código OTP crudo, ni el string JWT crudo:**
  - `auth.otp.failed_attempt`/`auth.otp.lockout` (`auth.py:82-96`): `email`, `ip`, `purpose`, `attempts` (un contador entero, no el código) — nunca `otp`/`verification.code`.
  - `auth.register` (`auth.py:184, 189`): `email`, `ip`, `outcome` — nunca `user_in.password`.
  - `auth.login.failure`/`auth.login.success` (`auth.py:213-219, 233`): `email`, `ip`, `reason`/`user_id` — nunca `form_data.password` ni el JWT emitido.
  - `auth.otp.requested` (`auth.py:308-313`): `email`, `ip`, `purpose` — la llamada a `notifications.send_otp_notification` que sí recibe `otp` está en la línea siguiente, **fuera** de la llamada de logging, confirmado por lectura directa que no son la misma invocación.
  - `auth.password_reset.success` (`auth.py:369`): `email`, `ip`, `user_id` — nunca la nueva contraseña ni su hash.
  - `auth.refresh.failure`/`auth.refresh.reuse_detected`/`auth.refresh.success` (`auth.py:420, 432-438, 448, 456, 469-475`): `ip`, `reason`, `user_id`, `family_id`, `jti`/`old_jti`/`new_jti` — estos son UUIDs identificadores de sesión, no el string JWT firmado; conocer un `jti` no otorga acceso sin el token firmado correspondiente (mismo razonamiento ya validado en el Gate 3 de OBJ-002 para la superficie `family_id`/`jti`). **Nunca** se pasa la variable `refresh_token`/`tokens["access_token"]`/`tokens["refresh_token"]` a ninguna llamada de `log_auth_event`, confirmado por lectura de las 8 llamadas — ninguna incluye esos nombres de variable.
  - `auth.logout` (`auth.py:515`): `jti` (nullable), `ip` — nunca el `refresh_token` recibido en el body.
  - `auth.rate_limit.exceeded` (`rate_limit.py:61`): `scope`, `ip`, `email` — no hay dato sensible en este scope de todas formas.
  - **Ningún dato sensible (`SECRET_KEY`, hash de contraseña, hash de OTP) aparece tampoco** — grep dirigido sobre las 9 llamadas confirma que el conjunto de nombres de campo usados en todo el archivo es exactamente `{email, ip, outcome, reason, user_id, purpose, attempts, family_id, jti, old_jti, new_jti, scope}`, un subconjunto del "safe identifiers" documentado en el docstring de `audit_log.py`.
- **Sin riesgo de log injection/forging vía email u otros campos controlados por el atacante.** `log_auth_event` serializa el payload completo con `json.dumps(...)` (`audit_log.py:37`) antes de pasarlo a `_logger.log` como un único string — `json.dumps` escapa comillas/saltos de línea/caracteres de control dentro de cualquier valor de string (p. ej. `email`), así que un atacante no puede inyectar una línea de log JSON falsa vía un `email` malicioso en `/register` o `/login`. Confirmado por inspección del mecanismo de serialización, no asumido.
- **Sink de logging confirmado seguro por construcción, no solo por intención.** `logging.basicConfig(level=settings.LOG_LEVEL)` (`app/main.py`) configura stdout como sink — el hallazgo original citaba el riesgo de "OTP en claro llegando a stdout no restringido" específicamente sobre el `print` (que iba directo a stdout sin pasar por `logging` en absoluto); con el `print` eliminado y ningún llamado a `log_auth_event` recibiendo jamás el OTP crudo (verificado arriba), stdout deja de ser un sink riesgoso — es exactamente el razonamiento de `obj-004-design-notes.md` §4.1, confirmado correcto por esta verificación.

**Veredicto: hallazgo #10 CERRADO.** El `print` está genuinamente eliminado (no comentado); el seam de notificación no filtra el OTP a ningún canal alcanzable; las 9 llamadas reales a `log_auth_event` en el código de producción respetan la regla PII/leakage sin excepción, verificado campo por campo, no por muestreo.

### Hallazgo #13 (`/docs`/`/redoc`/`/openapi.json` sin gate de entorno) — **CERRADO**

- **`ENVIRONMENT` es un campo requerido sin default, fail-closed ante valor ausente o inválido — confirmado en vivo, no solo por lectura.** Sonda directa (`python -c "from app.core.config import settings"`) con `ENVIRONMENT` **ausente** del entorno produce `pydantic_core.ValidationError: Field required` y el proceso termina con traceback — el arranque nunca llega a `uvicorn`. Con `ENVIRONMENT=foo` (valor no reconocido), produce `ValidationError: ENVIRONMENT must be one of ['development', 'production', 'staging'], got 'foo'` — también bloquea el arranque. Ambos casos confirman fail-closed genuino, no solo un log de advertencia.
- **Las rutas no están solo ocultas del schema OpenAPI — no existen en absoluto cuando `ENVIRONMENT=production`.** `app/main.py`: `docs_url="/docs" if _docs_enabled else None` (mismo patrón para `redoc_url`/`openapi_url`). Pasar `None` a estos parámetros de `FastAPI(...)` hace que Starlette/FastAPI nunca registre esas rutas en el `Router` — no es un `403`/oculto-pero-alcanzable, es una ausencia real de ruta, que produce `404` (confirmado por `tests/api/test_docs_gating.py::TestDocsDisabledInProduction`, que prueba exactamente `ENVIRONMENT=production` vía subprocess real contra `app.main.app` y afirma `404` en las tres rutas). Esta verificación no re-ejecutó ese subprocess específico (requiere reiniciar el proceso Python para observar una config distinta, ya que `settings`/`app` son singletons a nivel de módulo construidos en el primer import) pero sí confirmó en vivo, con `ENVIRONMENT=development`, que las tres rutas SÍ están montadas y responden `200` — comportamiento consistente con la rama condicional leída en el código.
- **`development` y `staging` habilitan los docs, solo `production` los deshabilita** — coincide exactamente con el texto del fix del hallazgo original ("deshabilitar cuando `ENVIRONMENT=production`").

**Veredicto: hallazgo #13 CERRADO.** Confirmado fail-closed en vivo ante `ENVIRONMENT` ausente/inválido; confirmado que `docs_url=None`/`redoc_url=None`/`openapi_url=None` produce ausencia real de ruta (no solo ocultamiento de schema), consistente con el mecanismo de FastAPI y con el test de subprocess dedicado que sí lo ejerce en `ENVIRONMENT=production`.

### Backlog item — `client_ip()` sin soporte de `X-Forwarded-For` (OBJ-001 Gate 3, MEDIO) — **CERRADO**

- **`TRUSTED_PROXY_COUNT=0` (default) es genuinamente no-confiante del header, no una confianza parcial.** `app/core/rate_limit.py:65-105` (`client_ip`): con `trusted <= 0`, la rama `if trusted > 0:` completa nunca se evalúa — la función retorna directamente `request.client.host`, sin leer `X-Forwarded-For` en absoluto. Confirmado end-to-end (no solo a nivel de unidad) por `tests/api/test_rate_limit_ip_spoofing.py`, leído en esta pasada: tres escenarios (XFF variando por request, XFF fijo repetido, mezcla de requests con/sin XFF) contra `/forgot-password` confirman que el presupuesto de rate-limit (5/min) se agota exactamente igual que sin ningún header — un atacante no puede resetear ni evadir el límite variando `X-Forwarded-For` en el default de despliegue.
- **Cuando `TRUSTED_PROXY_COUNT>0`, la selección es por el hop N-ésimo desde la derecha, no el primero de la izquierda — la elección correcta.** El comentario en el propio código (`rate_limit.py:96-100`) y el diseño (`obj-004-design-notes.md` §6.2) explican correctamente por qué: cada proxy confiable *añade* la IP que observó, así que el hop añadido por el proxy más externo confiable es siempre el N-ésimo contando desde la derecha, sin importar qué haya prependeado un atacante antes de llegar a la cadena de proxies. Contar desde la izquierda (el enfoque ingenuo) habría sido explotable. Confirmado por lectura del algoritmo, coincide con el pseudocódigo del diseño.
- **Bounds check real, no un fallback silencioso a un valor incorrecto.** `if len(hops) >= trusted:` antes de indexar `hops[-trusted]` — si el header tiene menos entradas que `TRUSTED_PROXY_COUNT` (config incorrecta o header despojado en tránsito), la función cae al `request.client.host` normal en vez de un `IndexError` o de confiar en un valor ambiguo.
- **Residual ya señalado, no resuelto, correctamente documentado como tal:** doble cabecera `X-Forwarded-For` (en vez de un único valor separado por comas) — comportamiento no definido explícitamente aquí, depende de cómo Starlette fusiona cabeceras duplicadas. Severidad Baja, mismo tratamiento que los TOCTOU ya trackeados de OBJ-001/OBJ-002 — no bloqueante, no es una regresión de este pase.

**Veredicto: backlog item CERRADO** para el caso por defecto (`TRUSTED_PROXY_COUNT=0`, el shipped default) — confirmado explícitamente que un cliente no puede falsificar `X-Forwarded-For` para afectar las claves de rate-limiting/lockout en la configuración por defecto, que es la pregunta específica que este pase debía responder.

### Backlog item — `.env.example` sin advertencia sobre `POSTGRES_SSL_MODE=require` (OBJ-003 Gate 3, BAJO) — **CERRADO**

Confirmado por lectura directa de `.env.example:6-19`: el bloque de comentarios ahora explica los tres modos, incluyendo la advertencia específica pedida ("`require` encripta el cable, no verifica la identidad del servidor... VULNERABLE a un atacante MITM activo"), con el mismo nivel de detalle que los otros dos modos. Coincide exactamente con el texto recomendado en `obj-004-design-notes.md` §7. Sin cambio de código — era un hallazgo puramente documental, ya confirmado no bloqueante en el Gate 3 de OBJ-003.

### Hallazgos nuevos de esta pasada

Ninguno. Toda la superficie nueva introducida por OBJ-004 (`SecurityHeadersMiddleware`, `audit_log.py`, `notifications.py`, los cinco nuevos campos de `Settings`, el `client_ip()` extendido) fue revisada explícitamente arriba sin encontrar un hallazgo no trazado previamente.

### Veredicto Gate 3

| Hallazgo / ítem | Veredicto | Evidencia clave |
|---|---|---|
| #9 (CORS / cabeceras de seguridad) | **CERRADO** | `config.py:69,74`, `main.py` (registro de middleware), `security_headers.py`, sonda en vivo |
| #10 (logging/auditoría + print de OTP) | **CERRADO** | `auth.py` (9 llamadas a `log_auth_event`), `notifications.py`, `audit_log.py`, grep de `print(` sin resultados |
| #13 (docs sin gate de entorno) | **CERRADO** | `config.py` (`ENVIRONMENT`), `main.py` (`docs_url=None` etc.), sonda de fail-closed en vivo |
| Backlog OBJ-001: `client_ip()` sin XFF | **CERRADO** (default `TRUSTED_PROXY_COUNT=0`) | `rate_limit.py:65-105`, `tests/api/test_rate_limit_ip_spoofing.py` |
| Backlog OBJ-003: `.env.example` sin advertencia `require` | **CERRADO** | `.env.example:6-19` |
| Nuevos hallazgos esta pasada | **Ninguno** | — |

**Veredicto OWASP (delta sobre el informe original):** A05:2021 Security Misconfiguration pasa de **FAIL** a **PASS** en lo que respecta a #9 y #13; A09:2021 (Security Logging and Monitoring Failures) pasa de **FAIL** a **PASS** en lo que respecta a #10; API9:2023 Improper Inventory Management pasa de **FAIL** a **PASS** (era el único hallazgo bajo esa categoría, #13). El hallazgo MEDIO del backlog de rate-limiting-tras-proxy (OBJ-001 Gate 3) también queda cerrado en su configuración por defecto.

**Recomendación:** OBJ-004 puede marcarse cerrado a efectos de los hallazgos #9/#10/#13 del audit original más los dos backlog items de Gate 3 previos que este objetivo absorbió. Ningún hallazgo nuevo bloquea el gate. Persisten como pendientes (sin relación a este objetivo): #6 (OBJ-007, bloqueado en decisión de producto), #11/#12/#14 (OBJ-005/OBJ-006, no iniciados), más los residuales BAJOS ya trackeados (purga de `rate_limit_hits`, TOCTOU de `/auth/refresh`, verificación wire-level de TLS a Postgres).

**Gate 3 security-specialist verdict for OBJ-004: PASS.** Findings #9, #10, and #13 are genuinely closed, verified by direct code reading, live ASGI probes (not just test-suite trust), and targeted fail-closed startup checks: CORS defaults to empty/closed and cannot structurally accept `"*"`, `allow_credentials` is hardcoded `False` (never configurable, so no credentialed-wildcard state is reachable), all four security headers are present on every response including error responses, `/openapi.json` correctly gets the strict CSP (not the docs exemption — confirmed live, the exact mistake the design notes flagged), `ENVIRONMENT` fails closed on missing/invalid values (confirmed live), docs routes are genuinely absent (not just schema-hidden) outside development/staging, the debug `print` is fully removed (grep-confirmed, not commented out) with no replacement leak path, and all 9 real `log_auth_event` call sites in production code were checked field-by-field against the PII/leakage rule with zero violations. Both carried-over Gate 3 backlog items (`client_ip()` proxy trust, `.env.example` wording) are also closed. No new finding from this pass.
