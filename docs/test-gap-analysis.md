# Test Gap Analysis — Ciclo de Auth (`api-fa-backend`)

**Fecha:** 2026-08-21
**Autor:** qa-engineer (fase de análisis, sin escritura de tests todavía)
**Alcance revisado:** `app/api/v1/endpoints/auth.py`, `app/api/deps.py`, `app/core/security.py`,
`app/models/user.py`, `app/models/verification.py`, `app/schemas/user.py`, `requirements.txt`,
`app/core/config.py`, `app/core/database.py`, `app/main.py`, `app/api/v1/router.py`.

## 0. Estado actual: cobertura = 0%

Confirmado por inspección directa del repo (no hay `.git` de workspace superior, pero sí hay uno
propio en `api-fa-backend/`):

- No existe carpeta `tests/`, ni `conftest.py`, ni ningún archivo `*test*`.
- No hay `pytest`, `pytest-asyncio`, `httpx`, `pytest-cov`, `faker`/`factory_boy`, ni `aiosqlite`
  en `requirements.txt` (contenido íntegro: `fastapi`, `uvicorn`, `sqlalchemy`, `alembic`,
  `psycopg2-binary`, `asyncpg`, `pydantic`, `pydantic-settings`, `email-validator`,
  `passlib[bcrypt]`, `bcrypt==3.2.2`, `python-jose[cryptography]`, `python-multipart`).
- No hay `pytest.ini`, `pyproject.toml` ni `setup.cfg`.
- No hay ningún workflow de CI (`.github/workflows`, etc.) ni config `.yml`/`.yaml` en el repo.
- `app/main.py` crea las tablas vía `Base.metadata.create_all` en el lifespan de arranque contra
  la DB configurada por `.env` (Postgres real) — no hay mecanismo de DB de test aislada.

**Conclusión: 0% del ciclo de auth está bajo test.** Todo lo que sigue es lo que falta para
llegar a una cobertura TDD razonable antes de tocar el código de implementación.

---

## 1. Infraestructura de testing faltante (bloqueante, va primero)

| Falta | Detalle |
|---|---|
| `pytest` + `pytest-asyncio` | Los endpoints y `deps.get_db` son `async def`; sin esto no se puede ejecutar nada async. |
| `httpx` (`AsyncClient` con `ASGITransport`) | Necesario para pegarle a `app` FastAPI in-process sin levantar un servidor real (contract/integration tests). `TestClient` de Starlette funciona sync pero con fixtures async es más limpio usar `httpx.AsyncClient`. |
| Base de datos de test aislada | Actualmente `engine`/`AsyncSessionLocal` están atados a `settings.SQLALCHEMY_DATABASE_URI` (Postgres) construido en import-time desde `.env`. No hay override de `get_db` ni de la URL para tests. Se necesita: (a) `aiosqlite` + SQLite in-memory, o (b) un Postgres de test (docker) + fixture que crea/dropea schema por sesión/test, y (c) un mecanismo de `app.dependency_overrides[deps.get_db]` para inyectar la sesión de test. |
| `conftest.py` con fixtures reutilizables | `event_loop`/`anyio_backend`, `db_session`, `client` (AsyncClient con override de `get_db`), `test_user` factory, `override_settings` para SECRET_KEY/expiración de tokens determinística en tests. |
| Factory/builder de usuarios | No hay `factory_boy` ni helpers — cada test tendría que construir `User`/`Verification` a mano repetidamente. Se necesita un factory mínimo (`create_user(email=..., password=..., is_active=..., is_verified=...)`) que hashee la password real vía `security.get_password_hash`. |
| Control de tiempo en tests | `expires_at` de `Verification` y `exp` de JWT dependen de `datetime.now(timezone.utc)`. Sin `freezegun` (o inyección de reloj) no se puede testear expiración de OTP/token de forma determinística sin `sleep()` real. |
| `pytest-cov` | Para medir cobertura real vs. declarada. |
| Config de test separada | `Settings` es obligatorio vía `.env` (no hay defaults para `SECRET_KEY`, `POSTGRES_*`, etc.) — hace falta un `.env.test` o fixture que monkeypatchee `get_settings()`/`settings` antes de importar `app.main` (ojo: `settings = get_settings()` se ejecuta a nivel de módulo, así que el orden de import/override en conftest importa). |
| CI | No hay pipeline que ejecute la suite automáticamente — fuera del scope de qa-engineer (le corresponde a devops-engineer), pero se deja constancia de que hoy nada se corre en cada push. |

**Veredicto sobre `requirements.txt`:** no soporta testear nada de esto hoy. Faltan como mínimo:
`pytest`, `pytest-asyncio`, `httpx`, `aiosqlite` (si se opta por SQLite para tests), `factory_boy`
(o equivalente), `freezegun`, `pytest-cov`. Esto debe ir a un `requirements-dev.txt` o extra
`[test]` — decisión para developer/devops, no implementada aquí.

---

## 2. Gap por endpoint / función

### 2.1 `POST /auth/register`

**Unit:**
- `validate_password_strength` (schemas/user.py): falta mayúscula → error; falta dígito → error;
  falta carácter especial → error; password válida → pasa; mensajes de error acumulados
  (múltiples reglas rotas a la vez).
- `security.get_password_hash` produce hash distinto de la password en claro y verificable con
  `verify_password`.

**Integration/API contract:**
- Registro exitoso → 201, body cumple `UserResponse` (incluye `is_active=True`, `is_verified=False`,
  no expone `hashed_password`).
- Email duplicado (exacto) → 400 con el mensaje esperado, no crea segundo registro.
- **Email duplicado con distinto casing** (`User@Example.com` vs `user@example.com`) — el filtro
  es `User.email == user_in.email` sin normalización; hoy probablemente permite duplicados
  case-sensitive. Test debe documentar el comportamiento real (bug candidato).
- Password fuera de longitud (`< 8` o `> 128`) → 422 (validación Pydantic, no 400 custom).
- Password sin mayúscula/dígito/especial → 422.
- Email inválido (`not-an-email`) → 422 (via `EmailStr`).
- Payload sin `email` o sin `password` → 422.
- Body vacío / `Content-Type` incorrecto → 422/415.
- Password de longitud extrema (>72 bytes, límite conocido de bcrypt) — verificar que no trunca
  silenciosamente ni rompe (`bcrypt==3.2.2` truncation caveat).
- Contrato: `UserResponse` no debe filtrar `hashed_password` (regression test explícito sobre
  las keys del JSON de respuesta).

### 2.2 `POST /auth/login`

**Unit:**
- `security.verify_password` con hash válido/​inválido.
- `security.create_access_token` / `create_refresh_token`: contienen `sub`, `exp` correcto según
  `expires_delta` o default de settings; `create_refresh_token` incluye `"refresh": True` y
  `create_access_token` NO lo incluye.

**Integration/API contract:**
- Credenciales correctas → 200, body cumple `Token` (`access_token`, `refresh_token`,
  `token_type=bearer`), tokens decodificables con el `SECRET_KEY` de test.
- Email inexistente → 400 "Incorrect email or password" (mismo mensaje que password incorrecta,
  para no filtrar existencia de cuenta).
- Password incorrecta (usuario existente) → 400, mismo mensaje genérico.
- Usuario `is_active=False` → 400 "Inactive user" — **nota:** este mensaje SÍ es distinto del de
  credenciales inválidas, lo que permite enumerar cuentas inactivas vs. inexistentes. Test debe
  capturar esto como hallazgo, no asumir que está bien.
- Usuario `is_verified=False` pero activo → **hoy el login no valida `is_verified` en absoluto**.
  Falta decidir con business-analyst/solution-architect si esto es un gap de negocio (¿debería
  bloquear login sin verificar email?) o es intencional. Test debe fijar el comportamiento actual
  explícitamente para que cualquier cambio futuro sea intencional y no una regresión silenciosa.
- **Timing side-channel:** rama `not user or not verify_password(...)` hace short-circuit — si el
  usuario no existe, NUNCA se ejecuta `verify_password` (bcrypt, costoso). Si existe, sí. Esto es
  un canal de timing que permite enumerar emails registrados. Se recomienda un test de
  caracterización (medir que la rama "user no existe" es medible más rápida) y escalar a
  security-specialist para mitigación (dummy hash verify cuando el usuario no existe).
- `OAuth2PasswordRequestForm` requiere `application/x-www-form-urlencoded` — test de contrato que
  confirma que JSON body es rechazado (415/422) y que `grant_type`/campos extra no rompen nada.
- Form incompleto (`username` sin `password`) → 422.

### 2.3 `POST /auth/forgot-password`

**Unit:**
- Generación de OTP: 6 dígitos, sólo `string.digits` (documentar que usa `random.choices`, no
  `secrets` — no criptográficamente seguro; señalar a security-specialist).

**Integration/API contract:**
- Email existente → 200, mensaje genérico, crea un `Verification` con `purpose=reset_password`,
  `expires_at` ≈ now+10min, código de 6 dígitos.
- Email inexistente → 200, **mismo mensaje genérico**, y confirmar que NO se crea ningún
  `Verification` (evita enumeración por efecto secundario, aunque el mensaje ya es igual).
- **Timing side-channel:** rama "existe" hace `delete` + `insert` + `commit` + `print`; rama "no
  existe" sólo hace un `select`. Diferencia de latencia medible → enumeración de usuarios por
  tiempo de respuesta pese al mensaje idéntico. Test de caracterización + hallazgo para
  security-specialist.
- Solicitudes repetidas para el mismo email → **invalidan (borran) el OTP anterior** y generan uno
  nuevo; test debe confirmar que el OTP viejo deja de ser válido en `verify-otp`/`reset-password`
  tras una segunda solicitud (comportamiento actual, vía el `delete()` previo al insert).
- Email inválido (`not-an-email`) → 422.
- **No hay rate limiting**: múltiples solicitudes consecutivas para el mismo email no están
  limitadas — endpoint puede usarse para spamear al usuario de "emails" (mock print) o para
  DoS de la tabla `verifications`. Falta de rate-limit es gap de negocio/seguridad, no sólo de
  test — documentar para business-analyst/security-specialist.

### 2.4 `POST /auth/verify-otp`

**Integration/API contract:**
- OTP válido y no expirado → 200 "OTP verified successfully".
- OTP incorrecto (email correcto, código erróneo) → 400 "Invalid or expired OTP".
- OTP correcto pero expirado (`expires_at` en el pasado, requiere control de tiempo/fixture con
  `freezegun` o insertar directamente con `expires_at` pasado) → 400.
- OTP de otro `purpose` (si en el futuro existe `verify_email`) no debe validar para
  `reset_password` — hoy sólo existe `reset_password`, pero el modelo ya soporta multi-purpose;
  test debe fijar el filtro por `purpose` explícitamente para prevenir regresión cuando se añada
  un segundo purpose.
- Email sin ningún OTP emitido → 400.
- **Reuso de OTP:** `verify-otp` **NO consume/borra** el `Verification` — sólo lee. Esto significa
  que el mismo OTP puede "verificarse" un número ilimitado de veces mientras no expire. Es
  intencional si `verify-otp` es sólo un paso de UX previo a `reset-password` (que sí consume),
  pero debe testearse explícitamente como comportamiento actual — y es candidato a brute-force:
  **no hay límite de intentos**, un atacante puede probar los 1,000,000 de combinaciones de 6
  dígitos contra `verify-otp` sin bloqueo/lockout. Prioridad alta para security-specialist.
- Payload incompleto (`email` sin `otp`, o viceversa) → 422.

### 2.5 `POST /auth/reset-password`

**Integration/API contract:**
- OTP válido → 200, password de usuario actualizada (verificar con `verify_password` sobre el
  nuevo hash), `Verification` **borrado** de la tabla (confirmar vía query directa post-request).
- OTP inválido/expirado → 400, password del usuario **no cambia**.
- Email con OTP válido pero usuario no existe (caso raro: OTP existe pero `User` fue borrado
  entre `forgot-password` y `reset-password`) → 404 "User not found" — test de esta rama
  específica (`result_user` vacío tras pasar la validación de `Verification`).
- **Reuso de OTP tras reset exitoso:** segundo intento con el mismo OTP → debe fallar 400 (porque
  ya fue borrado) — test de regresión explícito para la fuga de reuso que sí existe en
  `verify-otp`.
- Password nueva no cumple `validate_password_strength` → 422 (antes de tocar DB — confirmar que
  no se borra el `Verification` en este caso, porque la validación Pydantic ocurre antes del
  handler).
- **Race condition / TOCTOU:** dos requests concurrentes con el mismo OTP válido — sin lock,
  ambos podrían pasar el `select` antes de que el primero haga `commit`+delete. Difícil de testear
  de forma determinística en unit/integration estándar, pero debe quedar documentado como riesgo
  de concurrencia para un test de carga/concurrencia dedicado (fuera de scope de la suite básica,
  anotar como "flaky/entorno-dependiente").
- **No hay invalidación de tokens de sesión existentes** tras un reset de password — un
  `access_token`/`refresh_token` emitidos antes del reset siguen siendo válidos después
  (`create_access_token` no incluye versión/jti ligado al usuario). Gap de seguridad a nivel de
  diseño — no es testeable como "bug" sin decisión de arquitectura, documentar para
  solution-architect/security-specialist.

### 2.6 `POST /auth/refresh`

**Unit:**
- `security.verify_refresh_token`: token válido con `refresh=True` → retorna email; token sin
  claim `refresh` → excepción; token con `refresh=False` → excepción; token malformado/firma
  inválida → excepción; token expirado → excepción (requiere control de tiempo).

**Integration/API contract:**
- Refresh token válido, usuario activo → 200, nuevo `access_token` distinto del original,
  `refresh_token` devuelto es el mismo que se envió (comportamiento actual: no rota el refresh
  token — anotar como decisión de diseño a confirmar, no rotar refresh tokens es menos seguro).
- Refresh token de usuario `is_active=False` → 400.
- Refresh token de usuario que ya no existe (borrado) → 400.
- **Access token usado como refresh token** en `/auth/refresh` → debe rechazarse porque carece de
  `"refresh": True` — test explícito, es la defensa que sí existe.
- **Refresh token usado como access token contra un endpoint protegido** (`get_current_user` /
  `get_current_active_user`): `deps.get_current_user` **NO verifica** la ausencia/presencia del
  claim `"refresh"` — sólo lee `sub`. Esto significa que un refresh token (de vida mucho más
  larga, `REFRESH_TOKEN_EXPIRE_DAYS`) **puede usarse directamente como Bearer access token** en
  cualquier endpoint protegido por `get_current_active_user`. Es una vulnerabilidad real de
  escalación de privilegio temporal (token de larga duración actuando como sesión corta). Hoy no
  hay ningún endpoint protegido en el router además de auth mismo, pero en cuanto se añada uno
  (ej. `/users/me`), este test debe existir desde el día uno. **Prioridad crítica** — reportar a
  security-specialist además de cubrirlo con test.
- Refresh token con firma inválida / `SECRET_KEY` distinto → 400.
- Body malformado (`refresh_token` ausente o no-string) → 422.

### 2.7 `app/api/deps.py` (`get_current_user`, `get_current_active_user`)

**Unit/Integration** (vía un endpoint protegido de prueba montado en el test, ya que hoy ningún
endpoint real usa estas dependencias — anotar el gap: **no hay ningún endpoint que ejercite
`get_current_user` en producción actualmente**, sólo existe como dependency sin consumidor):
- Token válido → retorna `User` correcto.
- Token sin `sub` → 401.
- Token con `sub` de usuario inexistente → 401.
- Token expirado → 401 (requiere control de tiempo).
- Token con firma inválida → 401.
- Header `Authorization` ausente → 401 (comportamiento de `OAuth2PasswordBearer`).
- Header mal formado (`Bearer` sin token, esquema distinto de `Bearer`) → 401.
- `get_current_active_user` con usuario inactivo → 400 "Inactive user".
- **Nota de scope:** dado que hoy `deps.py` no tiene consumidores reales fuera de sí mismo, este
  bloque de tests debe marcarse explícitamente como infraestructura/preparación para futuros
  endpoints protegidos, no como cobertura de una feature de negocio visible hoy.

### 2.8 `app/core/security.py` (unit puro, sin DB)

- `verify_password`: hash bcrypt válido/inválido, password vacía, password no-string.
- `get_password_hash`: idempotencia de verificación (mismo password, hashes distintos por salt),
  hash de password de 0 caracteres (si el schema lo permitiera saltarse — no debería, pero
  security.py no valida nada por sí mismo, así que el unit test debe cubrir la función aislada).
- `create_access_token` / `create_refresh_token`: `exp` respeta `expires_delta` custom vs. default
  de `settings`; `sub` se serializa como string incluso si se pasa un no-string.
- `verify_refresh_token`: cubierto arriba en 2.6, pero como unit puro (sin HTTP) para aislar la
  lógica de decodificación de las reglas del endpoint.

### 2.9 Modelos (`User`, `Verification`) — nivel DB/integration

- Constraint `unique=True` en `User.email` a nivel de DB: insertar dos `User` con mismo email
  fuera del endpoint (test directo contra la sesión) debe lanzar `IntegrityError` — válido incluso
  si el gap de normalización de casing (2.1) no se corrige a nivel de aplicación.
- Defaults: `is_active=True`, `is_verified=False`, `created_at`/`updated_at` autogenerados.
- `Verification.purpose` no tiene constraint de valores permitidos (`String` libre) — test que
  documenta que hoy se puede insertar cualquier string arbitrario como `purpose` (no hay `Enum`).

---

## 3. Resumen de cobertura por capa (todo en 0% hoy)

| Capa | Tests necesarios (aprox.) | Estado |
|---|---|---|
| Unit (security.py, validators de schemas) | ~18 | 0% |
| Integration (endpoints + DB real de test) | ~45 | 0% |
| API contract (shape de request/response, status codes, content-type) | incluido arriba, transversal | 0% |
| Seguridad/edge-case (timing, reuso OTP, refresh-como-access, brute force) | ~10, algunos requieren coordinación con security-specialist | 0% |
| Concurrencia/carga (TOCTOU en reset-password) | 1, marcado como flaky/fuera de suite estándar | 0% |

---

## 4. Riesgos de flakiness / dependencia de entorno a anotar para la fase roja

- Tests que dependen de `datetime.now()` para expiración de OTP/JWT necesitan `freezegun` o
  inyección de reloj — sin esto, cualquier test de expiración real (`time.sleep`) será lento y
  potencialmente flaky en CI.
- Si se usa SQLite in-memory para tests, el tipo `UUID(as_uuid=True)` de
  `sqlalchemy.dialects.postgresql` puede no comportarse igual que en Postgres real — validar
  compatibilidad o usar Postgres real vía Docker en CI (decisión para devops-engineer).
- El timing side-channel de login/forgot-password (arriba) es inherentemente ruidoso de medir en
  CI compartido — cualquier test de timing debe ser un test de caracterización con tolerancia
  amplia, no una assertion estricta de "X ms más rápido", o marcarse como test manual/benchmark
  fuera de la suite de CI estándar.
- `Settings` exige variables de entorno obligatorias sin defaults — el orden de carga de
  `.env.test` vs. el import de `app.core.config` (que ejecuta `get_settings()` a nivel de módulo)
  es sensible al orden de imports en `conftest.py`; mal ordenado puede romper toda la suite de
  forma no obvia.

---

## 5. Fuera de scope de este análisis

- No se proponen aún nombres de archivos de test ni código de tests (eso es la fase roja,
  pendiente de aprobación).
- No se decide aquí SQLite vs. Postgres-docker para tests — recomendación a validar con
  database-architect/devops-engineer.
- No se implementan mitigaciones (rate limiting, rotación de refresh token, invalidación de
  sesión post-reset, normalización de email, OTP con `secrets` en vez de `random`) — se listan
  como hallazgos a escalar a security-specialist/solution-architect, no como parte del test gap
  per se, aunque varios de ellos deben convertirse en tests de regresión una vez corregidos.
