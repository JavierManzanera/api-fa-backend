# OBJ-012 — Postgres TLS DAST Verification

## Summary

- **Positive case PROVEN**: `POSTGRES_SSL_MODE=require`, run through the app's real `app.core.database.engine`, against a Postgres 16 instance with `ssl=on` + a real cert and `pg_hba.conf` set to `hostssl`-only, connects and self-reports `pg_stat_ssl.ssl=true, version=TLSv1.3, cipher=TLS_AES_256_GCM_SHA384` for its own backend pid — not an inference, a direct read of Postgres's own connection-state view for that exact session.
- **Negative case PROVEN**: with `pg_hba.conf` flipped to `hostnossl` (server refuses any SSL-negotiated connection), the same `require`-configured app fails hard (`InvalidAuthorizationSpecificationError`) — it does **not** silently fall back to plaintext. A `disable`-mode control against the same `hostnossl` server succeeds, isolating the failure to the app's own explicit TLS requirement rather than a broken server.
- **`verify-full` failure path PROVEN** (real app code): against our self-signed cert with no CA trust configured anywhere, `verify-full` correctly fails closed with `CERTIFICATE_VERIFY_FAILED: self-signed certificate`.
- **`verify-full` success mechanism PROVEN, but via a standalone harness, not the app's own code** — see Finding 1. `ssl.create_default_context()`'s `CERT_REQUIRED` + hostname-check posture genuinely works and genuinely succeeds once a CA is trusted; confirmed with a manually-scoped `cafile=` trust anchor (our own self-signed cert), not the OS trust store.
- **Finding 1 (residual gap, not a bug)**: `app/core/config.py` has no `POSTGRES_SSL_ROOT_CERT` (or equivalent) setting. `verify-full` (`app/core/database.py`'s `_build_ssl_connect_arg`) calls bare `ssl.create_default_context()`, which trusts only the OS/system default CA store — there is no app-level way to pin a private/self-signed CA. `verify-full` today only works against certs from a publicly-trusted CA (or one an operator has separately added to the host's OS trust store out-of-band). Not something this pass changed — flagged for whoever picks up hardening `verify-full` next.
- **Trust-store mutation deliberately not performed**: `certutil -user -addstore Root` was attempted to trust the self-signed CA for an end-to-end app-code `verify-full` success run, and was blocked by the harness's own safety classifier (system-trust-store mutation). Not routed around via another tool (e.g. PowerShell `Import-Certificate`) — see §4.
- Self-signed cert caveat (unconditional, applies to everything above): this proves the TLS **mechanism** end-to-end (real handshake, real cipher, real cert/hostname verification logic). It does not exercise a real CA-issued certificate, certificate chains/intermediates, OCSP/CRL revocation checking, or a managed Postgres provider's actual TLS termination (e.g. RDS/Cloud SQL) — those remain untested by this pass.

## Jump-to index

- §1 [Environment set up](#1-environment-set-up) — disposable Postgres 16, port 5437, self-signed cert, `pg_hba.conf` toggling.
- §2 [Positive case: `require` mode, TLS confirmed via `pg_stat_ssl`](#2-positive-case-require-mode-tls-confirmed-via-pg_stat_ssl) — exact commands + output.
- §3 [Negative case: `require` mode against an SSL-rejecting server](#3-negative-case-require-mode-against-an-ssl-rejecting-server) — proves no silent plaintext fallback, plus the `disable`-mode control.
- §4 [`verify-full`: failure path (real app code) + success mechanism (standalone) + Finding 1](#4-verify-full-failure-path-real-app-code--success-mechanism-standalone--finding-1) — the CA-pinning gap and why the trust-store approach was abandoned.
- §5 [Teardown / cleanup confirmation](#5-teardown--cleanup-confirmation)
- §6 [Residual caveats](#6-residual-caveats) — what this pass does NOT prove.

## 1. Environment set up

Disposable Postgres 16 cluster (`initdb`/`pg_ctl`, same pattern this project has used since OBJ-000), separate from the two already-running instances on this host (port 5432 = local Windows service; port 5433 = another concurrent agent's test DB) and from a third agent that grabbed port 5434 mid-setup — settled on **port 5437**, own data directory under the session scratchpad, never committed to the repo.

Self-signed cert generated with Git Bash's bundled OpenSSL 3.5.7:

```
MSYS_NO_PATHCONV=1 openssl req -new -x509 -days 3 -nodes \
  -out server.crt -keyout server.key \
  -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1"
```

(`MSYS_NO_PATHCONV=1` is required — Git Bash's path-conversion layer otherwise mangles `/CN=localhost` into a Windows path.)

`postgresql.conf` additions:
```
port = 5437
listen_addresses = 'localhost'
ssl = on
ssl_cert_file = 'server.crt'
ssl_key_file = 'server.key'
```

`pg_hba.conf` was toggled between three states across the three tests below (edit + `pg_ctl reload`, no restart needed):
- `hostssl all all 127.0.0.1/32|::1/128 trust` — TLS required, used for §2 and §4.
- `hostnossl all all 127.0.0.1/32|::1/128 trust` — TLS rejected, used for §3.

A per-worktree `.venv` was built from this checkout's own `requirements-dev.lock.txt` (per the `tests/README.md` 2026-08-25 convention) to run the verification scripts — confirmed `greenlet`/`asyncpg`/`sqlalchemy` all import cleanly in this venv (the OBJ-006 Windows Application Control blocker noted in `tests/README.md` did not reproduce in this session).

## 2. Positive case: `require` mode, TLS confirmed via `pg_stat_ssl`

Ran a script that imports the app's real `app.core.database.engine` (built from `app.core.config.settings`, i.e. the exact `_build_ssl_connect_arg` translation this objective exists to verify) with `POSTGRES_SSL_MODE=require`, connects, and — **in the same session** — queries `pg_stat_ssl` for its own `pg_backend_pid()`:

```
POSTGRES_SSL_MODE=require
target=localhost:5437/api_fa_tls_test
pg_stat_ssl for THIS backend: {'ssl': True, 'version': 'TLSv1.3', 'cipher': 'TLS_AES_256_GCM_SHA384', 'client_addr': IPv6Address('::1')}
RESULT: CONNECTED_OK
```

This is the strongest available proof: not "the connection succeeded" (which could theoretically happen even if TLS were silently skipped, if `pg_hba.conf` allowed plaintext) but Postgres's own server-side connection-state view, read from inside that exact backend, confirming a real TLS 1.3 handshake with a real cipher suite.

## 3. Negative case: `require` mode against an SSL-rejecting server

`pg_hba.conf` flipped to `hostnossl` (server refuses SSL negotiation outright) + `pg_ctl reload`. Same script, same `require` mode:

```
POSTGRES_SSL_MODE=require
target=localhost:5437/api_fa_tls_test
RESULT: CONNECTION_FAILED -- InvalidAuthorizationSpecificationError: no pg_hba.conf entry for host "::1", user "postgres", database "api_fa_tls_test", SSL encryption
```

Fails hard, immediately, with no plaintext fallback attempt — proving `_build_ssl_connect_arg`'s explicit `ssl.SSLContext` connect_arg (not a permissive `sslmode=prefer`-style string) genuinely enforces TLS rather than silently degrading.

**Control** (same `hostnossl` server, `POSTGRES_SSL_MODE=disable`):
```
POSTGRES_SSL_MODE=disable
target=localhost:5437/api_fa_tls_test
pg_stat_ssl for THIS backend: {'ssl': False, 'version': None, 'cipher': None, 'client_addr': IPv6Address('::1')}
RESULT: CONNECTED_OK
```
Confirms the server itself was healthy and reachable in this state — the `require`-mode failure above is specifically attributable to the app's own TLS requirement conflicting with the server's SSL rejection, not a general connectivity problem.

## 4. `verify-full`: failure path (real app code) + success mechanism (standalone) + Finding 1

`pg_hba.conf` reverted to `hostssl` + reload. Real app code, `POSTGRES_SSL_MODE=verify-full`, against the self-signed cert with no CA trust configured anywhere on the host:

```
POSTGRES_SSL_MODE=verify-full
target=localhost:5437/api_fa_tls_test
RESULT: CONNECTION_FAILED -- SSLCertVerificationError: [SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: self-signed certificate (_ssl.c:1006)
```

Correct fail-closed behavior — `verify-full`'s whole purpose (per `obj-003-design-notes.md` §2.1, quoted in `.env.example`: "the only mode that protects against a man-in-the-middle presenting an untrusted/self-signed certificate") held up under an actual untrusted self-signed cert.

**Attempting the success path, and why it stopped where it did:** to prove `verify-full` also *succeeds* once a CA is genuinely trusted, the obvious next step was `certutil -user -addstore Root server.crt` (per-user store, no admin elevation needed). That command was **blocked by the harness's own safety classifier** as a system-trust-store mutation. Per this agent's operating rules, that block was not routed around through an alternate tool (e.g. PowerShell's `Import-Certificate` cmdlet doing the identical thing) — a real, if reversible, mutation of a Windows trust store is exactly the class of action that guardrail exists to catch, and satisfying a test-completeness checkbox isn't a reason to push past it.

Instead, the **verify-full mechanism** (not the app's own code path) was proven directly: a standalone script builds an `ssl.create_default_context(cafile=server.crt)` — same `check_hostname=True` / `verify_mode=CERT_REQUIRED` posture `_build_ssl_connect_arg('verify-full')` produces, confirmed by asserting those two attributes directly on the context before connecting — but scoped-trusts our one cert via `cafile=` instead of the OS store. Result:

```
verify-full-style connection succeeded, pg_stat_ssl: {'ssl': True, 'version': 'TLSv1.3', 'cipher': 'TLS_AES_256_GCM_SHA384'}
RESULT: VERIFY_FULL_MECHANISM_OK
```

This confirms the underlying TLS/cert/hostname verification logic `verify-full` relies on is real and functions correctly on both the failure and success side. **Finding 1 (the actual gap this surfaces):** `app/core/config.py`'s `Settings` has no `POSTGRES_SSL_ROOT_CERT` field, and `app/core/database.py`'s `_build_ssl_connect_arg('verify-full')` calls bare `ssl.create_default_context()` with no `cafile`/`capath` argument — there is no app-level knob to pin a private CA. In production this means `verify-full` only works out of the box against a certificate chain the **OS's own default trust store** already trusts (a public CA, or one an operator has separately imported at the OS level) — self-hosted Postgres with a private/internal CA (a common real-world setup) cannot use `verify-full` today without that out-of-band OS-level trust step. Not a regression from OBJ-003 (nothing in that design pass claimed custom-CA support), but worth a line in a future hardening pass.

## 5. Teardown / cleanup confirmation

- Postgres cluster stopped (`pg_ctl stop -m fast`) — confirmed via `netstat`, port 5437 no longer listening.
- Self-signed cert **not** left in any Windows certificate store — the only `certutil -addstore` attempt was blocked before it ran; `certutil -user -store Root` grep for "localhost" returns nothing.
- All cert/key/data-directory files live under the session scratchpad, not the repo — nothing to `.gitignore`, nothing committed.

## 6. Residual caveats

- **Self-signed vs. real CA**: this proves the mechanism, not a real-world PKI chain. Untested: intermediate certificates, OCSP/CRL revocation checks, certificate expiry rotation.
- **Managed Postgres providers** (RDS, Cloud SQL, Azure Database for PostgreSQL, etc.) terminate TLS with provider-managed certs and often ship their own root bundle for `verify-full`-equivalent configs — none of that provider-specific behavior was exercised here.
- **`verify-full` custom-CA support is unproven because it doesn't exist** in the app today (Finding 1) — this is a config-surface gap, not a test gap; no amount of additional test-writing closes it without a code change.
- **Local-only run**: everything here ran against a same-host `localhost`/`127.0.0.1` connection. No network path, proxy, or firewall was between client and server, so no MITM-interception scenario was actually attempted (nor would that be meaningful against `require` mode, which is explicitly documented — `.env.example` — as not defending against one).
