"""
OBJ-008 Gate 3 verification gap-fill (qa-engineer, 2026-08-25) --
`python-jose` -> `PyJWT[crypto]` migration (docs/database N/A; see
docs/testing/obj-008-test-report.md).

None of the pre-existing suite (tests/unit/test_security.py,
tests/api/test_me_endpoint.py, tests/api/test_legacy_token_fail_closed.py,
tests/api/test_token_type_enforcement.py) crafts a token whose JWT *header*
`alg` differs from the app's configured `settings.ALGORITHM` (HS256) and
sends it to a live endpoint. That is a materially different case from
"wrong secret" (same alg, bad signature) or "malformed" (not a JWT at all)
-- it is the classic algorithm-confusion / `alg=none` attack surface, and
it is exactly the class of bug a library swap like OBJ-008 could
regress if the new decode call ever dropped the `algorithms=[...]`
allow-list argument (accepting whatever `alg` the caller's token header
claims) or reintroduced any legacy `verify_signature=False`-equivalent
behavior.

`app/core/security.py::_decode_refresh_payload` /
`app/api/deps.py::get_current_user` both call
`jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])` and catch
`PyJWTError` -- PyJWT raises `InvalidAlgorithmError` (a `PyJWTError`
subclass) whenever the token header's `alg` is not in that allow-list,
*before* attempting any signature check. This file proves that holds at
the HTTP layer: every case below must come back 401, never 500 (an
unhandled exception escaping to FastAPI's default handler) and never 200.

Manually confirmed via a standalone script against this exact PyJWT/
cryptography install (2.13.0 / 50.0.0) before writing this file:
alg=none, HS384 (same secret, different alg), and a fabricated RS256
header all raise `InvalidAlgorithmError`; wrong-signature raises
`InvalidSignatureError`; expired raises `ExpiredSignatureError`; garbage
raises `DecodeError` -- all `PyJWTError` subclasses, all already exercised
end-to-end below via the actual endpoints.
"""

import base64
import json

import jwt

from app.core.config import settings


def _b64url(data: bytes) -> bytes:
    return base64.urlsafe_b64encode(data).rstrip(b"=")


async def test_me_rejects_alg_none_unsigned_token(client, api_prefix, user_factory):
    """The classic `alg=none` forgery: no signature at all. PyJWT's
    `algorithms=["HS256"]` allow-list must reject this before any signature
    verification is even attempted."""
    user, _ = await user_factory(email="alg-none@example.com")
    forged = jwt.encode(
        {"sub": user.email, "type": "access", "ver": 0, "exp": 9999999999},
        key="",
        algorithm="none",
    )

    resp = await client.get(
        f"{api_prefix}/auth/me", headers={"Authorization": f"Bearer {forged}"}
    )

    assert resp.status_code == 401, (
        f"alg=none token must be rejected with 401, not {resp.status_code} "
        "(a 500 here would mean InvalidAlgorithmError escaped unhandled)"
    )


async def test_me_rejects_unexpected_but_validly_signed_algorithm(
    client, api_prefix, user_factory
):
    """A token signed with the REAL SECRET_KEY, just under a different
    (still HMAC) algorithm than the app is configured for. This isolates
    the algorithm check from the signature check -- the signature would
    actually verify under HS384 with this key, so if `algorithms=[...]`
    weren't enforced (or PyJWT silently accepted any HMAC alg), this would
    wrongly succeed."""
    user, _ = await user_factory(email="alg-hs384@example.com")
    forged = jwt.encode(
        {"sub": user.email, "type": "access", "ver": 0, "exp": 9999999999},
        key=settings.SECRET_KEY,
        algorithm="HS384",
    )

    resp = await client.get(
        f"{api_prefix}/auth/me", headers={"Authorization": f"Bearer {forged}"}
    )

    assert resp.status_code == 401, (
        f"HS384 token (unexpected alg, even though correctly 'signed' with "
        f"the real secret) must be rejected with 401, not {resp.status_code}"
    )


async def test_me_rejects_fabricated_rs256_header(client, api_prefix, user_factory):
    """A token whose header claims alg=RS256 (algorithm-confusion attack
    shape: trick the verifier into treating a public key as an HMAC secret).
    No real RSA keypair is needed to prove the point -- the alg allow-list
    check happens before any key-material handling, so a fabricated
    signature segment is sufficient to prove this is rejected early."""
    user, _ = await user_factory(email="alg-rs256@example.com")
    header = _b64url(json.dumps({"alg": "RS256", "typ": "JWT"}).encode())
    payload = _b64url(
        json.dumps(
            {"sub": user.email, "type": "access", "ver": 0, "exp": 9999999999}
        ).encode()
    )
    forged = (header + b"." + payload + b".fakesignature").decode()

    resp = await client.get(
        f"{api_prefix}/auth/me", headers={"Authorization": f"Bearer {forged}"}
    )

    assert resp.status_code == 401, (
        f"fabricated RS256-header token must be rejected with 401, not "
        f"{resp.status_code}"
    )


async def test_refresh_rejects_alg_none_unsigned_token(client, api_prefix, user_factory):
    """Same algorithm-confusion check against the OTHER decode path
    (`app/core/security.py::_decode_refresh_payload`, used by
    `/auth/refresh`) -- deliberately not just `/auth/me`/`deps.py`, since
    OBJ-008 touched both call sites independently."""
    user, _ = await user_factory(email="alg-none-refresh@example.com")
    forged = jwt.encode(
        {
            "sub": user.email,
            "type": "refresh",
            "ver": 0,
            "jti": "00000000-0000-0000-0000-000000000000",
            "exp": 9999999999,
        },
        key="",
        algorithm="none",
    )

    resp = await client.post(
        f"{api_prefix}/auth/refresh", json={"refresh_token": forged}
    )

    assert resp.status_code == 401, (
        f"alg=none refresh token must be rejected with 401, not "
        f"{resp.status_code}"
    )


async def test_refresh_rejects_unexpected_but_validly_signed_algorithm(
    client, api_prefix, user_factory
):
    user, _ = await user_factory(email="alg-hs384-refresh@example.com")
    forged = jwt.encode(
        {
            "sub": user.email,
            "type": "refresh",
            "ver": 0,
            "jti": "00000000-0000-0000-0000-000000000000",
            "exp": 9999999999,
        },
        key=settings.SECRET_KEY,
        algorithm="HS384",
    )

    resp = await client.post(
        f"{api_prefix}/auth/refresh", json={"refresh_token": forged}
    )

    assert resp.status_code == 401, (
        f"HS384 refresh token must be rejected with 401, not "
        f"{resp.status_code}"
    )
