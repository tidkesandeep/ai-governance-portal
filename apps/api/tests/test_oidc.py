from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient
from jwt.algorithms import RSAAlgorithm

from aigov.config import get_settings
from aigov.domains.identity.oidc import principal_from_jwt
from aigov.domains.identity.principal import AuthError
from aigov.main import create_app

ISSUER = "https://idp.example.test"
AUDIENCE = "aigov-api"
KID = "slice8-test-key"


def _rsa_pair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key, key.public_key()


def _jwks_json(public_key) -> str:
    jwk = json.loads(RSAAlgorithm.to_jwk(public_key))
    jwk["kid"] = KID
    jwk["use"] = "sig"
    jwk["alg"] = "RS256"
    return json.dumps({"keys": [jwk]})


def _token(private_key, **claims) -> str:
    now = datetime.now(tz=UTC)
    payload = {
        "iss": ISSUER,
        "aud": AUDIENCE,
        "sub": "u_oidc_engineer",
        "tid": "demo",
        "roles": ["ml_engineer", "owner"],
        "name": "OIDC Engineer",
        "iat": now,
        "exp": now + timedelta(minutes=10),
        **claims,
    }
    return jwt.encode(payload, private_key, algorithm="RS256", headers={"kid": KID})


@pytest.fixture
def keys():
    return _rsa_pair()


@pytest.fixture
def oidc_client(tmp_path, monkeypatch, keys):
    _private, public = keys
    monkeypatch.setenv("AIGOV_DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path}/oidc.db")
    monkeypatch.setenv("AIGOV_OPA_URL", "")
    monkeypatch.setenv("AIGOV_DEMO_AUTH", "false")
    monkeypatch.setenv("AIGOV_EVIDENCE_DIR", str(tmp_path / "evidence"))
    monkeypatch.setenv("AIGOV_OIDC_ISSUER", ISSUER)
    monkeypatch.setenv("AIGOV_OIDC_AUDIENCE", AUDIENCE)
    monkeypatch.setenv("AIGOV_OIDC_JWKS_JSON", _jwks_json(public))
    get_settings.cache_clear()
    application = create_app()
    with TestClient(application) as test_client:
        yield test_client, _private
    get_settings.cache_clear()


@pytest.fixture
def demo_client(tmp_path, monkeypatch):
    monkeypatch.setenv("AIGOV_DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path}/oidc-demo.db")
    monkeypatch.setenv("AIGOV_OPA_URL", "")
    monkeypatch.setenv("AIGOV_DEMO_AUTH", "true")
    monkeypatch.setenv("AIGOV_EVIDENCE_DIR", str(tmp_path / "evidence"))
    get_settings.cache_clear()
    application = create_app()
    with TestClient(application) as test_client:
        yield test_client
    get_settings.cache_clear()


def test_health_reports_demo_auth(demo_client) -> None:
    response = demo_client.get("/health")
    assert response.json()["details"]["auth"] == "demo"


def test_me_returns_demo_principal(demo_client) -> None:
    response = demo_client.get("/v1/me", headers={"Authorization": "Bearer demo"})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["actorId"] == "u_engineer"
    assert body["tenantId"] == "demo"
    assert body["authMethod"] == "demo"
    assert "ml_engineer" in body["roles"]


def test_demo_token_rejected_when_oidc_required(oidc_client) -> None:
    client, _private = oidc_client
    response = client.get("/v1/me", headers={"Authorization": "Bearer demo"})
    assert response.status_code == 401
    assert response.json()["code"] == "INVALID_TOKEN"


def test_valid_jwt_maps_tenant_roles_and_me(oidc_client) -> None:
    client, private = oidc_client
    token = _token(private)
    me = client.get("/v1/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200, me.text
    body = me.json()
    assert body["tenantId"] == "demo"
    assert body["actorId"] == "u_oidc_engineer"
    assert body["authMethod"] == "oidc"
    assert body["roles"] == ["ml_engineer", "owner"]
    listed = client.get("/v1/ai-systems", headers={"Authorization": f"Bearer {token}"})
    assert listed.status_code == 200


def test_expired_wrong_audience_and_missing_tenant_are_rejected(oidc_client) -> None:
    client, private = oidc_client
    expired = _token(private, exp=datetime.now(tz=UTC) - timedelta(minutes=5))
    assert client.get("/v1/me", headers={"Authorization": f"Bearer {expired}"}).status_code == 401
    wrong_aud = _token(private, aud="other-api")
    assert client.get("/v1/me", headers={"Authorization": f"Bearer {wrong_aud}"}).status_code == 401
    missing_tid = _token(private, tid="")
    denied = client.get("/v1/me", headers={"Authorization": f"Bearer {missing_tid}"})
    assert denied.status_code == 401
    assert denied.json()["code"] == "TENANT_CLAIM_MISSING"


def test_hs256_and_unknown_issuer_are_rejected(oidc_client, keys) -> None:
    client, _private = oidc_client
    now = datetime.now(tz=UTC)
    hmac_token = jwt.encode(
        {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "u_hmac",
            "tid": "demo",
            "exp": now + timedelta(minutes=5),
        },
        "not-an-oidc-secret-that-is-long-enough",
        algorithm="HS256",
    )
    hmac_resp = client.get("/v1/me", headers={"Authorization": f"Bearer {hmac_token}"})
    assert hmac_resp.status_code == 401
    other, _public = keys
    # reuse fixture private? keys is the pair for this test's generated key, not the server key
    forged = jwt.encode(
        {
            "iss": "https://evil.example",
            "aud": AUDIENCE,
            "sub": "u_forged",
            "tid": "demo",
            "exp": now + timedelta(minutes=5),
        },
        other,
        algorithm="RS256",
        headers={"kid": KID},
    )
    forged_resp = client.get("/v1/me", headers={"Authorization": f"Bearer {forged}"})
    assert forged_resp.status_code == 401


def test_tenant_isolation_and_reviewer_roles_from_jwt(oidc_client) -> None:
    client, private = oidc_client
    engineer = _token(private)
    created = client.post(
        "/v1/ai-systems",
        json={
            "name": "OIDC isolated model",
            "systemType": "PREDICTIVE_MODEL",
            "businessPurpose": "Prove tenant comes from the token",
            "owner": "payments-ml",
            "environment": "dev",
            "dataClassification": "INTERNAL",
            "geography": "US",
            "autonomyLevel": "HUMAN_IN_LOOP",
        },
        headers={"Authorization": f"Bearer {engineer}"},
    )
    assert created.status_code == 201, created.text
    system_id = created.json()["system"]["id"]
    other = _token(private, sub="u_acme", tid="acme", name="Acme Engineer")
    hidden = client.get(
        f"/v1/ai-systems/{system_id}",
        headers={"Authorization": f"Bearer {other}"},
    )
    assert hidden.status_code == 404
    reviewer = _token(
        private,
        sub="u_oidc_reviewer",
        roles=["privacy", "security", "risk"],
        name="OIDC Reviewer",
    )
    me = client.get("/v1/me", headers={"Authorization": f"Bearer {reviewer}"})
    assert set(me.json()["roles"]) == {"privacy", "security", "risk_reviewer"}


def test_principal_from_jwt_reads_keycloak_realm_roles(keys) -> None:
    private, public = keys
    token = _token(
        private,
        roles=None,
        realm_access={"roles": ["privacy", "engineer"]},
    )
    principal = principal_from_jwt(
        token,
        jwks=json.loads(_jwks_json(public)),
        issuer=ISSUER,
        audience=AUDIENCE,
    )
    assert principal.tenant_id == "demo"
    assert "privacy" in principal.roles
    assert "ml_engineer" in principal.roles
    try:
        principal_from_jwt(
            token,
            jwks=json.loads(_jwks_json(public)),
            issuer="https://other.example",
            audience=AUDIENCE,
        )
        raise AssertionError("expected AuthError")
    except AuthError as exc:
        assert exc.code == "INVALID_TOKEN"


def test_jwks_unreachable_fails_closed(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("AIGOV_DATABASE_URL", f"sqlite+aiosqlite:///{tmp_path}/oidc-down.db")
    monkeypatch.setenv("AIGOV_OPA_URL", "")
    monkeypatch.setenv("AIGOV_DEMO_AUTH", "false")
    monkeypatch.setenv("AIGOV_EVIDENCE_DIR", str(tmp_path / "evidence"))
    monkeypatch.setenv("AIGOV_OIDC_ISSUER", ISSUER)
    monkeypatch.setenv("AIGOV_OIDC_AUDIENCE", AUDIENCE)
    monkeypatch.setenv("AIGOV_OIDC_JWKS_URL", "http://127.0.0.1:1/jwks")
    get_settings.cache_clear()
    application = create_app()
    with TestClient(application) as client:
        response = client.get(
            "/v1/me",
            headers={"Authorization": "Bearer eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1In0.sig"},
        )
        assert response.status_code == 503
        assert response.json()["code"] == "AUTH_UNAVAILABLE"
    get_settings.cache_clear()
