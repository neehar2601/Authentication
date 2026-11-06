import base64, hashlib, hmac, json, time

import jwt
import pytest

from auth import KeyStore, issue_token, verify_token, naive_verify_token
from app import create_app


def b64(d):
    return base64.urlsafe_b64encode(d).rstrip(b"=").decode()


def forge(header, payload, secret=None):
    h, p = b64(json.dumps(header).encode()), b64(json.dumps(payload).encode())
    sig = b64(hmac.new(secret, f"{h}.{p}".encode(), hashlib.sha256).digest()) if secret else ""
    return f"{h}.{p}.{sig}"


def admin_claims():
    now = int(time.time())
    return {"iss": "http://localhost:5001", "aud": "authlab-api", "sub": "mallory",
            "roles": ["admin"], "iat": now, "exp": now + 900}


@pytest.fixture
def store():
    return KeyStore()


# ---------------------------------------------------------------- happy path
def test_valid_token_is_accepted(store):
    claims = verify_token(issue_token(store, "alice", ["viewer"]), store)
    assert claims["sub"] == "alice" and claims["roles"] == ["viewer"]


# ---------------------------------------------------------------- claim checks
def test_expired_token_rejected(store):
    with pytest.raises(jwt.ExpiredSignatureError):
        verify_token(issue_token(store, "alice", ["viewer"], exp=int(time.time()) - 60), store)


def test_wrong_audience_rejected(store):
    with pytest.raises(jwt.InvalidAudienceError):
        verify_token(issue_token(store, "alice", ["viewer"], aud="other-api"), store)


def test_wrong_issuer_rejected(store):
    with pytest.raises(jwt.InvalidIssuerError):
        verify_token(issue_token(store, "alice", ["viewer"], iss="https://evil.example"), store)


def test_missing_exp_rejected(store):
    with pytest.raises(jwt.MissingRequiredClaimError):
        verify_token(issue_token(store, "alice", ["viewer"], exp=None), store)


# ---------------------------------------------------------------- signature attacks
def test_tampered_payload_rejected(store):
    h, p, s = issue_token(store, "alice", ["viewer"]).split(".")
    payload = json.loads(base64.urlsafe_b64decode(p + "=" * (-len(p) % 4)))
    payload["roles"] = ["admin"]
    with pytest.raises(jwt.InvalidSignatureError):
        verify_token(f"{h}.{b64(json.dumps(payload).encode())}.{s}", store)


def test_token_signed_with_attacker_key_rejected(store):
    attacker = KeyStore()
    token = jwt.encode(admin_claims(), attacker.private_key(), algorithm="RS256",
                       headers={"kid": store.current})  # claims the real kid
    with pytest.raises(jwt.InvalidSignatureError):
        verify_token(token, store)


def test_unknown_kid_rejected(store):
    token = jwt.encode(admin_claims(), store.private_key(), algorithm="RS256",
                       headers={"kid": "nope"})
    with pytest.raises(jwt.InvalidTokenError):
        verify_token(token, store)


# ---------------------------------------------------------------- alg attacks
def test_alg_none_rejected_by_secure_verifier_but_fooled_naive(store):
    token = forge({"alg": "none", "typ": "JWT", "kid": store.current}, admin_claims())
    with pytest.raises(jwt.InvalidTokenError):
        verify_token(token, store)
    assert naive_verify_token(token, store)["roles"] == ["admin"]      # exploit works


def test_hs256_key_confusion_rejected_by_secure_verifier_but_fooled_naive(store):
    # Attacker only knows the PUBLIC key (it is published in the JWKS) and uses it as an HMAC secret.
    token = forge({"alg": "HS256", "typ": "JWT", "kid": store.current}, admin_claims(),
                  secret=store.public_pem(store.current))
    with pytest.raises(jwt.InvalidTokenError):
        verify_token(token, store)
    assert naive_verify_token(token, store)["roles"] == ["admin"]      # exploit works


# ---------------------------------------------------------------- key rotation
def test_rotation_old_tokens_valid_until_key_retired(store):
    old_kid = store.current
    old_token = issue_token(store, "alice", ["viewer"])
    store.rotate()
    assert verify_token(old_token, store)["sub"] == "alice"            # old key still published
    assert len(store.jwks()["keys"]) == 2
    store.retire(old_kid)
    with pytest.raises(jwt.InvalidTokenError):
        verify_token(old_token, store)


# ---------------------------------------------------------------- HTTP layer
@pytest.fixture
def client():
    return create_app().test_client()


def login(client, user, pw="demo-password"):
    return client.post("/token", json={"username": user, "password": pw})


def test_bad_password_is_401(client):
    assert login(client, "alice", "wrong").status_code == 401


def test_no_token_is_401(client):
    assert client.get("/api/me").status_code == 401


def test_viewer_gets_403_on_admin(client):
    t = login(client, "alice").json["access_token"]
    r = client.get("/api/admin", headers={"Authorization": f"Bearer {t}"})
    assert r.status_code == 403


def test_admin_gets_200_on_admin(client):
    t = login(client, "bob").json["access_token"]
    r = client.get("/api/admin", headers={"Authorization": f"Bearer {t}"})
    assert r.status_code == 200


def test_jwks_endpoint_publishes_public_keys_only(client):
    keys = client.get("/.well-known/jwks.json").json["keys"]
    assert keys and all("d" not in k and k["alg"] == "RS256" for k in keys)
