"""Phase 2: a tiny JWT issuer and verifier, written to be broken on purpose.

secure verify_token()  -> allow-list, kid lookup, iss/aud/exp checks
naive_verify_token()   -> trusts the alg header. Educational only. Never use it.
"""
import hashlib
import hmac
import json
import base64
import time
import uuid

import jwt
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

ISSUER = "http://localhost:5001"
AUDIENCE = "authlab-api"


class KeyStore:
    """Holds RSA signing keys by kid. Supports rotation and retirement."""

    def __init__(self):
        self.keys = {}
        self.current = None
        self.rotate()

    def rotate(self):
        kid = uuid.uuid4().hex[:8]
        self.keys[kid] = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.current = kid
        return kid

    def retire(self, kid):
        """Drop a key. Tokens signed with it stop validating."""
        self.keys.pop(kid, None)

    def private_key(self, kid=None):
        return self.keys[kid or self.current]

    def public_key(self, kid):
        return self.keys[kid].public_key() if kid in self.keys else None

    def public_pem(self, kid):
        return self.public_key(kid).public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)

    def jwks(self):
        out = []
        for kid in self.keys:
            jwk = jwt.algorithms.RSAAlgorithm.to_jwk(self.public_key(kid), as_dict=True)
            out.append({**jwk, "kid": kid, "use": "sig", "alg": "RS256"})
        return {"keys": out}


def issue_token(store, sub, roles, ttl=900, **overrides):
    now = int(time.time())
    payload = {"iss": ISSUER, "aud": AUDIENCE, "sub": sub, "roles": roles,
               "iat": now, "exp": now + ttl, "jti": uuid.uuid4().hex}
    payload.update(overrides)
    payload = {k: v for k, v in payload.items() if v is not None}  # None removes a claim
    return jwt.encode(payload, store.private_key(), algorithm="RS256",
                      headers={"kid": store.current})


def verify_token(token, store):
    """Secure verifier. Raises a jwt.InvalidTokenError subclass on any failure."""
    header = jwt.get_unverified_header(token)
    key = store.public_key(header.get("kid"))
    if key is None:
        raise jwt.InvalidTokenError("unknown kid")
    return jwt.decode(
        token, key,
        algorithms=["RS256"],                       # fixed allow-list
        issuer=ISSUER, audience=AUDIENCE,
        options={"require": ["exp", "iat", "iss", "aud", "sub"]},
    )


# ---------------------------------------------------------------- vulnerable
def _b64d(s):
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def naive_verify_token(token, store):
    """VULNERABLE on purpose: believes whatever 'alg' the token claims."""
    h, p, s = token.split(".")
    header, payload = json.loads(_b64d(h)), json.loads(_b64d(p))
    alg = header.get("alg")
    if alg == "none":
        return payload                                         # bug 1: unsigned accepted
    if alg == "HS256":                                         # bug 2: key confusion
        secret = store.public_pem(header["kid"])               # public key used as HMAC secret
        expected = base64.urlsafe_b64encode(
            hmac.new(secret, f"{h}.{p}".encode(), hashlib.sha256).digest()).rstrip(b"=").decode()
        if hmac.compare_digest(expected, s):
            return payload
        raise jwt.InvalidSignatureError("bad hmac")
    return jwt.decode(token, store.public_key(header["kid"]), algorithms=["RS256"],
                      options={"verify_aud": False, "verify_iss": False})
