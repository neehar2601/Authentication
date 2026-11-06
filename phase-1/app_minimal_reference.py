"""AuthLab resource API: validates Keycloak access tokens and enforces roles."""
import os
from functools import wraps

import jwt
from flask import Flask, g, jsonify, request
from jwt import PyJWKClient

ISSUER = os.environ["TOKEN_ISSUER"]
JWKS_URL = os.environ["JWKS_URL"]
AUDIENCE = os.environ.get("API_AUDIENCE", "authlab-api")

app = Flask(__name__)
jwks = PyJWKClient(JWKS_URL, cache_keys=True)  # caches signing keys, refetches on unknown kid


def err(status, code, detail):
    return jsonify(error=code, detail=detail), status


def require_auth(*roles):
    """401 = we can't trust who you are. 403 = we know you, and the answer is no."""
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            header = request.headers.get("Authorization", "")
            if not header.startswith("Bearer "):
                return err(401, "missing_token", "Send Authorization: Bearer <token>")
            token = header[7:]
            try:
                key = jwks.get_signing_key_from_jwt(token).key
                claims = jwt.decode(
                    token,
                    key,
                    algorithms=["RS256"],          # allow-list: never trust the alg header
                    issuer=ISSUER,
                    audience=AUDIENCE,
                    options={"require": ["exp", "iat", "iss", "aud", "sub"]},
                )
            except jwt.ExpiredSignatureError:
                return err(401, "token_expired", "Access token has expired")
            except jwt.InvalidTokenError as e:
                return err(401, "invalid_token", type(e).__name__)
            except Exception:
                return err(503, "jwks_unavailable", "Could not reach the identity provider")

            user_roles = claims.get("realm_access", {}).get("roles", [])
            if roles and not set(roles) & set(user_roles):
                return err(403, "forbidden", f"Requires one of: {', '.join(roles)}")
            g.claims = claims
            return fn(*a, **kw)
        return wrapper
    return deco


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.get("/api/public")
def public():
    return jsonify(message="No token needed")


@app.get("/api/me")
@require_auth()
def me():
    c = g.claims
    return jsonify(sub=c["sub"], username=c.get("preferred_username"),
                   roles=c.get("realm_access", {}).get("roles", []), exp=c["exp"])


@app.get("/api/users")
@require_auth("viewer", "developer", "admin")
def users():
    return jsonify(users=[{"id": 1024, "name": "demo"}])


@app.get("/api/admin/users")
@require_auth("admin")
def admin_users():
    return jsonify(message="Admin area", requested_by=g.claims.get("preferred_username"))
