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
STATIC_DIR = os.path.join(os.path.dirname(__file__), "frontend")


@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    return response


@app.route("/<path:subpath>", methods=["OPTIONS"])
@app.route("/", methods=["OPTIONS"])
def handle_options(subpath=None):
    return "", 204


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

            raw_roles = claims.get("realm_access", {}).get("roles", [])
            normalized_roles = set(r.lower() for r in raw_roles)
            if "user" in normalized_roles:
                normalized_roles.add("viewer")
            required_roles = set(r.lower() for r in roles)
            if roles and not (required_roles & normalized_roles):
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
    return jsonify(
        message="Public Resource: No authentication required",
        status="online",
        realm="Authlab",
    )


@app.get("/api/me")
@require_auth()
def me():
    c = g.claims
    roles = c.get("realm_access", {}).get("roles", [])
    clean_roles = [
        r for r in roles
        if r not in ("default-roles-authlab", "offline_access", "uma_authorization")
    ]
    primary_role = (
        "admin" if any(r.lower() == "admin" for r in roles)
        else "developer" if any(r.lower() == "developer" for r in roles)
        else "viewer"
    )
    return jsonify(
        sub=c["sub"],
        username=c.get("preferred_username"),
        name=c.get("name") or c.get("preferred_username"),
        email=c.get("email", ""),
        primary_role=primary_role,
        roles=clean_roles,
        exp=c["exp"],
        iss=c.get("iss"),
        aud=c.get("aud"),
    )


@app.get("/api/users")
@require_auth("viewer", "developer", "admin")
def users():
    """Tier 1: Accessible by Viewer (User), Developer, and Admin."""
    return jsonify(
        access_tier="Tier 1: General Reader Workspace",
        authorized_user=g.claims.get("preferred_username"),
        directory=[
            {"id": 101, "name": "Alice User", "username": "alice", "clearance": "Reader (L1)", "email": "alice@authlab.local", "status": "Active"},
            {"id": 102, "name": "Drench Dev", "username": "drench", "clearance": "Developer (L2)", "email": "drench@authlab.local", "status": "Active"},
            {"id": 103, "name": "Bob Admin", "username": "bob", "clearance": "Admin (L3)", "email": "bob@authlab.local", "status": "Active"},
        ],
        knowledge_base=[
            {"id": "KB-201", "title": "OAuth 2.0 / OIDC Architecture Overview", "category": "Architecture", "version": "v2.6", "updated": "2026-11-06"},
            {"id": "KB-202", "title": "RS256 Signature Verification via JWKS", "category": "Security Guide", "version": "v1.4", "updated": "2026-11-06"},
            {"id": "KB-203", "title": "Platform Service Health & Incident SLA", "category": "Operations", "version": "99.98% Uptime", "updated": "Today"},
        ],
    )


@app.get("/api/developer/config")
@require_auth("developer", "admin")
def developer_config():
    """Tier 2: Accessible ONLY by Developer and Admin."""
    return jsonify(
        access_tier="Tier 2: Developer Configuration & Pipelines",
        authorized_developer=g.claims.get("preferred_username"),
        environment="staging-eu-west-1",
        feature_flags={
            "ENABLE_ASYNC_PIPELINE": True,
            "CANARY_DEPLOYMENT_WEIGHT": 25,
            "DEBUG_TRACE_SAMPLING": False,
            "ENFORCE_STRICT_RATE_LIMITS": True,
        },
        services_topology=[
            {"name": "auth-service", "host": "keycloak:8080", "protocol": "OIDC", "status": "Healthy"},
            {"name": "resource-api", "host": "api:5000", "protocol": "REST / RS256", "status": "Healthy"},
            {"name": "postgres-cluster", "host": "postgres:5432", "protocol": "TCP", "status": "Healthy"},
        ],
        build_pipeline={
            "last_commit": "1d29755",
            "branch": "main",
            "tests_passed": 16,
            "code_coverage": "100%",
        },
    )


@app.get("/api/admin/users")
@require_auth("admin")
def admin_users():
    """Tier 3: Accessible ONLY by Admin."""
    return jsonify(
        access_tier="Tier 3: Administrator Security & Governance Control Center",
        requested_by=g.claims.get("preferred_username"),
        system_governance={
            "realm": "Authlab",
            "token_algorithm": "RS256 (RSA 2048-bit)",
            "token_ttl_seconds": 300,
            "jwks_active_keys": 2,
            "zero_trust_policy": "Strict Audience + Issuer Pinning Enforced",
        },
        security_audit_log=[
            {"id": "EV-941", "timestamp": "Just now", "action": "ADMIN_CONTROL_ACCESSED", "actor": g.claims.get("preferred_username"), "status": "SUCCESS"},
            {"id": "EV-940", "timestamp": "10 mins ago", "action": "TOKEN_ISSUED_RS256", "actor": "alice", "status": "SUCCESS"},
            {"id": "EV-939", "timestamp": "14 mins ago", "action": "UNAUTHORIZED_ADMIN_ATTEMPT", "actor": "alice", "status": "BLOCKED_403"},
            {"id": "EV-938", "timestamp": "1 hour ago", "action": "JWKS_KEY_ROTATION_CHECK", "actor": "system", "status": "VERIFIED"},
        ],
        privileged_actions=[
            "Revoke Active User Tokens",
            "Rotate Identity Provider RSA Keys",
            "Enforce Global Session Termination",
            "Export Audit Logs to Security Information and Event Management (SIEM)",
        ],
    )


@app.get("/")
@app.get("/index.html")
def serve_index():
    index_file = os.path.join(STATIC_DIR, "index.html")
    if os.path.exists(index_file):
        from flask import send_file
        return send_file(index_file)
    return jsonify(status="ok", service="AuthLab Phase 2 API")


@app.get("/<path:filename>")
def serve_static(filename):
    from flask import send_from_directory
    if os.path.exists(os.path.join(STATIC_DIR, filename)):
        return send_from_directory(STATIC_DIR, filename)
    return jsonify(error="not_found"), 404
