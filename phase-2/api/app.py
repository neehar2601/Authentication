"""AuthLab resource API: validates Keycloak access tokens, enforces roles, and records security audit logs."""
import collections
import logging
import os
import sys
from datetime import datetime, timezone
from functools import wraps

import jwt
from flask import Flask, g, jsonify, request, has_request_context
from jwt import PyJWKClient

ISSUER = os.environ["TOKEN_ISSUER"]
JWKS_URL = os.environ["JWKS_URL"]
AUDIENCE = os.environ.get("API_AUDIENCE", "authlab-api")

app = Flask(__name__)
jwks = PyJWKClient(JWKS_URL, cache_keys=True)  # caches signing keys, refetches on unknown kid
STATIC_DIR = os.path.join(os.path.dirname(__file__), "frontend")

# ============================================================================
# STRUCTURED SECURITY AUDIT LOGGER
# ============================================================================

security_logger = logging.getLogger("authlab.security")
security_logger.setLevel(logging.INFO)

if not security_logger.handlers:
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(
        logging.Formatter(
            "[%(asctime)s] [%(levelname)s] [SECURITY_AUDIT] %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )
    )
    security_logger.addHandler(console_handler)

AUDIT_LOG_BUFFER = collections.deque(maxlen=250)
EVENT_COUNTER = 0


def record_security_event(
    event_type: str,
    severity: str,
    actor: str,
    endpoint: str,
    method: str,
    status_code: int,
    detail: str,
    roles: list = None,
    client_ip: str = None,
):
    """Logs security access attempts and cryptographic attack vectors to stdout, file, and in-memory buffer."""
    global EVENT_COUNTER
    EVENT_COUNTER += 1
    event_id = f"SEC-{EVENT_COUNTER:04d}"
    now_utc = datetime.now(timezone.utc)
    timestamp_str = now_utc.strftime("%Y-%m-%d %H:%M:%S UTC")

    if client_ip:
        ip = client_ip
    elif has_request_context():
        ip = request.headers.get("X-Forwarded-For", request.remote_addr or "127.0.0.1")
    else:
        ip = "127.0.0.1"

    event = {
        "id": event_id,
        "timestamp": timestamp_str,
        "timestamp_epoch": int(now_utc.timestamp()),
        "event_type": event_type,
        "severity": severity,  # CRITICAL, HIGH, WARN, INFO
        "actor": actor or "anonymous",
        "roles": roles or [],
        "endpoint": endpoint,
        "method": method,
        "status_code": status_code,
        "ip": ip,
        "detail": detail,
    }

    AUDIT_LOG_BUFFER.appendleft(event)

    log_msg = (
        f"{event_id} | {event_type} | {severity} | "
        f"Actor: {event['actor']} | {method} {endpoint} | "
        f"HTTP {status_code} | {detail}"
    )

    if severity == "CRITICAL":
        security_logger.error(log_msg)
    elif severity in ("HIGH", "WARN"):
        security_logger.warning(log_msg)
    else:
        security_logger.info(log_msg)

    try:
        with open("/tmp/authlab_security.log", "a") as f:
            f.write(f"[{timestamp_str}] [{severity}] {log_msg}\n")
    except Exception:
        pass

    return event


# Seed server initialization event
record_security_event(
    event_type="SYSTEM_INITIALIZED",
    severity="INFO",
    actor="system",
    endpoint="/",
    method="INIT",
    status_code=200,
    detail="AuthLab Phase 2 Security Verifier started with live RS256 JWKS enforcement",
)


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
                record_security_event(
                    event_type="AUTH_TOKEN_MISSING",
                    severity="WARN",
                    actor="anonymous",
                    endpoint=request.path,
                    method=request.method,
                    status_code=401,
                    detail="Request missing Authorization: Bearer token header",
                )
                return err(401, "missing_token", "Send Authorization: Bearer <token>")

            token = header[7:].strip()

            # Pre-decode inspection for attack vector classification
            unverified_header = {}
            unverified_claims = {}
            try:
                unverified_header = jwt.get_unverified_header(token)
            except Exception:
                pass

            try:
                unverified_claims = jwt.decode(
                    token,
                    options={"verify_signature": False, "verify_exp": False, "verify_aud": False, "verify_iss": False},
                )
            except Exception:
                pass

            alg = unverified_header.get("alg")
            actor_attempted = unverified_claims.get("preferred_username") or unverified_claims.get("sub") or "untrusted_client"

            # -------------------------------------------------------------
            # EXPLOIT DETECTION 1: alg: "none" Signature Stripping Attack
            # -------------------------------------------------------------
            if alg == "none":
                record_security_event(
                    event_type="ATTACK_SIGNATURE_STRIPPING",
                    severity="CRITICAL",
                    actor=actor_attempted,
                    endpoint=request.path,
                    method=request.method,
                    status_code=401,
                    detail='Signature stripping exploit (alg: "none") detected and blocked by RS256 algorithm pinning',
                )
                return err(401, "invalid_algorithm", 'Algorithm "none" is strictly forbidden. RS256 required.')

            # -------------------------------------------------------------
            # EXPLOIT DETECTION 2: alg: "HS256" Key Confusion (CVE-2015-9235)
            # -------------------------------------------------------------
            if alg == "HS256":
                record_security_event(
                    event_type="ATTACK_KEY_CONFUSION",
                    severity="CRITICAL",
                    actor=actor_attempted,
                    endpoint=request.path,
                    method=request.method,
                    status_code=401,
                    detail='Public key confusion exploit (CVE-2015-9235, alg: "HS256") detected and blocked: symmetric HMAC rejected on asymmetric RS256 endpoint',
                )
                return err(401, "invalid_algorithm", 'Algorithm "HS256" is strictly forbidden. RS256 required.')

            # Ensure algorithm is strictly RS256
            if alg != "RS256":
                record_security_event(
                    event_type="ATTACK_DISALLOWED_ALGORITHM",
                    severity="HIGH",
                    actor=actor_attempted,
                    endpoint=request.path,
                    method=request.method,
                    status_code=401,
                    detail=f'Disallowed algorithm: "{alg}". Verifier requires RS256 only.',
                )
                return err(401, "invalid_algorithm", f'Algorithm "{alg}" is forbidden. RS256 required.')

            # -------------------------------------------------------------
            # CRYPTOGRAPHIC KEY RETRIEVAL & SIGNATURE VERIFICATION
            # -------------------------------------------------------------
            try:
                key = jwks.get_signing_key_from_jwt(token).key
            except jwt.exceptions.PyJWKClientError as e:
                record_security_event(
                    event_type="UNKNOWN_SIGNING_KEY",
                    severity="HIGH",
                    actor=actor_attempted,
                    endpoint=request.path,
                    method=request.method,
                    status_code=401,
                    detail=f"Token signed by unknown key ID (kid: {unverified_header.get('kid')}): not found in Keycloak JWKS",
                )
                return err(401, "invalid_key", "Signing key not found in identity provider JWKS")
            except Exception as e:
                record_security_event(
                    event_type="IDP_COMMUNICATION_ERROR",
                    severity="WARN",
                    actor=actor_attempted,
                    endpoint=request.path,
                    method=request.method,
                    status_code=503,
                    detail=f"Could not reach Keycloak JWKS endpoint: {str(e)}",
                )
                return err(503, "jwks_unavailable", "Could not reach the identity provider")

            try:
                claims = jwt.decode(
                    token,
                    key,
                    algorithms=["RS256"],          # allow-list: never trust the alg header
                    issuer=ISSUER,
                    audience=AUDIENCE,
                    options={"require": ["exp", "iat", "iss", "aud", "sub"]},
                )
            except jwt.ExpiredSignatureError:
                record_security_event(
                    event_type="TOKEN_EXPIRED_REPLAY",
                    severity="WARN",
                    actor=actor_attempted,
                    endpoint=request.path,
                    method=request.method,
                    status_code=401,
                    detail=f"Expired token presented for user '{actor_attempted}' (exp: {unverified_claims.get('exp')})",
                )
                return err(401, "token_expired", "Access token has expired")

            except jwt.InvalidSignatureError:
                record_security_event(
                    event_type="ATTACK_PAYLOAD_TAMPERING",
                    severity="CRITICAL",
                    actor=actor_attempted,
                    endpoint=request.path,
                    method=request.method,
                    status_code=401,
                    detail=f"Cryptographic signature check failed: payload was modified in transit (claimed roles: {unverified_claims.get('realm_access', {}).get('roles')})",
                )
                return err(401, "invalid_token", "Invalid signature: token payload was altered")

            except jwt.InvalidTokenError as e:
                record_security_event(
                    event_type="INVALID_TOKEN_ATTEMPT",
                    severity="HIGH",
                    actor=actor_attempted,
                    endpoint=request.path,
                    method=request.method,
                    status_code=401,
                    detail=f"Token validation failed: {type(e).__name__}",
                )
                return err(401, "invalid_token", type(e).__name__)

            # -------------------------------------------------------------
            # ROLE-BASED ACCESS CONTROL (RBAC) ENFORCEMENT
            # -------------------------------------------------------------
            raw_roles = claims.get("realm_access", {}).get("roles", [])
            normalized_roles = set(r.lower() for r in raw_roles)
            if "user" in normalized_roles:
                normalized_roles.add("viewer")
            required_roles = set(r.lower() for r in roles)
            actor = claims.get("preferred_username") or claims.get("sub")

            if roles and not (required_roles & normalized_roles):
                record_security_event(
                    event_type="RBAC_ACCESS_DENIED",
                    severity="HIGH",
                    actor=actor,
                    roles=list(raw_roles),
                    endpoint=request.path,
                    method=request.method,
                    status_code=403,
                    detail=f"Clearance violation: user '{actor}' has roles {list(raw_roles)}, but endpoint requires one of: {list(roles)}",
                )
                return err(403, "forbidden", f"Requires one of: {', '.join(roles)}")

            # Access Approved
            record_security_event(
                event_type="ACCESS_GRANTED",
                severity="INFO",
                actor=actor,
                roles=list(raw_roles),
                endpoint=request.path,
                method=request.method,
                status_code=200,
                detail=f"Access granted to {request.path} with verified RS256 token",
            )
            g.claims = claims
            return fn(*a, **kw)
        return wrapper
    return deco


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.get("/api/public")
def public():
    record_security_event(
        event_type="PUBLIC_ACCESS",
        severity="INFO",
        actor="anonymous",
        endpoint="/api/public",
        method="GET",
        status_code=200,
        detail="Public unauthenticated resource requested",
    )
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
    recent_logs = list(AUDIT_LOG_BUFFER)[:20]
    return jsonify(
        access_tier="Tier 3: Administrator Security & Governance Control Center",
        requested_by=g.claims.get("preferred_username"),
        system_governance={
            "realm": "Authlab",
            "token_algorithm": "RS256 (RSA 2048-bit)",
            "token_ttl_seconds": 300,
            "jwks_active_keys": 2,
            "zero_trust_policy": "Strict Audience + Issuer Pinning Enforced",
            "total_audit_events": len(AUDIT_LOG_BUFFER),
            "attacks_intercepted": sum(1 for e in AUDIT_LOG_BUFFER if "ATTACK" in e["event_type"]),
        },
        security_audit_log=recent_logs,
        privileged_actions=[
            "Revoke Active User Tokens",
            "Rotate Identity Provider RSA Keys",
            "Enforce Global Session Termination",
            "Export Audit Logs to Security Information and Event Management (SIEM)",
        ],
    )


@app.get("/api/audit-logs")
def get_audit_logs():
    """Live security audit log endpoint for monitoring and dashboard integration."""
    filter_type = request.args.get("filter", "all").lower()
    limit = int(request.args.get("limit", 50))

    events = list(AUDIT_LOG_BUFFER)

    if filter_type == "attacks":
        events = [e for e in events if "ATTACK" in e["event_type"] or "EXPIRED" in e["event_type"]]
    elif filter_type == "denied":
        events = [e for e in events if e["status_code"] in (401, 403)]
    elif filter_type == "granted":
        events = [e for e in events if e["status_code"] == 200]

    summary = {
        "total_events": len(AUDIT_LOG_BUFFER),
        "attacks_blocked": sum(1 for e in AUDIT_LOG_BUFFER if "ATTACK" in e["event_type"]),
        "forbidden_blocked": sum(1 for e in AUDIT_LOG_BUFFER if e["status_code"] == 403),
        "access_granted": sum(1 for e in AUDIT_LOG_BUFFER if e["status_code"] == 200),
        "expired_replays": sum(1 for e in AUDIT_LOG_BUFFER if "EXPIRED" in e["event_type"]),
    }

    return jsonify(
        status="ok",
        summary=summary,
        total_matched=len(events),
        events=events[:limit],
    )


@app.post("/api/audit-logs/clear")
def clear_audit_logs():
    """Clears the in-memory audit log buffer."""
    AUDIT_LOG_BUFFER.clear()
    record_security_event(
        event_type="AUDIT_LOG_CLEARED",
        severity="WARN",
        actor="admin",
        endpoint="/api/audit-logs/clear",
        method="POST",
        status_code=200,
        detail="Security audit log buffer was reset by administrator",
    )
    return jsonify(status="ok", message="Audit logs cleared successfully")


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
