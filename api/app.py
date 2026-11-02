"""AuthLab resource API: validates Keycloak access tokens and enforces roles."""
import collections
import datetime
import json
import os
import threading
import urllib.error
import urllib.parse
import urllib.request
from functools import wraps

import jwt
from flask import Flask, g, jsonify, request
from jwt import PyJWKClient

ISSUER = os.environ["TOKEN_ISSUER"]
JWKS_URL = os.environ["JWKS_URL"]
AUDIENCE = os.environ.get("API_AUDIENCE", "authlab-api")
KEYCLOAK_INTERNAL_URL = os.environ.get("KEYCLOAK_INTERNAL_URL", "http://keycloak:8080")
KEYCLOAK_REALM = os.environ.get("KEYCLOAK_REALM", "authlab")
KC_ADMIN_USER = os.environ.get("KC_ADMIN_USER", "admin")
KC_ADMIN_PASSWORD = os.environ.get("KC_ADMIN_PASSWORD", "")
ALLOWED_REGISTRATION_ROLES = {"viewer", "developer", "admin"}

app = Flask(__name__)
jwks = PyJWKClient(JWKS_URL, cache_keys=True)  # caches signing keys, refetches on unknown kid

# App-level audit log ring buffer (thread-safe)
_log_lock = threading.Lock()
audit_logs = collections.deque(maxlen=100)
_log_counter = 0


def record_log(endpoint, method, status, decision, detail, claims=None, kid=None):
    global _log_counter
    with _log_lock:
        _log_counter += 1
        entry = {
            "id": _log_counter,
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "endpoint": endpoint,
            "method": method,
            "status": status,
            "decision": decision,  # 'ALLOWED', 'DENIED_403', 'AUTH_ERROR_401', 'PUBLIC'
            "detail": detail,
            "kid": kid,
            "username": claims.get("preferred_username") if claims else None,
            "roles": claims.get("realm_access", {}).get("roles", []) if claims else [],
            "sub": claims.get("sub") if claims else None,
            "client_ip": request.remote_addr,
        }
        audit_logs.appendleft(entry)


@app.before_request
def handle_options():
    if request.method == "OPTIONS":
        response = jsonify({"status": "preflight_ok"})
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
        return response, 204


@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Authorization, Content-Type"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    return response


def err(status, code, detail, kid=None, claims=None):
    record_log(
        endpoint=request.path,
        method=request.method,
        status=status,
        decision="AUTH_ERROR_401" if status == 401 else "DENIED_403",
        detail=f"{code}: {detail}",
        kid=kid,
        claims=claims
    )
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
            kid = None
            claims = None
            try:
                signing_key = jwks.get_signing_key_from_jwt(token)
                kid = signing_key.key_id
                key = signing_key.key
                claims = jwt.decode(
                    token,
                    key,
                    algorithms=["RS256"],          # allow-list: never trust the alg header
                    issuer=ISSUER,
                    audience=AUDIENCE,
                    options={"require": ["exp", "iat", "iss", "aud", "sub"]},
                )
            except jwt.ExpiredSignatureError:
                return err(401, "token_expired", "Access token has expired", kid=kid)
            except jwt.InvalidTokenError as e:
                return err(401, "invalid_token", type(e).__name__, kid=kid)
            except Exception as e:
                return err(503, "jwks_unavailable", f"Could not reach identity provider: {type(e).__name__}", kid=kid)

            user_roles = claims.get("realm_access", {}).get("roles", [])
            if roles and not set(roles) & set(user_roles):
                return err(403, "forbidden", f"Requires one of: {', '.join(roles)}", kid=kid, claims=claims)
            g.claims = claims
            record_log(
                endpoint=request.path,
                method=request.method,
                status=200,
                decision="ALLOWED",
                detail=f"RS256 signature verified with key '{kid}'. Role check passed.",
                claims=claims,
                kid=kid
            )
            return fn(*a, **kw)
        return wrapper
    return deco


def _get_kc_admin_token():
    """Fetch a short-lived admin access token from Keycloak master realm."""
    token_url = f"{KEYCLOAK_INTERNAL_URL}/realms/master/protocol/openid-connect/token"
    form_data = urllib.parse.urlencode({
        "grant_type": "password",
        "client_id": "admin-cli",
        "username": KC_ADMIN_USER,
        "password": KC_ADMIN_PASSWORD,
    }).encode("utf-8")
    req = urllib.request.Request(
        token_url,
        data=form_data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=5) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
        return payload["access_token"]


def _kc_admin_request(path, method="GET", token=None, json_body=None):
    """Execute a request against the Keycloak Admin REST API."""
    if token is None:
        token = _get_kc_admin_token()
    url = f"{KEYCLOAK_INTERNAL_URL}/admin/realms/{KEYCLOAK_REALM}{path}"
    headers = {"Authorization": f"Bearer {token}"}
    data = None
    if json_body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(json_body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=5) as resp:
        raw = resp.read().decode("utf-8")
        return resp.status, resp.headers, (json.loads(raw) if raw else None)


@app.get("/health")
def health():
    return jsonify(status="ok")


@app.post("/api/register")
def register_user():
    """Register a new user in Keycloak and assign their realm role."""
    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip().lower()
    password = body.get("password") or ""
    role = (body.get("role") or "viewer").strip().lower()
    email = (body.get("email") or "").strip() or f"{username}@authlab.local"
    first_name = (body.get("firstName") or "").strip() or username.capitalize()
    last_name = (body.get("lastName") or "").strip() or role.capitalize()

    if not username or not password:
        return err(400, "invalid_input", "Username and password are required")
    if len(username) < 2 or " " in username:
        return err(400, "invalid_username", "Username must be at least 2 characters with no spaces")
    if len(password) < 4:
        return err(400, "weak_password", "Password must be at least 4 characters")
    if role not in ALLOWED_REGISTRATION_ROLES:
        return err(
            400,
            "invalid_role",
            f"Role must be one of: {', '.join(sorted(ALLOWED_REGISTRATION_ROLES))}",
        )

    try:
        admin_token = _get_kc_admin_token()

        # 1. Create the user in Keycloak with a non-temporary password and verified profile
        user_payload = {
            "username": username,
            "email": email,
            "firstName": first_name,
            "lastName": last_name,
            "enabled": True,
            "emailVerified": True,
            "requiredActions": [],
            "credentials": [
                {
                    "type": "password",
                    "value": password,
                    "temporary": False,
                }
            ],
        }
        _, headers, _ = _kc_admin_request(
            "/users", method="POST", token=admin_token, json_body=user_payload
        )

        # 2. Resolve the newly created user's ID
        location = headers.get("Location", "")
        user_id = location.rstrip("/").split("/")[-1] if location else None
        if not user_id:
            _, _, found_users = _kc_admin_request(
                f"/users?username={urllib.parse.quote(username)}&exact=true",
                method="GET",
                token=admin_token,
            )
            if found_users:
                user_id = found_users[0]["id"]

        # 3. Assign the requested realm role in Keycloak
        if user_id:
            _, _, role_rep = _kc_admin_request(
                f"/roles/{urllib.parse.quote(role)}", method="GET", token=admin_token
            )
            if role_rep:
                _kc_admin_request(
                    f"/users/{user_id}/role-mappings/realm",
                    method="POST",
                    token=admin_token,
                    json_body=[{"id": role_rep["id"], "name": role_rep["name"]}],
                )

        record_log(
            endpoint=request.path,
            method=request.method,
            status=201,
            decision="REGISTERED",
            detail=f"Keycloak user '{username}' registered and assigned realm role '{role}'",
            claims={"preferred_username": username, "realm_access": {"roles": [role]}, "sub": user_id},
        )
        return (
            jsonify(
                status="registered",
                message=f"User '{username}' created in Keycloak realm '{KEYCLOAK_REALM}'",
                user={
                    "id": user_id,
                    "username": username,
                    "email": email,
                    "firstName": first_name,
                    "lastName": last_name,
                    "role": role,
                },
            ),
            201,
        )

    except urllib.error.HTTPError as e:
        err_Raw = e.read().decode("utf-8", errors="replace")
        try:
            kc_err = json.loads(err_Raw)
            kc_msg = kc_err.get("errorMessage") or kc_err.get("error") or err_Raw
        except Exception:
            kc_msg = err_Raw or str(e)

        if e.code == 409:
            return err(409, "user_exists", f"Keycloak rejected registration: {kc_msg}")
        return err(502, "keycloak_error", f"Keycloak Admin API error ({e.code}): {kc_msg}")
    except Exception as e:
        return err(503, "keycloak_unavailable", f"Could not reach Keycloak Admin API: {type(e).__name__}")


@app.get("/api/public")
def public():
    record_log(
        endpoint=request.path,
        method=request.method,
        status=200,
        decision="PUBLIC",
        detail="Public endpoint accessed without token"
    )
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
    try:
        _, _, kc_users = _kc_admin_request("/users?max=50")
        if kc_users:
            formatted = [
                {
                    "id": u.get("id"),
                    "username": u.get("username"),
                    "name": f"{u.get('firstName', '')} {u.get('lastName', '')}".strip() or u.get("username"),
                    "email": u.get("email"),
                    "enabled": u.get("enabled", True),
                }
                for u in kc_users
            ]
            return jsonify(users=formatted)
    except Exception:
        pass
    return jsonify(users=[{"id": 1024, "name": "demo"}])


@app.get("/api/admin/users")
@require_auth("admin")
def admin_users():
    requested_by = g.claims.get("preferred_username")
    try:
        admin_token = _get_kc_admin_token()
        _, _, kc_users = _kc_admin_request("/users?max=50", token=admin_token)
        detailed_users = []
        for u in kc_users or []:
            uid = u.get("id")
            app_roles = []
            try:
                _, _, role_mappings = _kc_admin_request(
                    f"/users/{uid}/role-mappings/realm/composite", token=admin_token
                )
                if role_mappings:
                    app_roles = [
                        r.get("name")
                        for r in role_mappings
                        if r.get("name") in ALLOWED_REGISTRATION_ROLES
                    ]
            except Exception:
                pass
            detailed_users.append(
                {
                    "id": uid,
                    "username": u.get("username"),
                    "firstName": u.get("firstName", ""),
                    "lastName": u.get("lastName", ""),
                    "name": f"{u.get('firstName', '')} {u.get('lastName', '')}".strip() or u.get("username"),
                    "email": u.get("email", ""),
                    "enabled": u.get("enabled", True),
                    "emailVerified": u.get("emailVerified", True),
                    "requiredActions": u.get("requiredActions", []),
                    "roles": app_roles or ["viewer"],
                    "primaryRole": (
                        "admin"
                        if "admin" in app_roles
                        else "developer"
                        if "developer" in app_roles
                        else "viewer"
                    ),
                    "isBuiltIn": u.get("username") in {"alice", "bob"},
                }
            )
        return jsonify(
            message="Admin area",
            requested_by=requested_by,
            realm=KEYCLOAK_REALM,
            users=detailed_users,
        )
    except Exception:
        return jsonify(message="Admin area", requested_by=requested_by)


@app.post("/api/admin/users/<user_id>/reset-password")
@require_auth("admin")
def admin_reset_user_password(user_id):
    """Admin-only endpoint to reset a Keycloak user's login password."""
    body = request.get_json(silent=True) or {}
    new_password = (body.get("password") or "").strip()
    temporary = bool(body.get("temporary", False))

    if len(new_password) < 4:
        return err(400, "weak_password", "New password must be at least 4 characters", claims=g.claims)

    try:
        admin_token = _get_kc_admin_token()
        _, _, target_user = _kc_admin_request(f"/users/{urllib.parse.quote(user_id)}", token=admin_token)
        target_username = target_user.get("username", user_id) if target_user else user_id

        # Clear or set requiredActions so direct grant works immediately when temporary=False
        req_actions = ["UPDATE_PASSWORD"] if temporary else []
        _kc_admin_request(
            f"/users/{urllib.parse.quote(user_id)}",
            method="PUT",
            token=admin_token,
            json_body={"requiredActions": req_actions, "enabled": True, "emailVerified": True},
        )

        # Reset the password in Keycloak
        _kc_admin_request(
            f"/users/{urllib.parse.quote(user_id)}/reset-password",
            method="PUT",
            token=admin_token,
            json_body={
                "type": "password",
                "value": new_password,
                "temporary": temporary,
            },
        )

        record_log(
            endpoint=request.path,
            method=request.method,
            status=200,
            decision="ADMIN_PW_RESET",
            detail=f"Admin '{g.claims.get('preferred_username')}' reset Keycloak password for user '{target_username}'",
            claims=g.claims,
        )
        return jsonify(
            status="password_reset",
            message=f"Password updated in Keycloak for user '{target_username}'",
            userId=user_id,
            username=target_username,
            temporary=temporary,
        )
    except urllib.error.HTTPError as e:
        err_raw = e.read().decode("utf-8", errors="replace")
        return err(502, "keycloak_error", f"Keycloak rejected password reset ({e.code}): {err_raw}", claims=g.claims)
    except Exception as e:
        return err(503, "keycloak_unavailable", f"Could not reach Keycloak Admin API: {type(e).__name__}", claims=g.claims)


@app.put("/api/admin/users/<user_id>/role")
@require_auth("admin")
def admin_update_user_role(user_id):
    """Admin-only endpoint to change a user's Keycloak realm role."""
    body = request.get_json(silent=True) or {}
    new_role = (body.get("role") or "").strip().lower()
    if new_role not in ALLOWED_REGISTRATION_ROLES:
        return err(
            400,
            "invalid_role",
            f"Role must be one of: {', '.join(sorted(ALLOWED_REGISTRATION_ROLES))}",
            claims=g.claims,
        )

    try:
        admin_token = _get_kc_admin_token()
        _, _, target_user = _kc_admin_request(f"/users/{urllib.parse.quote(user_id)}", token=admin_token)
        target_username = target_user.get("username", user_id) if target_user else user_id

        # Remove existing app roles
        _, _, current_roles = _kc_admin_request(
            f"/users/{urllib.parse.quote(user_id)}/role-mappings/realm", token=admin_token
        )
        roles_to_remove = [
            {"id": r["id"], "name": r["name"]}
            for r in (current_roles or [])
            if r.get("name") in ALLOWED_REGISTRATION_ROLES and r.get("name") != new_role
        ]
        if roles_to_remove:
            _kc_admin_request(
                f"/users/{urllib.parse.quote(user_id)}/role-mappings/realm",
                method="DELETE",
                token=admin_token,
                json_body=roles_to_remove,
            )

        # Assign new role
        _, _, role_rep = _kc_admin_request(
            f"/roles/{urllib.parse.quote(new_role)}", method="GET", token=admin_token
        )
        if role_rep:
            _kc_admin_request(
                f"/users/{urllib.parse.quote(user_id)}/role-mappings/realm",
                method="POST",
                token=admin_token,
                json_body=[{"id": role_rep["id"], "name": role_rep["name"]}],
            )

        record_log(
            endpoint=request.path,
            method=request.method,
            status=200,
            decision="ADMIN_ROLE_UPDATE",
            detail=f"Admin '{g.claims.get('preferred_username')}' updated '{target_username}' role to '{new_role}'",
            claims=g.claims,
        )
        return jsonify(
            status="role_updated",
            message=f"Updated Keycloak role for '{target_username}' to '{new_role}'",
            userId=user_id,
            username=target_username,
            role=new_role,
        )
    except Exception as e:
        return err(502, "keycloak_error", f"Failed to update user role: {type(e).__name__}", claims=g.claims)


@app.put("/api/admin/users/<user_id>/status")
@require_auth("admin")
def admin_update_user_status(user_id):
    """Admin-only endpoint to enable or disable a user's login in Keycloak."""
    body = request.get_json(silent=True) or {}
    enabled = bool(body.get("enabled", True))

    try:
        admin_token = _get_kc_admin_token()
        _, _, target_user = _kc_admin_request(f"/users/{urllib.parse.quote(user_id)}", token=admin_token)
        target_username = target_user.get("username", user_id) if target_user else user_id

        _kc_admin_request(
            f"/users/{urllib.parse.quote(user_id)}",
            method="PUT",
            token=admin_token,
            json_body={"enabled": enabled},
        )

        state_str = "enabled" if enabled else "disabled"
        record_log(
            endpoint=request.path,
            method=request.method,
            status=200,
            decision="ADMIN_USER_STATUS",
            detail=f"Admin '{g.claims.get('preferred_username')}' {state_str} login for user '{target_username}'",
            claims=g.claims,
        )
        return jsonify(
            status="status_updated",
            message=f"User '{target_username}' login is now {state_str} in Keycloak",
            userId=user_id,
            username=target_username,
            enabled=enabled,
        )
    except Exception as e:
        return err(502, "keycloak_error", f"Failed to update user status: {type(e).__name__}", claims=g.claims)


@app.delete("/api/admin/users/<user_id>")
@require_auth("admin")
def admin_delete_user(user_id):
    """Admin-only endpoint to delete a user from Keycloak."""
    try:
        admin_token = _get_kc_admin_token()
        _, _, target_user = _kc_admin_request(f"/users/{urllib.parse.quote(user_id)}", token=admin_token)
        target_username = target_user.get("username", user_id) if target_user else user_id

        if target_username in {"alice", "bob"}:
            return err(
                400,
                "protected_user",
                f"Default lab user '{target_username}' is protected from deletion (you can still reset their password or toggle status).",
                claims=g.claims,
            )

        _kc_admin_request(
            f"/users/{urllib.parse.quote(user_id)}",
            method="DELETE",
            token=admin_token,
        )

        record_log(
            endpoint=request.path,
            method=request.method,
            status=200,
            decision="ADMIN_USER_DELETE",
            detail=f"Admin '{g.claims.get('preferred_username')}' deleted user '{target_username}' from Keycloak",
            claims=g.claims,
        )
        return jsonify(
            status="deleted",
            message=f"User '{target_username}' deleted from Keycloak",
            userId=user_id,
            username=target_username,
        )
    except Exception as e:
        return err(502, "keycloak_error", f"Failed to delete user: {type(e).__name__}", claims=g.claims)


@app.get("/api/logs")
def get_logs():
    with _log_lock:
        return jsonify(logs=list(audit_logs))


@app.post("/api/logs/clear")
def clear_logs():
    global _log_counter
    with _log_lock:
        audit_logs.clear()
        _log_counter = 0
    return jsonify(message="Logs cleared", status="ok")
