"""FarmSight 360 API: Sample agricultural platform integrated with Keycloak (farm360 realm) and PostgreSQL."""
import datetime
import json
import os
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from functools import wraps

import jwt
import psycopg2
import psycopg2.extras
from flask import Flask, g, jsonify, request
from jwt import PyJWKClient

KEYCLOAK_INTERNAL_URL = os.environ.get("KEYCLOAK_INTERNAL_URL", "http://keycloak:8080")
KEYCLOAK_REALM = os.environ.get("KEYCLOAK_REALM", "farm360")
ISSUER = os.environ.get("TOKEN_ISSUER", f"http://localhost:8080/realms/{KEYCLOAK_REALM}")
JWKS_URL = os.environ.get(
    "JWKS_URL",
    f"{KEYCLOAK_INTERNAL_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/certs",
)
AUDIENCE = os.environ.get("API_AUDIENCE", "farm360-api")
KC_ADMIN_USER = os.environ.get("KC_ADMIN_USER", "admin")
KC_ADMIN_PASSWORD = os.environ.get("KC_ADMIN_PASSWORD", "Admin@2601")

DB_HOST = os.environ.get("DB_HOST", "postgres")
DB_PORT = int(os.environ.get("DB_PORT", "5432"))
DB_NAME = os.environ.get("DB_NAME", "keycloak")
DB_USER = os.environ.get("DB_USER", "keycloak")
DB_PASSWORD = (
    os.environ.get("DB_PASSWORD")
    or os.environ.get("POSTGRES_PASSWORD")
    or "Stronghold_2501"
)

ALLOWED_REGISTRATION_ROLES = {"farmer", "service_provider"}
ALL_REALM_ROLES = {"farmer", "service_provider", "admin"}
ROLE_TO_GROUP = {
    "farmer": "Farmers",
    "service_provider": "ServiceProviders",
    "admin": "Admins",
}

app = Flask(__name__)
_jwks_client = PyJWKClient(JWKS_URL, cache_keys=True)
_bootstrap_lock = threading.Lock()
_realm_bootstrapped = False


# ============================================================================
# DATABASE INITIALIZATION & SEED DATA (PostgreSQL)
# ============================================================================

def _get_db_conn():
    return psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
    )


def _seed_defaults(cur):
    cur.execute("SELECT COUNT(*) FROM farm360_crops;")
    if cur.fetchone()[0] == 0:
        crops = [
            ("Green Valley Estate", "Coffee (Arabica)", "Coorg Selection-9", 14.5, "Growing", 4200, "ramesh"),
            ("Sunrise Paddy Fields", "Basmati Rice", "Pusa Basmati 1121", 8.0, "Ready for Harvest", 16500, "ramesh"),
            ("Deccan Highland Plot", "Arecanut & Pepper", "Mangala Mixed", 6.2, "Flowering", 3100, "ramesh"),
            ("Cauvery Riverbank Block", "Sugarcane", "Co-86032", 11.0, "Planted", 45000, "ramesh"),
        ]
        for c in crops:
            cur.execute(
                """
                INSERT INTO farm360_crops
                    (farm_name, crop_name, variety, area_acres, stage, expected_yield_kg, owner_username)
                VALUES (%s, %s, %s, %s, %s, %s, %s);
                """,
                c,
            )

    cur.execute("SELECT COUNT(*) FROM farm360_workers;")
    if cur.fetchone()[0] == 0:
        workers = [
            ("Manjunath K", "Field Supervisor & Pruning", 650, "Present", "Green Valley Estate", "ramesh"),
            ("Lakshmi Devi", "Harvesting & Grading Crew", 500, "Present", "Sunrise Paddy Fields", "ramesh"),
            ("basavaraj S", "Irrigation & Pump Operator", 550, "Half-Day", "Deccan Highland Plot", "ramesh"),
            ("Savitha M", "Crop Care & Organic Input", 500, "Absent", "Green Valley Estate", "ramesh"),
        ]
        for w in workers:
            cur.execute(
                """
                INSERT INTO farm360_workers
                    (worker_name, role_title, daily_wage, attendance_status, assigned_farm, owner_username)
                VALUES (%s, %s, %s, %s, %s, %s);
                """,
                w,
            )

    cur.execute("SELECT COUNT(*) FROM farm360_services;")
    if cur.fetchone()[0] == 0:
        services = [
            (
                "Agri-Drone Precision Spraying",
                "Crop Care & Spraying",
                "kiran",
                "Kiran AgriTech Contractors",
                850,
                "per acre",
                "Available Daily",
                "10L DJI Agras drone spraying for micronutrients & pest control with GPS mapping.",
            ),
            (
                "Combine Paddy Harvester (Kubota)",
                "Harvesting Machinery",
                "kiran",
                "Kiran AgriTech Contractors",
                2400,
                "per hour",
                "Available Now",
                "Low-grain-loss track harvester with operator and grain unloader.",
            ),
            (
                "Laser Land Leveling & Rotavator",
                "Soil Preparation",
                "kiran",
                "Kiran AgriTech Contractors",
                1500,
                "per hour",
                "Available on Booking",
                "55HP John Deere tractor with laser-guided leveler for water-efficient irrigation.",
            ),
            (
                "Digital Soil NPK & pH Lab Testing",
                "Agronomy & Diagnostics",
                "kiran",
                "Kiran AgriTech Contractors",
                1200,
                "per plot",
                "Available Daily",
                "12-parameter soil health card with fertilizer dosage recommendations.",
            ),
        ]
        for s in services:
            cur.execute(
                """
                INSERT INTO farm360_services
                    (service_name, category, provider_username, provider_name, rate_inr, rate_unit, availability, description)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
                """,
                s,
            )

    cur.execute("SELECT COUNT(*) FROM farm360_bookings;")
    if cur.fetchone()[0] == 0:
        cur.execute("SELECT id, service_name FROM farm360_services ORDER BY id LIMIT 2;")
        svc_rows = cur.fetchall()
        if len(svc_rows) >= 2:
            bookings = [
                (svc_rows[0][0], svc_rows[0][1], "kiran", "ramesh", "Green Valley Estate", "2026-11-05", "Confirmed", 4250),
                (svc_rows[1][0], svc_rows[1][1], "kiran", "ramesh", "Sunrise Paddy Fields", "2026-11-08", "Pending", 7200),
            ]
            for b in bookings:
                cur.execute(
                    """
                    INSERT INTO farm360_bookings
                        (service_id, service_name, provider_username, farmer_username, farm_name, scheduled_date, status, amount_inr)
                    VALUES (%s, %s, %s, %s, %s, %s, %s, %s);
                    """,
                    b,
                )

    cur.execute("SELECT COUNT(*) FROM farm360_finances;")
    if cur.fetchone()[0] == 0:
        finances = [
            ("INCOME", "Harvest Sale", "Sold 1,800 kg Grade-A Arabica Coffee Parchment to Coorg Co-op", 342000, "ramesh"),
            ("INCOME", "Harvest Sale", "Early batch Basmati Paddy sale (42 Quintals)", 148000, "ramesh"),
            ("EXPENSE", "Input & Fertilizer", "Organic Vermicompost & NPK Micronutrient Batch", 28500, "ramesh"),
            ("EXPENSE", "Workforce Wages", "Weekly Muster Roll Wage Settlement (4 Workers)", 15400, "ramesh"),
            ("EXPENSE", "Contractor Booking", "Agri-Drone Spraying Advance — Green Valley Estate", 4250, "ramesh"),
        ]
        for f in finances:
            cur.execute(
                """
                INSERT INTO farm360_finances
                    (tx_type, category, description, amount_inr, recorded_by)
                VALUES (%s, %s, %s, %s, %s);
                """,
                f,
            )


def _init_db():
    try:
        with _get_db_conn() as conn:
            with conn.cursor() as cur:
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS farm360_crops (
                        id SERIAL PRIMARY KEY,
                        farm_name VARCHAR(120) NOT NULL,
                        crop_name VARCHAR(120) NOT NULL,
                        variety VARCHAR(120) DEFAULT 'Standard',
                        area_acres NUMERIC(8,2) DEFAULT 1.0,
                        stage VARCHAR(64) DEFAULT 'Growing',
                        expected_yield_kg INTEGER DEFAULT 1000,
                        owner_username VARCHAR(80) NOT NULL,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                    """
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS farm360_workers (
                        id SERIAL PRIMARY KEY,
                        worker_name VARCHAR(120) NOT NULL,
                        role_title VARCHAR(120) NOT NULL,
                        daily_wage INTEGER DEFAULT 500,
                        attendance_status VARCHAR(32) DEFAULT 'Present',
                        assigned_farm VARCHAR(120) DEFAULT 'Main Estate',
                        owner_username VARCHAR(80) NOT NULL,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                    """
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS farm360_services (
                        id SERIAL PRIMARY KEY,
                        service_name VARCHAR(140) NOT NULL,
                        category VARCHAR(80) NOT NULL,
                        provider_username VARCHAR(80) NOT NULL,
                        provider_name VARCHAR(120) NOT NULL,
                        rate_inr INTEGER NOT NULL,
                        rate_unit VARCHAR(40) DEFAULT 'per hour',
                        availability VARCHAR(64) DEFAULT 'Available Daily',
                        description TEXT NOT NULL
                    );
                    """
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS farm360_bookings (
                        id SERIAL PRIMARY KEY,
                        service_id INTEGER,
                        service_name VARCHAR(140) NOT NULL,
                        provider_username VARCHAR(80) NOT NULL,
                        farmer_username VARCHAR(80) NOT NULL,
                        farm_name VARCHAR(120) NOT NULL,
                        scheduled_date VARCHAR(40) NOT NULL,
                        status VARCHAR(40) DEFAULT 'Pending',
                        amount_inr INTEGER DEFAULT 0,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                    """
                )
                cur.execute(
                    """
                    CREATE TABLE IF NOT EXISTS farm360_finances (
                        id SERIAL PRIMARY KEY,
                        tx_type VARCHAR(20) NOT NULL,
                        category VARCHAR(80) NOT NULL,
                        description TEXT NOT NULL,
                        amount_inr INTEGER NOT NULL,
                        recorded_by VARCHAR(80) NOT NULL,
                        tx_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    );
                    """
                )
                _seed_defaults(cur)
            conn.commit()
    except Exception as exc:
        app.logger.warning(f"PostgreSQL init warning: {exc}")


# ============================================================================
# KEYCLOAK REALM & USER BOOTSTRAP (farm360 REALM)
# ============================================================================

def _get_kc_admin_token():
    token_url = f"{KEYCLOAK_INTERNAL_URL}/realms/master/protocol/openid-connect/token"
    form_data = urllib.parse.urlencode(
        {
            "grant_type": "password",
            "client_id": "admin-cli",
            "username": KC_ADMIN_USER,
            "password": KC_ADMIN_PASSWORD,
        }
    ).encode("utf-8")
    req = urllib.request.Request(
        token_url,
        data=form_data,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=8) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        return data["access_token"]


def _kc_request(url_path, method="GET", payload=None, token=None):
    if token is None:
        token = _get_kc_admin_token()
    url = f"{KEYCLOAK_INTERNAL_URL}{url_path}"
    headers = {"Authorization": f"Bearer {token}"}
    body = None
    if payload is not None:
        headers["Content-Type"] = "application/json"
        body = json.dumps(payload).encode("utf-8")

    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=8) as resp:
        raw = resp.read().decode("utf-8")
        return resp.status, resp.headers, (json.loads(raw) if raw else None)


def _sync_user_role_and_group(user_id, role_name, token):
    """Assign direct realm role AND matching group in the farm360 realm."""
    if role_name not in ALL_REALM_ROLES:
        return

    # 1. Assign direct realm role
    _, _, role_rep = _kc_request(
        f"/admin/realms/{KEYCLOAK_REALM}/roles/{urllib.parse.quote(role_name)}",
        token=token,
    )
    _kc_request(
        f"/admin/realms/{KEYCLOAK_REALM}/users/{urllib.parse.quote(user_id)}/role-mappings/realm",
        method="POST",
        payload=[{"id": role_rep["id"], "name": role_rep["name"]}],
        token=token,
    )

    # 2. Assign matching Keycloak Group
    target_group = ROLE_TO_GROUP.get(role_name)
    if target_group:
        _, _, all_groups = _kc_request(f"/admin/realms/{KEYCLOAK_REALM}/groups", token=token)
        for g_obj in all_groups or []:
            if g_obj.get("name") == target_group:
                _kc_request(
                    f"/admin/realms/{KEYCLOAK_REALM}/users/{urllib.parse.quote(user_id)}/groups/{g_obj['id']}",
                    method="PUT",
                    token=token,
                )


def _ensure_farm360_realm():
    """Idempotently create and configure the `farm360` realm, client, roles, groups, and demo users in Keycloak."""
    global _realm_bootstrapped
    if _realm_bootstrapped:
        return
    with _bootstrap_lock:
        if _realm_bootstrapped:
            return
        try:
            token = _get_kc_admin_token()
            # Check if realm exists
            realm_exists = False
            try:
                _kc_request(f"/admin/realms/{KEYCLOAK_REALM}", token=token)
                realm_exists = True
            except urllib.error.HTTPError as e:
                if e.code != 404:
                    raise

            if not realm_exists:
                app.logger.info(f"Creating Keycloak realm '{KEYCLOAK_REALM}'...")
                _kc_request(
                    "/admin/realms",
                    method="POST",
                    payload={
                        "realm": KEYCLOAK_REALM,
                        "enabled": True,
                        "displayName": "FarmSight 360 Identity",
                        "registrationAllowed": True,
                        "resetPasswordAllowed": True,
                        "rememberMe": True,
                        "loginWithEmailAllowed": True,
                        "duplicateEmailsAllowed": False,
                        "accessTokenLifespan": 3600,
                    },
                    token=token,
                )

            # Ensure realm roles exist: farmer, service_provider, admin
            role_descriptions = {
                "farmer": "Farm Owner — manages farms, crops, workforce attendance, and books services",
                "service_provider": "Agricultural Service Provider — lists machinery/services and fulfills bookings",
                "admin": "FarmSight 360 Platform Administrator",
            }
            for r_name, r_desc in role_descriptions.items():
                try:
                    _kc_request(f"/admin/realms/{KEYCLOAK_REALM}/roles/{r_name}", token=token)
                except urllib.error.HTTPError as e:
                    if e.code == 404:
                        _kc_request(
                            f"/admin/realms/{KEYCLOAK_REALM}/roles",
                            method="POST",
                            payload={"name": r_name, "description": r_desc},
                            token=token,
                        )

            # Add 'farmer' to default-roles-farm360 so users registering via Keycloak's hosted page get 'farmer' role automatically
            try:
                _, _, farmer_role = _kc_request(
                    f"/admin/realms/{KEYCLOAK_REALM}/roles/farmer", token=token
                )
                _kc_request(
                    f"/admin/realms/{KEYCLOAK_REALM}/roles/default-roles-{KEYCLOAK_REALM}/composites",
                    method="POST",
                    payload=[{"id": farmer_role["id"], "name": farmer_role["name"]}],
                    token=token,
                )
            except Exception:
                pass

            # Ensure Groups exist and are mapped to their roles
            _, _, existing_groups = _kc_request(f"/admin/realms/{KEYCLOAK_REALM}/groups", token=token)
            group_map = {g["name"]: g["id"] for g in (existing_groups or [])}
            for r_name, g_name in ROLE_TO_GROUP.items():
                if g_name not in group_map:
                    _, headers, _ = _kc_request(
                        f"/admin/realms/{KEYCLOAK_REALM}/groups",
                        method="POST",
                        payload={"name": g_name},
                        token=token,
                    )
                    loc = headers.get("Location") or ""
                    if loc:
                        group_map[g_name] = loc.rstrip("/").split("/")[-1]
                g_id = group_map.get(g_name)
                if g_id:
                    _, _, r_rep = _kc_request(
                        f"/admin/realms/{KEYCLOAK_REALM}/roles/{r_name}", token=token
                    )
                    _kc_request(
                        f"/admin/realms/{KEYCLOAK_REALM}/groups/{g_id}/role-mappings/realm",
                        method="POST",
                        payload=[{"id": r_rep["id"], "name": r_rep["name"]}],
                        token=token,
                    )

            # Ensure public OIDC client 'farm360-web' exists with Audience mapper for 'farm360-api'
            _, _, clients = _kc_request(
                f"/admin/realms/{KEYCLOAK_REALM}/clients?clientId=farm360-web", token=token
            )
            if not clients:
                _kc_request(
                    f"/admin/realms/{KEYCLOAK_REALM}/clients",
                    method="POST",
                    payload={
                        "clientId": "farm360-web",
                        "name": "FarmSight 360 Web Portal",
                        "enabled": True,
                        "protocol": "openid-connect",
                        "publicClient": True,
                        "standardFlowEnabled": True,
                        "directAccessGrantsEnabled": True,
                        "rootUrl": "http://localhost:3000",
                        "baseUrl": "http://localhost:3000",
                        "redirectUris": [
                            "http://localhost:3000/*",
                            "http://127.0.0.1:3000/*",
                        ],
                        "webOrigins": ["*"],
                        "protocolMappers": [
                            {
                                "name": "farm360-api-audience",
                                "protocol": "openid-connect",
                                "protocolMapper": "oidc-audience-mapper",
                                "consentRequired": False,
                                "config": {
                                    "included.client.audience": AUDIENCE,
                                    "id.token.claim": "false",
                                    "access.token.claim": "true",
                                },
                            }
                        ],
                    },
                    token=token,
                )

            # Ensure pre-seeded demo users exist in the farm360 realm
            demo_users = [
                ("ramesh", "ramesh123", "Ramesh", "Gowda", "ramesh@farm360.local", "farmer"),
                ("kiran", "kiran123", "Kiran", "Patil", "kiran@farm360.local", "service_provider"),
                ("admin_farm", "admin123", "Neehar", "Admin", "admin@farm360.local", "admin"),
            ]
            for uname, pwd, fname, lname, email, role in demo_users:
                _, _, found = _kc_request(
                    f"/admin/realms/{KEYCLOAK_REALM}/users?username={uname}&exact=true",
                    token=token,
                )
                if not found:
                    _, headers, _ = _kc_request(
                        f"/admin/realms/{KEYCLOAK_REALM}/users",
                        method="POST",
                        payload={
                            "username": uname,
                            "firstName": fname,
                            "lastName": lname,
                            "email": email,
                            "emailVerified": True,
                            "enabled": True,
                            "requiredActions": [],
                        },
                        token=token,
                    )
                    loc = headers.get("Location") or ""
                    uid = loc.rstrip("/").split("/")[-1] if loc else None
                    if uid:
                        _kc_request(
                            f"/admin/realms/{KEYCLOAK_REALM}/users/{uid}/reset-password",
                            method="PUT",
                            payload={"type": "password", "value": pwd, "temporary": False},
                            token=token,
                        )
                        _sync_user_role_and_group(uid, role, token)

            _realm_bootstrapped = True
            app.logger.info(f"Keycloak realm '{KEYCLOAK_REALM}' is ready.")
        except Exception as exc:
            app.logger.warning(f"Keycloak bootstrap deferred: {exc}")


# Initialize DB and attempt Keycloak realm bootstrap
_init_db()
_ensure_farm360_realm()


# ============================================================================
# CORS & AUTHENTICATION MIDDLEWARE
# ============================================================================

@app.after_request
def add_cors_headers(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    return response


@app.route("/health", methods=["OPTIONS"])
@app.route("/api/<path:subpath>", methods=["OPTIONS"])
def handle_options(subpath=None):
    return "", 204


def _extract_bearer_token():
    auth_header = request.headers.get("Authorization", "")
    parts = auth_header.split()
    if len(parts) == 2 and parts[0].lower() == "bearer":
        return parts[1]
    return None


def _roles_from_claims(claims):
    realm_roles = claims.get("realm_access", {}).get("roles", []) or []
    resource_roles = (
        claims.get("resource_access", {}).get(AUDIENCE, {}).get("roles", []) or []
    )
    return set(realm_roles) | set(resource_roles)


def _primary_role(roles):
    if "admin" in roles:
        return "admin"
    if "service_provider" in roles:
        return "service_provider"
    return "farmer"


def require_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        _ensure_farm360_realm()
        token = _extract_bearer_token()
        if not token:
            return jsonify(error="missing_token", detail="Bearer token required"), 401
        try:
            signing_key = _jwks_client.get_signing_key_from_jwt(token)
            # Decode token; accept either farm360-api audience or account/azp from farm360-web
            claims = jwt.decode(
                token,
                signing_key.key,
                algorithms=["RS256"],
                issuer=ISSUER,
                options={"verify_aud": False},
            )
        except jwt.ExpiredSignatureError:
            return jsonify(error="token_expired", detail="Keycloak access token has expired"), 401
        except jwt.InvalidTokenError as exc:
            return jsonify(error="invalid_token", detail=str(exc)), 401

        g.claims = claims
        g.roles = _roles_from_claims(claims)
        g.username = claims.get("preferred_username", "unknown")
        g.primary_role = _primary_role(g.roles)
        return fn(*args, **kwargs)

    return wrapper


# ============================================================================
# PUBLIC ENDPOINTS (HEALTH & SELF-SERVICE REGISTRATION IN KEYCLOAK)
# ============================================================================

@app.get("/health")
def health():
    _ensure_farm360_realm()
    return jsonify(
        status="ok",
        app="FarmSight 360",
        realm=KEYCLOAK_REALM,
        issuer=ISSUER,
        keycloak_admin_url=f"http://localhost:8080/admin/master/console/#/{KEYCLOAK_REALM}/users",
    )


@app.post("/api/register")
def register_user():
    """Register a new Farmer or Service Provider directly inside Keycloak's `farm360` realm."""
    _ensure_farm360_realm()
    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip().lower()
    email = (body.get("email") or "").strip().lower()
    first_name = (body.get("firstName") or "").strip()
    last_name = (body.get("lastName") or "").strip()
    password = body.get("password") or ""
    requested_role = (body.get("role") or "farmer").strip().lower()

    if not username or len(username) < 3:
        return jsonify(error="invalid_input", detail="Username must be at least 3 characters."), 400
    if not password or len(password) < 4:
        return jsonify(error="invalid_input", detail="Password must be at least 4 characters."), 400
    if requested_role not in ALLOWED_REGISTRATION_ROLES:
        requested_role = "farmer"
    if not email:
        email = f"{username}@farm360.local"
    if not first_name:
        first_name = username.capitalize()
    if not last_name:
        last_name = "Farmer" if requested_role == "farmer" else "Contractor"

    try:
        token = _get_kc_admin_token()
        user_payload = {
            "username": username,
            "email": email,
            "firstName": first_name,
            "lastName": last_name,
            "enabled": True,
            "emailVerified": True,
            "requiredActions": [],
        }
        try:
            _, headers, _ = _kc_request(
                f"/admin/realms/{KEYCLOAK_REALM}/users",
                method="POST",
                payload=user_payload,
                token=token,
            )
        except urllib.error.HTTPError as http_err:
            if http_err.code == 409:
                return jsonify(
                    error="user_exists",
                    detail=f"User '{username}' or email '{email}' is already registered in Keycloak realm '{KEYCLOAK_REALM}'.",
                ), 409
            raise

        location = headers.get("Location") or ""
        user_id = location.rstrip("/").split("/")[-1] if location else None
        if not user_id:
            _, _, users = _kc_request(
                f"/admin/realms/{KEYCLOAK_REALM}/users?username={urllib.parse.quote(username)}&exact=true",
                token=token,
            )
            user_id = users[0]["id"]

        # Set permanent password in Keycloak
        _kc_request(
            f"/admin/realms/{KEYCLOAK_REALM}/users/{urllib.parse.quote(user_id)}/reset-password",
            method="PUT",
            payload={"type": "password", "value": password, "temporary": False},
            token=token,
        )

        # Assign role & group in Keycloak
        _sync_user_role_and_group(user_id, requested_role, token)

        return jsonify(
            status="created",
            username=username,
            user_id=user_id,
            role=requested_role,
            realm=KEYCLOAK_REALM,
            message=f"Account '{username}' created in Keycloak realm '{KEYCLOAK_REALM}' as '{requested_role}'.",
        ), 201
    except Exception as exc:
        return jsonify(error="registration_failed", detail=str(exc)), 500


# ============================================================================
# PROTECTED FARMSIGHT 360 ENDPOINTS (KEYCLOAK JWT REQUIRED)
# ============================================================================

@app.get("/api/me")
@require_auth
def get_me():
    return jsonify(
        sub=g.claims.get("sub"),
        username=g.username,
        name=g.claims.get("name") or g.username,
        email=g.claims.get("email", ""),
        primary_role=g.primary_role,
        roles=sorted(list(g.roles)),
        realm=KEYCLOAK_REALM,
        issuer=g.claims.get("iss"),
    )


@app.get("/api/dashboard")
@require_auth
def get_dashboard():
    """Return FarmSight 360 operational data from PostgreSQL."""
    with _get_db_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM farm360_crops ORDER BY id DESC;")
            crops = []
            for r in cur.fetchall():
                d = dict(r)
                d["area_acres"] = float(d["area_acres"] or 0)
                if isinstance(d.get("updated_at"), datetime.datetime):
                    d["updated_at"] = d["updated_at"].strftime("%Y-%m-%d %H:%M")
                crops.append(d)

            cur.execute("SELECT * FROM farm360_workers ORDER BY id ASC;")
            workers = []
            for r in cur.fetchall():
                d = dict(r)
                if isinstance(d.get("updated_at"), datetime.datetime):
                    d["updated_at"] = d["updated_at"].strftime("%Y-%m-%d %H:%M")
                workers.append(d)

            cur.execute("SELECT * FROM farm360_services ORDER BY id ASC;")
            services = [dict(r) for r in cur.fetchall()]

            cur.execute("SELECT * FROM farm360_bookings ORDER BY id DESC;")
            bookings = []
            for r in cur.fetchall():
                d = dict(r)
                if isinstance(d.get("created_at"), datetime.datetime):
                    d["created_at"] = d["created_at"].strftime("%Y-%m-%d %H:%M")
                bookings.append(d)

            cur.execute("SELECT * FROM farm360_finances ORDER BY id DESC LIMIT 20;")
            finances = []
            for r in cur.fetchall():
                d = dict(r)
                if isinstance(d.get("tx_date"), datetime.datetime):
                    d["tx_date"] = d["tx_date"].strftime("%Y-%m-%d")
                finances.append(d)

    total_acres = round(sum(c["area_acres"] for c in crops), 1)
    present_workers = sum(1 for w in workers if w["attendance_status"] == "Present")
    total_income = sum(f["amount_inr"] for f in finances if f["tx_type"] == "INCOME")
    total_expense = sum(f["amount_inr"] for f in finances if f["tx_type"] == "EXPENSE")

    return jsonify(
        user={
            "username": g.username,
            "name": g.claims.get("name") or g.username,
            "email": g.claims.get("email", ""),
            "primary_role": g.primary_role,
            "roles": sorted(list(g.roles)),
            "sub": g.claims.get("sub"),
        },
        kpis={
            "total_plots": len(crops),
            "total_acres": total_acres,
            "active_workers": f"{present_workers} / {len(workers)}",
            "open_bookings": sum(1 for b in bookings if b["status"] in ("Pending", "Confirmed")),
            "total_income": total_income,
            "total_expense": total_expense,
            "net_balance": total_income - total_expense,
        },
        crops=crops,
        workers=workers,
        services=services,
        bookings=bookings,
        finances=finances,
    )


@app.post("/api/crops")
@require_auth
def create_crop():
    body = request.get_json(silent=True) or {}
    farm_name = (body.get("farm_name") or "").strip()
    crop_name = (body.get("crop_name") or "").strip()
    variety = (body.get("variety") or "Standard").strip()
    area_acres = float(body.get("area_acres") or 1.0)
    stage = (body.get("stage") or "Planted").strip()
    expected_yield_kg = int(body.get("expected_yield_kg") or 1000)

    if not farm_name or not crop_name:
        return jsonify(error="invalid_input", detail="Farm name and crop name are required."), 400

    with _get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO farm360_crops
                    (farm_name, crop_name, variety, area_acres, stage, expected_yield_kg, owner_username)
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING id;
                """,
                (farm_name, crop_name, variety, area_acres, stage, expected_yield_kg, g.username),
            )
            new_id = cur.fetchone()[0]
        conn.commit()

    return jsonify(status="created", id=new_id, message=f"Added '{crop_name}' at '{farm_name}'."), 201


@app.put("/api/crops/<int:crop_id>")
@require_auth
def update_crop(crop_id):
    body = request.get_json(silent=True) or {}
    stage = (body.get("stage") or "Growing").strip()
    expected_yield_kg = int(body.get("expected_yield_kg") or 0)

    with _get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE farm360_crops
                SET stage = %s,
                    expected_yield_kg = CASE WHEN %s > 0 THEN %s ELSE expected_yield_kg END,
                    updated_at = CURRENT_TIMESTAMP
                WHERE id = %s;
                """,
                (stage, expected_yield_kg, expected_yield_kg, crop_id),
            )
        conn.commit()

    return jsonify(status="updated", id=crop_id, message=f"Crop #{crop_id} updated to stage '{stage}'.")


@app.delete("/api/crops/<int:crop_id>")
@require_auth
def delete_crop(crop_id):
    with _get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute("DELETE FROM farm360_crops WHERE id = %s;", (crop_id,))
        conn.commit()
    return jsonify(status="deleted", id=crop_id)


@app.post("/api/workers")
@require_auth
def add_worker():
    body = request.get_json(silent=True) or {}
    worker_name = (body.get("worker_name") or "").strip()
    role_title = (body.get("role_title") or "Field Worker").strip()
    daily_wage = int(body.get("daily_wage") or 500)
    assigned_farm = (body.get("assigned_farm") or "Main Estate").strip()

    if not worker_name:
        return jsonify(error="invalid_input", detail="Worker name is required."), 400

    with _get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO farm360_workers
                    (worker_name, role_title, daily_wage, attendance_status, assigned_farm, owner_username)
                VALUES (%s, %s, %s, 'Present', %s, %s)
                RETURNING id;
                """,
                (worker_name, role_title, daily_wage, assigned_farm, g.username),
            )
            new_id = cur.fetchone()[0]
        conn.commit()

    return jsonify(status="created", id=new_id, message=f"Worker '{worker_name}' added to roster."), 201


@app.put("/api/workers/<int:worker_id>/attendance")
@require_auth
def update_worker_attendance(worker_id):
    body = request.get_json(silent=True) or {}
    status = (body.get("attendance_status") or "Present").strip()
    if status not in ("Present", "Half-Day", "Absent"):
        status = "Present"

    with _get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE farm360_workers
                SET attendance_status = %s, updated_at = CURRENT_TIMESTAMP
                WHERE id = %s;
                """,
                (status, worker_id),
            )
        conn.commit()

    return jsonify(status="updated", id=worker_id, attendance_status=status)


@app.post("/api/services")
@require_auth
def create_service():
    body = request.get_json(silent=True) or {}
    service_name = (body.get("service_name") or "").strip()
    category = (body.get("category") or "Machinery & Equipment").strip()
    rate_inr = int(body.get("rate_inr") or 1000)
    rate_unit = (body.get("rate_unit") or "per hour").strip()
    description = (body.get("description") or "Agricultural contractor service.").strip()
    provider_name = g.claims.get("name") or f"{g.username.capitalize()} Agri Services"

    if not service_name:
        return jsonify(error="invalid_input", detail="Service name is required."), 400

    with _get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO farm360_services
                    (service_name, category, provider_username, provider_name, rate_inr, rate_unit, availability, description)
                VALUES (%s, %s, %s, %s, %s, %s, 'Available Now', %s)
                RETURNING id;
                """,
                (service_name, category, g.username, provider_name, rate_inr, rate_unit, description),
            )
            new_id = cur.fetchone()[0]
        conn.commit()

    return jsonify(status="created", id=new_id, message=f"Listed service '{service_name}'."), 201


@app.post("/api/bookings")
@require_auth
def create_booking():
    body = request.get_json(silent=True) or {}
    service_id = int(body.get("service_id") or 0)
    farm_name = (body.get("farm_name") or "Green Valley Estate").strip()
    scheduled_date = (body.get("scheduled_date") or datetime.date.today().isoformat()).strip()
    units = max(1, int(body.get("units") or 1))

    with _get_db_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM farm360_services WHERE id = %s;", (service_id,))
            svc = cur.fetchone()
            if not svc:
                return jsonify(error="not_found", detail="Service not found."), 404

            total_amount = int(svc["rate_inr"]) * units
            cur.execute(
                """
                INSERT INTO farm360_bookings
                    (service_id, service_name, provider_username, farmer_username, farm_name, scheduled_date, status, amount_inr)
                VALUES (%s, %s, %s, %s, %s, %s, 'Pending', %s)
                RETURNING id;
                """,
                (
                    svc["id"],
                    svc["service_name"],
                    svc["provider_username"],
                    g.username,
                    farm_name,
                    scheduled_date,
                    total_amount,
                ),
            )
            booking_id = cur.fetchone()["id"]
        conn.commit()

    return jsonify(
        status="booked",
        id=booking_id,
        message=f"Booked '{svc['service_name']}' for '{farm_name}' on {scheduled_date} (₹{total_amount:,}).",
    ), 201


@app.put("/api/bookings/<int:booking_id>/status")
@require_auth
def update_booking_status(booking_id):
    body = request.get_json(silent=True) or {}
    new_status = (body.get("status") or "Confirmed").strip()
    if new_status not in ("Pending", "Confirmed", "Completed", "Cancelled"):
        return jsonify(error="invalid_status", detail="Invalid booking status."), 400

    with _get_db_conn() as conn:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            cur.execute("SELECT * FROM farm360_bookings WHERE id = %s;", (booking_id,))
            booking = cur.fetchone()
            if not booking:
                return jsonify(error="not_found", detail="Booking not found."), 404

            cur.execute(
                "UPDATE farm360_bookings SET status = %s WHERE id = %s;",
                (new_status, booking_id),
            )

            # When a booking is marked Completed, automatically log the expense in farm360_finances
            if new_status == "Completed" and booking["status"] != "Completed":
                cur.execute(
                    """
                    INSERT INTO farm360_finances (tx_type, category, description, amount_inr, recorded_by)
                    VALUES ('EXPENSE', 'Contractor Booking', %s, %s, %s);
                    """,
                    (
                        f"Completed Service: {booking['service_name']} ({booking['farm_name']})",
                        booking["amount_inr"],
                        g.username,
                    ),
                )
        conn.commit()

    return jsonify(status="updated", id=booking_id, new_status=new_status)


@app.post("/api/finances")
@require_auth
def create_finance_entry():
    body = request.get_json(silent=True) or {}
    tx_type = (body.get("tx_type") or "EXPENSE").strip().upper()
    if tx_type not in ("INCOME", "EXPENSE"):
        tx_type = "EXPENSE"
    category = (body.get("category") or "General").strip()
    description = (body.get("description") or "").strip()
    amount_inr = int(body.get("amount_inr") or 0)

    if not description or amount_inr <= 0:
        return jsonify(error="invalid_input", detail="Description and positive amount are required."), 400

    with _get_db_conn() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO farm360_finances (tx_type, category, description, amount_inr, recorded_by)
                VALUES (%s, %s, %s, %s, %s)
                RETURNING id;
                """,
                (tx_type, category, description, amount_inr, g.username),
            )
            tx_id = cur.fetchone()[0]
        conn.commit()

    return jsonify(status="created", id=tx_id, message=f"Recorded {tx_type} of ₹{amount_inr:,}."), 201
