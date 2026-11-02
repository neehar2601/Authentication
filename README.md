# AuthLab — Security & Access X-Ray

Keycloak + PostgreSQL + Flask Resource API + Interactive Security X-Ray Frontend that validates Keycloak RS256 JWTs, enforces RBAC roles, provisions new Keycloak users, and provides an Admin User & Password Management Console.

> **Note:** Local development only. Ports are bound to `127.0.0.1`. Do not expose this stack publicly.

## Quick Start

```bash
cp .env.example .env        # or configure POSTGRES_PASSWORD, KC_ADMIN_USER, KC_ADMIN_PASSWORD in .env
docker compose up -d --build
docker compose logs -f keycloak   # wait for "Listening on: http://0.0.0.0:8080"
```

### Local Service URLs
| Service | URL | Notes |
| :--- | :--- | :--- |
| **Frontend Security X-Ray & Admin UI** | http://localhost:3000 | Login, User Registration, Live RBAC Matrix & Admin Console |
| **Keycloak Admin Console** | http://localhost:8080/admin | Native Keycloak UI (login with `KC_ADMIN_USER` / `KC_ADMIN_PASSWORD` from `.env`) |
| **Flask Resource API** | http://localhost:5001 | JWT-protected API & Keycloak Admin proxy |

### Pre-configured Lab Accounts (`authlab` realm)
| Username | Password | Realm Role | `/api/users` | `/api/admin/users` & Admin Console |
| :--- | :--- | :--- | :--- | :--- |
| `alice` | `alice123` | `viewer` | `200 OK` | `403 FORBIDDEN` (Locked) |
| `bob` | `bob123` | `admin` | `200 OK` | `200 OK` (Unlocked) |

---

## Frontend Features (http://localhost:3000)

1. **🔐 Sign In & Live Security X-Ray**
   - Authenticate against Keycloak (`authlab` realm) via Direct Grant or test anonymous requests (`401 Unauthorized`).
   - Inspect the 3-step cryptographic & RBAC pipeline (**Keycloak Token Minting** -> **Flask JWKS RS256 Verification** -> **Flask Role Permission Decision**).
   - View the **All 4 Endpoints Live Access Matrix** (`/api/public`, `/api/me`, `/api/users`, `/api/admin/users`) and live backend audit log.

2. **✨ Register New User (Handled via Keycloak)**
   - Switch to the **Register New User** tab on the frontend to create a new user directly in the Keycloak `authlab` realm (`POST /api/register`).
   - Assign a Keycloak realm role (`viewer`, `developer`, or `admin`), automatically add a Quick Fill button for the new account, and immediately sign in to verify their JWT and endpoint permissions.

3. **🛡️ Admin Keycloak User & Password Console**
   - Protected by `@require_auth("admin")`. Locked with `HTTP 403 FORBIDDEN` when signed in as `alice` (`viewer`); unlocked when signed in as `bob` (`admin`) or any custom `admin` user.
   - **Reset Login Passwords**: Reset any user's password in Keycloak (`POST /api/admin/users/<id>/reset-password`) and immediately test signing in with the new password.
   - **Role & Status Management**: Change a user's Keycloak realm role (`viewer`, `developer`, `admin`), enable/disable their login status in Keycloak, or delete custom users.
   - Includes a direct shortcut to open the native **Keycloak Admin Console (`:8080/admin`)**.

---

## Flask API Endpoints

| Method | Endpoint | Auth Requirement | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/health` | Public | Health check |
| `GET` | `/api/public` | Public | Open endpoint accessible without a token |
| `POST` | `/api/register` | Public | Provisions a new user & realm role in Keycloak |
| `GET` | `/api/me` | Any valid JWT | Unpacks verified token claims (`sub`, `username`, `roles`, `exp`) |
| `GET` | `/api/users` | `viewer`, `developer`, or `admin` | Lists users in the Keycloak `authlab` realm |
| `GET` | `/api/admin/users` | `admin` | Lists detailed Keycloak users and effective realm roles |
| `POST` | `/api/admin/users/<id>/reset-password` | `admin` | Resets a user's password in Keycloak |
| `PUT` | `/api/admin/users/<id>/role` | `admin` | Updates a user's realm role in Keycloak |
| `PUT` | `/api/admin/users/<id>/status` | `admin` | Enables or disables a user's login in Keycloak |
| `DELETE` | `/api/admin/users/<id>` | `admin` | Deletes a custom user from Keycloak (`alice` & `bob` protected) |
| `GET` | `/api/logs` | Public | Returns recent in-memory Flask audit log entries |

---

## Configure Keycloak (First-Time Setup Reference)
1. **Realm**: create `authlab` (with user registration enabled).
2. **Realm roles**: create `viewer`, `developer`, `admin`.
3. **Users**: create `alice` (role `viewer`) and `bob` (role `admin`). Set passwords under Credentials (turn Temporary off).
4. **Client** `authlab-web`: Client authentication OFF (public), Standard flow ON,
   Direct access grants ON (**lab-only shortcut for curl; the real flow is Authorization Code + PKCE**),
   Valid redirect URIs `http://localhost:3000/*`. Under Advanced, set PKCE method `S256`.
5. **Audience**: Clients > `authlab-web` > Client scopes > `authlab-web-dedicated` > Add mapper >
   *Audience*, Included Custom Audience `authlab-api`, Add to access token ON.
   (Without this the API rejects tokens with an `InvalidAudienceError`. That is the audience check working.)

## Try it from the Terminal

```bash
./demo_auth.sh   # Automated live walkthrough of all 8 checks

# Or run manual curl requests:
# Passwords configured: alice -> alice123, bob -> bob123
TOKEN=$(curl -s -X POST http://localhost:8080/realms/authlab/protocol/openid-connect/token \
  -d grant_type=password -d client_id=authlab-web \
  -d username=alice -d password='alice123' | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

curl -i localhost:5001/api/public                                         # 200
curl -i localhost:5001/api/me                                             # 401 missing_token
curl -i -H "Authorization: Bearer $TOKEN" localhost:5001/api/me           # 200
curl -i -H "Authorization: Bearer $TOKEN" localhost:5001/api/admin/users  # 403 (alice is a viewer)
```
Decode the token at the payload level (`cut -d. -f2 | base64 -d`) and compare `iss`, `aud`, `exp`,
`realm_access.roles` with what the API checks in `api/app.py`.

## Gotcha worth writing about
The token `iss` is `http://localhost:8080/...` (the URL you used), but the API fetches keys from
`http://keycloak:8080/...` (Docker network). That is why `TOKEN_ISSUER` and `JWKS_URL` are separate settings.

## Reset
`docker compose down -v` deletes the Keycloak database volume.
