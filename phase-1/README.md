# Phase 1: Keycloak Identity Stack & Multi-Tier RBAC Applications

Phase 1 provides an enterprise-style OAuth2/OIDC identity and access management stack featuring **Keycloak 26**, **PostgreSQL 16**, a **Flask Resource API**, and two interactive web applications served via **Nginx**.

---

## 🏛️ Phase 1 Architecture

```
phase-1/
├── docker-compose.yml          # Container topology (Postgres, Keycloak, Flask API, Nginx)
├── .env / .env.example         # Passwords and Keycloak admin credentials
├── demo_auth.sh                # CLI curl script testing Keycloak password flow & API access
├── PHASE1_MINIMAL_GUIDE.md     # Reference guide for the minimal 83-line starter lab
├── app_minimal_reference.py    # Clean reference API implementation
│
├── api/                        # Flask Resource API (Port 5001)
│   ├── Dockerfile              # Python 3.12-slim container
│   ├── app.py                  # API validating RS256 JWTs & scoping DB queries
│   └── requirements.txt        # Flask, PyJWT[crypto], psycopg2-binary, gunicorn
│
└── frontend/                   # Web Client Applications (Port 3000)
    ├── index.html & app.js     # FarmSight 360 Application (farm360 Realm)
    ├── authlab.html & authlab.js # Multi-Tier Access Level Showcase (authlab Realm)
    └── styles.css              # Unified UI stylesheet
```

---

## 🚀 Quick Start (Docker Compose)

```bash
cd phase-1

# 1. Prepare environment variables
cp .env.example .env

# 2. Boot the entire stack
docker compose up -d --build
```

### Services & Endpoints:

| Service | Internal Port | Host Port | URL | Description |
|---|---|---|---|---|
| **Web Frontend** | `80` | `3000` | http://localhost:3000 | Nginx static server hosting both web applications |
| **Flask Resource API** | `5000` | `5001` | http://localhost:5001/health | RS256 JWT validation, JWKS fetching, DB queries |
| **Keycloak Identity Provider** | `8080` | `8080` | http://localhost:8080 | OIDC Identity Provider with `farm360` & `authlab` realms |
| **Keycloak Admin Console** | `8080` | `8080` | http://localhost:8080/admin | Official Keycloak administration dashboard |
| **PostgreSQL Database** | `5432` | internal | `postgres:5432` | Backing database for Keycloak and application tables |

---

## 📱 Two Interactive Web Applications Included

### 1. 🌾 FarmSight 360 Portal (`http://localhost:3000`)
Modeled after **FarmSight 360**, backed by PostgreSQL tables and authenticated through Keycloak realm **`farm360`** (Client: `farm360-web`):
- **User Roles**:
  - `farmer`: Farm Owner — manages crop plots, records worker attendance, logs finances, and books contractor machinery.
  - `service_provider`: Agricultural Contractor — lists equipment/services (drone spraying, harvesters) and fulfills bookings.
  - `admin`: Platform Administrator.
- **Core Modules**:
  - **Farms & Crops**: Track crop stages (`Planted` → `Growing` → `Flowering` → `Ready for Harvest` → `Harvested`), acreage, and yield projections.
  - **Workforce & Attendance**: Roster farm laborers and toggle daily attendance (`Present`, `Half-Day`, `Absent`).
  - **Service Marketplace**: Book contractor machinery and update booking statuses (`Pending` → `Confirmed` → `Completed`).
  - **Farm Finances**: Real-time income & expense ledger.

### 2. 🔐 AuthLab Multi-Tier Access Showcase (`http://localhost:3000/authlab.html`)
Demonstrates strict **Role-Based Access Control (RBAC)** where all users authenticate through the **same login page** using Keycloak realm **`authlab`**, and content is dynamically unlocked and permitted based on the user's role:

| Access Level | Demo User | Visible Content | Permissions & Controls |
|---|---|---|---|
| **📖 Reader (`viewer`)** | `alice` / `alice123` | **Tier 1: Reader Content ONLY** | **Strict Read-Only**: Can view architecture guides, system status, and security handbooks. Developer & Admin sections are locked. |
| **💻 Developer (`developer`)** | `dev` / `dev123` | **Tier 1 (Reader) + Tier 2 (Developer)** | **Read + Edit + Create**: Unlocks runtime feature flags, CI/CD specs, and webhooks with `💾 Save Edit` and `+ Publish Content`. Admin section is locked. |
| **🛡️ Admin (`admin`)** | `bob` / `bob123` | **All 3 Tiers (Reader + Developer + Admin)** | **Full Control**: Unlocks database rotation policies, Zero-Trust IAM governance, and disaster recovery controls with full Create, Edit, and Delete privileges. |

---

## 👥 Pre-Seeded User Accounts

### `authlab` Realm Accounts:
| Username | Password | Role | Description |
|---|---|---|---|
| `alice` | `alice123` | `viewer` | Reader — L1 read-only access to reader content |
| `dev` | `dev123` | `developer` | Developer — L2 read & write access to reader and developer content |
| `bob` | `bob123` | `admin` | Admin — L3 full access to all three tiers |

### `farm360` Realm Accounts:
| Username | Password | Role | Description |
|---|---|---|---|
| `ramesh` | `ramesh123` | `farmer` | Farm Owner — manages farms, crops, workers, and bookings |
| `kiran` | `kiran123` | `service_provider` | Contractor — manages machinery listings & fulfills bookings |
| `admin_farm`| `admin123` | `admin` | Farm platform administrator |

### 🛡️ Keycloak Master Admin Console:
- **URL**: http://localhost:8080/admin
- **Username**: `admin` (configured in `.env`)
- **Password**: `Admin@2601` (configured in `.env`)

---

## 🔒 Token Verification Architecture (`api/app.py`)

1. **JWKS Fetching**: The API uses `PyJWKClient` pointing at Keycloak's JWKS endpoint over the internal Docker network (`http://keycloak:8080/realms/<realm>/protocol/openid-connect/certs`).
2. **Asymmetric Verification**: Validates the RS256 signature using the Keycloak public key corresponding to the token's `kid`.
3. **Claim Validation**:
   - `iss`: Validated against `http://localhost:8080/realms/<realm>`.
   - `aud`: Validated against the target API audience.
   - `exp` & `iat`: Enforced to prevent replay attacks and expired session access.
4. **Role Enforcement**: Roles are extracted from `claims["realm_access"]["roles"]` to enforce permissions on protected endpoints.

---

## 🛠️ CLI Verification Script

To test the Keycloak password flow and API authorization via `curl`:
```bash
./demo_auth.sh
```

---

## 🧹 Teardown & Reset

```bash
# Stop containers
docker compose down

# Stop containers and delete PostgreSQL database volume (resets all Keycloak & application data)
docker compose down -v
```
