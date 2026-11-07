# Phase 2: Keycloak RBAC Testing & JWT Attack Simulator

Phase 2 provides a complete testing suite with both an **Interactive Web UI** and a **Standalone Cryptographic Exploit Engine**.

---

## 🏛️ Phase 2 Architecture

```
phase-2/
├── docker-compose.yml          # Postgres + Keycloak 26 + Resource API + Nginx Web UI
├── .env / .env.example         # Passwords and Keycloak credentials
│
├── frontend/                   # Interactive Web Testing Suite (Port 3000 & 5000)
│   ├── index.html              # Test bench UI (RBAC, Attack Simulator, JWKS Explorer)
│   ├── app.js                  # OIDC password flow, token decoder & live attack exploits
│   └── styles.css              # Cyber dark-mode UI stylesheet
│
├── api/                        # Flask Resource API (Port 5000)
│   ├── app.py                  # Validates RS256 JWTs via JWKS, enforces RBAC, serves UI
│   ├── Dockerfile
│   └── requirements.txt
│
└── jwtlab/                     # Standalone Cryptographic Attack Suite (Pytest)
    ├── auth.py                 # In-memory KeyStore, rotation, secure vs naive verifier
    ├── app.py                  # Standalone token issuer API (Port 5001)
    ├── tests/
    │   └── test_jwt_attacks.py # 16 automated exploit unit tests
    └── README.md
```

---

## 🚀 Quick Start (Interactive Web UI)

```bash
cd phase-2

# 1. Start all containers (Postgres, Keycloak, Flask API, Nginx Web UI)
docker compose up -d --build
```

### Access URLs:
| Service | URL | Purpose |
|---|---|---|
| **Phase 2 Web Test Suite** | [http://localhost:3000](http://localhost:3000) *(or [:5000](http://localhost:5000))* | Complete Web UI with RBAC Test Bench & JWT Attack Simulator |
| **Resource API** | [http://localhost:5000/api/public](http://localhost:5000/api/public) | Flask API validating RS256 Keycloak tokens |
| **Keycloak Admin Console** | [http://localhost:8080/admin](http://localhost:8080/admin) | Keycloak console (`admin` / `Admin@2601`) |

---

## 🖥️ What You Can Test in the Web UI (`:3000`)

### 1. 🔐 Privilege-Based Landing & Authentication Flow
- **Unauthenticated Login Page Gate**:
  - The UI starts on a clean, dedicated Login Page (no protected content or tabs visible before signing in).
  - Authenticates directly against Keycloak realm `Authlab` via client `authlab-web` using the OIDC Resource Owner Password Credentials (ROPC) grant.
  - 1-Click Quick Demo Sign-In buttons:
    - 📖 **`alice`** (`alice123`) &rarr; Role: `User` (Reader Clearance)
    - 🧑‍💻 **`drench`** (`drench123`) &rarr; Role: `Developer` (Developer Clearance)
    - 🛡️ **`bob`** (`bob123`) &rarr; Role: `Admin` (Administrator Clearance)

### 2. 🏛️ Dynamic Privilege-Based Workspaces
Once logged in, the dashboard dynamically unlocks workspace tiers according to the user's Keycloak realm roles:
- **Level 1: Reader Workspace (Unlocked for Alice, Drench, and Bob)**:
  - Accessible via `GET /api/users`.
  - Displays company directory and architecture knowledge base in strict read-only mode.
- **Level 2: Developer Workspace (Unlocked for Drench and Bob; Locked for Alice)**:
  - Accessible via `GET /api/developer/config`.
  - Displays runtime feature flags, microservice topology, and CI/CD build metrics.
  - Locked card placeholder is shown for Alice with an inline switch button to test privilege elevation.
- **Level 3: Administrator Security Control Center (Unlocked ONLY for Bob)**:
  - Accessible via `GET /api/admin/users`.
  - Displays real-time security audit logs, token algorithm and TTL governance, and Keycloak JWKS rotation controls.
  - Locked card placeholder is shown for Alice and Drench with quick switch to Bob.

### 3. 🔑 Active Token Inspector Modal & User Switcher
- **Hero Privilege Banner**: Shows active clearance badge, visual tier status indicators (Unlocked vs Locked), and 1-click user switcher buttons.
- **Token Inspector Modal**: Click **Inspect Token** in the top navigation to view decoded JWT claims (`sub`, `iss`, `aud`, `exp`, `realm_access.roles`) and copy the raw Bearer token.
- **Sign Out**: One-click session termination that clears tokens and returns to the Login Page.

### 4. 📜 Real-Time Security & Attack Audit Logging
Phase 2 features a comprehensive security logging subsystem that captures every access attempt, privilege evaluation, and blocked attack vector:
- **Logged Event Classifications**:
  - 🟢 **`ACCESS_GRANTED`** (`HTTP 200`): Successful token validation and role clearance match.
  - 🚫 **`RBAC_ACCESS_DENIED`** (`HTTP 403`): Valid identity, but user lacked necessary roles (e.g. Alice attempting to access Developer or Admin APIs).
  - 🚨 **`ATTACK_SIGNATURE_STRIPPING`** (`HTTP 401`): Exploit using `alg: "none"` with empty signature blocked by RS256 algorithm pinning.
  - 🚨 **`ATTACK_KEY_CONFUSION`** (`HTTP 401`): Exploit using `alg: "HS256"` (CVE-2015-9235) with RSA public key blocked.
  - 🚨 **`ATTACK_PAYLOAD_TAMPERING`** (`HTTP 401`): Token payload modified in transit without valid Keycloak RSA private signature.
  - 🟡 **`TOKEN_EXPIRED_REPLAY`** (`HTTP 401`): Replay of expired access tokens caught by timestamp enforcement.
- **Where to View Audit Logs**:
  1. **Interactive Web UI**: Open the **📜 Live Security & Attack Logs** tab on [http://localhost:3000](http://localhost:3000) (includes live filter pills, summary metrics, auto-refresh, and reset buttons).
  2. **CLI / Terminal Stream**: Stream logs in real time via:
     ```bash
     docker logs -f phase-2-api-1
     # or: docker compose logs -f api
     ```
  3. **REST Endpoint**: Query `GET http://localhost:5000/api/audit-logs?filter=attacks` or `GET http://localhost:5000/api/audit-logs?filter=all`.
  4. **Tier 3 Admin Workspace**: Live audit events are automatically integrated into Bob's Admin Control Center.

---

### 5. 💥 JWT Attack & Defense Simulator Tab
Simulates real-world JWT attacks in your browser and contrasts **naive verifiers** against **hardened verifiers**:
- **Exploit 1: `alg: "none"` Signature Stripping**:
  Forges a token with `{"alg": "none"}` and empty signature. Shows why naive verifiers are fooled and how RS256 pinning blocks it.
- **Exploit 2: `alg: "HS256"` Public Key Confusion (CVE-2015-9235)**:
  Fetches the server's public RSA PEM key and uses it as an HMAC secret. Shows why asymmetric allow-lists prevent symmetric key confusion.
- **Exploit 3: Payload Tampering**:
  Modifies Alice's token to claim `roles: ["admin"]` without re-signing, proving that signature verification catches payload edits.
- **Exploit 4: Expired Token Replay**:
  Sends an expired token timestamp, proving mandatory `exp` validation.

---

### 6. 🔑 Live JWKS & Key Inspector Tab
- Fetches and visualizes active public keys in real time from Keycloak:
  `http://localhost:8080/realms/Authlab/protocol/openid-connect/certs`
- Shows Key ID (`kid`), Algorithm (`RS256`), Key Type (`RSA`), and verifies that private key components (`d`) are strictly withheld.

---

## ⚡ Standalone Pytest Attack Suite (`jwtlab/`)

To test the cryptographic attack suite via CLI without Keycloak:

```bash
cd phase-2/jwtlab
source .venv/bin/activate    # or: python3 -m venv .venv && pip install -r requirements.txt
pytest -v
```

All 16 security exploit tests pass (100%).
