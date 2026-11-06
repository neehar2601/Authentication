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

### 1. 🔐 Keycloak RBAC Test Bench Tab
- **1-Click Quick Sign-In**:
  - 👩‍💻 **`alice`** (`alice123`) &rarr; Role: `User` / `viewer`
  - 🛡️ **`bob`** (`bob123`) &rarr; Role: `Admin` / `admin`
  - 🧑‍💻 **`drench`** (`drench123`) &rarr; Role: `Developer`
- **Active Token Inspector**:
  - Visual display of Subject UUID (`sub`), Username, Audience (`aud`), Realm Roles, and Live Expiration countdown.
  - Complete raw decoded JSON inspector and 1-click **📋 Copy Token** button.
- **Interactive Endpoint Runner**:
  - `GET /api/public` &rarr; 🟢 **`200 OK`** (Unauthenticated)
  - `GET /api/me` &rarr; 🔵 **`200 OK`** (Profile with verified claims)
  - `GET /api/users` &rarr; 🟣 **`200 OK`** (Allowed for all users)
  - `GET /api/admin/users` &rarr; 🔴 **`403 Forbidden`** for Alice, 🟢 **`200 OK`** for Bob!
- **Live Response Console**: Shows status code badges, roundtrip latency (ms), and formatted JSON.

---

### 2. 💥 JWT Attack & Defense Simulator Tab
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

### 3. 🔑 Live JWKS & Key Inspector Tab
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
