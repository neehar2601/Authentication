# AuthLab & Identity Security Engineering Platform

A multi-phase identity, authentication, and token security engineering lab.

---

## 🏛️ Project Architecture & Phases

```
authlab-lab/
├── phase-1/              # Phase 1: Keycloak 26 Identity Stack & Multi-Tier RBAC App
│   ├── docker-compose.yml# Keycloak + PostgreSQL + Resource API + Nginx Frontend
│   ├── api/              # Flask Resource API with RS256 token verification & DB sync
│   ├── frontend/         # Interactive UI: FarmSight 360 & AuthLab Access Showcase
│   ├── demo_auth.sh      # CLI token test script
│   ├── README.md         # Full setup guide for Phase 1
│   └── PHASE1_MINIMAL_GUIDE.md # Minimal reference guide
│
├── phase-2/              # Phase 2: JWT Attack & Defense Lab (Build & Break JWTs)
│   ├── auth.py           # In-memory KeyStore, rotation, secure vs naive verifiers
│   ├── app.py            # Standalone API with /token & /.well-known/jwks.json
│   ├── requirements.txt  # flask, pyjwt[crypto], pytest
│   ├── pytest.ini        # Test runner configuration
│   ├── README.md         # Attack matrix & defense guide
│   └── tests/
│       └── test_jwt_attacks.py # 16 automated security exploit tests
│
└── README.md             # This master directory index
```

---

## 🧭 Phase Comparison

| Dimension | [Phase 1: Enterprise IdP & App Stack](file:///home/neehar/Documents/authlab-lab/phase-1/README.md) | [Phase 2: JWT Attack & Defense Lab](file:///home/neehar/Documents/authlab-lab/phase-2/README.md) |
|---|---|---|
| **Primary Focus** | Complete OIDC integration, Keycloak administration, and real-world UI access control | Deep cryptographic inspection of JWT internals, attack vectors, and exploit unit tests |
| **Identity Provider** | **Keycloak 26** (`quay.io/keycloak/keycloak:26.0`) | In-memory Python **`KeyStore`** with JWKS endpoint |
| **Storage Tier** | **PostgreSQL 16** (`postgres:16-alpine`) | Ephemeral in-memory structures |
| **Frontend UI** | Nginx web dashboard hosting **FarmSight 360** and **AuthLab Showcase** | CLI / Pytest automated exploit suite |
| **Key Scenarios** | Login/Register flows, Keycloak Admin Console role updates, DB query scoping | `alg: "none"` bypass, `HS256` key confusion (CVE-2015-9235), signature tampering, key rotation |
| **Execution** | `docker compose up -d --build` (in `phase-1/`) | `pytest -v` (in `phase-2/`) |

---

## 🚀 Quick Start Guide

### 🌾 Phase 1: Keycloak + PostgreSQL + Multi-Tier RBAC Web App

Phase 1 provides an enterprise-style OAuth2/OIDC stack with **Keycloak 26**, **PostgreSQL 16**, a **Flask API**, and a modern web dashboard.

```bash
cd phase-1

# 1. Prepare environment
cp .env.example .env

# 2. Start services (PostgreSQL, Keycloak, Flask API, Nginx Web UI)
docker compose up -d --build
```

#### Services Available:
| Service | URL | Purpose |
|---|---|---|
| **FarmSight 360 Portal** | `http://localhost:3000` | Sample agricultural app with roles `farmer` & `service_provider` |
| **AuthLab RBAC Showcase** | `http://localhost:3000/authlab.html` | Multi-tier content portal dynamically filtered for `viewer`, `developer`, `admin` |
| **Resource API** | `http://localhost:5001/health` | RS256 JWT validation, JWKS fetching, role scoping |
| **Keycloak Admin Console** | `http://localhost:8080/admin` | Master admin console (`admin` / `Admin@2601` or `.env` credentials) |

👉 **Read the complete Phase 1 documentation**: [phase-1/README.md](file:///home/neehar/Documents/authlab-lab/phase-1/README.md)

---

### 🛡️ Phase 2: JWT Attack & Defense Lab

Phase 2 is a lightweight, self-contained Python security playground designed to build and systematically break a JWT issuer without needing Keycloak.

```bash
cd phase-2

# 1. Create virtual environment and install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 2. Run the automated exploit suite (16 tests covering all attack vectors)
pytest -v

# 3. (Optional) Run the standalone token issuer API on port 5001
python app.py
```

#### Attack Vectors Tested & Proved:
- **`alg: "none"` bypass**: Stripping the signature; fools naive verifiers, rejected by strict allow-lists.
- **`alg: "HS256"` Key Confusion (CVE-2015-9235)**: Reusing public key PEM as an HMAC secret; fools naive verifiers, rejected by asymmetric allow-lists.
- **Payload Tampering**: Modifying role claims without signing key; caught by RSA signature check.
- **Attacker Key Substitution**: Signing with rogue RSA key while claiming legitimate `kid`.
- **Token Expiration / Replay**: Expired tokens rejected via mandatory `exp` claim checks.
- **Audience & Issuer Confusion**: Tokens intended for other services rejected via `aud` / `iss` pinning.
- **Key Rotation & Retirement**: Graceful rotation via JWKS; retired keys immediately stop validating.

👉 **Read the complete Phase 2 documentation**: [phase-2/README.md](file:///home/neehar/Documents/authlab-lab/phase-2/README.md)
