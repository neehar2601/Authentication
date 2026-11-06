# Phase 2: JWT Attack & Defense Lab (Build & Break a JWT Issuer)

Phase 2 is a lightweight, standalone Python security playground designed to build and systematically break a JWT issuer without needing Keycloak.

It demonstrates how JWTs work at the cryptographic level, how signing keys rotate via a JSON Web Key Set (JWKS), and why specific cryptographic controls are vital to block classic token exploits.

---

## 🏛️ Phase 2 Structure

```
phase-2/
├── auth.py              # In-memory KeyStore, rotation, secure vs naive verifier
├── app.py               # Standalone API with /token & /.well-known/jwks.json
├── requirements.txt     # flask, pyjwt[crypto], pytest
├── pytest.ini           # Test runner configuration
├── README.md            # This documentation
└── tests/
    └── test_jwt_attacks.py # 16 automated security exploit tests
```

---

## 🚀 Quick Start

### 1. Set Up Virtual Environment & Dependencies

```bash
cd phase-2

# Create and activate virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install required dependencies (flask, pyjwt[crypto], pytest)
pip install -r requirements.txt
```

### 2. Run the Automated Exploit Suite

```bash
pytest -v
```

Expected output:
```text
============================= test session starts ==============================
phase-2/tests/test_jwt_attacks.py::test_valid_token_is_accepted PASSED   [  6%]
phase-2/tests/test_jwt_attacks.py::test_expired_token_rejected PASSED    [ 12%]
phase-2/tests/test_jwt_attacks.py::test_wrong_audience_rejected PASSED   [ 18%]
phase-2/tests/test_jwt_attacks.py::test_wrong_issuer_rejected PASSED     [ 25%]
phase-2/tests/test_jwt_attacks.py::test_missing_exp_rejected PASSED      [ 31%]
phase-2/tests/test_jwt_attacks.py::test_tampered_payload_rejected PASSED [ 37%]
phase-2/tests/test_jwt_attacks.py::test_token_signed_with_attacker_key_rejected PASSED [ 43%]
phase-2/tests/test_jwt_attacks.py::test_unknown_kid_rejected PASSED      [ 50%]
phase-2/tests/test_jwt_attacks.py::test_alg_none_rejected_by_secure_verifier_but_fooled_naive PASSED [ 56%]
phase-2/tests/test_jwt_attacks.py::test_hs256_key_confusion_rejected_by_secure_verifier_but_fooled_naive PASSED [ 62%]
phase-2/tests/test_jwt_attacks.py::test_rotation_old_tokens_valid_until_key_retired PASSED [ 68%]
phase-2/tests/test_jwt_attacks.py::test_bad_password_is_401 PASSED       [ 75%]
phase-2/tests/test_jwt_attacks.py::test_no_token_is_401 PASSED           [ 81%]
phase-2/tests/test_jwt_attacks.py::test_viewer_gets_403_on_admin PASSED  [ 87%]
phase-2/tests/test_jwt_attacks.py::test_admin_gets_200_on_admin PASSED   [ 93%]
phase-2/tests/test_jwt_attacks.py::test_jwks_endpoint_publishes_public_keys_only PASSED [100%]

============================== 16 passed in ~2s ==============================
```

---

## 🛡️ Attack Vectors & Defense Matrix

| Test | Attack Vector | Security Control That Blocks It |
|---|---|---|
| `test_valid_token_is_accepted` | Legitimate user sign-in | Proper RS256 signature & matching claims |
| `test_expired_token_rejected` | Replaying an expired token | `exp` timestamp check (`ExpiredSignatureError`) |
| `test_wrong_audience_rejected` | Token minted for another API service | Strict audience pinning (`aud="authlab-api"`) |
| `test_wrong_issuer_rejected` | Token from an untrusted issuer | Strict issuer pinning (`iss="http://localhost:5001"`) |
| `test_missing_exp_rejected` | Omitting expiration to create "forever tokens" | Enforcing `exp` in `options={"require": ["exp", ...]}` |
| `test_tampered_payload_rejected` | Modifying `roles: ["admin"]` without private key | RSA signature mismatch (`InvalidSignatureError`) |
| `test_token_signed_with_attacker_key_rejected` | Signing with attacker's own RSA key while spoofing real `kid` | Verifier only trusts its own `KeyStore` public keys |
| `test_unknown_kid_rejected` | Pointing token header to a nonexistent `kid` | Reject unknown keys immediately, never fall back |
| `test_alg_none_rejected_...` | Stripping signature with `alg: "none"` | Fixed algorithm allow-list `algorithms=["RS256"]` |
| `test_hs256_key_confusion_...` | Signing HMAC with server's public key (PEM) | Fixed algorithm allow-list pins asymmetric RS256 |
| `test_rotation_old_tokens_valid_...` | Key rotation & retirement lifecycle | Multi-key JWKS lookup; retired keys fail immediately |
| `test_bad_password_is_401` | Brute force / credential stuffing | Password hash verification with werkzeug security |
| `test_no_token_is_401` | Unauthenticated API access | Authorization header check (`Bearer <token>`) |
| `test_viewer_gets_403_on_admin` | Privilege escalation by lower-tier role | Role-based check on `claims["roles"]` |
| `test_admin_gets_200_on_admin` | Legitimate administrative access | Role match allows execution |
| `test_jwks_endpoint_publishes_public_keys_only` | Private key leakage check | JWKS contains only public modulus/exponent, never private exponent (`d`) |

---

## 🔍 Deep-Dive: Core Vulnerabilities Explored

### 1. The `alg: "none"` Bypass
- **The Exploit**: Some early JWT implementations checked the token header's `alg` field. If `alg` was set to `"none"` or `"NONE"`, the verifier assumed the token was meant to be unsigned and skipped signature verification entirely.
- **The Proof**: In [`auth.py`](file:///home/neehar/Documents/authlab-lab/phase-2/auth.py#L90-L92), `naive_verify_token()` accepts `alg: "none"`, allowing an attacker to forge an admin token with an empty signature. `verify_token()` pins `algorithms=["RS256"]`, rejecting it with `InvalidTokenError`.

### 2. The `HS256` Key Confusion Attack (CVE-2015-9235 / CVE-2016-5431)
- **The Exploit**: 
  - RS256 is an **asymmetric** algorithm (private key signs, public key verifies).
  - HS256 is a **symmetric** algorithm (same secret signs and verifies).
  - An attacker takes the server's RSA **public key** (which is publicly readable via `/.well-known/jwks.json` or PEM).
  - The attacker crafts a token with `alg: "HS256"` and signs it using the **public key text as the HMAC secret**.
  - If a verifier naively uses the key retrieved for `kid` without checking that the algorithm matches, it passes the public key to the HMAC verifier, and the signature validates!
- **The Proof**: In [`auth.py`](file:///home/neehar/Documents/authlab-lab/phase-2/auth.py#L93-L99), `naive_verify_token()` falls for this confusion attack. `verify_token()` explicitly restricts accepted algorithms to `["RS256"]`, causing PyJWT to reject HMAC tokens immediately.

### 3. Key Rotation & JWKS Multi-Key Support
- **The Mechanism**: [`KeyStore`](file:///home/neehar/Documents/authlab-lab/phase-2/auth.py#L21-L55) maintains a dictionary of RSA key pairs keyed by `kid`. Calling `store.rotate()` generates a new key pair and makes it the active signing key for new tokens, while keeping the previous key in the JWKS.
- **Retirement**: Once all in-flight tokens signed with the old key have expired, `store.retire(old_kid)` removes it from the JWKS, immediately invalidating any remaining tokens signed with that key.

---

## 🌐 Running the Standalone API

To interact with the Phase 2 token issuer manually:

```bash
# In phase-2 directory with .venv active:
python app.py
```

The API starts on `http://localhost:5001`. In another terminal:

```bash
# 1. Inspect the public JWKS
curl -s http://localhost:5001/.well-known/jwks.json | python3 -m json.tool

# 2. Issue a token for alice (viewer)
TOKEN=$(curl -s -X POST http://localhost:5001/token \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "password": "demo-password"}' | python3 -c 'import sys, json; print(json.load(sys.stdin)["access_token"])')

# 3. Access user profile (200 OK)
curl -s -H "Authorization: Bearer $TOKEN" http://localhost:5001/api/me

# 4. Attempt admin endpoint with alice's token (403 Forbidden)
curl -i -H "Authorization: Bearer $TOKEN" http://localhost:5001/api/admin
```
