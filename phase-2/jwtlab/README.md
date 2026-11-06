# Phase 2: build and break a JWT issuer

`auth.py` issues RS256 tokens, publishes a JWKS, and has two verifiers:
a secure one and a deliberately vulnerable one (`naive_verify_token`) that trusts the `alg` header.

## Run
```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pytest -v                 # every attack is a test
python app.py             # API on http://localhost:5001
```

## What each test proves
| Test | Attack | Control that stops it |
|---|---|---|
| expired / missing exp | replay old token, omit expiry | `exp` required and checked |
| wrong audience / issuer | token meant for another service | `aud` and `iss` pinned |
| tampered payload | edit role without re-signing | signature covers the payload |
| attacker key | sign with own key, claim real `kid` | verify against the issuer's key only |
| unknown kid | point at a key that doesn't exist | reject, never fall back |
| alg none | unsigned token | fixed algorithm allow-list |
| HS256 key confusion | public key reused as HMAC secret | allow-list pins RS256 |
| rotation | old key retired | retired kid no longer validates |

The two alg tests assert both sides: the naive verifier is fooled, the secure one is not.
That contrast is the point worth showing on your page.

## Safety
Demo password and keys are for local use only. Keys are generated in memory at startup.
Never run `naive_verify_token` anywhere real.
