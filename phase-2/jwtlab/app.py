"""Phase 2 API: /token issues RS256 JWTs, /.well-known/jwks.json publishes keys."""
import os
from functools import wraps

import jwt
from flask import Flask, g, jsonify, request
from werkzeug.security import check_password_hash, generate_password_hash

from auth import KeyStore, issue_token, verify_token

DEMO_PASSWORD = os.environ.get("DEMO_PASSWORD", "demo-password")  # local lab only
USERS = {"alice": ("viewer", generate_password_hash(DEMO_PASSWORD)),
         "bob": ("admin", generate_password_hash(DEMO_PASSWORD))}


def create_app(store=None):
    app = Flask(__name__)
    app.store = store or KeyStore()

    def require(*roles):
        def deco(fn):
            @wraps(fn)
            def wrapper(*a, **kw):
                h = request.headers.get("Authorization", "")
                if not h.startswith("Bearer "):
                    return jsonify(error="missing_token"), 401
                try:
                    g.claims = verify_token(h[7:], app.store)
                except jwt.ExpiredSignatureError:
                    return jsonify(error="token_expired"), 401
                except jwt.InvalidTokenError as e:
                    return jsonify(error="invalid_token", detail=type(e).__name__), 401
                if roles and not set(roles) & set(g.claims.get("roles", [])):
                    return jsonify(error="forbidden"), 403
                return fn(*a, **kw)
            return wrapper
        return deco

    @app.post("/token")
    def token():
        body = request.get_json(silent=True) or {}
        user = USERS.get(body.get("username"))
        if not user or not check_password_hash(user[1], body.get("password", "")):
            return jsonify(error="invalid_credentials"), 401
        return jsonify(access_token=issue_token(app.store, body["username"], [user[0]]),
                       token_type="Bearer", expires_in=900)

    @app.get("/.well-known/jwks.json")
    def jwks():
        return jsonify(app.store.jwks())

    @app.get("/api/me")
    @require()
    def me():
        return jsonify(sub=g.claims["sub"], roles=g.claims["roles"])

    @app.get("/api/admin")
    @require("admin")
    def admin():
        return jsonify(message="admin area")

    return app


if __name__ == "__main__":
    create_app().run(port=5001)
