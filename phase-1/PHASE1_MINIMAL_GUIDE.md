# AuthLab local lab (Phase 1)

Keycloak + Postgres + a Flask API that validates Keycloak JWTs and enforces roles.
Local development only. Do not expose this stack publicly.

## Start
```bash
cp .env.example .env        # edit the passwords
docker compose up -d --build
docker compose logs -f keycloak   # wait for "Listening on: http://0.0.0.0:8080"
```
Keycloak admin console: http://localhost:8080  (login with the values from .env)

## Configure Keycloak (once)
1. **Realm**: create `authlab`.
2. **Realm roles**: create `viewer`, `developer`, `admin`.
3. **Users**: create `alice` (role `viewer`) and `bob` (role `admin`). Set passwords under Credentials (turn Temporary off).
4. **Client** `authlab-web`: Client authentication OFF (public), Standard flow ON,
   Direct access grants ON (**lab-only shortcut for curl; the real flow is Authorization Code + PKCE**),
   Valid redirect URIs `http://localhost:3000/*`. Under Advanced, set PKCE method `S256`.
5. **Audience**: Clients > `authlab-web` > Client scopes > `authlab-web-dedicated` > Add mapper >
   *Audience*, Included Custom Audience `authlab-api`, Add to access token ON.
   (Without this the API rejects tokens with an `InvalidAudienceError`. That is the audience check working.)

## Try it
```bash
TOKEN=$(curl -s -X POST http://localhost:8080/realms/authlab/protocol/openid-connect/token \
  -d grant_type=password -d client_id=authlab-web \
  -d username=alice -d password='<alice password>' | python3 -c 'import sys,json;print(json.load(sys.stdin)["access_token"])')

curl -i localhost:5000/api/public                                         # 200
curl -i localhost:5000/api/me                                             # 401 missing_token
curl -i -H "Authorization: Bearer $TOKEN" localhost:5000/api/me           # 200
curl -i -H "Authorization: Bearer $TOKEN" localhost:5000/api/admin/users  # 403 (alice is a viewer)
```
Decode the token at the payload level (`cut -d. -f2 | base64 -d`) and compare `iss`, `aud`, `exp`,
`realm_access.roles` with what the API checks in `api/app.py`.

## Gotcha worth writing about
The token `iss` is `http://localhost:8080/...` (the URL you used), but the API fetches keys from
`http://keycloak:8080/...` (Docker network). That is why `TOKEN_ISSUER` and `JWKS_URL` are separate settings.

## Reset
`docker compose down -v` deletes the Keycloak database volume.
