#!/usr/bin/env bash
set -e

KEYCLOAK_URL="http://localhost:8080"
API_URL="http://localhost:5001"
REALM="authlab"
CLIENT_ID="authlab-web"

echo "============================================================"
echo " AuthLab: JWT & OAuth 2.0 Live Walkthrough"
echo "============================================================"

# Helper function to decode JWT payload
decode_jwt() {
  local token="$1"
  python3 -c "
import sys, json, base64
raw = sys.argv[1].split('.')[1]
raw += '=' * (-len(raw) % 4)
print(json.dumps(json.loads(base64.urlsafe_b64decode(raw).decode('utf-8')), indent=2))
" "$token"
}

echo -e "\n1. Testing Public Endpoint (/api/public):"
curl -s -i "${API_URL}/api/public" | head -n 7

echo -e "\n2. Testing Protected Endpoint WITHOUT Token (/api/me):"
curl -s -i "${API_URL}/api/me" | head -n 7

echo -e "\n3. Requesting Token for Alice (Role: viewer):"
ALICE_RESPONSE=$(curl -s -X POST "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
  -d grant_type=password \
  -d client_id="${CLIENT_ID}" \
  -d username=alice \
  -d password=alice123)

ALICE_TOKEN=$(echo "$ALICE_RESPONSE" | python3 -c 'import sys, json; print(json.load(sys.stdin).get("access_token", ""))')

if [ -z "$ALICE_TOKEN" ]; then
  echo "Error fetching token: $ALICE_RESPONSE"
  exit 1
fi

echo "Alice Access Token acquired!"
echo -e "\n--- Decoded Alice JWT Payload ---"
decode_jwt "$ALICE_TOKEN"

echo -e "\n4. Alice accesses /api/me (Expect 200 OK):"
curl -s -i -H "Authorization: Bearer $ALICE_TOKEN" "${API_URL}/api/me" | head -n 7

echo -e "\n5. Alice accesses /api/users (Requires viewer, developer, or admin -> Expect 200 OK):"
curl -s -i -H "Authorization: Bearer $ALICE_TOKEN" "${API_URL}/api/users" | head -n 7

echo -e "\n6. Alice accesses /api/admin/users (Requires admin -> Expect 403 Forbidden):"
curl -s -i -H "Authorization: Bearer $ALICE_TOKEN" "${API_URL}/api/admin/users" | head -n 7

echo -e "\n7. Requesting Token for Bob (Role: admin):"
BOB_RESPONSE=$(curl -s -X POST "${KEYCLOAK_URL}/realms/${REALM}/protocol/openid-connect/token" \
  -d grant_type=password \
  -d client_id="${CLIENT_ID}" \
  -d username=bob \
  -d password=bob123)

BOB_TOKEN=$(echo "$BOB_RESPONSE" | python3 -c 'import sys, json; print(json.load(sys.stdin).get("access_token", ""))')

echo "Bob Access Token acquired!"
echo -e "\n8. Bob accesses /api/admin/users (Requires admin -> Expect 200 OK):"
curl -s -i -H "Authorization: Bearer $BOB_TOKEN" "${API_URL}/api/admin/users" | head -n 7

echo -e "\n============================================================"
echo " All tests completed successfully!"
echo "============================================================"
