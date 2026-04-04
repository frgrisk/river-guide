#!/bin/bash
# Configures Keycloak for river-guide OIDC integration testing.
# Creates a realm, OIDC client, groups, and test users.
#
# Usage: ./configure_keycloak.sh [--keycloak-url URL] [--redirect-uris URIS]

set -Eeuo pipefail
trap 'printf "ERROR: Script failed on line %s\n" "$LINENO" >&2' ERR

for cmd in curl jq; do
  command -v "$cmd" &>/dev/null || { printf "ERROR: Missing %s\n" "$cmd" >&2; exit 1; }
done

KEYCLOAK_URL="${KEYCLOAK_URL:-http://localhost:9090}"
REDIRECT_URIS="http://localhost:3000/* https://localhost:3000/*"
REALM="river-guide"
CLIENT_ID="river-guide"
USER_PASSWORD="testpass"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --keycloak-url) KEYCLOAK_URL="$2"; shift ;;
    --redirect-uris) REDIRECT_URIS="$2"; shift ;;
    *) printf "Unknown option: %s\n" "$1" >&2; exit 1 ;;
  esac
  shift
done

# Word splitting is intentional here to split space-separated URIs into lines
# shellcheck disable=SC2086
REDIRECT_URIS_JSON=$(printf '%s\n' $REDIRECT_URIS | jq -R . | jq -s .)
API="$KEYCLOAK_URL/admin"

CACERT="${CACERT:-/etc/ssl/certs/rootCA.pem}"

get_token() {
  curl -sf --cacert "$CACERT" "$KEYCLOAK_URL/realms/master/protocol/openid-connect/token" \
    -d "grant_type=password" -d "client_id=admin-cli" \
    -d "username=admin" -d "password=admin" | jq -r '.access_token'
}

api() {
  local method="$1" path="$2"; shift 2
  curl -sf --cacert "$CACERT" -X "$method" "$API$path" \
    -H "Authorization: Bearer $TOKEN" \
    -H "Content-Type: application/json" "$@"
}

# Wait for Keycloak
printf "Waiting for Keycloak at %s...\n" "$KEYCLOAK_URL"
for i in $(seq 1 120); do
  curl -sf --cacert "$CACERT" "$KEYCLOAK_URL/realms/master" > /dev/null 2>&1 && break
  [[ "$i" -eq 120 ]] && { printf "ERROR: Keycloak not ready\n" >&2; exit 1; }
  sleep 1
done
printf "Keycloak is ready.\n"

TOKEN=$(get_token)
if [[ -z "$TOKEN" || "$TOKEN" == "null" ]]; then
  printf "ERROR: Failed to get admin access token\n" >&2
  exit 1
fi

# Create realm
api POST "/realms" -d "$(jq -n --arg r "$REALM" '{realm:$r, enabled:true}')" 2>/dev/null || true
printf "Realm: %s\n" "$REALM"

# Create or update client
CLIENT_INTERNAL=$(api GET "/realms/$REALM/clients?clientId=$CLIENT_ID" | jq -r '.[0].id // empty')
if [[ -z "$CLIENT_INTERNAL" ]]; then
  printf "Creating client: %s\n" "$CLIENT_ID"
  api POST "/realms/$REALM/clients" -d "$(jq -n \
    --arg id "$CLIENT_ID" --argjson uris "$REDIRECT_URIS_JSON" '{
    clientId:$id, protocol:"openid-connect", publicClient:false,
    standardFlowEnabled:true, directAccessGrantsEnabled:true,
    enabled:true, redirectUris:$uris, webOrigins:["+"]
  }')"
  CLIENT_INTERNAL=$(api GET "/realms/$REALM/clients?clientId=$CLIENT_ID" | jq -r '.[0].id')
else
  printf "Updating client redirect URIs: %s\n" "$CLIENT_ID"
  api GET "/realms/$REALM/clients/$CLIENT_INTERNAL" \
    | jq --argjson uris "$REDIRECT_URIS_JSON" '.redirectUris = $uris | .webOrigins = ["+"]' \
    | api PUT "/realms/$REALM/clients/$CLIENT_INTERNAL" -d @-
fi
if [[ -z "$CLIENT_INTERNAL" || "$CLIENT_INTERNAL" == "null" ]]; then
  printf "ERROR: Failed to get client internal ID\n" >&2
  exit 1
fi
CLIENT_SECRET=$(api GET "/realms/$REALM/clients/$CLIENT_INTERNAL/client-secret" | jq -r '.value')

# Add groups mapper
api POST "/realms/$REALM/clients/$CLIENT_INTERNAL/protocol-mappers/models" -d '{
  "name":"groups","protocol":"openid-connect","protocolMapper":"oidc-group-membership-mapper",
  "config":{"full.path":"false","id.token.claim":"true","access.token.claim":"true","claim.name":"groups","userinfo.token.claim":"true"}
}' 2>/dev/null || true

# Create groups
for group in "allowed-group" "other-group"; do
  api POST "/realms/$REALM/groups" -d "$(jq -n --arg n "$group" '{name:$n}')" 2>/dev/null || true
done

GROUP_ID=$(api GET "/realms/$REALM/groups?search=allowed-group&exact=true" | jq -r '.[0].id')
OTHER_GROUP_ID=$(api GET "/realms/$REALM/groups?search=other-group&exact=true" | jq -r '.[0].id')
if [[ -z "$GROUP_ID" || "$GROUP_ID" == "null" || -z "$OTHER_GROUP_ID" || "$OTHER_GROUP_ID" == "null" ]]; then
  printf "ERROR: Failed to get group IDs\n" >&2
  exit 1
fi

# Create users
create_user() {
  local username="$1" group_id="$2"
  api POST "/realms/$REALM/users" -d "$(jq -n \
    --arg u "$username" --arg p "$USER_PASSWORD" '{
    username:$u, firstName:$u, lastName:"Test", email:($u+"@test.example.com"),
    enabled:true, emailVerified:true,
    credentials:[{type:"password",value:$p,temporary:false}]
  }')" 2>/dev/null || true
  local uid
  uid=$(api GET "/realms/$REALM/users?username=$username&exact=true" | jq -r '.[0].id')
  api PUT "/realms/$REALM/users/$uid/groups/$group_id" 2>/dev/null || true
}

create_user "testuser" "$GROUP_ID"
create_user "denieduser" "$OTHER_GROUP_ID"

printf "\n=== Keycloak configured ===\n"
printf "Realm:         %s\n" "$REALM"
printf "Client ID:     %s\n" "$CLIENT_ID"
printf "Client Secret: %s\n" "$CLIENT_SECRET"
printf "Issuer URL:    %s/realms/%s\n" "$KEYCLOAK_URL" "$REALM"
printf "Users:         testuser (allowed-group), denieduser (other-group)\n"
printf "Password:      %s\n" "$USER_PASSWORD"
