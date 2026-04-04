#!/bin/bash
# Start a local Keycloak instance with TLS for OIDC development testing.
# Generates TLS certificates via mkcert, starts Keycloak with docker-compose,
# and prints connection details for running river-guide.
#
# Usage: ./e2e/keycloak.sh
#
# Requirements: docker, mkcert
#
# Ctrl-C to stop and clean up.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
CERT_DIR="$PROJECT_DIR/tls_certificates"

cleanup() {
  printf "\nStopping Keycloak...\n"
  cd "$PROJECT_DIR"
  docker compose -f docker-compose.test.yml down -v 2>/dev/null || true
  printf "Done.\n"
}
trap cleanup EXIT

# --- Generate TLS certificates ---

if ! command -v mkcert &>/dev/null; then
  printf "ERROR: mkcert is required. Install it: https://github.com/FiloSottile/mkcert\n" >&2
  exit 1
fi

if [[ ! -f "$CERT_DIR/keycloak/cert.pem" ]]; then
  printf "Generating TLS certificates...\n"
  mkcert -install 2>/dev/null

  mkdir -p "$CERT_DIR/keycloak" "$CERT_DIR/app"
  mkcert -cert-file "$CERT_DIR/keycloak/cert.pem" \
         -key-file "$CERT_DIR/keycloak/key.pem" \
         keycloak localhost 127.0.0.1 "$(hostname)"
  mkcert -cert-file "$CERT_DIR/app/cert.pem" \
         -key-file "$CERT_DIR/app/key.pem" \
         localhost 127.0.0.1 "$(hostname)"

  cp "$(mkcert -CAROOT)/rootCA.pem" "$CERT_DIR/rootCA.pem"
  printf "Certificates generated in %s\n\n" "$CERT_DIR"
else
  printf "Using existing TLS certificates in %s\n\n" "$CERT_DIR"
fi

# --- Start Keycloak ---

cd "$PROJECT_DIR"
docker compose -f docker-compose.test.yml up -d

printf "Waiting for Keycloak setup to complete...\n"
for i in $(seq 1 120); do
  if docker compose -f docker-compose.test.yml logs keycloak-setup 2>/dev/null | grep -q "Keycloak configured"; then
    break
  fi
  if [[ "$i" -eq 120 ]]; then
    printf "ERROR: Keycloak setup did not complete within 120 seconds\n" >&2
    docker compose -f docker-compose.test.yml logs keycloak-setup >&2
    exit 1
  fi
  sleep 1
done

CLIENT_SECRET=$(docker compose -f docker-compose.test.yml logs keycloak-setup 2>/dev/null | grep "Client Secret:" | tail -1 | awk '{print $NF}')

printf "\n"
printf "============================================\n"
printf "  Keycloak is running (HTTPS)\n"
printf "============================================\n"
printf "\n"
printf "  Admin console:  https://localhost:9443\n"
printf "  Admin login:    admin / admin\n"
printf "\n"
printf "  Issuer URL:     https://localhost:9443/realms/river-guide\n"
printf "  Client ID:      river-guide\n"
printf "  Client Secret:  %s\n" "$CLIENT_SECRET"
printf "\n"
printf "  Test users (password: testpass):\n"
printf "    testuser    - member of 'allowed-group'\n"
printf "    denieduser  - member of 'other-group'\n"
printf "\n"
printf "  Example river-guide command:\n"
printf "\n"
printf "    go run . \\\\\n"
printf "      --provider aws --tags \"Environment=dev\" \\\\\n"
printf "      --oidc-issuer https://localhost:9443/realms/river-guide \\\\\n"
printf "      --oidc-client-id river-guide \\\\\n"
printf "      --oidc-client-secret %s \\\\\n" "$CLIENT_SECRET"
printf "      --oidc-redirect-url https://localhost:3000/callback \\\\\n"
printf "      --oidc-groups allowed-group \\\\\n"
printf "      --oidc-scopes openid,profile,email \\\\\n"
printf "      --oidc-log-claims sub,email \\\\\n"
printf "      --tls-cert tls_certificates/app/cert.pem \\\\\n"
printf "      --tls-key tls_certificates/app/key.pem\n"
printf "\n"
printf "============================================\n"
printf "  Press Ctrl-C to stop\n"
printf "============================================\n"
printf "\n"

# Tail Keycloak logs until interrupted
docker compose -f docker-compose.test.yml logs -f keycloak 2>/dev/null || true
