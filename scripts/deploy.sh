#!/usr/bin/env bash
# ==============================================================================
# DroidTTP - Automated Production Deployment Script
# Provisions environment, generates secrets/certs, builds & starts containers
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "================================================================"
echo "    DroidTTP: Android CTI Workbench - Production Deployment"
echo "================================================================"

# 1. Dependency Checks
echo "[*] Verifying deployment prerequisites..."
for cmd in docker openssl; do
    if ! command -v "$cmd" >/dev/null 2>&1; then
        echo "[ERROR] Required utility '$cmd' is not installed or not in PATH."
        exit 1
    fi
done

# Check Docker Compose (plugin or standalone)
if docker compose version >/dev/null 2>&1; then
    DOCKER_COMPOSE="docker compose"
elif command -v docker-compose >/dev/null 2>&1; then
    DOCKER_COMPOSE="docker-compose"
else
    echo "[ERROR] Neither 'docker compose' nor 'docker-compose' was found."
    exit 1
fi
echo "[OK] Prerequisites verified."

# 2. Environment Configuration (.env)
ENV_FILE="${ROOT_DIR}/.env"
if [[ ! -f "${ENV_FILE}" ]]; then
    echo "[*] Creating production .env configuration..."
    cp "${ROOT_DIR}/.env.production.example" "${ENV_FILE}"

    # Generate high-entropy 48-byte base64 secret
    GENERATED_SECRET="$(openssl rand -base64 48 | tr -d '\n')"
    sed -i "s|REPLACE_WITH_LONG_RANDOM_SECRET_AT_LEAST_32_CHARACTERS_ABC123|${GENERATED_SECRET}|g" "${ENV_FILE}"

    # Generate random admin password
    GENERATED_PASSWORD="$(openssl rand -hex 16)"
    sed -i "s|REPLACE_WITH_STRONG_PRODUCTION_PASSWORD|${GENERATED_PASSWORD}|g" "${ENV_FILE}"

    chmod 600 "${ENV_FILE}"
    echo "[OK] Generated .env file with secure secrets."
    NEW_ENV=true
else
    echo "[INFO] Existing .env file found. Preserving current credentials."
    NEW_ENV=false
fi

# 3. TLS Certificates
echo "[*] Verifying TLS certificates for Nginx reverse proxy..."
bash "${ROOT_DIR}/nginx/generate_certs.sh" localhost

# 4. Prepare Data Directory
echo "[*] Ensuring private storage directories exist..."
mkdir -p "${ROOT_DIR}/data/samples"
chmod 700 "${ROOT_DIR}/data" "${ROOT_DIR}/data/samples" 2>/dev/null || true

# 5. Build and Start Docker Containers
echo "[*] Building and starting DroidTTP containers via Docker Compose..."
cd "${ROOT_DIR}"
${DOCKER_COMPOSE} up -d --build

# 6. Health & Readiness Verification
echo "[*] Waiting for DroidTTP backend and proxy to become healthy..."
MAX_ATTEMPTS=30
ATTEMPT=0
HEALTHY=false

while [[ $ATTEMPT -lt $MAX_ATTEMPTS ]]; do
    ATTEMPT=$((ATTEMPT + 1))
    if curl -skf https://127.0.0.1/healthz >/dev/null 2>&1; then
        HEALTHY=true
        break
    fi
    sleep 2
done

if [[ "${HEALTHY}" != "true" ]]; then
    echo "[WARN] Service did not respond within 60 seconds."
    echo "[*] Inspect container logs with: ${DOCKER_COMPOSE} logs"
    exit 1
fi

echo "================================================================"
echo " [SUCCESS] DroidTTP is deployed and running!"
echo "================================================================"
echo " - Access URL:      https://localhost (or https://<server-ip>)"
echo " - Health Probe:    https://localhost/healthz"
echo " - Readiness Probe: https://localhost/readyz"

if [[ "${NEW_ENV}" == "true" ]]; then
    echo ""
    echo " Initial Sign-in Credentials:"
    echo " ----------------------------"
    echo " Username: $(grep '^DROIDTTP_USERNAME=' "${ENV_FILE}" | cut -d= -f2)"
    echo " Password: ${GENERATED_PASSWORD}"
    echo " Role:     $(grep '^DROIDTTP_ROLE=' "${ENV_FILE}" | cut -d= -f2)"
    echo ""
    echo " Please save these credentials securely. They are stored in .env."
fi

echo ""
echo " Management commands:"
echo "   View logs:   ${DOCKER_COMPOSE} logs -f"
echo "   Stop stack:  ${DOCKER_COMPOSE} down"
echo "   Take backup: ./scripts/backup.sh"
echo "================================================================"
