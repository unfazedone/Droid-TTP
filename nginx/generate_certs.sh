#!/usr/bin/env bash
# ==============================================================================
# DroidTTP - TLS Self-Signed Certificate Generator
# Generates high-strength 4096-bit RSA TLS certificates with SAN extensions
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="${SCRIPT_DIR}/certs"
DOMAIN="${1:-localhost}"

mkdir -p "${CERTS_DIR}"

CRT_PATH="${CERTS_DIR}/droidttp.crt"
KEY_PATH="${CERTS_DIR}/droidttp.key"

if [[ -f "${CRT_PATH}" && -f "${KEY_PATH}" ]]; then
    echo "[INFO] Existing certificates detected at ${CERTS_DIR}."
    echo "[INFO] If you want to regenerate, remove droidttp.crt and droidttp.key."
    exit 0
fi

echo "[*] Generating private key and self-signed certificate for: ${DOMAIN}..."

openssl req -x509 -nodes -days 365 -newkey rsa:4096 \
    -keyout "${KEY_PATH}" \
    -out "${CRT_PATH}" \
    -subj "/C=US/ST=Security/L=Operations/O=DroidTTP/CN=${DOMAIN}" \
    -addext "subjectAltName=DNS:${DOMAIN},DNS:localhost,IP:127.0.0.1"

chmod 600 "${KEY_PATH}"
chmod 644 "${CRT_PATH}"

echo "[SUCCESS] Generated TLS Certificate: ${CRT_PATH}"
echo "[SUCCESS] Generated Private Key:    ${KEY_PATH}"
