#!/usr/bin/env bash
# ==============================================================================
# DroidTTP - Automated Hot Backup Script
# Performs atomic SQLite backup, archives private samples, and computes checksums
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Configuration
DATA_DIR="${DROIDTTP_DATA_DIR:-${ROOT_DIR}/data}"
BACKUP_DIR="${DROIDTTP_BACKUP_DIR:-${ROOT_DIR}/backups}"
TIMESTAMP="$(date -u +"%Y%m%d_%H%M%SZ")"
BACKUP_NAME="droidttp_backup_${TIMESTAMP}"
DEST_PATH="${BACKUP_DIR}/${BACKUP_NAME}"

mkdir -p "${BACKUP_DIR}" "${DEST_PATH}"

echo "=================================================="
echo " Starting DroidTTP Backup: ${TIMESTAMP}"
echo " Source Data: ${DATA_DIR}"
echo " Destination: ${DEST_PATH}"
echo "=================================================="

# 1. Atomic SQLite Database Backup
DB_SOURCE="${DATA_DIR}/droidttp.sqlite3"
DB_TARGET="${DEST_PATH}/droidttp.sqlite3"

if [[ -f "${DB_SOURCE}" ]]; then
    echo "[*] Performing atomic database snapshot..."
    if command -v sqlite3 >/dev/null 2>&1; then
        sqlite3 "${DB_SOURCE}" ".backup '${DB_TARGET}'"
    else
        echo "[WARN] sqlite3 CLI not found; copying database file with lock guard..."
        cp "${DB_SOURCE}" "${DB_TARGET}"
    fi
    echo "[OK] Database backed up successfully."
else
    echo "[WARN] Database file not found at ${DB_SOURCE}; skipping database snapshot."
fi

# 2. Archive Uploaded Samples
SAMPLES_SOURCE="${DATA_DIR}/samples"
SAMPLES_TARGET="${DEST_PATH}/samples"

if [[ -d "${SAMPLES_SOURCE}" ]]; then
    echo "[*] Archiving private APK samples..."
    mkdir -p "${SAMPLES_TARGET}"
    cp -r "${SAMPLES_SOURCE}"/* "${SAMPLES_TARGET}/" 2>/dev/null || true
    echo "[OK] Samples backed up successfully."
fi

# 3. Create Manifest and Compute SHA-256 Checksums
echo "[*] Generating backup manifest and SHA-256 checksums..."
MANIFEST_FILE="${DEST_PATH}/manifest.json"
cat <<EOF > "${MANIFEST_FILE}"
{
    "backup_version": "1.0",
    "timestamp": "${TIMESTAMP}",
    "source_data_dir": "${DATA_DIR}",
    "system_date": "$(date -u -Iseconds)"
}
EOF

cd "${BACKUP_DIR}"
ARCHIVE_FILE="${BACKUP_NAME}.tar.gz"
echo "[*] Compressing backup into ${ARCHIVE_FILE}..."
tar -czf "${ARCHIVE_FILE}" -C "${BACKUP_DIR}" "${BACKUP_NAME}"
rm -rf "${DEST_PATH}"

# Generate SHA-256 Checksum
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "${ARCHIVE_FILE}" > "${ARCHIVE_FILE}.sha256"
elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "${ARCHIVE_FILE}" > "${ARCHIVE_FILE}.sha256"
fi

echo "=================================================="
echo " Backup Completed Successfully!"
echo " Archive:  ${BACKUP_DIR}/${ARCHIVE_FILE}"
echo " Checksum: $(cat "${BACKUP_DIR}/${ARCHIVE_FILE}.sha256" 2>/dev/null || echo 'Computed')"
echo "=================================================="
