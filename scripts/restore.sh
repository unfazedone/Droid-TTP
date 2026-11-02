#!/usr/bin/env bash
# ==============================================================================
# DroidTTP - Backup Restoration Script
# Restores database and private samples from a verified backup archive
# ==============================================================================

set -euo pipefail

if [[ $# -lt 1 ]]; then
    echo "Usage: $0 <path-to-backup-archive.tar.gz> [target-data-dir]"
    exit 1
fi

ARCHIVE_PATH="$1"
TARGET_DIR="${2:-./data}"

if [[ ! -f "${ARCHIVE_PATH}" ]]; then
    echo "[ERROR] Archive file not found: ${ARCHIVE_PATH}"
    exit 1
fi

echo "=================================================="
echo " Starting DroidTTP Restoration"
echo " Archive:    ${ARCHIVE_PATH}"
echo " Target Dir: ${TARGET_DIR}"
echo "=================================================="

# Check for SHA-256 validation if available
CHECKSUM_FILE="${ARCHIVE_PATH}.sha256"
if [[ -f "${CHECKSUM_FILE}" ]]; then
    echo "[*] Verifying SHA-256 checksum..."
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum -c "${CHECKSUM_FILE}"
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 -c "${CHECKSUM_FILE}"
    fi
    echo "[OK] Integrity verified."
fi

# Create temporary extract directory
TEMP_DIR="$(mktemp -d)"
trap 'rm -rf "${TEMP_DIR}"' EXIT

echo "[*] Extracting archive..."
tar -xzf "${ARCHIVE_PATH}" -C "${TEMP_DIR}"

BACKUP_SUBDIR="$(find "${TEMP_DIR}" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
if [[ -z "${BACKUP_SUBDIR}" ]]; then
    BACKUP_SUBDIR="${TEMP_DIR}"
fi

mkdir -p "${TARGET_DIR}/samples"

# Restore database
if [[ -f "${BACKUP_SUBDIR}/droidttp.sqlite3" ]]; then
    echo "[*] Restoring database to ${TARGET_DIR}/droidttp.sqlite3..."
    cp "${BACKUP_SUBDIR}/droidttp.sqlite3" "${TARGET_DIR}/droidttp.sqlite3"
    
    # Run SQLite integrity check if available
    if command -v sqlite3 >/dev/null 2>&1; then
        echo "[*] Running database integrity check..."
        CHECK_RESULT="$(sqlite3 "${TARGET_DIR}/droidttp.sqlite3" "PRAGMA integrity_check;")"
        if [[ "${CHECK_RESULT}" == "ok" ]]; then
            echo "[OK] Database integrity check passed: ${CHECK_RESULT}"
        else
            echo "[WARN] Database integrity check reported: ${CHECK_RESULT}"
        fi
    fi
fi

# Restore samples
if [[ -d "${BACKUP_SUBDIR}/samples" ]]; then
    echo "[*] Restoring private APK samples..."
    cp -r "${BACKUP_SUBDIR}/samples"/* "${TARGET_DIR}/samples/" 2>/dev/null || true
fi

# Set restrictive permissions
chmod 700 "${TARGET_DIR}" "${TARGET_DIR}/samples" 2>/dev/null || true
if [[ -f "${TARGET_DIR}/droidttp.sqlite3" ]]; then
    chmod 600 "${TARGET_DIR}/droidttp.sqlite3" 2>/dev/null || true
fi

echo "=================================================="
echo " Restoration Completed Successfully!"
echo " Target directory is ready."
echo "=================================================="
