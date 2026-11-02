import json
import os
import sys
from pathlib import Path

# Ensure app directory and project root are in sys.path
APP_DIR = Path(__file__).resolve().parent
ROOT_DIR = APP_DIR.parent
for p in (str(APP_DIR), str(ROOT_DIR)):
    if p not in sys.path:
        sys.path.insert(0, p)

try:
    from app.analyzer import analyze_apk
except ImportError:
    try:
        from analyzer import analyze_apk
    except ImportError:
        from main import analyze_apk


if len(sys.argv) != 2:
    raise SystemExit("Expected one private APK path.")

target_path = Path(sys.argv[1]).resolve()
if not target_path.is_file():
    raise SystemExit(f"Sample file not found: {target_path}")

manifest, findings = analyze_apk(target_path)
sys.stdout.write(json.dumps({"manifest": manifest, "findings": findings}, ensure_ascii=False))
