"""Read-only views over the bundled CSV metadata dataset."""

from __future__ import annotations

import csv
import hashlib
import io
import math
import zipfile
from collections import Counter
from functools import lru_cache
from pathlib import Path

DATASET_PATH = Path(__file__).resolve().parent.parent / "data" / "TTP Dataset.zip"
MAX_CSV_BYTES = 32 * 1024 * 1024
MAX_RECORDS = 100_000
REQUIRED_FIELDS = {"pkg_name", "sha256", "label"}

PROFILE_FIELDS = (
    "cert_present",
    "is_self_signed",
    "valid_years",
    "cert_algo",
    "cert_key_size",
    "signature_strength",
    "perm_count",
    "sensitive_perm_count",
    "api_call_count",
    "distinct_opcodes",
    "opcode_entropy",
    "control_flow_ratio",
    "reflection_ratio",
    "string_op_ratio",
    "total_opcodes",
    "control_flow_count",
    "reflection_count",
    "vt_detection",
    "perm_send_sms",
    "perm_receive_sms",
    "perm_read_sms",
    "perm_write_sms",
    "perm_call_phone",
    "perm_read_phone_state",
    "perm_read_call_log",
    "perm_read_contacts",
    "perm_access_fine_location",
    "perm_access_coarse_location",
    "perm_camera",
    "perm_record_audio",
    "perm_request_install_packages",
    "perm_system_alert_window",
    "perm_write_settings",
)

SUMMARY_NUMERIC_FIELDS = (
    "api_call_count",
    "perm_count",
    "sensitive_perm_count",
    "vt_detection",
)


class DatasetUnavailableError(RuntimeError):
    """Raised when the bundled metadata archive is missing or invalid."""


def _number(value: str) -> float | None:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return parsed if math.isfinite(parsed) else None


@lru_cache(maxsize=1)
def load_bundled_dataset() -> tuple[dict, list[dict[str, str]]]:
    """Read the bounded, bundled CSV in memory without extracting its archive."""
    if not DATASET_PATH.is_file():
        raise DatasetUnavailableError("The bundled TTP Dataset.zip file is not available.")
    try:
        archive_hash = hashlib.sha256()
        with DATASET_PATH.open("rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                archive_hash.update(chunk)
        with zipfile.ZipFile(DATASET_PATH) as archive:
            csv_entries = [item for item in archive.infolist() if item.filename.lower().endswith(".csv")]
            if len(csv_entries) != 1:
                raise DatasetUnavailableError("The bundled dataset must contain exactly one CSV file.")
            entry = csv_entries[0]
            if entry.file_size > MAX_CSV_BYTES:
                raise DatasetUnavailableError("The bundled dataset CSV exceeds the 32 MB read limit.")
            if entry.flag_bits & 0x1:
                raise DatasetUnavailableError("The bundled dataset CSV is encrypted and cannot be read.")
            with archive.open(entry) as raw:
                reader = csv.DictReader(io.TextIOWrapper(raw, encoding="utf-8-sig"))
                fields = set(reader.fieldnames or [])
                if not REQUIRED_FIELDS.issubset(fields):
                    raise DatasetUnavailableError("The bundled CSV is missing required package, hash, or label fields.")
                rows: list[dict[str, str]] = []
                for index, row in enumerate(reader, start=1):
                    if index > MAX_RECORDS:
                        raise DatasetUnavailableError("The bundled dataset exceeds the 100,000 record limit.")
                    rows.append({
                        "row_id": str(index),
                        "package_name": (row.get("pkg_name") or "").strip()[:255],
                        "sha256": (row.get("sha256") or "").strip()[:128],
                        "label": (row.get("label") or "").strip()[:40],
                        **{
                            field: (row.get(field) or "").strip()[:255]
                            for field in PROFILE_FIELDS
                        },
                    })
    except DatasetUnavailableError:
        raise
    except (OSError, UnicodeError, csv.Error, zipfile.BadZipFile, zipfile.LargeZipFile, RuntimeError) as exc:
        raise DatasetUnavailableError("The bundled TTP Dataset.zip could not be read as a CSV dataset.") from exc

    labels = Counter(row["label"] or "(missing)" for row in rows)
    unique_packages = len({row["package_name"] for row in rows if row["package_name"]})
    grouped: dict[str, dict[str, list[float]]] = {}
    for row in rows:
        label = row["label"] or "(missing)"
        grouped.setdefault(label, {})
        for field in SUMMARY_NUMERIC_FIELDS:
            value = _number(row[field])
            if value is not None:
                grouped[label].setdefault(field, []).append(value)

    label_counts = [
        {
            "value": label,
            "count": count,
            "percentage": round(count * 100 / len(rows), 1) if rows else 0,
        }
        for label, count in sorted(labels.items())
    ]
    feature_summary = {
        label: {
            field: {
                "count": len(values),
                "mean": round(sum(values) / len(values), 2) if values else None,
            }
            for field, values in fields.items()
        }
        for label, fields in sorted(grouped.items())
    }
    summary = {
        "available": True,
        "source_file": f"{DATASET_PATH.name} / {entry.filename}",
        "source_sha256": archive_hash.hexdigest(),
        "record_count": len(rows),
        "unique_package_count": unique_packages,
        "label_counts": label_counts,
        "feature_summary_by_label": feature_summary,
        "label_semantics": "Labels are shown exactly as stored in the source dataset; their meaning is not asserted.",
        "analysis_scope": "These are CSV metadata profiles, not APK files. Descriptive statistics are not model predictions or classifier accuracy.",
    }
    return summary, rows


def filter_dataset_records(
    rows: list[dict[str, str]],
    query: str = "",
    label: str = "all",
) -> list[dict[str, str]]:
    normalized_query = query.strip().casefold()[:120]
    return [
        row for row in rows
        if (label == "all" or row["label"] == label)
        and (
            not normalized_query
            or normalized_query in row["package_name"].casefold()
            or normalized_query in row["sha256"].casefold()
        )
    ]
