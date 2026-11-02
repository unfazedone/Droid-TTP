"""DroidTTP - Static APK Analysis Engine.

Performs bounded, secure static inspection of Android Application Packages (APKs).
Does NOT execute sample code. Inspects archive entries, manifest XML, packaged strings,
native libraries, and signing artifacts.
"""

from __future__ import annotations

import ipaddress
import json
import re
import struct
import zipfile
from pathlib import Path
from urllib.parse import urlparse
from xml.etree import ElementTree


def _length8(data: bytes, offset: int) -> tuple[int, int]:
    if offset >= len(data):
        raise ValueError("Truncated Android string length.")
    first = data[offset]
    if first & 0x80:
        if offset + 2 > len(data):
            raise ValueError("Truncated Android string length.")
        return ((first & 0x7f) << 8) | data[offset + 1], offset + 2
    return first, offset + 1


def _length16(data: bytes, offset: int) -> tuple[int, int]:
    if offset + 2 > len(data):
        raise ValueError("Truncated Android string length.")
    first = struct.unpack_from("<H", data, offset)[0]
    if first & 0x8000:
        if offset + 4 > len(data):
            raise ValueError("Truncated Android string length.")
        second = struct.unpack_from("<H", data, offset + 2)[0]
        return ((first & 0x7fff) << 16) | second, offset + 4
    return first, offset + 2


def _string_pool(data: bytes, offset: int, chunk_end: int) -> list[str]:
    if offset + 28 > chunk_end:
        raise ValueError("Invalid Android string pool.")
    string_count = struct.unpack_from("<I", data, offset + 8)[0]
    flags = struct.unpack_from("<I", data, offset + 16)[0]
    strings_start = struct.unpack_from("<I", data, offset + 20)[0]
    if string_count > 100_000 or offset + 28 + string_count * 4 > chunk_end:
        raise ValueError("Android string pool exceeds parsing limits.")
    strings: list[str] = []
    utf8 = bool(flags & 0x100)
    for index in range(string_count):
        string_offset = struct.unpack_from("<I", data, offset + 28 + index * 4)[0]
        cursor = offset + strings_start + string_offset
        if cursor >= chunk_end:
            raise ValueError("Invalid Android string offset.")
        if utf8:
            _, cursor = _length8(data, cursor)
            byte_length, cursor = _length8(data, cursor)
            if cursor + byte_length > chunk_end:
                raise ValueError("Invalid Android UTF-8 string length.")
            strings.append(data[cursor:cursor + byte_length].decode("utf-8", "replace"))
        else:
            char_length, cursor = _length16(data, cursor)
            byte_length = char_length * 2
            if byte_length > 24 * 1024 * 1024 or cursor + byte_length > chunk_end:
                raise ValueError("Invalid Android UTF-16 string length.")
            strings.append(data[cursor:cursor + byte_length].decode("utf-16le", "replace"))
    return strings


def _typed_value(data: bytes, offset: int, strings: list[str]):
    value_type = data[offset + 3]
    value = struct.unpack_from("<I", data, offset + 4)[0]
    if value_type == 0x03:
        return strings[value] if value < len(strings) else ""
    if value_type == 0x12:
        return bool(value)
    if value_type in (0x10, 0x11):
        return str(value)
    if value_type == 0x01:
        return f"@0x{value:08x}"
    return None


def _binary_manifest(data: bytes) -> dict:
    result = {
        "package_name": "", "app_name": "", "version_name": "", "version_code": "",
        "min_sdk": "", "target_sdk": "", "permissions": [], "components": [],
        "manifest_kind": "binary-axml",
    }
    if len(data) < 8 or struct.unpack_from("<H", data, 0)[0] != 0x0003:
        raise ValueError("AndroidManifest.xml is not recognized text XML or binary XML.")
    declared_size = struct.unpack_from("<I", data, 4)[0]
    if declared_size < 8 or declared_size > len(data):
        raise ValueError("Invalid binary Android manifest size.")
    strings: list[str] = []
    offset = 8
    while offset + 8 <= declared_size:
        chunk_type, header_size = struct.unpack_from("<HH", data, offset)
        chunk_size = struct.unpack_from("<I", data, offset + 4)[0]
        chunk_end = offset + chunk_size
        if header_size < 8 or chunk_size < header_size or chunk_end > declared_size:
            raise ValueError("Invalid binary Android manifest chunk.")
        if chunk_type == 0x0001:
            strings = _string_pool(data, offset, chunk_end)
        elif chunk_type == 0x0102 and chunk_size >= 36:
            name_index = struct.unpack_from("<I", data, offset + 20)[0]
            name = strings[name_index] if name_index < len(strings) else ""
            attribute_start, attribute_size, attribute_count = struct.unpack_from("<HHH", data, offset + 24)
            attributes_offset = offset + 16 + attribute_start
            if not name or attribute_size < 20 or attribute_count > 4096 or attributes_offset + attribute_count * attribute_size > chunk_end:
                raise ValueError("Invalid binary Android manifest element.")
            attrs = {}
            for index in range(attribute_count):
                attr = attributes_offset + index * attribute_size
                attr_name_index = struct.unpack_from("<I", data, attr + 4)[0]
                attr_name = strings[attr_name_index] if attr_name_index < len(strings) else ""
                raw_index = struct.unpack_from("<I", data, attr + 8)[0]
                value = strings[raw_index] if raw_index != 0xffffffff and raw_index < len(strings) else _typed_value(data, attr + 12, strings)
                if attr_name:
                    attrs[attr_name] = value
            if name == "manifest":
                result["package_name"] = attrs.get("package") or ""
                result["version_name"] = attrs.get("versionName") or ""
                result["version_code"] = str(attrs.get("versionCode") or "")
            elif name in ("uses-permission", "uses-permission-sdk-m") or re.fullmatch(r"uses-permission-sdk-\d+", name):
                permission = attrs.get("name")
                if permission and len(result["permissions"]) < 1000:
                    result["permissions"].append(str(permission))
            elif name == "uses-sdk":
                result["min_sdk"] = str(attrs.get("minSdkVersion") or "")
                result["target_sdk"] = str(attrs.get("targetSdkVersion") or "")
            elif name == "application":
                result["app_name"] = str(attrs.get("label") or "")
            elif name in ("activity", "activity-alias", "service", "receiver", "provider"):
                if len(result["components"]) < 1000:
                    exported = attrs.get("exported", "unspecified")
                    result["components"].append({
                        "type": name,
                        "name": str(attrs.get("name") or ""),
                        "exported": str(exported).lower() if isinstance(exported, bool) else str(exported),
                    })
        offset = chunk_end
    if offset != declared_size:
        raise ValueError("Binary Android manifest has trailing partial data.")
    result["permissions"] = list(dict.fromkeys(result["permissions"]))
    return result


def parse_manifest(data: bytes) -> dict:
    """Parse text XML or Android's bounded binary XML manifest format."""
    result = {
        "package_name": "",
        "app_name": "",
        "version_name": "",
        "version_code": "",
        "min_sdk": "",
        "target_sdk": "",
        "permissions": [],
        "components": [],
        "manifest_kind": "binary-or-unavailable",
    }
    try:
        root = ElementTree.fromstring(data)
        result["manifest_kind"] = "text-xml"
        result["package_name"] = root.attrib.get("package", "")
        ns = "{http://schemas.android.com/apk/res/android}"
        result["version_name"] = root.attrib.get(ns + "versionName", "")
        app_node = root.find("application")
        if app_node is not None:
            result["app_name"] = app_node.attrib.get(ns + "label", "")
        for node in root:
            tag = node.tag.rsplit("}", 1)[-1]
            if tag in ("uses-permission", "uses-permission-sdk-23", "uses-permission-sdk-m"):
                value = node.attrib.get(ns + "name", "")
                if value and len(result["permissions"]) < 1000:
                    result["permissions"].append(value)
            if tag == "uses-sdk":
                result["min_sdk"] = node.attrib.get(ns + "minSdkVersion", "")
                result["target_sdk"] = node.attrib.get(ns + "targetSdkVersion", "")
            if tag == "application":
                for child in node:
                    child_tag = child.tag.rsplit("}", 1)[-1]
                    if child_tag in ("activity", "service", "receiver", "provider"):
                        if len(result["components"]) < 1000:
                            result["components"].append({
                                "type": child_tag,
                                "name": child.attrib.get(ns + "name", ""),
                                "exported": child.attrib.get(ns + "exported", "unspecified"),
                            })
    except ElementTree.ParseError:
        try:
            return _binary_manifest(data)
        except (ValueError, struct.error, IndexError):
            return result
    return result


def analyze_apk(path: Path) -> tuple[dict, list[dict]]:
    """Safely inspect an APK file under strict size, entry, and extraction limits."""
    findings: list[dict] = []
    with zipfile.ZipFile(path) as zf:
        infos = zf.infolist()
        if len(infos) > 10000 or sum(i.file_size for i in infos) > 512 * 1024 * 1024:
            raise ValueError("APK archive exceeds inspection limits.")
        names = set(zf.namelist())
        if "AndroidManifest.xml" not in names:
            raise ValueError("This ZIP does not contain AndroidManifest.xml; it may not be an APK.")
        manifest = parse_manifest(zf.read("AndroidManifest.xml"))
        for p in manifest["permissions"]:
            findings.append({
                "kind": "permission",
                "value": p,
                "location": "AndroidManifest.xml",
                "source": "static manifest inspection",
                "note": "Declared permission; this alone does not show that the capability was used.",
            })
        for c in manifest["components"]:
            findings.append({
                "kind": "component",
                "value": json.dumps(c, ensure_ascii=False),
                "location": "AndroidManifest.xml",
                "source": "static manifest inspection",
                "note": "Component declaration; exported status may be unspecified or platform-dependent.",
            })
        for cert in sorted(n for n in names if n.startswith("META-INF/") and n.lower().endswith((".rsa", ".dsa", ".ec"))):
            findings.append({
                "kind": "signing_artifact",
                "value": cert,
                "location": cert,
                "source": "APK archive inspection",
                "note": "Signature-related file present; cryptographic signature validity is not verified by this MVP.",
            })
        text_blobs = []
        extracted_strings = []
        scanned_text_bytes = 0
        for info in infos:
            if len(text_blobs) >= 500 or scanned_text_bytes >= 10 * 1024 * 1024:
                break
            if info.file_size <= 2_000_000 and info.filename.lower().endswith((".txt", ".json", ".xml", ".properties", ".html", ".js")):
                try:
                    text = zf.read(info).decode("utf-8", "ignore")
                    scanned_text_bytes += len(text.encode("utf-8"))
                    text_blobs.append((info.filename, text))
                    for line in text.splitlines():
                        value = line.strip()
                        if value and len(value) <= 240 and len(extracted_strings) < 200:
                            extracted_strings.append({"value": value, "location": info.filename})
                except (OSError, RuntimeError):
                    continue
        seen = set()
        url_re = re.compile(r"https?://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]+", re.I)
        for filename, blob in text_blobs:
            for raw in url_re.findall(blob):
                raw = raw.rstrip(".,;)]}")
                if len(raw) > 500 or raw in seen or len(seen) >= 500:
                    continue
                seen.add(raw)
                findings.append({
                    "kind": "url",
                    "value": raw,
                    "location": filename,
                    "source": "static string extraction",
                    "note": "String found in packaged text resource; runtime use is not established.",
                })
                host = urlparse(raw).hostname or ""
                if host:
                    try:
                        ipaddress.ip_address(host)
                        kind = "ip"
                    except ValueError:
                        kind = "domain"
                    findings.append({
                        "kind": kind,
                        "value": host,
                        "location": filename,
                        "source": "URL host parsed from static string",
                        "note": "Host indicator parsed from a packaged URL string; network contact is not established.",
                    })
        manifest["manifest_kind"] = manifest["manifest_kind"]
        if manifest["manifest_kind"] != "text-xml":
            findings.append({
                "kind": "analysis_note",
                "value": "AndroidManifest.xml uses binary or unsupported XML encoding.",
                "location": "AndroidManifest.xml",
                "source": "static inspection",
                "note": "Structured manifest fields and permissions could not be extracted by this MVP.",
            })
        manifest["archive_entries"] = len(infos)
        manifest["native_libraries"] = sum(1 for n in names if n.startswith("lib/") and n.endswith(".so"))
        manifest["dex_files"] = sum(1 for n in names if n.endswith(".dex"))
        manifest["native_library_names"] = sorted(n for n in names if n.startswith("lib/") and n.endswith(".so"))[:500]
        manifest["dex_file_names"] = sorted(n for n in names if n.endswith(".dex"))[:500]
        manifest["certificate_artifacts"] = sorted(n for n in names if n.startswith("META-INF/") and n.lower().endswith((".rsa", ".dsa", ".ec")))[:100]
        manifest["strings"] = extracted_strings
        manifest["unsupported_data"] = [
            "Binary Android XML manifest decoding",
            "DEX bytecode and API-call analysis",
            "Cryptographic signing-certificate verification",
            "Dynamic behavior and runtime network activity",
        ]
    return manifest, findings


def validate_apk_archive(path: Path) -> None:
    """Validate an APK container without extracting files or executing its contents."""
    try:
        with zipfile.ZipFile(path) as archive:
            entries = archive.infolist()
            if len(entries) > 10_000 or sum(entry.file_size for entry in entries) > 512 * 1024 * 1024:
                raise ValueError("APK archive exceeds inspection limits.")
            try:
                manifest = archive.getinfo("AndroidManifest.xml")
            except KeyError as exc:
                raise ValueError("The ZIP archive does not contain AndroidManifest.xml; it is not a valid APK.") from exc
            if manifest.flag_bits & 0x1:
                raise ValueError("The APK manifest is encrypted and cannot be inspected.")
            if manifest.file_size > 16 * 1024 * 1024:
                raise ValueError("The APK manifest exceeds the 16 MB inspection limit.")
            archive.read(manifest)
    except ValueError:
        raise
    except (OSError, RuntimeError, zipfile.BadZipFile, zipfile.LargeZipFile, NotImplementedError) as exc:
        raise ValueError("The file is not a readable APK ZIP archive.") from exc
