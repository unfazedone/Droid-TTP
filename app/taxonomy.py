"""Reviewed subset of the MITRE ATT&CK Mobile Android matrix.

Names and IDs are aligned with the live Android matrix reviewed 2026-11-02.
Automatic rules intentionally use only low-confidence permission observations.
"""

from __future__ import annotations

from typing import NamedTuple


class TechniqueInfo(NamedTuple):
    name: str
    tactic: str
    description: str


ATTACK_MOBILE_ANDROID: dict[str, TechniqueInfo] = {
    "T1407": TechniqueInfo("Download New Code at Runtime", "Defense Evasion", "Download and execute dynamic code not included in the original application package."),
    "T1409": TechniqueInfo("Stored Application Data", "Collection", "Access and collect application data resident on the device."),
    "T1414": TechniqueInfo("Clipboard Data", "Collection", "Access or collect data from the device clipboard."),
    "T1418": TechniqueInfo("Software Discovery", "Discovery", "Discover applications installed on the device."),
    "T1420": TechniqueInfo("File and Directory Discovery", "Discovery", "Enumerate files and directories on the device."),
    "T1424": TechniqueInfo("Process Discovery", "Discovery", "Discover processes running on the device."),
    "T1426": TechniqueInfo("System Information Discovery", "Discovery", "Gather information about the device and operating system."),
    "T1429": TechniqueInfo("Audio Capture", "Collection", "Capture audio using the device's audio capabilities."),
    "T1430": TechniqueInfo("Location Tracking", "Collection / Discovery", "Track a device's physical location through operating system capabilities."),
    "T1437": TechniqueInfo("Application Layer Protocol", "Command and Control", "Communicate using application-layer protocols."),
    "T1453": TechniqueInfo("Abuse Accessibility Features", "Collection / Credential Access", "Abuse Android accessibility features to collect sensitive data or control the interface."),
    "T1512": TechniqueInfo("Video Capture", "Collection", "Capture video using the device camera."),
    "T1513": TechniqueInfo("Screen Capture", "Collection", "Capture the device screen."),
    "T1517": TechniqueInfo("Access Notifications", "Collection", "Access notifications displayed on the device."),
    "T1521": TechniqueInfo("Encrypted Channel", "Command and Control", "Use an encrypted channel for communications."),
    "T1624": TechniqueInfo("Event Triggered Execution", "Persistence", "Use system events to trigger execution."),
    "T1624.001": TechniqueInfo("Broadcast Receivers", "Persistence", "Use broadcast receivers to trigger execution from system events."),
    "T1628": TechniqueInfo("Hide Artifacts", "Defense Evasion", "Hide artifacts associated with activity to evade detection."),
    "T1628.001": TechniqueInfo("Suppress Application Icon", "Defense Evasion", "Suppress an application's launcher icon."),
    "T1628.002": TechniqueInfo("User Evasion", "Defense Evasion", "Evade user awareness of application activity."),
    "T1628.003": TechniqueInfo("Conceal Multimedia Files", "Defense Evasion", "Conceal multimedia files from the user."),
    "T1635": TechniqueInfo("Steal Application Access Token", "Credential Access", "Steal access tokens used by applications."),
    "T1636": TechniqueInfo("Protected User Data", "Collection", "Access protected user data stored or managed on the device."),
    "T1636.001": TechniqueInfo("Calendar Entries", "Collection", "Access calendar entries."),
    "T1636.002": TechniqueInfo("Call Log", "Collection", "Access call log data."),
    "T1636.003": TechniqueInfo("Contact List", "Collection", "Access the device contact list."),
    "T1636.004": TechniqueInfo("SMS Messages", "Collection", "Access SMS messages."),
    "T1636.005": TechniqueInfo("Accounts", "Collection", "Access account information on the device."),
    "T1641": TechniqueInfo("Data Manipulation", "Impact", "Manipulate data on the device."),
    "T1642": TechniqueInfo("Endpoint Denial of Service", "Impact", "Cause a denial of service on the device."),
    "T1646": TechniqueInfo("Exfiltration Over C2 Channel", "Exfiltration", "Exfiltrate data over a command and control channel."),
}


# Permission declarations are capability indicators only. They never imply
# that the app used the permission or performed the mapped behavior.
HEURISTIC_RULES: list[tuple[str, str, str, str]] = [
    ("android.permission.ACCESS_FINE_LOCATION", "T1430", "Manifest declares fine location permission; use is not established.", "low"),
    ("android.permission.ACCESS_COARSE_LOCATION", "T1430", "Manifest declares coarse location permission; use is not established.", "low"),
    ("android.permission.ACCESS_BACKGROUND_LOCATION", "T1430", "Manifest declares background location permission; use is not established.", "low"),
    ("android.permission.RECORD_AUDIO", "T1429", "Manifest declares audio recording permission; capture is not established.", "low"),
    ("android.permission.CAMERA", "T1512", "Manifest declares camera permission; capture is not established.", "low"),
    ("android.permission.READ_SMS", "T1636.004", "Manifest declares SMS read permission; access is not established.", "low"),
    ("android.permission.RECEIVE_SMS", "T1636.004", "Manifest declares SMS receipt permission; access is not established.", "low"),
    ("android.permission.READ_CALL_LOG", "T1636.002", "Manifest declares call log permission; access is not established.", "low"),
    ("android.permission.READ_CONTACTS", "T1636.003", "Manifest declares contacts permission; access is not established.", "low"),
    ("android.permission.READ_CALENDAR", "T1636.001", "Manifest declares calendar permission; access is not established.", "low"),
    ("android.permission.READ_PHONE_STATE", "T1426", "Manifest declares phone state permission; collection is not established.", "low"),
    ("android.permission.QUERY_ALL_PACKAGES", "T1418", "Manifest declares broad package visibility; discovery is not established.", "low"),
    ("android.permission.BIND_ACCESSIBILITY_SERVICE", "T1453", "Manifest declares an accessibility service; abuse is not established.", "low"),
    ("android.permission.BIND_NOTIFICATION_LISTENER_SERVICE", "T1517", "Manifest declares notification listener access; collection is not established.", "low"),
    ("android.permission.RECEIVE_BOOT_COMPLETED", "T1624.001", "Manifest declares boot broadcast handling; execution is not established.", "low"),
]

TAXONOMY_VERSION = "MITRE ATT&CK Mobile Android matrix snapshot 2026-11-02"
TAXONOMY_SOURCE = "https://attack.mitre.org/matrices/mobile/android/"
