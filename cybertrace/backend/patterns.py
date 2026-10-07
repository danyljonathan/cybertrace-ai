"""Attack-pattern registry and anomaly-rule metadata.

This is data, not detector code: adding a new multi-stage attack means adding a pattern
entry here (plus an anomaly rule in engine.RULES if it needs a new signal type).
"""

from __future__ import annotations

from typing import Any

# Anomaly rule metadata: title shown to analysts + deterministic risk weight.
ANOMALY_RULES: dict[str, dict[str, Any]] = {
    "NEW_LOCATION_LOGIN": {
        "title": "Unusual Login", "points": 15,
        "why": "Login from a location, IP or device not in the user's baseline",
    },
    "NEW_RESOURCE_ACCESS": {
        "title": "Unusual Resource Access", "points": 20,
        "why": "First-time access to a resource with no baseline history",
    },
    "USB_CONNECTION": {
        "title": "New USB Device", "points": 20,
        "why": "Removable device not in the user's baseline",
    },
    "FILE_COPY_TO_REMOVABLE": {
        "title": "File Copy to Removable Media", "points": 25,
        "why": "Copying to a new USB device / first-time resource",
    },
    "LARGE_OUTBOUND_TRANSFER": {
        "title": "Large Transfer to New Destination", "points": 25,
        "why": ">= 100 MB sent to a destination never seen for this user",
    },
}

CORRELATION_BONUS = 10  # "Strong entity correlation" — 3+ anomalies in matching order

RISK_TIERS = ((80, "CRITICAL"), (60, "HIGH"), (30, "MEDIUM"), (0, "LOW"))


def risk_tier(score: int) -> str:
    for floor, tier in RISK_TIERS:
        if score >= floor:
            return tier
    return "LOW"


PATTERNS: list[dict[str, Any]] = [
    {
        "id": "DATA_EXFILTRATION_REMOVABLE_MEDIA",
        "name": "Coordinated Data Exfiltration via Removable Media",
        "description": (
            "Credential/geo anomaly, followed by first-time access to a sensitive resource, followed by "
            "a newly-connected USB device, followed by copying the accessed data to that device."
        ),
        "status": "active",
        "stages": [
            {"key": "UNUSUAL_LOGIN", "name": "Unusual Login", "mitre_id": "T1078"},
            {"key": "UNUSUAL_RESOURCE_ACCESS", "name": "Unusual Resource Access", "mitre_id": "T1005"},
            {"key": "USB_CONNECTION", "name": "USB Connection", "mitre_id": "T1200"},
            {"key": "FILE_COLLECTION_COPY", "name": "File Collection / Copy", "mitre_id": "T1052.001"},
        ],
        "synthesis": "Coordinated Data Exfiltration",
        "synthesis_mitre": "T1052.001",
        "synthesis_reason": (
            "Stages 1-{n} share the same user and device and occur in a meaningful chronological sequence: "
            "the accessed files were copied to the USB device connected minutes earlier by a session opened "
            "from an unusual location. Interpreted as coordinated data exfiltration."
        ),
        "conclusion": "The combined evidence indicates a coordinated data-exfiltration activity.",
        "anomaly_mapping": {
            "NEW_LOCATION_LOGIN": "UNUSUAL_LOGIN",
            "NEW_RESOURCE_ACCESS": "UNUSUAL_RESOURCE_ACCESS",
            "USB_CONNECTION": "USB_CONNECTION",
            "FILE_COPY_TO_REMOVABLE": "FILE_COLLECTION_COPY",
        },
    },
    {
        "id": "DATA_EXFILTRATION_NETWORK",
        "name": "Account Takeover with Network Exfiltration",
        "description": (
            "Credential/geo anomaly, followed by first-time access to a sensitive resource, followed by a "
            "large transfer to a destination never seen for the user. Try it: download the "
            "network-exfiltration sample in the Log Explorer and import it."
        ),
        "status": "active",
        "stages": [
            {"key": "UNUSUAL_LOGIN", "name": "Unusual Login", "mitre_id": "T1078"},
            {"key": "UNUSUAL_RESOURCE_ACCESS", "name": "Unusual Resource Access", "mitre_id": "T1005"},
            {"key": "EXFIL_OVER_NETWORK", "name": "Exfiltration over Network", "mitre_id": "T1041"},
        ],
        "synthesis": "Coordinated Network Exfiltration",
        "synthesis_mitre": "T1041",
        "synthesis_reason": (
            "Stages 1-{n} share the same user and source and occur in a meaningful chronological sequence: "
            "data read for the first time was sent to a never-seen destination by a session opened from an "
            "unusual location. Interpreted as account takeover followed by exfiltration."
        ),
        "conclusion": "The combined evidence indicates account takeover followed by network data exfiltration.",
        "anomaly_mapping": {
            "NEW_LOCATION_LOGIN": "UNUSUAL_LOGIN",
            "NEW_RESOURCE_ACCESS": "UNUSUAL_RESOURCE_ACCESS",
            "LARGE_OUTBOUND_TRANSFER": "EXFIL_OVER_NETWORK",
        },
    },
    {
        "id": "LATERAL_MOVEMENT_SMB",
        "name": "Lateral Movement via Administrative Shares",
        "description": (
            "Roadmap pattern: new-host authentication, remote admin-share access, credential dump, propagation. "
            "Requires anomaly rules for remote service logons and share enumeration — not yet implemented."
        ),
        "status": "roadmap",
        "stages": [
            {"key": "REMOTE_AUTH", "name": "Remote Authentication", "mitre_id": "T1021"},
            {"key": "ADMIN_SHARE_ACCESS", "name": "Admin Share Access", "mitre_id": "T1021.002"},
            {"key": "CREDENTIAL_DUMP", "name": "Credential Dumping", "mitre_id": "T1003"},
        ],
        "synthesis": None,
        "anomaly_mapping": {},
    },
    {
        "id": "SLOW_DRIP_EXFILTRATION",
        "name": "Slow Drip Exfiltration (low-and-slow)",
        "description": (
            "Roadmap pattern: small repeated uploads below volume thresholds across many days. Requires "
            "cross-day correlation windows — not yet implemented."
        ),
        "status": "roadmap",
        "stages": [
            {"key": "REPEATED_SMALL_UPLOADS", "name": "Repeated Small Uploads", "mitre_id": "T1041"},
            {"key": "OFF_HOURS_PATTERN", "name": "Off-Hours Pattern", "mitre_id": "T1071"},
        ],
        "synthesis": None,
        "anomaly_mapping": {},
    },
]

PUBLIC_PATTERN_FIELDS = ("id", "name", "description", "status", "stages", "synthesis", "anomaly_mapping")


def public_patterns() -> list[dict[str, Any]]:
    return [{k: p.get(k) for k in PUBLIC_PATTERN_FIELDS} for p in PATTERNS]


def active_patterns() -> list[dict[str, Any]]:
    return [p for p in PATTERNS if p["status"] == "active"]


# Playbook: recommended actions keyed by stage type (deduplicated, order preserved).
PLAYBOOK: dict[str, list[dict[str, str]]] = {
    "UNUSUAL_LOGIN": [
        {"action": "Suspend active sessions for the affected user and require a credential reset",
         "priority": "IMMEDIATE", "category": "identity"},
        {"action": "Block the source IP at the perimeter firewall and add it to watchlists",
         "priority": "HIGH", "category": "network"},
    ],
    "UNUSUAL_RESOURCE_ACCESS": [
        {"action": "Alert the data owner of the accessed resource and review its access control list",
         "priority": "HIGH", "category": "containment"},
    ],
    "USB_CONNECTION": [
        {"action": "Quarantine the USB device and preserve it for forensic imaging",
         "priority": "IMMEDIATE", "category": "forensics"},
        {"action": "Isolate the affected device from the network pending EDR inspection",
         "priority": "IMMEDIATE", "category": "containment"},
    ],
    "FILE_COLLECTION_COPY": [
        {"action": "Recover the copied data and verify whether it left the environment",
         "priority": "IMMEDIATE", "category": "forensics"},
    ],
    "EXFIL_OVER_NETWORK": [
        {"action": "Block the external destination at the egress proxy and DNS layer",
         "priority": "IMMEDIATE", "category": "network"},
        {"action": "Pull egress/proxy logs to scope the volume and content transferred",
         "priority": "HIGH", "category": "forensics"},
    ],
}
