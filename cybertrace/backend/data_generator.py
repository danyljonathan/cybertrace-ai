"""Deterministic synthetic security-log generator.

Produces 14 days of benign "ambient" activity for 8 users (the behavioral baseline) plus
one of two evaluated scenarios:

* attack — the official HackNex example: unusual login -> first-time access to confidential
  files -> new USB device -> 2.1 GB copied to that USB device.
* clean  — benign activity that must keep the system quiet, including an in-baseline USB
  backup and exactly one isolated signal (a conference login from a new city).

The same seed always yields the same events, so every demo run is reproducible.
ALL DATA IS SYNTHETIC DEMONSTRATION DATA.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

SEED = 2026
BASELINE_DAYS = 14
SYNTHETIC_NOTE = "SYNTHETIC DEMONSTRATION DATA"


@dataclass(frozen=True)
class UserProfile:
    user: str
    device: str
    ip: str
    location: str
    apps: tuple[str, ...]
    resources: tuple[str, ...]
    start_hour: int
    usb_devices: tuple[str, ...] = field(default_factory=tuple)


USERS: tuple[UserProfile, ...] = (
    UserProfile("user_001", "device_07", "10.20.30.45", "Chennai, IN",
                ("file_manager", "intranet_portal", "email_client"),
                ("shared_drive", "reports_2025", "project_files"), 8),
    UserProfile("user_002", "device_12", "10.20.30.61", "Chennai, IN",
                ("crm_app", "email_client"), ("crm_database", "shared_drive"), 9),
    UserProfile("user_003", "device_03", "10.20.31.12", "Singapore, SG",
                ("spreadsheet_app", "email_client"), ("finance_reports", "shared_drive"), 8),
    UserProfile("user_004", "device_15", "10.20.30.88", "London, UK",
                ("file_manager", "design_suite"),
                ("confidential_project_files", "shared_drive", "project_files"), 9),
    UserProfile("user_005", "device_21", "10.20.32.19", "Bengaluru, IN",
                ("hr_app", "email_client"), ("hr_portal", "shared_drive"), 9),
    UserProfile("user_006", "device_09", "10.20.30.72", "Chennai, IN",
                ("backup_utility", "file_manager"), ("backup_archive", "shared_drive"), 7,
                ("usb_device_01",)),
    UserProfile("user_007", "device_04", "10.20.31.55", "Chennai, IN",
                ("intranet_portal", "email_client"), ("knowledge_base", "shared_drive"), 8),
    UserProfile("user_008", "device_11", "10.20.32.08", "Mumbai, IN",
                ("bi_suite", "email_client"), ("analytics_dashboard", "shared_drive"), 10),
)

INTERNAL_DESTINATIONS = ("cdn.internal-corp.example", "mail.internal-corp.example", "sso.internal-corp.example")

SCENARIO_LABELS = {
    "attack": "Multi-Stage Coordinated Attack (official HackNex example)",
    "clean": "Clean Benign Activity (false-positive control)",
}


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def anchor_day(now: datetime | None = None) -> datetime:
    """Midnight UTC of the demo day (today)."""
    now = now or datetime.now(timezone.utc)
    return now.astimezone(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)


def _ev(ts: datetime, p: UserProfile | None, event_type: str, action: str, *, tag: str,
        user: str | None = None, device: str | None = None, ip: str | None = None,
        application: str | None = None, resource: str | None = None,
        location: str | None = None, metadata: dict[str, Any] | None = None) -> dict[str, Any]:
    return {
        "event_id": "",  # assigned after chronological sort
        "timestamp": iso(ts),
        "user": user if user is not None else (p.user if p else None),
        "device": device if device is not None else (p.device if p else None),
        "ip": ip,
        "application": application,
        "resource": resource,
        "event_type": event_type,
        "action": action,
        "location": location,
        "severity": "informational",
        "metadata": metadata or {},
        "source_tag": tag,
    }


def _ambient_day(rng: random.Random, p: UserProfile, day: datetime, *, cutoff: datetime | None) -> list[dict]:
    """One working day of normal behaviour for one user."""
    out: list[dict] = []
    t = day + timedelta(hours=p.start_hour, minutes=rng.randint(0, 50))
    out.append(_ev(t, p, "AUTH_LOGIN", "LOGIN", tag="ambient", ip=p.ip, location=p.location,
                   metadata={"auth_result": "success", "session_id": f"sess-{rng.randint(10000, 99999)}"}))
    n_actions = rng.randint(3, 5)
    for _ in range(n_actions):
        t += timedelta(minutes=rng.randint(20, 140), seconds=rng.randint(0, 59))
        roll = rng.random()
        if roll < 0.5:
            out.append(_ev(t, p, "FILE_ACCESS", "READ", tag="ambient", ip=p.ip,
                           application=next((a for a in p.apps if a in ("file_manager", "crm_app", "spreadsheet_app",
                                                                        "hr_app", "bi_suite", "intranet_portal",
                                                                        "backup_utility")), p.apps[0]),
                           resource=rng.choice(p.resources)))
        elif roll < 0.78:
            out.append(_ev(t, p, "APP_USAGE", "USE", tag="ambient", ip=p.ip, application=rng.choice(p.apps)))
        else:
            out.append(_ev(t, p, "NETWORK_CONNECTION", "TRANSFER", tag="ambient", ip=p.ip,
                           application=rng.choice(p.apps),
                           metadata={"destination": rng.choice(INTERNAL_DESTINATIONS),
                                     "bytes": rng.randint(5_000, 900_000)}))
    # Operator backups: user_006 regularly copies the backup archive to a known USB drive.
    if p.usb_devices and day.toordinal() % 3 == 0:
        t_usb = day + timedelta(hours=15, minutes=rng.randint(0, 20))
        usb = p.usb_devices[0]
        out.append(_ev(t_usb, p, "USB_CONNECT", "CONNECT", tag="ambient",
                       metadata={"usb_device": usb, "usb_vendor": "Kingston"}))
        out.append(_ev(t_usb + timedelta(minutes=3), p, "FILE_COPY", "COPY", tag="ambient",
                       application="backup_utility", resource="backup_archive",
                       metadata={"usb_device": usb, "bytes": rng.randint(800_000_000, 3_500_000_000)}))
    if cutoff is not None:
        out = [e for e in out if e["timestamp"] <= iso(cutoff)]
    return out


def _today_morning(rng: random.Random, today: datetime) -> list[dict]:
    """Ambient activity on the demo day before the scenario starts (all before 09:05)."""
    by = {p.user: p for p in USERS}
    out: list[dict] = []
    u1 = by["user_001"]
    out += [
        _ev(today + timedelta(hours=8, minutes=47), u1, "AUTH_LOGIN", "LOGIN", tag="ambient", ip=u1.ip,
            location=u1.location, metadata={"auth_result": "success", "session_id": "sess-8790"}),
        _ev(today + timedelta(hours=8, minutes=51), u1, "FILE_ACCESS", "READ", tag="ambient", ip=u1.ip,
            application="file_manager", resource="shared_drive"),
        _ev(today + timedelta(hours=9, minutes=2), u1, "APP_USAGE", "USE", tag="ambient", ip=u1.ip,
            application="intranet_portal"),
    ]
    u4 = by["user_004"]
    out += [
        _ev(today + timedelta(hours=8, minutes=31), u4, "AUTH_LOGIN", "LOGIN", tag="ambient", ip=u4.ip,
            location=u4.location, metadata={"auth_result": "success", "session_id": "sess-8772"}),
        # The confidential share is normal for user_004 — the baseline is per user.
        _ev(today + timedelta(hours=8, minutes=45), u4, "FILE_ACCESS", "READ", tag="ambient", ip=u4.ip,
            application="file_manager", resource="confidential_project_files"),
    ]
    for p in USERS:
        if p.user in ("user_001", "user_004"):
            continue
        t = today + timedelta(hours=7, minutes=30 + rng.randint(0, 80))
        out.append(_ev(t, p, "AUTH_LOGIN", "LOGIN", tag="ambient", ip=p.ip, location=p.location,
                       metadata={"auth_result": "success"}))
        out.append(_ev(t + timedelta(minutes=rng.randint(3, 9)), p, "APP_USAGE", "USE", tag="ambient",
                       ip=p.ip, application=p.apps[0]))
    return out


def _attack_events(today: datetime) -> list[dict]:
    by = {p.user: p for p in USERS}
    u = by["user_001"]
    meta = {"attack_scenario": "data_exfiltration_via_removable_media", "note": SYNTHETIC_NOTE}
    t = lambda h, m: today + timedelta(hours=h, minutes=m)  # noqa: E731
    return [
        _ev(t(9, 12), u, "AUTH_LOGIN", "LOGIN", tag="attack_demo", ip="203.0.113.99", location="Singapore, SG",
            metadata={**meta, "auth_result": "success", "session_id": "sess-8841",
                      "baseline_ips": [u.ip], "previous_locations": [u.location]}),
        _ev(t(9, 16), u, "FILE_ACCESS", "READ", tag="attack_demo", ip="203.0.113.99",
            application="file_manager", resource="confidential_project_files",
            metadata={**meta, "bytes": 48_000_000, "session_id": "sess-8841"}),
        _ev(t(9, 21), u, "USB_CONNECT", "CONNECT", tag="attack_demo",
            metadata={**meta, "usb_device": "usb_device_03", "usb_vendor": "SanDisk", "usb_serial": "4C530001"}),
        _ev(t(9, 23), u, "FILE_COPY", "COPY", tag="attack_demo", ip="203.0.113.99",
            application="file_manager", resource="confidential_project_files",
            metadata={**meta, "usb_device": "usb_device_03", "bytes": 2_100_000_000, "files": 214}),
    ]


def _clean_events(today: datetime) -> list[dict]:
    by = {p.user: p for p in USERS}
    meta = {"scenario": "clean_benign_activity", "note": SYNTHETIC_NOTE}
    t = lambda h, m: today + timedelta(hours=h, minutes=m)  # noqa: E731
    u2, u3, u5, u6, u7, u8 = (by[k] for k in ("user_002", "user_003", "user_005", "user_006", "user_007", "user_008"))
    return [
        _ev(t(9, 10), u2, "FILE_ACCESS", "READ", tag="clean_demo", ip=u2.ip, application="crm_app",
            resource="crm_database", metadata=meta),
        _ev(t(9, 12), u7, "FILE_ACCESS", "READ", tag="clean_demo", ip=u7.ip, application="intranet_portal",
            resource="knowledge_base", metadata=meta),
        # The ONE isolated signal: a conference login from a new city. Nothing else follows it.
        _ev(t(9, 14), u3, "AUTH_LOGIN", "LOGIN", tag="clean_demo", ip="198.51.100.24",
            location="Kuala Lumpur, MY",
            metadata={**meta, "auth_result": "success", "context": "regional finance conference"}),
        _ev(t(9, 18), u3, "FILE_ACCESS", "READ", tag="clean_demo", ip="198.51.100.24",
            application="spreadsheet_app", resource="finance_reports", metadata=meta),
        # Routine, in-baseline operator backup to the operator's known USB drive.
        _ev(t(9, 20), u6, "USB_CONNECT", "CONNECT", tag="clean_demo",
            metadata={**meta, "usb_device": "usb_device_01", "usb_vendor": "Kingston"}),
        _ev(t(9, 24), u6, "FILE_COPY", "COPY", tag="clean_demo", application="backup_utility",
            resource="backup_archive", metadata={**meta, "usb_device": "usb_device_01", "bytes": 3_400_000_000}),
        _ev(t(9, 26), u5, "FILE_ACCESS", "READ", tag="clean_demo", ip=u5.ip, application="hr_app",
            resource="hr_portal", metadata=meta),
        _ev(t(9, 31), u8, "AUTH_LOGIN", "LOGIN", tag="clean_demo", ip=u8.ip, location=u8.location,
            metadata={**meta, "auth_result": "success"}),
        _ev(t(9, 35), u8, "FILE_ACCESS", "READ", tag="clean_demo", ip=u8.ip, application="bi_suite",
            resource="analytics_dashboard", metadata=meta),
        _ev(t(9, 38), u2, "NETWORK_CONNECTION", "TRANSFER", tag="clean_demo", ip=u2.ip,
            application="email_client", metadata={**meta, "destination": "mail.internal-corp.example",
                                                  "bytes": 420_000}),
    ]


def generate(scenario: str, now: datetime | None = None) -> list[dict[str, Any]]:
    """Return the full dataset (ambient baseline + scenario) with chronological EVT ids."""
    if scenario not in SCENARIO_LABELS:
        raise ValueError(f"unknown scenario {scenario!r}")
    rng = random.Random(SEED)
    today = anchor_day(now)
    events: list[dict] = []
    for d in range(BASELINE_DAYS, 0, -1):
        day = today - timedelta(days=d)
        for p in USERS:
            events += _ambient_day(rng, p, day, cutoff=None)
    events += _today_morning(rng, today)
    events.sort(key=lambda e: (e["timestamp"], e["user"] or ""))
    scenario_events = _attack_events(today) if scenario == "attack" else _clean_events(today)
    scenario_events.sort(key=lambda e: e["timestamp"])
    events += scenario_events  # evaluated events get the highest ids, like a live stream
    for i, e in enumerate(events, start=1):
        e["event_id"] = f"EVT-{i:05d}"
    return events
