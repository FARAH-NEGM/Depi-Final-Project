"""
Asset Inventory
==================
Unifies the `devices` and `servers` tables (seeded from real event data —
see db/seed.py) with incident counts and risk, into one "asset" view: every
device or server is a node that can appear in an incident, and this module
answers "how exposed is each asset, and which incidents touched it."

This is intentionally NOT a fabricated asset list. Every row here traces
back to an actual IP address that appeared in the ingested event log:
  - devices: one row per (subject_user, src_ip) pair actually observed
  - servers: one row per destination IP actually observed

Risk per asset
----------------
An asset's risk score is the highest severity of any incident whose
source_ip (for devices) or dst_ip (for servers) matches that asset's IP,
mapped onto the same 0-100 risk scale the Trust Score and Cyber Digital
Twin modules already use (see trust_score/engine.py SEVERITY_RISK and
graph/twin.py SEVERITY_TO_RISK) -- kept in sync with both rather than
introducing a third scale.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict

from db.schema import get_connection

SEVERITY_RISK = {"Critical": 100, "High": 70, "Medium": 40, "Low": 15}


@dataclass
class Asset:
    asset_id: str          # ip address, used as the stable identifier
    name: str               # device subject_user or server hostname
    asset_type: str         # 'device' | 'server'
    ip_address: str
    incident_count: int
    max_severity: str | None
    risk_score: int
    open_incident_count: int  # incidents not yet Resolved

    def to_dict(self) -> dict:
        return asdict(self)


def _severity_rank(sev: str | None) -> int:
    order = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1, None: 0}
    return order.get(sev, 0)


def get_assets() -> list[Asset]:
    conn = get_connection()
    try:
        devices = conn.execute("SELECT * FROM devices").fetchall()
        servers = conn.execute("SELECT * FROM servers").fetchall()

        assets: list[Asset] = []

        for d in devices:
            ip = d["ip_address"]
            incidents = conn.execute(
                "SELECT severity, status FROM incidents WHERE source_ip = ?", (ip,)
            ).fetchall()
            max_sev = None
            for inc in incidents:
                if _severity_rank(inc["severity"]) > _severity_rank(max_sev):
                    max_sev = inc["severity"]
            open_count = sum(1 for inc in incidents if inc["status"] != "Resolved")

            assets.append(
                Asset(
                    asset_id=ip,
                    name=f"{d['subject_user']}'s {d['type'] or 'Device'}",
                    asset_type="device",
                    ip_address=ip,
                    incident_count=len(incidents),
                    max_severity=max_sev,
                    risk_score=SEVERITY_RISK.get(max_sev, 0),
                    open_incident_count=open_count,
                )
            )

        for s in servers:
            ip = s["ip_address"]
            incidents = conn.execute(
                "SELECT severity, status FROM incidents WHERE dst_ip = ?", (ip,)
            ).fetchall()
            max_sev = None
            for inc in incidents:
                if _severity_rank(inc["severity"]) > _severity_rank(max_sev):
                    max_sev = inc["severity"]
            open_count = sum(1 for inc in incidents if inc["status"] != "Resolved")

            assets.append(
                Asset(
                    asset_id=ip,
                    name=s["hostname"] or ip,
                    asset_type="server",
                    ip_address=ip,
                    incident_count=len(incidents),
                    max_severity=max_sev,
                    risk_score=SEVERITY_RISK.get(max_sev, 0),
                    open_incident_count=open_count,
                )
            )

        assets.sort(key=lambda a: (-a.risk_score, -a.incident_count))
        return assets
    finally:
        conn.close()


def get_asset_incidents(ip_address: str) -> list[dict]:
    """All incidents touching this IP, whether as the source (device) or
    destination (server)."""
    conn = get_connection()
    try:
        rows = conn.execute(
            "SELECT * FROM incidents WHERE source_ip = ? OR dst_ip = ? ORDER BY occurred_at DESC",
            (ip_address, ip_address),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def asset_summary() -> dict:
    assets = get_assets()
    by_type: dict[str, int] = {}
    by_severity: dict[str, int] = {}
    for a in assets:
        by_type[a.asset_type] = by_type.get(a.asset_type, 0) + 1
        if a.max_severity:
            by_severity[a.max_severity] = by_severity.get(a.max_severity, 0) + 1

    return {
        "total_assets": len(assets),
        "by_type": by_type,
        "by_severity": by_severity,
        "high_risk_assets": sum(1 for a in assets if a.risk_score >= 70),
    }


if __name__ == "__main__":
    assets = get_assets()
    print(f"{len(assets)} assets")
    for a in assets[:8]:
        print(f"  {a.asset_type:7s} {a.name:30s} risk={a.risk_score:3d} incidents={a.incident_count} open={a.open_incident_count}")
    print()
    print("Summary:", asset_summary())
