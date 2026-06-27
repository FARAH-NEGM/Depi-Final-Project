"""
API Smoke Test Suite  v2
==========================
Tests all original endpoints PLUS new v2 endpoints.
Run from cct/backend/:
    python3 test_api.py
"""
import json
import sys

sys.path.insert(0, ".")
from app import app

client = app.test_client()

endpoints = [
    "/api/events",
    "/api/incidents",
    "/api/incidents/chains",
    "/api/mitre/heatmap",
    "/api/mitre/catalog",
    "/api/trust-scores",
    "/api/metrics",
    "/api/graph",
    "/api/live-feed?cursor=0&page_size=3",
    "/api/summary",
    "/api/risk-summary",
    "/api/incidents?severity=High",
    "/api/incidents?risk_min=70",
]

print("=" * 65)
print(f"{'STATUS':<8} {'ENDPOINT':<45} {'BYTES':>8}")
print("=" * 65)
for ep in endpoints:
    resp = client.get(ep)
    body = resp.get_json()
    size = len(json.dumps(body)) if body is not None else 0
    status = resp.status_code
    flag = "  ✓" if status == 200 else "  ✗ ERROR"
    print(f"{status:<8} {ep:<45} {size:>8}{flag}")
    if status != 200:
        print("   ERROR:", body)

# Deep spot-checks
print("\n" + "=" * 65)
print("SPOT CHECKS")
print("=" * 65)

incidents = client.get("/api/incidents").get_json()
sample = incidents[0]
print(f"\nTotal incidents (after grouping): {len(incidents)}")
print(f"\nSample incident fields present:")
for field in ["incident_id","event_count","related_events","attack_chain",
              "chain_confidence","mitre_chain","risk_score","risk_level",
              "correlation_reason","affected_users","affected_ips",
              "mitre_techniques","tactic_chain"]:
    present = field in sample
    val = sample.get(field, "MISSING")
    print(f"  {'✓' if present else '✗'} {field}: {val if not isinstance(val, list) else val[:2]}")

# Multi-event incident
multi = [i for i in incidents if i.get("event_count", 0) > 1]
print(f"\nMulti-event incidents: {len(multi)}")
if multi:
    m = multi[0]
    print(f"  Sample multi-event incident:")
    print(json.dumps({
        "incident_id":       m["incident_id"],
        "event_count":       m["event_count"],
        "related_events":    m["related_events"][:3],
        "attack_chain":      m["attack_chain"],
        "chain_confidence":  m["chain_confidence"],
        "mitre_chain":       m["mitre_chain"],
        "risk_score":        m["risk_score"],
        "risk_level":        m["risk_level"],
        "correlation_reason": m["correlation_reason"],
        "affected_users":    m["affected_users"],
    }, indent=2))

# Risk summary
risk = client.get("/api/risk-summary").get_json()
print(f"\nRisk distribution: {risk['risk_distribution']}")
print(f"Avg risk score:    {risk['avg_risk_score']}")

# Chain endpoint
chains = client.get("/api/incidents/chains").get_json()
print(f"\nAttack chain incidents: {len(chains)}")
if chains:
    c = chains[0]
    print(f"  chain: {c['attack_chain']}  conf={c['chain_confidence']}")

# Summary
summary = client.get("/api/summary").get_json()
print(f"\nSummary: total_events={summary['total_events']} "
      f"total_incidents={summary['total_incidents']} "
      f"multi_event={summary['multi_event_incidents']} "
      f"chains={summary['attack_chain_count']}")

# 404 check
nf = client.get("/api/incidents/DOES-NOT-EXIST")
print(f"\n404 test: {nf.status_code}  {nf.get_json()}")

print("\n✓ All tests complete")
