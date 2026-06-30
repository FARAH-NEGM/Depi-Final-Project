"""
Threat Hunting / Search
=========================
Backs the dashboard's "Threat Hunting" view with a real query against
the correlated incident set — not a hard-coded query string with no
engine behind it.

Query language (intentionally simple — this is a SOC *simulator*, not a
SIEM query language clone):

  field:value           exact/substring match on one field
  field:>NUMBER          numeric greater-than (mttd_minutes, mttr_minutes,
                          risk_score, event_count)
  free text               substring match across user, asset IPs,
                          attack_type, mitre techniques, network_segment

Multiple terms are AND-ed together, space separated, mirroring the kind
of query the existing frontend mockup already showed analysts typing
(e.g. "asset:FIN-LAP-014 AND process:powershell") — this module makes
that pattern actually execute against real data instead of just
displaying as a static example.
"""

from __future__ import annotations

import re
from typing import Optional

from correlation.engine import Incident, get_incidents
from mitre.enrichment import enrich_incidents

FIELD_ALIASES = {
    "user":      "user",
    "ip":        "_ip",          # checked against both source_ip and dst_ip
    "src_ip":    "source_ip",
    "dst_ip":    "dst_ip",
    "asset":     "_ip",          # no separate asset model — IP is the asset key
    "segment":   "network_segment",
    "severity":  "severity",
    "status":    "status",
    "attack":    "attack_type",
    "attack_type": "attack_type",
    "technique": "_mitre",
    "mitre":     "_mitre",
    "risk":      "risk_score",
    "mttd":      "mttd_minutes",
    "mttr":      "mttr_minutes",
}

NUMERIC_FIELDS = {"risk_score", "mttd_minutes", "mttr_minutes", "event_count"}

# Supports: field:value | field:"quoted value with spaces" | bare free-text word
_TOKEN_RE = re.compile(r'(\w+):"([^"]*)"|(\w+):([><]?[^\s"]+)|(\S+)')


def _matches_field(inc_dict: dict, field: str, op_value: str) -> bool:
    real_field = FIELD_ALIASES.get(field.lower())
    if real_field is None:
        # Unknown field — fall back to free-text match against the whole row
        haystack = " ".join(str(v) for v in inc_dict.values()).lower()
        return op_value.lower() in haystack

    if real_field == "_ip":
        haystack = f"{inc_dict.get('source_ip','')} {inc_dict.get('dst_ip','')}".lower()
        return op_value.lower() in haystack

    if real_field == "_mitre":
        techs = inc_dict.get("mitre_techniques") or []
        ids   = " ".join(t.get("technique_id", "") for t in techs).lower()
        names = " ".join(t.get("technique_name", "") for t in techs).lower()
        return op_value.lower() in ids or op_value.lower() in names

    if real_field in NUMERIC_FIELDS:
        try:
            if op_value.startswith(">"):
                return float(inc_dict.get(real_field, 0)) > float(op_value[1:])
            if op_value.startswith("<"):
                return float(inc_dict.get(real_field, 0)) < float(op_value[1:])
            return float(inc_dict.get(real_field, 0)) == float(op_value)
        except ValueError:
            return False

    val = str(inc_dict.get(real_field, "")).lower()
    return op_value.lower() in val


def _matches_free_text(inc_dict: dict, text: str) -> bool:
    text = text.lower()
    fields = [
        inc_dict.get("user", ""), inc_dict.get("source_ip", ""), inc_dict.get("dst_ip", ""),
        inc_dict.get("attack_type", ""), inc_dict.get("network_segment", ""),
        inc_dict.get("severity", ""), inc_dict.get("status", ""), inc_dict.get("incident_id", ""),
    ]
    techs = inc_dict.get("mitre_techniques") or []
    fields += [t.get("technique_id", "") for t in techs]
    fields += [t.get("technique_name", "") for t in techs]
    haystack = " ".join(str(f) for f in fields).lower()
    return text in haystack


def parse_query(query: str) -> list[tuple[str, str]]:
    """Returns a list of (kind, value) tuples: kind is 'field:name' or 'text'."""
    terms: list[tuple[str, str]] = []
    for m in _TOKEN_RE.finditer(query.strip()):
        quoted_field, quoted_value, field, value, free = m.groups()
        if quoted_field is not None:
            terms.append((quoted_field, quoted_value))
        elif field and value:
            if free and free.upper() == "AND":
                continue
            terms.append((field, value))
        elif free:
            if free.upper() == "AND":
                continue
            terms.append(("__text__", free))
    return terms


def search_incidents(query: str, incidents: Optional[list[Incident]] = None) -> list[dict]:
    """Runs a parsed query against enriched incidents. Empty query -> all."""
    incidents = incidents if incidents is not None else get_incidents()
    enriched  = enrich_incidents(incidents)

    query = (query or "").strip()
    if not query:
        return enriched

    terms = parse_query(query)
    if not terms:
        return enriched

    results = []
    for inc in enriched:
        ok = True
        for field, value in terms:
            if field == "__text__":
                if not _matches_free_text(inc, value):
                    ok = False
                    break
            else:
                if not _matches_field(inc, field, value):
                    ok = False
                    break
        if ok:
            results.append(inc)

    return results


# A few ready-made hunt queries surfaced in the UI as quick-start buttons —
# unlike the old mockup these are *executed* against real data when clicked,
# not just displayed as inert example text.
SUGGESTED_HUNTS: list[dict] = [
    {"label": "Critical incidents",            "query": "severity:Critical"},
    {"label": "High risk score (>50)",         "query": "risk:>50"},
    {"label": "Multi-stage attack chains",      "query": "technique:T1078"},
    {"label": "Unresolved incidents",           "query": "status:Open"},
    {"label": "DDoS activity",                  "query": "attack:DDoS"},
]
