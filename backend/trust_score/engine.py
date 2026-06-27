"""
Trust Score Engine  (core module — Data/Logic Developer responsibility)
=========================================================================
Computes a per-user behavioral risk score ("Trust Score") from 0-100, where
100 = fully trusted / no risk signal, 0 = maximally risky.

Design rationale
-----------------
A Trust Score should answer: "given everything we've observed about this
account, how much should an analyst worry about it?" That means it needs to
combine multiple weighted signals rather than any single field, and it
should respond to BOTH the severity of what happened and how well it was
handled (an Ignored Critical alert is worse than a Blocked Critical alert).

Score components (each normalised to 0-100 risk, then weighted):

  1. Severity Risk (40%)
     Average severity of all incidents involving this user, mapped to a
     0-100 risk scale (Critical=100, High=70, Medium=40, Low=15).

  2. Response Quality Risk (25%)
     How well incidents involving this user were handled. Ignored/Logged
     incidents contribute high risk; Blocked/Quarantined incidents
     contribute low risk — an account whose alerts keep getting ignored is
     a bigger organisational risk than one whose alerts get blocked fast.

  3. Anomaly Score Risk (20%)
     Average of the dataset's own `Anomaly Scores` field (already 0-100)
     for this user's events — directly reuses the existing signal in the
     data rather than ignoring it.

  4. Frequency Risk (15%)
     How many separate incidents this user has been involved in, relative
     to the rest of the population (more incidents = more risk),
     log-scaled so a jump from 1->2 incidents matters more than 5->6.

Final Trust Score = 100 - weighted_risk   (so higher = more trustworthy)

This produces a continuous, explainable score — every component can be
shown to the user/analyst (see `explain()`), which matters a lot for a
"Trust Score" that's meant to justify itself to a SOC analyst, not be a
black box.

Score decay
-----------
Old incidents should matter less than recent ones (a clean record for the
last year should start outweighing one bad incident three years ago). We
apply a simple exponential time-decay weight to each incident based on its
age relative to the most recent event in the whole dataset, so demos stay
meaningful even though this dataset spans several years.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Optional

from ingestion.loader import Event, get_events
from correlation.engine import Incident, get_incidents, get_user_threads

SEVERITY_RISK = {"Critical": 100, "High": 70, "Medium": 40, "Low": 15}
ACTION_RISK = {"Ignored": 100, "Logged": 60, "Quarantined": 25, "Blocked": 10}

WEIGHTS = {
    "severity": 0.40,
    "response": 0.25,
    "anomaly": 0.20,
    "frequency": 0.15,
}

# Half-life (in days) for incident-age decay — incidents older than this
# contribute roughly half as much weight as a brand-new incident.
DECAY_HALF_LIFE_DAYS = 365


@dataclass
class TrustScoreBreakdown:
    user: str
    trust_score: float
    risk_level: str  # Low / Medium / High / Critical risk-of-account
    severity_risk: float
    response_risk: float
    anomaly_risk: float
    frequency_risk: float
    incident_count: int
    most_recent_incident_at: str
    weights: dict
    explanation: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


def _risk_level(trust_score: float) -> str:
    if trust_score >= 80:
        return "Low Risk"
    if trust_score >= 60:
        return "Medium Risk"
    if trust_score >= 35:
        return "High Risk"
    return "Critical Risk"


def _decay_weight(incident_dt: datetime, reference_dt: datetime) -> float:
    age_days = max((reference_dt - incident_dt).days, 0)
    # exponential decay: weight = 0.5 ^ (age / half_life)
    return 0.5 ** (age_days / DECAY_HALF_LIFE_DAYS)


def compute_trust_scores(
    events: Optional[list[Event]] = None,
    incidents: Optional[list[Incident]] = None,
) -> dict[str, TrustScoreBreakdown]:
    events = events if events is not None else get_events()
    incidents = incidents if incidents is not None else get_incidents()

    events_by_id = {e.event_id: e for e in events}
    threads = get_user_threads(incidents)
  
  # Prevent crash when dataset contains no events
    if not events:
        return {}

    # All events are historical in this dataset, so "now" for decay purposes
    # is the timestamp of the most recent event — this keeps the decay model
    # meaningful for a static historical dataset (as opposed to using the
    # real wall-clock date, which would decay *everything* into irrelevance
    # since the data ends in the past).
    reference_dt = max(e.timestamp for e in events)

    # For frequency normalisation, we need the max incident count across all
    # users so the frequency component can be expressed relative to peers.
    max_incident_count = max((len(v) for v in threads.values()), default=1)

    results: dict[str, TrustScoreBreakdown] = {}

    for thread_id, user_incidents in threads.items():
        user = user_incidents[0].user

        weighted_sev_risk = 0.0
        weighted_resp_risk = 0.0
        weighted_anom_risk = 0.0
        total_weight = 0.0

        for inc in user_incidents:
            inc_dt = datetime.fromisoformat(inc.occurred_at)
            w = _decay_weight(inc_dt, reference_dt)
            total_weight += w

            weighted_sev_risk += w * SEVERITY_RISK.get(inc.severity, 50)
            weighted_resp_risk += w * ACTION_RISK.get(inc.action_taken, 50)

            ev = events_by_id.get(inc.event_id)
            anomaly = ev.anomaly_score if ev else 50.0
          # Keep anomaly score within valid range
            anomaly = max(0, min(100, anomaly))
            weighted_anom_risk += w * anomaly

        severity_risk = weighted_sev_risk / total_weight if total_weight else 0
        response_risk = weighted_resp_risk / total_weight if total_weight else 0
        anomaly_risk = weighted_anom_risk / total_weight if total_weight else 0

        # Frequency risk: log-scaled relative to the most "active" user.
        count = len(user_incidents)
        frequency_risk = (
            100 * math.log1p(count) / math.log1p(max_incident_count)
            if max_incident_count > 0
            else 0
        )

        total_risk = (
            WEIGHTS["severity"] * severity_risk
            + WEIGHTS["response"] * response_risk
            + WEIGHTS["anomaly"] * anomaly_risk
            + WEIGHTS["frequency"] * frequency_risk
        )
        trust_score = round(max(0.0, min(100.0, 100 - total_risk)), 2)

        most_recent = max(user_incidents, key=lambda i: i.occurred_at)

        explanation = [
            f"{count} incident(s) on record, weighted by recency (older incidents count less).",
            f"Average severity risk: {severity_risk:.1f}/100 "
            f"(based on {', '.join(sorted(set(i.severity for i in user_incidents)))} severity incidents).",
            f"Response-quality risk: {response_risk:.1f}/100 "
            f"(actions taken: {', '.join(sorted(set(i.action_taken for i in user_incidents)))}).",
            f"Average anomaly-score risk: {anomaly_risk:.1f}/100 (from raw detection telemetry).",
            f"Frequency risk: {frequency_risk:.1f}/100 ({count} incident(s) vs. peer max of {max_incident_count}).",
        ]

        results[user] = TrustScoreBreakdown(
            user=user,
            trust_score=trust_score,
            risk_level=_risk_level(trust_score),
            severity_risk=round(severity_risk, 2),
            response_risk=round(response_risk, 2),
            anomaly_risk=round(anomaly_risk, 2),
            frequency_risk=round(frequency_risk, 2),
            incident_count=count,
            most_recent_incident_at=most_recent.occurred_at,
            weights=WEIGHTS,
            explanation=explanation,
        )

    return results


_CACHE: dict[str, TrustScoreBreakdown] | None = None


def get_trust_scores(force_reload: bool = False) -> dict[str, TrustScoreBreakdown]:
    global _CACHE
    if _CACHE is None or force_reload:
        _CACHE = compute_trust_scores()
    return _CACHE


def get_leaderboard(ascending: bool = True) -> list[TrustScoreBreakdown]:
    """Riskiest users first by default (ascending trust score)."""
    scores = list(get_trust_scores().values())
    return sorted(scores, key=lambda s: s.trust_score, reverse=not ascending)


if __name__ == "__main__":
    board = get_leaderboard()
    print(f"Computed trust scores for {len(board)} users\n")
    print("Riskiest 10 users:")
    for s in board[:10]:
        print(f"  {s.user:20s} score={s.trust_score:6.2f}  {s.risk_level:14s} incidents={s.incident_count}")
    print("\nMost trusted 5 users:")
    for s in sorted(board, key=lambda s: s.trust_score, reverse=True)[:5]:
        print(f"  {s.user:20s} score={s.trust_score:6.2f}  {s.risk_level:14s} incidents={s.incident_count}")
