"""
MTTD / MTTR Metrics Engine  (core module — Data/Logic Developer responsibility)
==================================================================================
Aggregates Mean Time To Detect (MTTD) and Mean Time To Respond/Resolve (MTTR)
across incidents — the standard SOC performance KPIs called out explicitly
in the project proposal.

Definitions used here
----------------------
  MTTD = detected_at - occurred_at   (time from attack occurring to being
                                       flagged by the detection layer)
  MTTR = resolved_at - detected_at   (time from detection to the analyst
                                       action resolving/mitigating it)

Both are computed per-incident by the Correlation Engine (which synthesises
detected_at/resolved_at — see correlation/engine.py for why), and this module
is purely the aggregation/statistics layer on top: overall KPIs, breakdowns
by severity, attack type, and network segment, and a time-series so the
dashboard can chart "is MTTD/MTTR improving over time?".
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, asdict
from datetime import datetime
from statistics import mean, median
from typing import Optional

from correlation.engine import Incident, get_incidents


@dataclass
class MetricSummary:
    count: int
    mttd_mean: float
    mttd_median: float
    mttr_mean: float
    mttr_median: float

    def to_dict(self) -> dict:
        return asdict(self)


def _summarize(incidents: list[Incident]) -> MetricSummary:
    if not incidents:
        return MetricSummary(0, 0, 0, 0, 0)
    mttds = [i.mttd_minutes for i in incidents if i.mttd_minutes is not None]
    mttrs = [i.mttr_minutes for i in incidents if i.mttr_minutes is not None]

    if not mttds or not mttrs:
        return MetricSummary(0, 0, 0, 0, 0)
    
    return MetricSummary(
        count=len(incidents),
        mttd_mean=round(mean(mttds), 2),
        mttd_median=round(median(mttds), 2),
        mttr_mean=round(mean(mttrs), 2),
        mttr_median=round(median(mttrs), 2),
    )


def overall_metrics(incidents: Optional[list[Incident]] = None) -> MetricSummary:
    incidents = incidents if incidents is not None else get_incidents()
    return _summarize(incidents)


def metrics_by_severity(incidents: Optional[list[Incident]] = None) -> dict[str, MetricSummary]:
    incidents = incidents if incidents is not None else get_incidents()
    grouped: dict[str, list[Incident]] = defaultdict(list)
    for inc in incidents:
        grouped[inc.severity].append(inc)
    order = ["Critical", "High", "Medium", "Low"]
    return {sev: _summarize(grouped[sev]) for sev in order if sev in grouped}


def metrics_by_attack_type(incidents: Optional[list[Incident]] = None) -> dict[str, MetricSummary]:
    incidents = incidents if incidents is not None else get_incidents()
    grouped: dict[str, list[Incident]] = defaultdict(list)
    for inc in incidents:
        grouped[inc.attack_type].append(inc)
    return {k: _summarize(v) for k, v in sorted(grouped.items())}


def metrics_by_segment(incidents: Optional[list[Incident]] = None) -> dict[str, MetricSummary]:
    incidents = incidents if incidents is not None else get_incidents()
    grouped: dict[str, list[Incident]] = defaultdict(list)
    for inc in incidents:
        grouped[inc.network_segment].append(inc)
    return {k: _summarize(v) for k, v in sorted(grouped.items())}


def metrics_by_action(incidents: Optional[list[Incident]] = None) -> dict[str, MetricSummary]:
    incidents = incidents if incidents is not None else get_incidents()
    grouped: dict[str, list[Incident]] = defaultdict(list)
    for inc in incidents:
        grouped[inc.action_taken].append(inc)
    return {k: _summarize(v) for k, v in sorted(grouped.items())}


def monthly_trend(incidents: Optional[list[Incident]] = None) -> list[dict]:
    """Time series of MTTD/MTTR aggregated by calendar month, for trend charts."""
    incidents = incidents if incidents is not None else get_incidents()
    grouped: dict[str, list[Incident]] = defaultdict(list)
    for inc in incidents:
        dt = datetime.fromisoformat(inc.occurred_at)
        key = f"{dt.year}-{dt.month:02d}"
        grouped[key].append(inc)

    trend = []
    for month_key in sorted(grouped.keys()):
        summary = _summarize(grouped[month_key])
        trend.append({"month": month_key, **summary.to_dict()})
    return trend


def full_report(incidents: Optional[list[Incident]] = None) -> dict:
    incidents = incidents if incidents is not None else get_incidents()
    return {
        "overall": overall_metrics(incidents).to_dict(),
        "by_severity": {k: v.to_dict() for k, v in metrics_by_severity(incidents).items()},
        "by_attack_type": {k: v.to_dict() for k, v in metrics_by_attack_type(incidents).items()},
        "by_segment": {k: v.to_dict() for k, v in metrics_by_segment(incidents).items()},
        "by_action": {k: v.to_dict() for k, v in metrics_by_action(incidents).items()},
        "monthly_trend": monthly_trend(incidents),
    }


if __name__ == "__main__":
    report = full_report()
    print("Overall:", report["overall"])
    print()
    print("By severity:")
    for k, v in report["by_severity"].items():
        print(f"  {k:10s} {v}")
    print()
    print("By attack type:")
    for k, v in report["by_attack_type"].items():
        print(f"  {k:15s} {v}")
