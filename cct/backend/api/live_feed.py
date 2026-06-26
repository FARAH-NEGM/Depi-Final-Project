"""
Live SOC Feed Simulator
=========================
Powers the dashboard's "Live Mode" toggle: replays the dataset's events (and
their derived incidents) in chronological order as if they were arriving in
real time, one every few seconds, looping forever so a demo never runs dry.

This is intentionally a SIMULATION (the project is an SOC *simulator* per
the README's own framing) — it does not claim the underlying log timestamps
are happening now; it replays history at demo speed so the dashboard can show
a believable "incidents arriving live" experience.

Implementation
---------------
Stateless on the server: the frontend just asks "give me the next N events
after cursor X" via a simple incrementing pointer, polled every few seconds.
This keeps the backend simple (no websockets / no background threads needed)
while still feeling live in the browser.
"""

from __future__ import annotations

from typing import Optional

from correlation.engine import Incident, get_incidents
from mitre.enrichment import enrich_incident


def get_feed_page(cursor: int = 0, page_size: int = 1, incidents: Optional[list[Incident]] = None) -> dict:
    """
    Returns the next `page_size` incidents starting at `cursor`, looping back
    to the start once the dataset is exhausted (so a live demo can run
    indefinitely). Returns the new cursor for the client to use on its next
    poll.
    """
    incidents = incidents if incidents is not None else get_incidents()
    n = len(incidents)
    if n == 0:
        return {"items": [], "next_cursor": 0, "total": 0, "looped": False}

    items = []
    looped = False
    for i in range(page_size):
        idx = (cursor + i) % n
        if cursor + i >= n:
            looped = True
        items.append(enrich_incident(incidents[idx]))

    next_cursor = (cursor + page_size) % n

    return {
        "items": items,
        "next_cursor": next_cursor,
        "total": n,
        "looped": looped,
    }


if __name__ == "__main__":
    page = get_feed_page(cursor=0, page_size=3)
    print(f"Total incidents: {page['total']}")
    for item in page["items"]:
        print(item["incident_id"], item["attack_type"], item["severity"])
    print("Next cursor:", page["next_cursor"])
