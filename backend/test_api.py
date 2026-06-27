"""
API Smoke Test Suite
======================
Quick regression test exercising every backend API endpoint using Flask's
built-in test client (no real server/socket needed). Run this after any
backend change to confirm nothing broke:

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
    "/api/mitre/heatmap",
    "/api/mitre/catalog",
    "/api/trust-scores",
    "/api/metrics",
    "/api/graph",
    "/api/live-feed?cursor=0&page_size=3",
    "/api/summary",
]

for ep in endpoints:
    resp = client.get(ep)
    body = resp.get_json()
    size = len(json.dumps(body)) if body is not None else 0
    print(f"{resp.status_code}  {ep:45s}  payload_bytes={size}")
    if resp.status_code != 200:
        print("   ERROR BODY:", body)

# Spot-check a few details
print("\n--- spot checks ---")
incidents = client.get("/api/incidents").get_json()
print("incident sample:", json.dumps(incidents[0], indent=2)[:600])

trust = client.get("/api/trust-scores").get_json()
print("\nriskiest user:", trust[0])

summary = client.get("/api/summary").get_json()
print("\nsummary:", json.dumps(summary, indent=2)[:800])

# Test index page (frontend serving)
idx = client.get("/")
print("\nindex status:", idx.status_code)

# Test 404 path
notfound = client.get("/api/incidents/DOES-NOT-EXIST")
print("404 test:", notfound.status_code, notfound.get_json())
