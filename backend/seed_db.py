"""
CCT – Cyber Control Tower
DB Seed Script
==============
Seeds the Events database from the provided example files:
  • cybersecurity_example.csv
  • cybersecurity_example.json  (JSONL format)

Run once after creating tables:
    python seed_db.py --csv cybersecurity_example.csv --jsonl cybersecurity_example.json
"""

import argparse
import os
import sys

# Ensure log_ingestion module is importable
sys.path.insert(0, os.path.dirname(__file__))

from log_ingestion import app, db, ingest_csv, ingest_jsonl


def main():
    parser = argparse.ArgumentParser(description="Seed CCT Events DB from example files")
    parser.add_argument("--csv",   type=str, help="Path to .csv log file")
    parser.add_argument("--jsonl", type=str, help="Path to .json / .jsonl log file")
    args = parser.parse_args()

    with app.app_context():
        db.create_all()
        print("[SEED] Database tables ready.")

        if args.csv:
            if not os.path.exists(args.csv):
                print(f"[SEED] ERROR: CSV not found: {args.csv}")
            else:
                result = ingest_csv(args.csv)
                print(f"[SEED] CSV  → total: {result['total']}, "
                      f"accepted: {result['accepted']}, rejected: {result['rejected']}")

        if args.jsonl:
            if not os.path.exists(args.jsonl):
                print(f"[SEED] ERROR: JSONL not found: {args.jsonl}")
            else:
                result = ingest_jsonl(args.jsonl)
                print(f"[SEED] JSONL → total: {result['total']}, "
                      f"accepted: {result['accepted']}, rejected: {result['rejected']}")

        if not args.csv and not args.jsonl:
            print("[SEED] No input files provided. Use --csv and/or --jsonl flags.")


if __name__ == "__main__":
    main()
