#!/usr/bin/env bash
# Convenience launcher for the Cyber Control Tower backend + frontend.
# Usage:
#   ./run.sh
# Then open http://127.0.0.1:5000 in your browser.

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR/backend"

if [ ! -d "venv" ]; then
  echo "Creating virtual environment..."
  python3 -m venv venv
fi

source venv/bin/activate
pip install -q -r requirements.txt

echo ""
echo "Starting Cyber Control Tower..."
echo "Open http://127.0.0.1:5000 in your browser once it says 'Running on...'"
echo ""
python3 app.py
