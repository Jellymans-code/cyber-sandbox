#!/usr/bin/env bash
# Starts the backend (needs sudo for eBPF) and frontend together.
# Ctrl+C stops both.
set -e
 
cleanup() {
  kill "$BACKEND_PID" "$FRONTEND_PID" 2>/dev/null
}
trap cleanup EXIT INT TERM
 
echo "Starting backend (requires sudo for eBPF)..."
(cd backend && sudo venv/bin/python api.py) &
BACKEND_PID=$!
 
echo "Starting frontend..."
(cd frontend && npm run dev) &
FRONTEND_PID=$!
 
wait
