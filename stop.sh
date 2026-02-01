#!/bin/bash
# ===========================================
# CertiTrust Stop Script
# ===========================================

set -e

echo "🛑 Stopping CertiTrust..."

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Stop backend
if [ -f "backend.pid" ]; then
    PID=$(cat backend.pid)
    if kill -0 $PID 2>/dev/null; then
        kill $PID
        echo "✅ Backend stopped"
    fi
    rm -f backend.pid
fi

# Stop frontend
if [ -f "frontend.pid" ]; then
    PID=$(cat frontend.pid)
    if kill -0 $PID 2>/dev/null; then
        kill $PID
        echo "✅ Frontend stopped"
    fi
    rm -f frontend.pid
fi

# Stop PM2 if used
if command -v pm2 &> /dev/null; then
    pm2 stop certitrust-frontend 2>/dev/null || true
    pm2 delete certitrust-frontend 2>/dev/null || true
fi

# Kill any remaining uvicorn/gunicorn processes
pkill -f "uvicorn main:app" 2>/dev/null || true
pkill -f "gunicorn main:app" 2>/dev/null || true

echo "✅ All services stopped"
