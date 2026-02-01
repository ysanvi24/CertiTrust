#!/bin/bash
# ===========================================
# CertiTrust Local Production Start Script
# (No Docker required)
# ===========================================

set -e

echo "🚀 CertiTrust Local Production Start"
echo "====================================="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# Check Python virtual environment
if [ ! -d ".venv" ]; then
    echo -e "${YELLOW}Creating Python virtual environment...${NC}"
    python3 -m venv .venv
fi

source .venv/bin/activate

# Install/update backend dependencies
echo -e "${YELLOW}Installing backend dependencies...${NC}"
pip install -q -r backend/requirements.txt

# Check if .env exists
if [ ! -f "backend/.env" ]; then
    echo -e "${RED}Warning: backend/.env not found${NC}"
    echo "Copy .env.production.template to backend/.env and configure it"
fi

# Start backend in background
echo -e "${YELLOW}Starting backend server...${NC}"
cd backend
gunicorn main:app -k uvicorn.workers.UvicornWorker -w 2 -b 0.0.0.0:8000 --daemon --access-logfile ../logs/backend-access.log --error-logfile ../logs/backend-error.log --pid ../backend.pid
cd ..

# Wait for backend
sleep 3

# Check backend health
if curl -s http://localhost:8000/health | grep -q "healthy"; then
    echo -e "${GREEN}✅ Backend running at http://localhost:8000${NC}"
else
    echo -e "${RED}❌ Backend failed to start${NC}"
    exit 1
fi

# Start frontend
echo -e "${YELLOW}Building and starting frontend...${NC}"
cd web

# Install npm dependencies if needed
if [ ! -d "node_modules" ]; then
    npm ci
fi

# Build for production
npm run build

# Start with PM2 or node directly
if command -v pm2 &> /dev/null; then
    pm2 start npm --name "certitrust-frontend" -- start
    echo -e "${GREEN}✅ Frontend running with PM2 at http://localhost:3000${NC}"
else
    echo -e "${YELLOW}Starting frontend with node (install PM2 for production)${NC}"
    nohup npm start > ../logs/frontend.log 2>&1 &
    echo $! > ../frontend.pid
    echo -e "${GREEN}✅ Frontend running at http://localhost:3000${NC}"
fi

cd ..

echo ""
echo "====================================="
echo -e "${GREEN}🎉 CertiTrust is running!${NC}"
echo ""
echo "Services:"
echo "  Frontend: http://localhost:3000"
echo "  Backend:  http://localhost:8000"
echo "  API Docs: http://localhost:8000/docs"
echo ""
echo "To stop: ./stop.sh"
echo ""
