#!/bin/bash
# ===========================================
# CertiTrust Production Deployment Script
# ===========================================

set -e

echo "🚀 CertiTrust Production Deployment"
echo "===================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Check if .env exists
if [ ! -f .env ]; then
    echo -e "${RED}❌ .env file not found!${NC}"
    echo "   Copy .env.production.template to .env and fill in the values"
    exit 1
fi

# Load environment variables
source .env

# Validate required variables
REQUIRED_VARS=("SUPABASE_URL" "SUPABASE_SERVICE_ROLE_KEY" "KMS_MASTER_KEY")
for var in "${REQUIRED_VARS[@]}"; do
    if [ -z "${!var}" ]; then
        echo -e "${RED}❌ Missing required variable: $var${NC}"
        exit 1
    fi
done

echo -e "${GREEN}✅ Environment variables validated${NC}"

# Check Docker
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker is not installed${NC}"
    exit 1
fi

if ! command -v docker-compose &> /dev/null && ! docker compose version &> /dev/null; then
    echo -e "${RED}❌ Docker Compose is not installed${NC}"
    exit 1
fi

echo -e "${GREEN}✅ Docker is available${NC}"

# Build images
echo ""
echo -e "${YELLOW}📦 Building Docker images...${NC}"
docker-compose build --no-cache

# Stop existing containers
echo ""
echo -e "${YELLOW}🛑 Stopping existing containers...${NC}"
docker-compose down --remove-orphans || true

# Start services
echo ""
echo -e "${YELLOW}🚀 Starting services...${NC}"
docker-compose up -d backend frontend

# Wait for health checks
echo ""
echo -e "${YELLOW}⏳ Waiting for services to be healthy...${NC}"
sleep 10

# Check backend health
BACKEND_HEALTH=$(curl -s http://localhost:8000/health | grep -o '"status":"healthy"' || echo "")
if [ -n "$BACKEND_HEALTH" ]; then
    echo -e "${GREEN}✅ Backend is healthy${NC}"
else
    echo -e "${RED}❌ Backend health check failed${NC}"
    docker-compose logs backend
    exit 1
fi

# Check frontend
FRONTEND_STATUS=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:3000/)
if [ "$FRONTEND_STATUS" = "200" ]; then
    echo -e "${GREEN}✅ Frontend is running${NC}"
else
    echo -e "${YELLOW}⚠️  Frontend returned status $FRONTEND_STATUS${NC}"
fi

echo ""
echo "===================================="
echo -e "${GREEN}🎉 Deployment Complete!${NC}"
echo ""
echo "Services:"
echo "  - Frontend: http://localhost:3000"
echo "  - Backend:  http://localhost:8000"
echo "  - API Docs: http://localhost:8000/docs"
echo ""
echo "Commands:"
echo "  - View logs: docker-compose logs -f"
echo "  - Stop:      docker-compose down"
echo "  - Restart:   docker-compose restart"
echo ""
