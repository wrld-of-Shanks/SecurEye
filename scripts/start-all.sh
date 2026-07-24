#!/bin/bash

# SentinelAI Startup Script
# Starts all services in the correct order

set -e

echo "🛡️  Starting SentinelAI Platform..."

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}Checking MongoDB...${NC}"
if ! pgrep -x "mongod" > /dev/null; then
    echo -e "${YELLOW}Starting MongoDB...${NC}"
    mkdir -p data/db
    mongod --dbpath ./data/db --fork --logpath ./data/mongod.log
    sleep 2
fi

start_service() {
    local name=$1
    local dir=$2
    local command=$3
    echo -e "${YELLOW}Starting ${name}...${NC}"
    cd "$dir"
    eval "$command" &
    echo -e "${GREEN}${name} started${NC}"
    cd - > /dev/null
}

start_service "Network Service" "./services/network" "python3 app.py"
start_service "Code Service" "./services/code" "python3 app.py"
start_service "DAST Service" "./services/dast" "python3 app.py"

sleep 3

start_service "Gateway" "./gateway" "npm start"

sleep 2

echo ""
echo -e "${GREEN}✅ All services started!${NC}"
echo ""
echo "📊 Dashboard: http://localhost:3001"
echo "🔗 Gateway API: http://localhost:3000"
echo "🌐 Network Service: http://localhost:5001"
echo "💻 Code Service: http://localhost:5002"
echo "🔍 DAST Service: http://localhost:5003"
echo ""
echo "Press Ctrl+C to stop all services"

cleanup() {
    echo ""
    echo -e "${YELLOW}Stopping all services...${NC}"
    kill $(jobs -p) 2>/dev/null || true
    echo -e "${GREEN}All services stopped${NC}"
    exit 0
}

trap cleanup SIGINT SIGTERM

wait
