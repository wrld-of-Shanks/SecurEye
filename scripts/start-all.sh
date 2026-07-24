#!/bin/bash

# SentinelAI Startup Script
# Starts all services in the correct order

set -e

echo "🛡️  Starting SentinelAI Platform..."

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Check if MongoDB is running
echo -e "${YELLOW}Checking MongoDB...${NC}"
if ! pgrep -x "mongod" > /dev/null; then
    echo -e "${YELLOW}Starting MongoDB...${NC}"
    mkdir -p data/db
    mongod --dbpath ./data/db --fork --logpath ./data/mongod.log
    sleep 2
fi

# Function to start a service
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

# Start Network Service
start_service "Network Service" "./services/network" "python3 app.py"

# Start Code Service
start_service "Code Service" "./services/code" "python3 app.py"

# Wait for services to start
sleep 3

# Start Gateway
start_service "Gateway" "./gateway" "npm start"

# Wait for gateway
sleep 2

echo ""
echo -e "${GREEN}✅ All services started!${NC}"
echo ""
echo "📊 Dashboard: http://localhost:3001"
echo "🔗 Gateway API: http://localhost:3000"
echo "🌐 Network Service: http://localhost:5001"
echo "💻 Code Service: http://localhost:5002"
echo ""
echo "Press Ctrl+C to stop all services"

# Trap to cleanup on exit
cleanup() {
    echo ""
    echo -e "${YELLOW}Stopping all services...${NC}"
    kill $(jobs -p) 2>/dev/null || true
    echo -e "${GREEN}All services stopped${NC}"
    exit 0
}

trap cleanup SIGINT SIGTERM

# Wait for all background processes
wait
