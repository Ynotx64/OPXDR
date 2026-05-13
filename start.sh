#!/usr/bin/env bash
# ─── OPXDR Clean Start Script ─────────────────────────────────────────────────
# Kills stale processes, starts backend on 5174, frontend on 5173
# Usage:  bash ~/OPXDR/start.sh
# Alias:  echo 'alias opxdr="bash ~/OPXDR/start.sh"' >> ~/.bashrc

set -e
cd "$(dirname "$0")"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; BOLD='\033[1m'; RESET='\033[0m'

echo -e "\n${BOLD}${CYAN}⚡ OPXDR — Starting platform...${RESET}\n"

# ── Kill stale processes ──────────────────────────────────────────────────────
echo -e "${YELLOW}→ Killing stale processes on 5173/5174...${RESET}"
fuser -k 5173/tcp 2>/dev/null || true
fuser -k 5174/tcp 2>/dev/null || true
pkill -f "node.*server/index" 2>/dev/null || true
pkill -f "vite" 2>/dev/null || true
sleep 1

# ── Ensure .env exists ────────────────────────────────────────────────────────
if [ ! -f ".env" ]; then
  echo -e "${YELLOW}⚠  No .env found — copying .env.example...${RESET}"
  if [ -f ".env.example" ]; then
    cp .env.example .env
  else
    cat > .env << 'EOF'
PORT=5174
WAZUH_API_URL=https://localhost:55000
WAZUH_API_USER=wazuh-wui
WAZUH_API_PASS=
WAZUH_INDEXER_URL=https://localhost:9200
WAZUH_INDEXER_PASS=
EOF
  fi
  echo -e "${GREEN}✓  .env created — edit ~/OPXDR/.env to add keys${RESET}"
fi

# ── Install deps if missing ───────────────────────────────────────────────────
if [ ! -d "node_modules" ]; then
  echo -e "${YELLOW}→ Installing npm dependencies...${RESET}"
  npm install
fi

# ── Start backend ─────────────────────────────────────────────────────────────
echo -e "${CYAN}→ Starting Express backend on port 5174...${RESET}"
node server/index.js &
BACKEND_PID=$!
echo -e "${GREEN}✓  Backend PID: $BACKEND_PID${RESET}"

# Wait up to 8s for backend to be healthy
for i in $(seq 1 8); do
  if curl -sf http://localhost:5174/api/health > /dev/null 2>&1; then
    echo -e "${GREEN}✓  Backend healthy${RESET}"; break
  fi
  [ $i -eq 8 ] && echo -e "${YELLOW}⚠  Backend health check timed out — frontend will retry${RESET}"
  sleep 1
done

# ── Start frontend ────────────────────────────────────────────────────────────
echo -e "${CYAN}→ Starting Vite frontend on port 5173...${RESET}"
npm run dev &
FRONTEND_PID=$!
echo -e "${GREEN}✓  Frontend PID: $FRONTEND_PID${RESET}"

echo -e "\n${BOLD}${GREEN}✅ OPXDR is running:${RESET}"
echo -e "   ${BOLD}SIEM:    ${CYAN}http://100.86.115.94:5173${RESET}"
echo -e "   ${BOLD}GEO:     ${CYAN}http://100.86.115.94:5173/geo.html${RESET}"
echo -e "   ${BOLD}API:     ${CYAN}http://100.86.115.94:5174/api/health${RESET}"
echo -e "\n   ${YELLOW}Ctrl+C to stop both servers${RESET}\n"

cleanup() {
  echo -e "\n${RED}→ Shutting down...${RESET}"
  kill $BACKEND_PID $FRONTEND_PID 2>/dev/null || true
  fuser -k 5173/tcp 2>/dev/null || true
  fuser -k 5174/tcp 2>/dev/null || true
  echo -e "${GREEN}✓  Stopped${RESET}\n"
  exit 0
}
trap cleanup SIGINT SIGTERM

wait
