#!/bin/bash
echo "==================================================="
echo "    🛡️ STARTING ARCHON FULL-STACK ECOSYSTEM 🛡️"
echo "==================================================="

echo "[*] Initializing background Watcher daemon..."
python watcher.py &
WATCHER_PID=$!

echo "[*] Initializing Streamlit Command Center..."
streamlit run dashboard.py &
DASHBOARD_PID=$!

echo "[+] Watcher PID: $WATCHER_PID"
echo "[+] Dashboard PID: $DASHBOARD_PID"
echo "Press [CTRL+C] to stop all processes."

trap "kill $WATCHER_PID $DASHBOARD_PID; exit" INT

while true; do
    sleep 1
done
