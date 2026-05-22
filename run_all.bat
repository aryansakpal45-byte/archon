@echo off
echo ===================================================
echo     🛡️ STARTING ARCHON FULL-STACK ECOSYSTEM 🛡️
echo ===================================================

echo [*] Initializing background Watcher daemon...
start "Archon Watcher" python watcher.py

echo [*] Initializing Streamlit Command Center...
streamlit run dashboard.py

pause
