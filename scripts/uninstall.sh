#!/bin/bash
echo "[*] Uninstalling MWAVS..."
sudo rm -f /usr/local/bin/mwavs
sudo rm -rf /opt/mwavs
echo "[✓] Uninstalled!"
EOF

chmod +x scripts/uninstall.sh

