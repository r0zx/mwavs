#!/bin/bash
set -e

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root (sudo)"
    exit 1
fi

INSTALL_DIR="/opt/mwavs"
SOURCE_DIR="$(cd "$(dirname "$0")/.." && pwd)"

echo "[*] Installing MWAVS..."

rm -rf "$INSTALL_DIR" /usr/local/bin/mwavs
mkdir -p "$INSTALL_DIR"
cp -r "$SOURCE_DIR"/* "$INSTALL_DIR/"

cd "$INSTALL_DIR"
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip
pip install -e .
deactivate

cat > /usr/local/bin/mwavs << 'WRAPPER'
#!/bin/bash
source /opt/mwavs/venv/bin/activate
python -m scanner.cli.main "$@"
WRAPPER
chmod +x /usr/local/bin/mwavs

echo "[✓] Installation complete!"
echo "    Run: mwavs --version"
EOF

chmod +x scripts/install.sh
