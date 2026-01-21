 'EOF'
"""MWAVS Test Suite"""
EOF

cat > tests/test_basic.py << 'EOF'
"""Basic tests."""

def test_import():
    from scanner import __version__
    assert __version__ == "1.0.0"

def test_config():
    from scanner.core.config import ScannerConfig
    config = ScannerConfig()
    assert config is not None
EOF
