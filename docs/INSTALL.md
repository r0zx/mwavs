# Installation Guide

## System Requirements

### Minimum Requirements
- Python 3.8 or higher
- pip 21.0 or higher
- 512 MB RAM
- 100 MB disk space

### Recommended
- Python 3.10+
- 2 GB RAM (for large scans)
- SSD storage for faster wordlist operations

### Supported Operating Systems
- Linux (Ubuntu 18.04+, Debian 10+, CentOS 7+, Kali Linux)
- macOS 10.15+
- Windows 10/11

## Installation Methods

### Method 1: Install from Source (Recommended for Development)

```bash
# Clone the repository
git clone https://github.com/example/mwavs.git
cd mwavs

# Create virtual environment (recommended)
python3 -m venv venv

# Activate virtual environment
# On Linux/macOS:
source venv/bin/activate
# On Windows:
venv\Scripts\activate

# Install in development mode with all dependencies
pip install -e ".[dev]"

# Verify installation
mwavs --version
mwavs --list-plugins 