# Contributing to MWAVS

Thank you for considering contributing! 🎉

## How to Contribute

### Report Bugs
1. Check [existing issues](https://github.com/r0zx/mwavs/issues)
2. Create new issue with details

### Suggest Features
1. Open issue with "enhancement" label
2. Describe use case

### Submit Code
1. Fork repository
2. Create branch: `git checkout -b feature/my-feature`
3. Make changes
4. Test: `pytest`
5. Commit: `git commit -m "feat: add feature"`
6. Push: `git push origin feature/my-feature`
7. Create Pull Request

## Development Setup

```bash
git clone https://github.com/YOUR_USERNAME/mwavs.git
cd mwavs
python3 -m venv venv
source venv/bin/activate
pip install -e ".[dev]"
pytest
