#!/usr/bin/env python3
"""Setup script for MWAVS."""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""

# Read requirements
requirements_path = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_path.exists():
    with open(requirements_path) as f:
        requirements = [
            line.strip() for line in f 
            if line.strip() and not line.startswith('#')
        ]

setup(
    name="mwavs",
    version="1.0.0",
    author="r0zx",
    author_email="dhimanyatin4@gmail.com",
    description="Modular Web Application Vulnerability Scanner",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/example/mwavs",
    packages=find_packages(exclude=["tests", "tests.*"]),
    include_package_data=True,
    package_data={
        "mwavs": [
            "data/payloads/*.txt",
            "data/wordlists/*.txt",
        ],
    },
    python_requires=">=3.8",
    install_requires=[
        "requests>=2.31.0",
        "urllib3>=2.0.0",
        "pyyaml>=6.0.1",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-cov>=4.1.0",
            "black>=23.0.0",
            "flake8>=6.1.0",
            "mypy>=1.7.0",
        ],
        "async": [
            "aiohttp>=3.9.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "mwavs=scanner.cli.main:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Console",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: Security",
        "Topic :: Internet :: WWW/HTTP",
    ],
    keywords="security, vulnerability, scanner, web, penetration-testing, xss, sqli",
)
