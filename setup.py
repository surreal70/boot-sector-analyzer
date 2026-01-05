"""Setup script for boot sector analyzer."""

from setuptools import setup, find_packages
from pathlib import Path

# Read README file
readme_path = Path(__file__).parent / "README.md"
long_description = readme_path.read_text(encoding="utf-8") if readme_path.exists() else ""

# Read requirements
requirements_path = Path(__file__).parent / "requirements.txt"
requirements = []
if requirements_path.exists():
    with open(requirements_path) as f:
        requirements = [line.strip() for line in f if line.strip() and not line.startswith('#')]

setup(
    name="boot-sector-analyzer",
    version="0.3.0",
    author="Boot Sector Analyzer Team",
    author_email="team@bootsectoranalyzer.com",
    description="A comprehensive boot sector analysis tool",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/bootsectoranalyzer/boot-sector-analyzer",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Information Technology",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "flake8>=5.0.0",
            "black>=22.0.0",
            "pytest>=7.0.0",
            "hypothesis>=6.0.0",
        ]
    },
    entry_points={
        "console_scripts": [
            "boot-sector-analyzer=boot_sector_analyzer.cli:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)