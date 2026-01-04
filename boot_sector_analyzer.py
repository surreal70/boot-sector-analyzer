#!/usr/bin/env python3
"""
Boot Sector Analyzer - Single file entry point

This script provides a single-file entry point for the Boot Sector Analyzer application.
It can be run directly from the project root without installation.

Usage:
    python boot_sector_analyzer.py [options] <source>
    python3 boot_sector_analyzer.py --help
    ./boot_sector_analyzer.py /dev/sda

Requirements:
    - Python 3.8 or higher
    - Dependencies listed in requirements.txt
"""

import sys
import os
from pathlib import Path

# Add the project directory to Python path so we can import our modules
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def check_python_version():
    """Check if Python version meets minimum requirements."""
    if sys.version_info < (3, 8):
        print("Error: Python 3.8 or higher is required.", file=sys.stderr)
        print(f"Current version: {sys.version}", file=sys.stderr)
        sys.exit(1)

def check_dependencies():
    """Check if required dependencies are available."""
    missing_deps = []
    
    # Check for required packages
    required_packages = [
        'configparser',  # Built-in, but let's be explicit
        'argparse',      # Built-in
        'pathlib',       # Built-in
        'logging',       # Built-in
    ]
    
    # Optional packages that should be available
    optional_packages = [
        ('hypothesis', 'Property-based testing'),
        ('pytest', 'Unit testing'),
    ]
    
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            missing_deps.append(package)
    
    if missing_deps:
        print("Error: Missing required dependencies:", file=sys.stderr)
        for dep in missing_deps:
            print(f"  - {dep}", file=sys.stderr)
        print("\nPlease install dependencies with:", file=sys.stderr)
        print("  pip install -r requirements.txt", file=sys.stderr)
        sys.exit(1)
    
    # Check optional packages and warn if missing
    missing_optional = []
    for package, description in optional_packages:
        try:
            __import__(package)
        except ImportError:
            missing_optional.append((package, description))
    
    if missing_optional:
        print("Warning: Some optional dependencies are missing:", file=sys.stderr)
        for package, description in missing_optional:
            print(f"  - {package}: {description}", file=sys.stderr)
        print("Install with: pip install -r requirements.txt", file=sys.stderr)
        print()

def main():
    """Main entry point for the single-file application."""
    # Check Python version first
    check_python_version()
    
    # Check dependencies
    check_dependencies()
    
    # Import and run the CLI
    try:
        from boot_sector_analyzer.cli import main as cli_main
        return cli_main()
    except ImportError as e:
        print(f"Error: Failed to import boot sector analyzer modules: {e}", file=sys.stderr)
        print("Make sure you're running this script from the project root directory.", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1

if __name__ == '__main__':
    sys.exit(main())