#!/usr/bin/env python3
"""
Environment setup script for Boot Sector Analyzer

This script ensures the project follows Python development framework requirements:
- Creates and manages virtual environments
- Installs dependencies
- Validates Python version
- Checks for PEP 8 compliance tools
"""

import sys
import subprocess
import os
from pathlib import Path

def check_python_version():
    """Check if Python version meets requirements (3.8+)."""
    if sys.version_info < (3, 8):
        print(f"❌ Error: Python 3.8 or higher is required.")
        print(f"   Current version: {sys.version}")
        print(f"   Please upgrade Python and try again.")
        return False
    
    print(f"✅ Python version: {sys.version.split()[0]} (meets requirement ≥3.8)")
    return True

def check_virtual_environment():
    """Check if we're in a virtual environment."""
    in_venv = (
        hasattr(sys, 'real_prefix') or 
        (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix)
    )
    
    if in_venv:
        print(f"✅ Virtual environment active: {sys.prefix}")
        return True
    else:
        print("⚠️  Not in a virtual environment")
        return False

def create_virtual_environment():
    """Create virtual environment if it doesn't exist."""
    venv_path = Path("venv")
    
    if venv_path.exists():
        print("✅ Virtual environment directory exists")
        return True
    
    print("📦 Creating virtual environment...")
    try:
        subprocess.run([sys.executable, "-m", "venv", "venv"], check=True)
        print("✅ Virtual environment created successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to create virtual environment: {e}")
        return False

def get_venv_python():
    """Get the path to Python executable in virtual environment."""
    if os.name == 'nt':  # Windows
        return Path("venv") / "Scripts" / "python.exe"
    else:  # Unix-like
        return Path("venv") / "bin" / "python"

def install_dependencies():
    """Install project dependencies."""
    requirements_file = Path("requirements.txt")
    
    if not requirements_file.exists():
        print("⚠️  requirements.txt not found")
        return False
    
    venv_python = get_venv_python()
    
    if not venv_python.exists():
        print("❌ Virtual environment Python not found")
        return False
    
    print("📦 Installing dependencies...")
    try:
        subprocess.run([
            str(venv_python), "-m", "pip", "install", "-r", "requirements.txt"
        ], check=True)
        print("✅ Dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install dependencies: {e}")
        return False

def install_dev_dependencies():
    """Install development dependencies for PEP 8 compliance."""
    venv_python = get_venv_python()
    
    dev_packages = [
        "flake8>=5.0.0",      # PEP 8 linting
        "black>=22.0.0",      # Code formatting
        "pytest>=7.0.0",      # Testing
        "hypothesis>=6.0.0",  # Property-based testing
    ]
    
    print("📦 Installing development dependencies...")
    try:
        subprocess.run([
            str(venv_python), "-m", "pip", "install"
        ] + dev_packages, check=True)
        print("✅ Development dependencies installed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ Failed to install development dependencies: {e}")
        return False

def check_pep8_compliance():
    """Check PEP 8 compliance of the codebase."""
    venv_python = get_venv_python()
    
    print("🔍 Checking PEP 8 compliance...")
    try:
        # Run flake8 on the main package
        result = subprocess.run([
            str(venv_python), "-m", "flake8", "boot_sector_analyzer/", "--max-line-length=88"
        ], capture_output=True, text=True)
        
        if result.returncode == 0:
            print("✅ Code is PEP 8 compliant")
            return True
        else:
            print("⚠️  PEP 8 violations found:")
            print(result.stdout)
            return False
    except subprocess.CalledProcessError as e:
        print(f"⚠️  Could not check PEP 8 compliance: {e}")
        return False

def validate_project_structure():
    """Validate that project follows standard Python structure."""
    required_files = [
        "requirements.txt",
        "setup.py",
        "README.md",
        "boot_sector_analyzer/__init__.py",
        "tests/__init__.py",
    ]
    
    required_dirs = [
        "boot_sector_analyzer/",
        "tests/",
    ]
    
    print("🏗️  Validating project structure...")
    
    all_good = True
    
    for file_path in required_files:
        if Path(file_path).exists():
            print(f"✅ {file_path}")
        else:
            print(f"❌ Missing: {file_path}")
            all_good = False
    
    for dir_path in required_dirs:
        if Path(dir_path).is_dir():
            print(f"✅ {dir_path}")
        else:
            print(f"❌ Missing directory: {dir_path}")
            all_good = False
    
    return all_good

def print_usage_instructions():
    """Print instructions for using the environment."""
    print("\n" + "="*60)
    print("🎉 Environment setup complete!")
    print("="*60)
    
    if os.name == 'nt':  # Windows
        activate_cmd = "venv\\Scripts\\activate"
    else:  # Unix-like
        activate_cmd = "source venv/bin/activate"
    
    print(f"""
To use the Boot Sector Analyzer:

1. Activate the virtual environment:
   {activate_cmd}

2. Run the application:
   python boot_sector_analyzer.py --help
   python boot_sector_analyzer.py /path/to/boot/sector

3. Run tests:
   python -m pytest tests/

4. Check code quality:
   python -m flake8 boot_sector_analyzer/
   python -m black --check boot_sector_analyzer/

5. Format code:
   python -m black boot_sector_analyzer/
""")

def main():
    """Main setup function."""
    print("🚀 Boot Sector Analyzer - Environment Setup")
    print("="*50)
    
    # Check Python version
    if not check_python_version():
        return 1
    
    # Validate project structure
    if not validate_project_structure():
        print("❌ Project structure validation failed")
        return 1
    
    # Create virtual environment if needed
    if not create_virtual_environment():
        return 1
    
    # Install dependencies
    if not install_dependencies():
        return 1
    
    # Install development dependencies
    if not install_dev_dependencies():
        print("⚠️  Development dependencies failed, but continuing...")
    
    # Check if we're in the virtual environment
    if not check_virtual_environment():
        print("ℹ️  Run this script from within the virtual environment for full validation")
    else:
        # Check PEP 8 compliance if in venv
        check_pep8_compliance()
    
    print_usage_instructions()
    return 0

if __name__ == "__main__":
    sys.exit(main())