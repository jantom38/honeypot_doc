#!/usr/bin/env python3
"""
Quick Install Script - Instaluje wszystkie wymagane zależności
"""

import subprocess
import sys

def install_package(package):
    """Install a Python package using pip"""
    print(f"📦 Installing {package}...")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
        print(f"✅ {package} installed successfully")
        return True
    except subprocess.CalledProcessError:
        print(f"❌ Failed to install {package}")
        return False

def main():
    print("="*60)
    print("  🛡️ HONEYPOT - DEPENDENCY INSTALLER")
    print("="*60)
    print()
    
    # Lista pakietów do zainstalowania
    packages = [
        "streamlit",
        "pandas",
        "plotly",
        "requests",
        "geoip2",
        "maxminddb",
        "paramiko",
        "python-dateutil"
    ]
    
    print(f"Will install {len(packages)} packages:")
    for pkg in packages:
        print(f"  - {pkg}")
    print()
    
    input("Press Enter to continue or Ctrl+C to cancel...")
    print()
    
    success = 0
    failed = 0
    
    for package in packages:
        if install_package(package):
            success += 1
        else:
            failed += 1
        print()
    
    print("="*60)
    print("  📊 INSTALLATION SUMMARY")
    print("="*60)
    print(f"✅ Successfully installed: {success}/{len(packages)}")
    print(f"❌ Failed: {failed}/{len(packages)}")
    print()
    
    if failed == 0:
        print("🎉 All packages installed successfully!")
        print()
        print("Next steps:")
        print("1. python test_installation.py  # Verify installation")
        print("2. python main.py               # Start honeypot")
        print("3. streamlit run dashboard.py   # Start dashboard")
    else:
        print("⚠️ Some packages failed to install.")
        print("Try running: pip install -r requirements.txt")
    
    return 0 if failed == 0 else 1

if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\n\n⚠️ Installation cancelled by user")
        sys.exit(1)
