#!/usr/bin/env python3
"""
Test Installation Script
Sprawdza czy wszystkie komponenty systemu są poprawnie zainstalowane
"""

import sys
import os
from datetime import datetime

def print_header(text):
    print("\n" + "="*60)
    print(f"  {text}")
    print("="*60)

def print_test(name, status, message=""):
    status_symbol = "✅" if status else "❌"
    print(f"{status_symbol} {name}")
    if message:
        print(f"   └─ {message}")

def test_python_version():
    """Test Python version"""
    version = sys.version_info
    required = (3, 8)
    
    if version >= required:
        print_test("Python Version", True, f"Python {version.major}.{version.minor}.{version.micro}")
        return True
    else:
        print_test("Python Version", False, f"Python {version.major}.{version.minor} (wymagana 3.8+)")
        return False

def test_module(module_name, package_name=None):
    """Test if Python module is installed"""
    try:
        __import__(module_name)
        print_test(f"Module: {package_name or module_name}", True)
        return True
    except ImportError:
        print_test(f"Module: {package_name or module_name}", False, 
                  f"Zainstaluj: pip install {package_name or module_name}")
        return False

def test_file_exists(filepath, description):
    """Test if file exists"""
    if os.path.exists(filepath):
        size = os.path.getsize(filepath)
        print_test(description, True, f"Rozmiar: {size:,} bytes")
        return True
    else:
        print_test(description, False, "Plik nie istnieje")
        return False

def test_config():
    """Test config.json"""
    try:
        import json
        with open('config.json', 'r', encoding='utf-8') as f:
            config = json.load(f)
        
        services = config.get('services', [])
        print_test("Config.json", True, f"{len(services)} usług skonfigurowanych")
        return True
    except Exception as e:
        print_test("Config.json", False, str(e))
        return False

def test_database():
    """Test database creation"""
    try:
        import sqlite3
        conn = sqlite3.connect(':memory:')
        cursor = conn.cursor()
        cursor.execute("CREATE TABLE test (id INTEGER)")
        conn.close()
        print_test("SQLite Database", True, "Działa poprawnie")
        return True
    except Exception as e:
        print_test("SQLite Database", False, str(e))
        return False

def test_geoip():
    """Test GeoIP2 database"""
    db_path = 'GeoLite2-City.mmdb'
    
    # Obsługa przypadku gdy ścieżka jest katalogiem (np. po rozpakowaniu)
    if os.path.isdir(db_path):
        found = False
        for root, dirs, files in os.walk(db_path):
            for file in files:
                if file.endswith('.mmdb') and 'City' in file:
                    db_path = os.path.join(root, file)
                    found = True
                    break
            if found:
                break
        
        if not found:
            # Próba znalezienia jakiegokolwiek pliku mmdb jeśli nie znaleziono City
            for root, dirs, files in os.walk('GeoLite2-City.mmdb'):
                for file in files:
                    if file.endswith('.mmdb'):
                        db_path = os.path.join(root, file)
                        found = True
                        break
                if found:
                    break

    if not os.path.exists(db_path) or os.path.isdir(db_path):
        print_test("GeoIP2 Database", False, "Plik GeoLite2-City.mmdb nie znaleziony (opcjonalny)")
        return False
    
    try:
        import geoip2.database
        reader = geoip2.database.Reader(db_path)
        response = reader.city('8.8.8.8')
        reader.close()
        print_test("GeoIP2 Database", True, 
                  f"Test OK: {response.country.name}, {response.city.name}")
        return True
    except Exception as e:
        print_test("GeoIP2 Database", False, str(e))
        return False

def test_ports():
    """Test if ports are available"""
    import socket
    
    ports_to_test = [
        (2222, "SSH Honeypot"),
        (8080, "HTTP Honeypot"),
        (2121, "FTP Honeypot"),
        (2323, "Telnet Honeypot"),
        (2525, "SMTP Honeypot"),
        (8501, "Dashboard (Streamlit)")
    ]
    
    all_ok = True
    for port, description in ports_to_test:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex(('localhost', port))
        sock.close()
        
        if result == 0:
            print_test(f"Port {port} ({description})", False, 
                      "Port zajęty - zatrzymaj usługę lub zmień port")
            all_ok = False
        else:
            print_test(f"Port {port} ({description})", True, "Dostępny")
    
    return all_ok

def main():
    print_header("🛡️ ADVANCED HONEYPOT - TEST INSTALACJI")
    print(f"Data: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"System: {sys.platform}")
    
    results = {
        'total': 0,
        'passed': 0,
        'failed': 0
    }
    
    # Python Version
    print_header("1️⃣ Python Environment")
    result = test_python_version()
    results['total'] += 1
    results['passed' if result else 'failed'] += 1
    
    # Required Modules
    print_header("2️⃣ Required Python Modules")
    modules = [
        ('streamlit', None),
        ('pandas', None),
        ('plotly', None),
        ('requests', None),
        ('sqlite3', None),
    ]
    
    for module, package in modules:
        result = test_module(module, package)
        results['total'] += 1
        results['passed' if result else 'failed'] += 1
    
    # Optional Modules
    print_header("3️⃣ Optional Python Modules")
    optional_modules = [
        ('geoip2', 'geoip2'),
        ('paramiko', 'paramiko'),
    ]
    
    for module, package in optional_modules:
        result = test_module(module, package)
        results['total'] += 1
        results['passed' if result else 'failed'] += 1
    
    # Project Files
    print_header("4️⃣ Project Files")
    files = [
        ('main.py', 'Main honeypot file'),
        ('dashboard.py', 'Dashboard file'),
        ('config.json', 'Configuration file'),
        ('database_manager.py', 'Database manager'),
        ('connection_handler.py', 'Connection handlers'),
        ('threat_intelligence.py', 'Threat intelligence'),
        ('requirements.txt', 'Requirements file'),
    ]
    
    for filepath, description in files:
        result = test_file_exists(filepath, description)
        results['total'] += 1
        results['passed' if result else 'failed'] += 1
    
    # Configuration
    print_header("5️⃣ Configuration")
    result = test_config()
    results['total'] += 1
    results['passed' if result else 'failed'] += 1
    
    result = test_database()
    results['total'] += 1
    results['passed' if result else 'failed'] += 1
    
    # Optional: GeoIP
    print_header("6️⃣ Optional Components")
    result = test_geoip()
    results['total'] += 1
    # Don't count GeoIP as failed since it's optional
    if not result:
        print("   ℹ️  GeoIP2 jest opcjonalny - system będzie działał bez niego")
    
    # Port Availability
    print_header("7️⃣ Port Availability")
    result = test_ports()
    results['total'] += 1
    results['passed' if result else 'failed'] += 1
    
    # Summary
    print_header("📊 PODSUMOWANIE")
    
    success_rate = (results['passed'] / results['total']) * 100
    
    print(f"\n✅ Testy zakończone: {results['passed']}/{results['total']}")
    print(f"❌ Testy nie zakończone: {results['failed']}/{results['total']}")
    print(f"📈 Procent sukcesu: {success_rate:.1f}%")
    
    if results['failed'] == 0:
        print("\n🎉 WSZYSTKO DZIAŁA! System jest gotowy do uruchomienia!")
        print("\nKolejne kroki:")
        print("1. python main.py          # Uruchom honeypot")
        print("2. streamlit run dashboard.py  # Uruchom dashboard (nowy terminal)")
        print("3. python attacker.py      # Testuj system (opcjonalnie)")
        return 0
    else:
        print("\n⚠️ Niektóre testy nie przeszły. Sprawdź błędy powyżej.")
        print("\nAby naprawić problemy:")
        print("1. pip install -r requirements.txt")
        print("2. Sprawdź SETUP_GUIDE.md dla szczegółów")
        return 1

if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\n\n⚠️ Test przerwany przez użytkownika")
        sys.exit(1)
    except Exception as e:
        print(f"\n\n❌ Nieoczekiwany błąd: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)
