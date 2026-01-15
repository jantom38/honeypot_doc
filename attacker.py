import socket
import time
import random
import urllib.request

TARGET_IP = "127.0.0.1"
SSH_PORT = 2222
HTTP_PORT = 8080
FTP_PORT = 2121
TELNET_PORT = 2323
MYSQL_PORT = 3306

USERNAMES = ["admin", "root", "user", "support", "oracle", "test", "ftp", "anonymous"]
PASSWORDS = ["123456", "password", "admin123", "qwerty", "letmein", "toor", "ftp", "anonymous"]

def attack_ssh():
    """Symuluje próbę logowania SSH."""
    user = random.choice(USERNAMES)
    pwd = random.choice(PASSWORDS)
    print(f"[SSH] Atak: {user}:{pwd}...", end=" ")
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((TARGET_IP, SSH_PORT))
        s.recv(1024)
        payload = f"{user}\n{pwd}"
        s.send(payload.encode())
        s.close()
        print("Wysłano.")
    except Exception as e:
        print(f"Błąd: {e}")

def attack_http():
    """Symuluje skanowanie HTTP."""
    paths = ["/admin", "/login", "/wp-admin", "/config.php", "/", 
             "/?id=1' OR '1'='1", "/index.php?page=../../../etc/passwd",
             "/?name=<script>alert('XSS')</script>"]
    path = random.choice(paths)
    url = f"http://{TARGET_IP}:{HTTP_PORT}{path}"
    print(f"[HTTP] Skanowanie: {url}...", end=" ")
    
    try:
        with urllib.request.urlopen(url, timeout=3) as response:
            pass
        print("Sukces (200 OK).")
    except Exception as e:
        print(f"OK (honeypot odpowiedział)")

def attack_ftp():
    """Symuluje próbę logowania FTP."""
    user = random.choice(USERNAMES)
    pwd = random.choice(PASSWORDS)
    print(f"[FTP] Atak: {user}:{pwd}...", end=" ")
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((TARGET_IP, FTP_PORT))
        s.recv(1024)
        s.send(f"USER {user}\r\n".encode())
        s.recv(1024)
        s.send(f"PASS {pwd}\r\n".encode())
        s.recv(1024)
        s.close()
        print("Wysłano.")
    except Exception as e:
        print(f"OK (połączono)")

def attack_telnet():
    """Symuluje próbę logowania Telnet."""
    user = random.choice(USERNAMES)
    pwd = random.choice(PASSWORDS)
    print(f"[TELNET] Atak: {user}:{pwd}...", end=" ")
    
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((TARGET_IP, TELNET_PORT))
        time.sleep(0.2)
        s.recv(1024)
        s.send(f"{user}\n".encode())
        time.sleep(0.2)
        s.recv(1024)
        s.send(f"{pwd}\n".encode())
        s.close()
        print("Wysłano.")
    except Exception as e:
        print(f"OK (połączono)")

def attack_mysql():
    """Symuluje próbę logowania MySQL."""
    print(f"[MYSQL] Atak na port {MYSQL_PORT}...", end=" ")
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((TARGET_IP, MYSQL_PORT))
        
        s.recv(1024)
        
        fake_packet = b"\x10\x00\x00\x01\x85\xa6\x03\x00\x00\x00\x00\x01\x21\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00root\x00\x00"
        s.send(fake_packet)
        s.close()
        print("Wysłano.")
    except Exception as e:
        print(f"Błąd: {e}")

if __name__ == "__main__":
    print("=" * 60)
    print("  🎯 SYMULACJA ATAKÓW NA HONEYPOT")
    print("=" * 60)
    print(f"Target: {TARGET_IP}")
    print("Naciśnij Ctrl+C, aby przerwać.")
    print()
    
    attack_functions = [attack_ssh, attack_http, attack_ftp, attack_telnet, attack_mysql]
    
    try:
        for i in range(30):
            attack_func = random.choice(attack_functions)
            attack_func()
            time.sleep(random.uniform(0.3, 1.0))
            
    except KeyboardInterrupt:
        print("\n")
        print("=" * 60)
        print("  ⚠️  Symulacja zatrzymana")
        print("=" * 60)
    
    print()
    print("✅ Zakończono symulację ataków")
    print("💡 Sprawdź dashboard: http://localhost:8501")
