import json
import socket
import threading
import logging
import sys
import os
from database_manager import DatabaseManager
from connection_handler import (SSHHandler, HTTPHandler, FTPHandler, 
                                TelnetHandler, SMTPHandler, MySQLHandler)
from threat_intelligence import ThreatIntelligence

IS_DOCKER = os.environ.get('IS_DOCKER', 'false').lower() == 'true'

if IS_DOCKER:
    DATA_DIR = '/app/data'
    LOG_FILE = os.path.join(DATA_DIR, 'honeypot_debug.log')
    DB_FILE = os.path.join(DATA_DIR, 'honeypot_events.db')
else:
    DATA_DIR = 'data'
    if not os.path.exists(DATA_DIR):
        os.makedirs(DATA_DIR, exist_ok=True)
    LOG_FILE = os.path.join(DATA_DIR, 'honeypot_debug.log')
    DB_FILE = os.path.join(DATA_DIR, 'honeypot_events.db')

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler(LOG_FILE, encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)

if sys.platform == 'win32':
    import codecs
    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer, 'strict')
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer, 'strict')

class HoneypotServer:
    def __init__(self, config_path='config.json'):
        self.config = self._load_config(config_path)
        self.db_manager = DatabaseManager(DB_FILE)
        self.threat_intel = ThreatIntelligence(self.config.get('threat_intelligence', {}))
        self.running = True
        
        logging.info("=== ADVANCED HONEYPOT SYSTEM ===")
        logging.info(f"Environment: {'Docker' if IS_DOCKER else 'Local'}")
        logging.info(f"Database Path: {DB_FILE}")
        logging.info(f"Threat Intelligence: {'Enabled' if self.config.get('threat_intelligence') else 'Disabled'}")

    def _load_config(self, path):
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception as e:
            logging.critical(f"Nie można załadować pliku konfiguracyjnego: {e}")
            sys.exit(1)

    def _get_handler_class(self, service_type):
        handlers = {
            'ssh': SSHHandler,
            'http': HTTPHandler,
            'ftp': FTPHandler,
            'telnet': TelnetHandler,
            'smtp': SMTPHandler,
            'mysql': MySQLHandler
        }
        return handlers.get(service_type.lower(), HTTPHandler)

    def _start_service_listener(self, service_conf):
        port = service_conf['port']
        host = '0.0.0.0'
        
        try:
            server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            server_socket.bind((host, port))
            server_socket.listen(5)
            
            logging.info(f"[*] Uruchomiono usługę '{service_conf['name']}' ({service_conf['type'].upper()}) na porcie {port}")

            while self.running:
                try:
                    client_sock, addr = server_socket.accept()
                    logging.info(f"[+] Połączenie z {addr[0]}:{addr[1]} na porcie {port} ({service_conf['type'].upper()})")
                    
                    handler_class = self._get_handler_class(service_conf['type'])
                    
                    handler = handler_class(
                        client_sock, 
                        addr, 
                        service_conf, 
                        self.db_manager,
                        self.threat_intel
                    )
                    
                    client_thread = threading.Thread(target=handler.handle)
                    client_thread.daemon = True
                    client_thread.start()
                    
                except Exception as e:
                    if self.running:
                        logging.error(f"Błąd obsługi połączenia na porcie {port}: {e}")
                
        except Exception as e:
            logging.error(f"Błąd serwera na porcie {port}: {e}")
        finally:
            try:
                server_socket.close()
            except:
                pass

    def start(self):
        logging.info("=" * 50)
        logging.info("🛡️  ADVANCED HONEYPOT SYSTEM - STARTING")
        logging.info("=" * 50)
        
        threads = []
        
        for service in self.config['services']:
            t = threading.Thread(target=self._start_service_listener, args=(service,))
            t.daemon = True
            t.start()
            threads.append(t)

        logging.info(f"\n✅ Uruchomiono {len(threads)} usług honeypot")
        logging.info("🔍 System monitoruje połączenia...")
        logging.info("⚠️  Naciśnij Ctrl+C aby zatrzymać\n")

        try:
            for t in threads:
                t.join()
        except KeyboardInterrupt:
            logging.info("\n\n" + "=" * 50)
            logging.info("🛑 Zatrzymywanie systemu...")
            self.running = False
            
            stats = self.db_manager.get_statistics()
            logging.info("\n📊 STATYSTYKI SESJI:")
            logging.info(f"   Całkowita liczba zdarzeń: {stats.get('total_events', 0)}")
            logging.info(f"   Unikalne adresy IP: {stats.get('unique_ips', 0)}")
            logging.info(f"   Zdarzenia wysokiego ryzyka: {stats.get('high_threat_events', 0)}")
            
            if stats.get('top_countries'):
                logging.info("\n   Top kraje atakujące:")
                for country, count in stats.get('top_countries', []):
                    logging.info(f"      - {country}: {count} ataków")
            
            logging.info("\n" + "=" * 50)
            logging.info("👋 System zatrzymany")
            logging.info("=" * 50 + "\n")

if __name__ == "__main__":
    server = HoneypotServer()
    server.start()
