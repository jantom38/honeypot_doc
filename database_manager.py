import sqlite3
import logging
from datetime import datetime
import json
import os

class DatabaseManager:
    def __init__(self, db_name):
        self.db_name = db_name
        self._initialize_db()

    def _get_connection(self):
        db_dir = os.path.dirname(os.path.abspath(self.db_name))
        if db_dir and not os.path.exists(db_dir):
            try:
                os.makedirs(db_dir, exist_ok=True)
            except Exception as e:
                logging.error(f"Nie można utworzyć katalogu bazy danych: {e}")

        conn = sqlite3.connect(self.db_name)
        try:
            conn.execute('PRAGMA journal_mode=WAL;')
        except:
            pass
        return conn

    def _initialize_db(self):
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    service_name TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    source_port INTEGER,
                    payload TEXT,
                    
                    threat_level INTEGER DEFAULT 0,
                    is_malicious INTEGER DEFAULT 0,
                    abuse_confidence_score INTEGER DEFAULT 0,
                    
                    attack_type TEXT,
                    attack_category TEXT,
                    
                    session_id TEXT,
                    username_attempted TEXT,
                    password_attempted TEXT,
                    command_executed TEXT,
                    
                    user_agent TEXT,
                    request_method TEXT,
                    http_path TEXT,
                    protocol_version TEXT
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS ip_reputation (
                    ip_address TEXT PRIMARY KEY,
                    last_checked TEXT,
                    abuse_confidence_score INTEGER,
                    is_whitelisted INTEGER DEFAULT 0,
                    country_code TEXT,
                    isp TEXT,
                    total_reports INTEGER DEFAULT 0
                )
            ''')
            
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    message TEXT,
                    event_id INTEGER,
                    acknowledged INTEGER DEFAULT 0,
                    FOREIGN KEY (event_id) REFERENCES events(id)
                )
            ''')
            
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_source_ip ON events(source_ip)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_service_name ON events(service_name)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_threat_level ON events(threat_level)')
            
            conn.commit()
            conn.close()
            logging.info(f"Baza danych zainicjalizowana pomyślnie: {self.db_name}")
        except Exception as e:
            logging.error(f"Błąd inicjalizacji bazy danych: {e}")

    def log_event(self, service_name, source_ip, source_port, payload, 
                  threat_data=None, session_data=None, http_data=None):
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            data = {
                'timestamp': timestamp,
                'service_name': service_name,
                'source_ip': source_ip,
                'source_port': source_port,
                'payload': payload,
            }
            
            if threat_data:
                data.update({
                    'threat_level': threat_data.get('threat_level', 0),
                    'is_malicious': threat_data.get('is_malicious', 0),
                    'abuse_confidence_score': threat_data.get('abuse_confidence_score', 0),
                    'attack_type': threat_data.get('attack_type'),
                    'attack_category': threat_data.get('attack_category'),
                })
            
            if session_data:
                data.update({
                    'session_id': session_data.get('session_id'),
                    'username_attempted': session_data.get('username'),
                    'password_attempted': session_data.get('password'),
                    'command_executed': session_data.get('command'),
                })
            
            if http_data:
                data.update({
                    'user_agent': http_data.get('user_agent'),
                    'request_method': http_data.get('method'),
                    'http_path': http_data.get('path'),
                    'protocol_version': http_data.get('protocol'),
                })
            
            columns = ', '.join(data.keys())
            placeholders = ', '.join(['?' for _ in data])
            query = f'INSERT INTO events ({columns}) VALUES ({placeholders})'
            
            cursor.execute(query, list(data.values()))
            conn.commit()
            event_id = cursor.lastrowid
            conn.close()
            
            logging.info(f"Zapisano zdarzenie #{event_id} w DB: {service_name} od {source_ip}")
            return event_id
            
        except Exception as e:
            logging.error(f"Błąd zapisu do bazy danych: {e}")
            return None

    def update_ip_reputation(self, ip_address, reputation_data):
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            cursor.execute('''
                INSERT OR REPLACE INTO ip_reputation 
                (ip_address, last_checked, abuse_confidence_score, country_code, isp, total_reports)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                ip_address,
                timestamp,
                reputation_data.get('abuse_confidence_score', 0),
                reputation_data.get('country_code'),
                reputation_data.get('isp'),
                reputation_data.get('total_reports', 0)
            ))
            
            conn.commit()
            conn.close()
            logging.info(f"Zaktualizowano reputację IP: {ip_address}")
        except Exception as e:
            logging.error(f"Błąd aktualizacji reputacji IP: {e}")

    def get_ip_reputation(self, ip_address):
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT * FROM ip_reputation WHERE ip_address = ?
            ''', (ip_address,))
            
            result = cursor.fetchone()
            conn.close()
            
            if result:
                return {
                    'ip_address': result[0],
                    'last_checked': result[1],
                    'abuse_confidence_score': result[2],
                    'is_whitelisted': result[3],
                    'country_code': result[4],
                    'isp': result[5],
                    'total_reports': result[6]
                }
            return None
        except Exception as e:
            logging.error(f"Błąd pobierania reputacji IP: {e}")
            return None

    def create_alert(self, alert_type, severity, message, event_id=None):
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            cursor.execute('''
                INSERT INTO alerts (timestamp, alert_type, severity, message, event_id)
                VALUES (?, ?, ?, ?, ?)
            ''', (timestamp, alert_type, severity, message, event_id))
            
            conn.commit()
            alert_id = cursor.lastrowid
            conn.close()
            
            logging.warning(f"Utworzono alert #{alert_id}: [{severity}] {message}")
            return alert_id
        except Exception as e:
            logging.error(f"Błąd tworzenia alertu: {e}")
            return None

    def get_statistics(self):
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            
            stats = {}
            
            cursor.execute('SELECT COUNT(*) FROM events')
            stats['total_events'] = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(DISTINCT source_ip) FROM events')
            stats['unique_ips'] = cursor.fetchone()[0]
            
            cursor.execute('SELECT COUNT(*) FROM events WHERE threat_level >= 3')
            stats['high_threat_events'] = cursor.fetchone()[0]
            
            conn.close()
            return stats
        except Exception as e:
            logging.error(f"Błąd pobierania statystyk: {e}")
            return {}
