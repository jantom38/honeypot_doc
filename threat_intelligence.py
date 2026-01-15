import requests
import logging
import json
from datetime import datetime, timedelta

class ThreatIntelligence:
    """
    Moduł do analizy zagrożeń wykorzystujący:
    - AbuseIPDB dla reputacji IP
    - Lokalne reguły klasyfikacji
    """
    
    def __init__(self, config):
        self.config = config
        self.abuseipdb_api_key = config.get('abuseipdb_api_key')
        self.cache_timeout = config.get('cache_timeout_hours', 24)
    
    def check_abuseipdb(self, ip_address):
        if not self.abuseipdb_api_key:
            logging.debug("Brak klucza API AbuseIPDB - pomijam sprawdzanie")
            return None
        
        if ip_address in ['127.0.0.1', 'localhost'] or ip_address.startswith('192.168.') or ip_address.startswith('10.'):
            return None
        
        try:
            url = 'https://api.abuseipdb.com/api/v2/check'
            headers = {
                'Accept': 'application/json',
                'Key': self.abuseipdb_api_key
            }
            params = {
                'ipAddress': ip_address,
                'maxAgeInDays': '90',
                'verbose': ''
            }
            
            response = requests.get(url, headers=headers, params=params, timeout=5)
            
            if response.status_code == 200:
                data = response.json()['data']
                
                abuse_score = data.get('abuseConfidenceScore', 0)
                total_reports = data.get('totalReports', 0)
                
                threat_level = self._calculate_threat_level(abuse_score, total_reports)
                
                return {
                    'abuse_confidence_score': abuse_score,
                    'total_reports': total_reports,
                    'is_malicious': 1 if abuse_score > 50 else 0,
                    'threat_level': threat_level,
                    'isp': data.get('isp'),
                    'domain': data.get('domain'),
                    'country_code': data.get('countryCode')
                }
            else:
                logging.warning(f"AbuseIPDB API error: {response.status_code}")
                
        except Exception as e:
            logging.error(f"Błąd sprawdzania AbuseIPDB dla {ip_address}: {e}")
        
        return None
    
    def _calculate_threat_level(self, abuse_score, total_reports):
        if abuse_score == 0 and total_reports == 0:
            return 0
        elif abuse_score < 25:
            return 1
        elif abuse_score < 50:
            return 2
        elif abuse_score < 75:
            return 3
        elif abuse_score < 90:
            return 4
        else:
            return 5
    
    def classify_attack(self, service_name, payload, session_data=None):
        attack_type = "Unknown"
        attack_category = "Reconnaissance"
        
        if service_name.lower() in ['fake ssh', 'ssh']:
            if session_data and session_data.get('username'):
                attack_type = "Brute Force Login"
                attack_category = "Credential Attack"
            else:
                attack_type = "SSH Probe"
                attack_category = "Reconnaissance"
        
        elif service_name.lower() in ['fake http', 'http']:
            payload_lower = payload.lower() if payload else ""
            
            if any(x in payload_lower for x in ['admin', 'phpmyadmin', 'wp-admin', 'login']):
                attack_type = "Admin Panel Scan"
                attack_category = "Web Vulnerability Scan"
            elif any(x in payload_lower for x in ['sql', 'select', 'union', 'drop']):
                attack_type = "SQL Injection Attempt"
                attack_category = "Injection Attack"
            elif any(x in payload_lower for x in ['<script', 'javascript:', 'onerror=']):
                attack_type = "XSS Attempt"
                attack_category = "Injection Attack"
            elif any(x in payload_lower for x in ['../../../', '..\\..\\', 'etc/passwd']):
                attack_type = "Path Traversal"
                attack_category = "File System Attack"
            elif any(x in payload_lower for x in ['.php', '.asp', '.jsp', 'shell']):
                attack_type = "Backdoor/Shell Upload"
                attack_category = "Malware"
            else:
                attack_type = "HTTP Probe"
                attack_category = "Reconnaissance"
        
        elif service_name.lower() in ['fake ftp', 'ftp']:
            if session_data and session_data.get('username'):
                attack_type = "FTP Brute Force"
                attack_category = "Credential Attack"
            else:
                attack_type = "FTP Probe"
                attack_category = "Reconnaissance"
        
        elif service_name.lower() in ['fake telnet', 'telnet']:
            attack_type = "Telnet Brute Force"
            attack_category = "Credential Attack"
        
        elif service_name.lower() in ['fake smtp', 'smtp']:
            if 'spam' in payload.lower() if payload else False:
                attack_type = "Spam Relay Attempt"
                attack_category = "Abuse"
            else:
                attack_type = "SMTP Probe"
                attack_category = "Reconnaissance"
        
        elif service_name.lower() in ['fake mysql', 'mysql']:
            attack_type = "Database Brute Force"
            attack_category = "Credential Attack"
        
        return {
            'attack_type': attack_type,
            'attack_category': attack_category
        }
    
    def analyze_event(self, ip_address, service_name, payload, session_data=None, db_manager=None):
        result = {
            'threat_data': None,
            'classification': None
        }
        
        cached_reputation = None
        if db_manager:
            cached_reputation = db_manager.get_ip_reputation(ip_address)
        
        if cached_reputation:
            try:
                last_checked = datetime.strptime(cached_reputation['last_checked'], '%Y-%m-%d %H:%M:%S')
                age = datetime.now() - last_checked
                
                if age < timedelta(hours=self.cache_timeout):
                    result['threat_data'] = {
                        'abuse_confidence_score': cached_reputation['abuse_confidence_score'],
                        'threat_level': self._calculate_threat_level(
                            cached_reputation['abuse_confidence_score'],
                            cached_reputation['total_reports']
                        ),
                        'is_malicious': 1 if cached_reputation['abuse_confidence_score'] > 50 else 0,
                        'total_reports': cached_reputation['total_reports']
                    }
                    logging.debug(f"Użyto cached reputation dla {ip_address}")
                else:
                    threat_data = self.check_abuseipdb(ip_address)
                    if threat_data and db_manager:
                        db_manager.update_ip_reputation(ip_address, threat_data)
                        result['threat_data'] = threat_data
            except Exception as e:
                logging.error(f"Błąd przetwarzania cache: {e}")
        else:
            threat_data = self.check_abuseipdb(ip_address)
            if threat_data and db_manager:
                db_manager.update_ip_reputation(ip_address, threat_data)
            result['threat_data'] = threat_data
        
        classification = self.classify_attack(service_name, payload, session_data)
        result['classification'] = classification
        
        if result['threat_data']:
            result['threat_data'].update(classification)
        else:
            result['threat_data'] = classification.copy()
            result['threat_data']['threat_level'] = 1
        
        return result
