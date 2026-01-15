import smtplib
import logging
import requests
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime
from typing import Dict, List
import json

class AlertSystem:
    """System for sending alerts about honeypot events via Email, Discord, and Slack"""
    
    def __init__(self, config: Dict = None):
        self.config = config or {}
        
        # Email config
        self.email_enabled = self.config.get('email', {}).get('enabled', False)
        self.smtp_server = self.config.get('email', {}).get('smtp_server', 'smtp.gmail.com')
        self.smtp_port = self.config.get('email', {}).get('smtp_port', 587)
        self.smtp_username = self.config.get('email', {}).get('from_email', '')
        self.smtp_password = self.config.get('email', {}).get('password', '')
        self.alert_recipients = [self.config.get('email', {}).get('to_email', '')]
        
        # Webhook config
        self.discord_url = self.config.get('webhook', {}).get('discord_url', '')
        self.slack_url = self.config.get('webhook', {}).get('slack_url', '')
        
        # Alert thresholds
        self.thresholds = {
            'threat_score': 50,
            'failed_logins': 5,
            'requests_per_minute': 100
        }
        
        # Track sent alerts to avoid spam
        self.alert_cooldown = {}  # ip -> last_alert_time
        self.cooldown_seconds = 300  # 5 minutes
    
    def should_send_alert(self, ip_address: str, event_type: str, details: Dict) -> bool:
        """Determine if an alert should be sent based on thresholds"""
        
        # Check cooldown
        cooldown_key = f"{ip_address}_{event_type}"
        if cooldown_key in self.alert_cooldown:
            last_alert = self.alert_cooldown[cooldown_key]
            time_diff = (datetime.now() - last_alert).total_seconds()
            if time_diff < self.cooldown_seconds:
                return False
        
        # Check if event is critical
        critical_events = [
            'malicious_command',
            'sql_injection',
            'xss_attack',
            'brute_force',
            'port_scan',
            'high_threat_ip'
        ]
        
        if any(critical in event_type.lower() for critical in critical_events):
            return True
        
        # Check threat score
        if 'threat_score' in details:
            if details['threat_score'] >= self.thresholds['threat_score']:
                return True
        
        return False
    
    def send_alert(self, event_type: str, ip_address: str, details: Dict):
        """Send alert about security event via all enabled channels"""
        
        if not self.should_send_alert(ip_address, event_type, details):
            return
        
        # Update cooldown
        cooldown_key = f"{ip_address}_{event_type}"
        self.alert_cooldown[cooldown_key] = datetime.now()
        
        # Send via Webhooks (Discord/Slack) - Fast & Modern
        if self.discord_url:
            self._send_discord_alert(event_type, ip_address, details)
            
        if self.slack_url:
            self._send_slack_alert(event_type, ip_address, details)
            
        # Send via Email - Traditional
        if self.email_enabled and self.alert_recipients:
            self._send_email_alert(event_type, ip_address, details)
        
        logging.warning(f"ALERT SENT: {event_type} from {ip_address}")

    def _send_discord_alert(self, event_type: str, ip_address: str, details: Dict):
        """Send alert to Discord Webhook"""
        try:
            threat_level = details.get('threat_level', 0)
            color = 16711680 if threat_level >= 4 else 16753920 # Red or Orange
            
            embed = {
                "title": f"🚨 Honeypot Alert: {event_type}",
                "description": f"Wykryto podejrzaną aktywność z adresu **{ip_address}**",
                "color": color,
                "fields": [
                    {"name": "IP Address", "value": ip_address, "inline": True},
                    {"name": "Service", "value": details.get('service', 'Unknown'), "inline": True},
                    {"name": "Threat Level", "value": str(threat_level), "inline": True},
                    {"name": "Location", "value": f"{details.get('country', 'Unknown')}, {details.get('city', 'Unknown')}", "inline": True},
                    {"name": "Payload", "value": f"```{str(details.get('payload', ''))[:100]}```", "inline": False}
                ],
                "footer": {"text": f"Honeypot System • {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"}
            }
            
            payload = {"embeds": [embed]}
            requests.post(self.discord_url, json=payload, timeout=5)
            
        except Exception as e:
            logging.error(f"Failed to send Discord alert: {e}")

    def _send_slack_alert(self, event_type: str, ip_address: str, details: Dict):
        """Send alert to Slack Webhook"""
        try:
            payload = {
                "text": f"🚨 *Honeypot Alert: {event_type}*\nSuspicious activity detected from `{ip_address}`",
                "attachments": [
                    {
                        "color": "#ff0000",
                        "fields": [
                            {"title": "Service", "value": details.get('service', 'Unknown'), "short": True},
                            {"title": "Location", "value": f"{details.get('country', 'Unknown')}", "short": True},
                            {"title": "Payload", "value": str(details.get('payload', ''))[:200], "short": False}
                        ]
                    }
                ]
            }
            requests.post(self.slack_url, json=payload, timeout=5)
        except Exception as e:
            logging.error(f"Failed to send Slack alert: {e}")

    def _send_email_alert(self, event_type: str, ip_address: str, details: Dict):
        """Send email alert"""
        try:
            msg = MIMEMultipart('alternative')
            msg['Subject'] = f"[Honeypot Alert] {event_type} from {ip_address}"
            msg['From'] = self.smtp_username
            msg['To'] = ', '.join(self.alert_recipients)
            
            text_body = f"""
Honeypot Security Alert
========================
Event Type: {event_type}
IP Address: {ip_address}
Timestamp: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}

Details:
{json.dumps(details, indent=2)}
            """
            
            msg.attach(MIMEText(text_body, 'plain'))
            
            with smtplib.SMTP(self.smtp_server, self.smtp_port) as server:
                server.starttls()
                server.login(self.smtp_username, self.smtp_password)
                server.send_message(msg)
            
        except Exception as e:
            logging.error(f"Failed to send email alert: {e}")
