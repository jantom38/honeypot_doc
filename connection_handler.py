import socket
import logging
import threading
import uuid
import re
import time
from datetime import datetime

class ConnectionHandler:
    def __init__(self, client_socket, client_address, service_config, db_manager, threat_intel=None):
        self.client_socket = client_socket
        self.client_address = client_address
        self.service_config = service_config
        self.db_manager = db_manager
        self.threat_intel = threat_intel
        self.session_id = str(uuid.uuid4())[:8]

    def handle(self):
        raise NotImplementedError("Subklasy muszą implementować metodę handle()")

    def log_activity(self, payload, session_data=None, http_data=None):
        logging.info(f"[{self.service_config['name']}] Dane od {self.client_address[0]}: {payload}")
        
        threat_data = None
        
        if self.threat_intel:
            analysis = self.threat_intel.analyze_event(
                ip_address=self.client_address[0],
                service_name=self.service_config['name'],
                payload=payload,
                session_data=session_data,
                db_manager=self.db_manager
            )
            threat_data = analysis.get('threat_data')
        
        event_id = self.db_manager.log_event(
            service_name=self.service_config['name'],
            source_ip=self.client_address[0],
            source_port=self.client_address[1],
            payload=payload,
            threat_data=threat_data,
            session_data=session_data,
            http_data=http_data
        )
        
        if threat_data and threat_data.get('threat_level', 0) >= 4:
            self.db_manager.create_alert(
                alert_type='high_threat_ip',
                severity='HIGH',
                message=f"Atak z wysokiego ryzyka IP: {self.client_address[0]} ({threat_data.get('attack_type', 'Unknown')})",
                event_id=event_id
            )
        
        return event_id


class SSHHandler(ConnectionHandler):
    def handle(self):
        try:
            banner = self.service_config.get('banner', 'SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n')
            self.client_socket.send(banner.encode())
            
            session_data = {'session_id': self.session_id}
            self.log_activity("CONNECTION_ATTEMPT", session_data=session_data)

            username = None
            password = None
            
            while True:
                data = self.client_socket.recv(1024)
                if not data:
                    break
                
                decoded = data.decode('utf-8', errors='ignore').strip()
                if decoded:
                    lines = decoded.split('\n')
                    if len(lines) >= 1 and not username:
                        username = lines[0].strip()
                    if len(lines) >= 2 and not password:
                        password = lines[1].strip()
                    
                    session_data = {
                        'session_id': self.session_id,
                        'username': username,
                        'password': password
                    }
                    
                    self.log_activity(decoded, session_data=session_data)
                    
        except Exception as e:
            logging.error(f"Błąd w SSHHandler: {e}")
        finally:
            self.client_socket.close()


class HTTPHandler(ConnectionHandler):
    def handle(self):
        try:
            data = self.client_socket.recv(4096)
            if data:
                decoded = data.decode('utf-8', errors='ignore').strip()
                
                lines = decoded.split('\n')
                first_line = lines[0] if lines else ""
                
                http_parts = first_line.split()
                method = http_parts[0] if len(http_parts) > 0 else "GET"
                path = http_parts[1] if len(http_parts) > 1 else "/"
                protocol = http_parts[2] if len(http_parts) > 2 else "HTTP/1.1"
                
                user_agent = None
                for line in lines:
                    if line.lower().startswith('user-agent:'):
                        user_agent = line.split(':', 1)[1].strip()
                        break
                
                http_data = {
                    'method': method,
                    'path': path,
                    'protocol': protocol,
                    'user_agent': user_agent
                }
                
                session_data = {'session_id': self.session_id}
                
                self.log_activity(f"REQUEST: {first_line}", 
                                session_data=session_data, 
                                http_data=http_data)
                
                server_header = self.service_config.get('server_header', 'Server: Apache/2.4.41 (Ubuntu)')
                
                if path in ['/admin', '/wp-admin', '/phpmyadmin']:
                    status = "HTTP/1.1 401 Unauthorized"
                    body = "<html><body><h1>401 Unauthorized</h1></body></html>"
                elif path.endswith('.php'):
                    status = "HTTP/1.1 200 OK"
                    body = "<?php /* Fake PHP */ ?>"
                else:
                    status = "HTTP/1.1 200 OK"
                    body = "<html><body><h1>It works!</h1></body></html>"
                
                response = (
                    f"{status}\r\n"
                    f"{server_header}\r\n"
                    "Content-Type: text/html\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    "Connection: close\r\n\r\n"
                    f"{body}"
                )
                self.client_socket.send(response.encode())
                
        except Exception as e:
            logging.error(f"Błąd w HTTPHandler: {e}")
        finally:
            self.client_socket.close()


class FTPHandler(ConnectionHandler):
    def handle(self):
        try:
            banner = self.service_config.get('banner', '220 FTP Server ready.\r\n')
            self.client_socket.send(banner.encode())
            
            session_data = {'session_id': self.session_id}
            self.log_activity("FTP_CONNECTION", session_data=session_data)
            
            username = None
            authenticated = False
            
            while True:
                data = self.client_socket.recv(1024)
                if not data:
                    break
                
                decoded = data.decode('utf-8', errors='ignore').strip()
                if not decoded:
                    continue
                
                command = decoded.upper().split()[0] if decoded else ""
                
                if command == "USER":
                    username = decoded.split(maxsplit=1)[1] if len(decoded.split()) > 1 else "unknown"
                    session_data['username'] = username
                    self.log_activity(decoded, session_data=session_data)
                    
                    time.sleep(1.0)
                    self.client_socket.send(b"331 Password required.\r\n")
                    
                elif command == "PASS":
                    password = decoded.split(maxsplit=1)[1] if len(decoded.split()) > 1 else "unknown"
                    session_data['password'] = password
                    self.log_activity(decoded, session_data=session_data)
                    
                    time.sleep(2.0)
                    
                    if username == "admin" and password == "admin":
                        authenticated = True
                        self.client_socket.send(b"230 User logged in.\r\n")
                    else:
                        self.client_socket.send(b"530 Login incorrect.\r\n")
                
                elif command == "SYST":
                    self.client_socket.send(b"215 UNIX Type: L8\r\n")
                    
                elif command == "PWD":
                    if authenticated:
                        self.client_socket.send(b"257 \"/\" is the current directory\r\n")
                    else:
                        self.client_socket.send(b"530 Please login with USER and PASS.\r\n")
                
                elif command == "TYPE":
                    self.client_socket.send(b"200 Type set to I.\r\n")

                elif command == "PASV":
                    self.client_socket.send(b"227 Entering Passive Mode (127,0,0,1,200,100).\r\n")
                    
                elif command == "LIST":
                    if authenticated:
                        self.log_activity("LIST command received (Fake Success)", session_data=session_data)
                        self.client_socket.send(b"150 Opening ASCII mode data connection for file list\r\n")
                    else:
                        self.client_socket.send(b"530 Please login with USER and PASS.\r\n")

                elif command == "QUIT":
                    self.log_activity(decoded, session_data=session_data)
                    self.client_socket.send(b"221 Goodbye.\r\n")
                    break
                    
                else:
                    self.log_activity(decoded, session_data=session_data)
                    self.client_socket.send(b"502 Command not implemented.\r\n")
                    
        except Exception as e:
            logging.error(f"Błąd w FTPHandler: {e}")
        finally:
            self.client_socket.close()


class TelnetHandler(ConnectionHandler):
    def handle(self):
        try:
            banner = self.service_config.get('banner', 'Ubuntu 20.04 LTS\r\nlogin: ')
            self.client_socket.send(banner.encode())
            
            session_data = {'session_id': self.session_id}
            self.log_activity("TELNET_CONNECTION", session_data=session_data)
            
            username = None
            password = None
            
            while not username or not password:
                data = self.client_socket.recv(1024)
                if not data: return
                
                decoded = data.decode('utf-8', errors='ignore').strip()
                if not decoded: continue
                
                if not username:
                    username = decoded
                    session_data['username'] = username
                    self.log_activity(f"Username: {decoded}", session_data=session_data)
                    self.client_socket.send(b"Password: ")
                elif not password:
                    password = decoded
                    session_data['password'] = password
                    self.log_activity(f"Password: {decoded}", session_data=session_data)
                    
                    if username == "admin" and password == "admin":
                        welcome_msg = (
                            b"\r\nWelcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-88-generic x86_64)\r\n\r\n"
                            b" * Documentation:  https://help.ubuntu.com\r\n"
                            b" * Management:     https://landscape.canonical.com\r\n"
                            b" * Support:        https://ubuntu.com/advantage\r\n\r\n"
                            b"Last login: " + datetime.now().strftime("%a %b %d %H:%M:%S %Y").encode() + b" from 192.168.1.10\r\n"
                        )
                        self.client_socket.send(welcome_msg)
                        self._fake_shell(session_data)
                        return
                    else:
                        self.client_socket.send(b"\r\nLogin incorrect\r\nlogin: ")
                        username = None
                        password = None
                        
        except Exception as e:
            logging.error(f"Błąd w TelnetHandler: {e}")
        finally:
            self.client_socket.close()

    def _fake_shell(self, session_data):
        prompt = b"admin@ubuntu:~$ "
        self.client_socket.send(prompt)
        
        while True:
            data = self.client_socket.recv(1024)
            if not data: break
            
            cmd = data.decode('utf-8', errors='ignore').strip()
            
            if not cmd:
                self.client_socket.send(prompt)
                continue
                
            session_data['command'] = cmd
            self.log_activity(f"SHELL: {cmd}", session_data=session_data)
            
            response = b""
            if cmd == "ls":
                response = b"Documents  Downloads  Pictures  secret_passwords.txt  backup.sql\r\n"
            elif cmd == "pwd":
                response = b"/home/admin\r\n"
            elif cmd == "whoami":
                response = b"admin\r\n"
            elif cmd == "id":
                response = b"uid=1000(admin) gid=1000(admin) groups=1000(admin),4(adm),24(cdrom),27(sudo)\r\n"
            elif cmd == "cat secret_passwords.txt":
                response = b"root:supersecret123\r\nmysql:dbpass2024\r\n"
            elif cmd == "exit":
                self.client_socket.send(b"logout\r\n")
                break
            else:
                response = f"{cmd}: command not found\r\n".encode()
            
            self.client_socket.send(response + prompt)


class SMTPHandler(ConnectionHandler):
    def handle(self):
        try:
            banner = self.service_config.get('banner', '220 mail.example.com ESMTP Postfix\r\n')
            self.client_socket.send(banner.encode())
            
            session_data = {'session_id': self.session_id}
            self.log_activity("SMTP_CONNECTION", session_data=session_data)
            
            state = 'COMMAND'
            
            while True:
                data = self.client_socket.recv(1024)
                if not data:
                    break
                
                decoded = data.decode('utf-8', errors='ignore').strip()
                if not decoded:
                    continue
                
                self.log_activity(decoded, session_data=session_data)
                
                if state == 'DATA':
                    if decoded == '.':
                        state = 'COMMAND'
                        self.client_socket.send(b"250 Ok\r\n")
                    else:
                        pass
                    continue
                
                command = decoded.upper().split()[0] if decoded else ""
                
                if command == "EHLO" or command == "HELO":
                    response = "250-mail.example.com\r\n250-PIPELINING\r\n250-SIZE 10240000\r\n250 HELP\r\n"
                    self.client_socket.send(response.encode())
                    
                elif command == "MAIL":
                    self.client_socket.send(b"250 Ok\r\n")
                    
                elif command == "RCPT":
                    self.client_socket.send(b"250 Ok\r\n")
                    
                elif command == "DATA":
                    state = 'DATA'
                    self.client_socket.send(b"354 End data with <CR><LF>.<CR><LF>\r\n")
                    
                elif command == "QUIT":
                    self.client_socket.send(b"221 Bye\r\n")
                    break
                    
                else:
                    self.client_socket.send(b"502 Command not implemented\r\n")
                    
        except Exception as e:
            logging.error(f"Błąd w SMTPHandler: {e}")
        finally:
            self.client_socket.close()


class MySQLHandler(ConnectionHandler):
    def handle(self):
        try:
            handshake = (
                b"\x4a\x00\x00\x00\x0a"
                b"5.7.31-0ubuntu0.18.04.1\x00"
                b"\x01\x00\x00\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00"
                b"\x00\x00"
                b"\x21"
                b"\x02\x00"
                b"\x00\x00"
                b"\x00"
                b"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            )
            
            self.client_socket.send(handshake)
            
            session_data = {'session_id': self.session_id}
            self.log_activity("MYSQL_CONNECTION", session_data=session_data)
            
            data = self.client_socket.recv(1024)
            if data:
                try:
                    decoded = data.decode('utf-8', errors='ignore')
                    session_data['username'] = 'extracted_from_packet'
                    self.log_activity(f"MySQL auth attempt: {decoded[:50]}", session_data=session_data)
                except:
                    self.log_activity("MySQL auth attempt (binary data)", session_data=session_data)
                
                error_packet = (
                    b"\x17\x00\x00\x02\xff"
                    b"\x15\x04"
                    b"#28000"
                    b"Access denied"
                )
                self.client_socket.send(error_packet)
                
        except Exception as e:
            logging.error(f"Błąd w MySQLHandler: {e}")
        finally:
            self.client_socket.close()
