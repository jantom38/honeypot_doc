import sqlite3
import json
from datetime import datetime
from typing import List, Dict, Optional
import logging
import os

class SessionReplay:
    """System for recording and replaying attack sessions"""
    
    def __init__(self, db_path=None):
        if db_path is None:
            IS_DOCKER = os.environ.get('IS_DOCKER', 'false').lower() == 'true'
            if IS_DOCKER:
                self.db_path = '/app/data/honeypot_events.db'
            else:
                self.db_path = 'data/honeypot_events.db'
        else:
            self.db_path = db_path
    
    def get_session_details(self, session_id: str) -> Optional[Dict]:
        """Get detailed information about a session"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("""
                SELECT session_id, source_ip, timestamp, timestamp, 
                       service_name, country, city, threat_level
                FROM events 
                WHERE session_id = ?
                ORDER BY timestamp ASC
                LIMIT 1
            """, (session_id,))
            
            session_info = cursor.fetchone()
            if not session_info:
                return None
            
            cursor.execute("""
                SELECT timestamp, attack_type, payload, command_executed
                FROM events
                WHERE session_id = ?
                ORDER BY timestamp ASC
            """, (session_id,))
            
            events = cursor.fetchall()
            
            conn.close()
            
            return {
                'session_id': session_info[0],
                'source_ip': session_info[1],
                'start_time': session_info[2],
                'end_time': session_info[3],
                'service': session_info[4],
                'country': session_info[5],
                'city': session_info[6],
                'threat_level': session_info[7],
                'events': [
                    {
                        'timestamp': e[0],
                        'event_type': e[1],
                        'payload': e[2],
                        'details': e[3]
                    }
                    for e in events
                ]
            }
        except Exception as e:
            logging.error(f"Error getting session details: {e}")
            return None
    
    def get_all_sessions(self, limit: int = 100, service: str = None) -> List[Dict]:
        """Get list of all sessions"""
        try:
            if not os.path.exists(self.db_path):
                return []

            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='events'")
            if not cursor.fetchone():
                conn.close()
                return []

            query = """
                SELECT DISTINCT session_id, source_ip, MIN(timestamp) as start_time,
                       service_name, country, threat_level, COUNT(*) as event_count
                FROM events
                WHERE session_id IS NOT NULL
            """
            
            params = []
            if service:
                query += " AND service_name = ?"
                params.append(service)
            
            query += """
                GROUP BY session_id
                ORDER BY start_time DESC
                LIMIT ?
            """
            params.append(limit)
            
            cursor.execute(query, params)
            sessions = cursor.fetchall()
            
            conn.close()
            
            return [
                {
                    'session_id': s[0],
                    'source_ip': s[1],
                    'start_time': s[2],
                    'service': s[3],
                    'country': s[4],
                    'threat_level': s[5],
                    'event_count': s[6]
                }
                for s in sessions
            ]
        except Exception as e:
            logging.error(f"Error getting sessions: {e}")
            return []
    
    def replay_session(self, session_id: str, speed: float = 1.0):
        """
        Replay a session with timing information
        
        Args:
            session_id: Session ID to replay
            speed: Playback speed multiplier (1.0 = real-time, 2.0 = 2x speed)
        
        Yields:
            Dict with event information and timing
        """
        session = self.get_session_details(session_id)
        if not session:
            return
        
        events = session['events']
        if not events:
            return
        
        start_time = datetime.fromisoformat(events[0]['timestamp'])
        
        for i, event in enumerate(events):
            event_time = datetime.fromisoformat(event['timestamp'])
            
            if i > 0:
                prev_time = datetime.fromisoformat(events[i-1]['timestamp'])
                delay = (event_time - prev_time).total_seconds() / speed
            else:
                delay = 0
            
            yield {
                'event': event,
                'delay': delay,
                'elapsed_time': (event_time - start_time).total_seconds(),
                'index': i + 1,
                'total': len(events)
            }
    
    def export_session_to_text(self, session_id: str) -> str:
        """Export session as readable text"""
        session = self.get_session_details(session_id)
        if not session:
            return "Session not found"
        
        output = []
        output.append("=" * 80)
        output.append(f"SESSION REPLAY: {session_id}")
        output.append("=" * 80)
        output.append(f"Source IP: {session['source_ip']}")
        output.append(f"Service: {session['service']}")
        output.append(f"Location: {session['city']}, {session['country']}")
        output.append(f"Threat Level: {session['threat_level']}")
        output.append(f"Start Time: {session['start_time']}")
        output.append(f"End Time: {session['end_time']}")
        output.append(f"Total Events: {len(session['events'])}")
        output.append("=" * 80)
        output.append("")
        
        for i, event in enumerate(session['events'], 1):
            output.append(f"[{i}] {event['timestamp']} - {event['event_type']}")
            if event['payload']:
                output.append(f"    Payload: {event['payload'][:200]}")
            if event['details']:
                for key, value in event['details'].items():
                    output.append(f"    {key}: {value}")
            output.append("")
        
        return "\n".join(output)
    
    def get_session_statistics(self, session_id: str) -> Dict:
        """Get statistics for a specific session"""
        session = self.get_session_details(session_id)
        if not session:
            return {}
        
        events = session['events']
        
        event_types = {}
        total_payload_size = 0
        
        for event in events:
            event_type = event['event_type']
            event_types[event_type] = event_types.get(event_type, 0) + 1
            
            if event['payload']:
                total_payload_size += len(str(event['payload']))
        
        start = datetime.fromisoformat(events[0]['timestamp'])
        end = datetime.fromisoformat(events[-1]['timestamp'])
        duration = (end - start).total_seconds()
        
        return {
            'session_id': session_id,
            'total_events': len(events),
            'duration_seconds': duration,
            'event_types': event_types,
            'total_payload_size': total_payload_size,
            'events_per_minute': len(events) / (duration / 60) if duration > 0 else 0
        }
