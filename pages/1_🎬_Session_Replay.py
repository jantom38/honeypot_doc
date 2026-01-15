import streamlit as st
import sqlite3
import pandas as pd
import sys
import os
import time

# Add parent directory to path to import session_replay + db resolver
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from session_replay import SessionReplay
from db_paths import resolve_db_path

st.set_page_config(
    page_title="Session Replay",
    page_icon="🎬",
    layout="wide"
)

st.title("🎬 Session Replay & Analysis")

st.markdown("""
Przeglądaj i odtwarzaj szczegółowe sesje ataków. Każda sesja zawiera kompletną sekwencję 
zdarzeń z informacjami o czasie, payloadach i działaniach atakującego.
""")

# Initialize session replay
replay = SessionReplay(db_path=resolve_db_path())

# Sidebar - Session selection
with st.sidebar:
    st.header("🔍 Wybierz sesję")
    
    service_filter = st.selectbox(
        "Filtruj po usłudze",
        ["Wszystkie", "SSH", "HTTP", "FTP", "Telnet", "SMTP", "MySQL"]
    )
    
    limit = st.slider("Liczba sesji", 10, 500, 100)

# Get sessions
service = None if service_filter == "Wszystkie" else service_filter
sessions = replay.get_all_sessions(limit=limit, service=service)

if not sessions:
    st.warning("⚠️ Brak sesji w bazie danych")
    st.info("💡 Uruchom honeypot i poczekaj na połączenia")
    st.stop()

# Display sessions table
st.markdown("### 📋 Lista Sesji")

sessions_df = pd.DataFrame(sessions)
sessions_df['start_time'] = pd.to_datetime(sessions_df['start_time'])

# Add color coding for threat levels
def threat_color(level):
    if level >= 4:
        return '🔴'
    elif level >= 3:
        return '🟠'
    elif level >= 2:
        return '🟡'
    else:
        return '🟢'

if 'threat_level' in sessions_df.columns:
    sessions_df['threat'] = sessions_df['threat_level'].apply(threat_color)

# Display table
st.dataframe(
    sessions_df[['threat', 'session_id', 'source_ip', 'country', 'service', 'event_count', 'start_time']],
    use_container_width=True,
    height=400
)

# Session selection
st.markdown("---")
st.markdown("### 🎯 Szczegóły Sesji")

col1, col2 = st.columns([3, 1])

with col1:
    selected_session_id = st.selectbox(
        "Wybierz sesję do analizy",
        options=[s['session_id'] for s in sessions],
        format_func=lambda x: f"{x} - {[s for s in sessions if s['session_id'] == x][0]['source_ip']}"
    )

with col2:
    if st.button("🔄 Odśwież", use_container_width=True):
        st.rerun()

if selected_session_id:
    session = replay.get_session_details(selected_session_id)
    
    if session:
        # Session header
        col_info1, col_info2, col_info3, col_info4 = st.columns(4)
        
        with col_info1:
            st.metric("🌐 Source IP", session['source_ip'])
        with col_info2:
            st.metric("🛠️ Service", session['service'])
        with col_info3:
            st.metric("🌍 Location", f"{session['city']}, {session['country']}")
        with col_info4:
            threat_emoji = threat_color(session['threat_level'])
            st.metric("⚠️ Threat Level", f"{threat_emoji} {session['threat_level']}/5")
        
        st.markdown("---")
        
        # Session statistics
        stats = replay.get_session_statistics(selected_session_id)
        
        col_stat1, col_stat2, col_stat3, col_stat4 = st.columns(4)
        
        with col_stat1:
            st.metric("📊 Total Events", stats['total_events'])
        with col_stat2:
            st.metric("⏱️ Duration", f"{stats['duration_seconds']:.1f}s")
        with col_stat3:
            st.metric("📈 Events/min", f"{stats['events_per_minute']:.1f}")
        with col_stat4:
            st.metric("💾 Payload Size", f"{stats['total_payload_size']} bytes")
        
        st.markdown("---")
        
        # Tabs for different views
        tab1, tab2, tab3 = st.tabs(["🎬 Replay", "📊 Analysis", "📄 Export"])
        
        with tab1:
            st.markdown("### 🎬 Session Replay")
            
            col_replay1, col_replay2 = st.columns([3, 1])
            
            with col_replay1:
                speed = st.slider("Playback Speed", 0.5, 10.0, 1.0, 0.5)
            
            with col_replay2:
                auto_play = st.checkbox("Auto-play", value=False)
            
            if st.button("▶️ Start Replay", use_container_width=True) or auto_play:
                st.markdown("---")
                
                progress_bar = st.progress(0)
                status_text = st.empty()
                event_display = st.empty()
                
                for replay_data in replay.replay_session(selected_session_id, speed=speed):
                    event = replay_data['event']
                    index = replay_data['index']
                    total = replay_data['total']
                    delay = replay_data['delay']
                    
                    # Update progress
                    progress = index / total
                    progress_bar.progress(progress)
                    status_text.text(f"Event {index}/{total} - Elapsed: {replay_data['elapsed_time']:.1f}s")
                    
                    # Display event
                    with event_display.container():
                        st.markdown(f"**[{event['timestamp']}] {event['event_type']}**")
                        
                        if event['payload']:
                            st.code(event['payload'][:500], language='text')
                        
                        if event['details']:
                            with st.expander("Details"):
                                st.json(event['details'])
                    
                    # Wait for next event
                    if delay > 0 and index < total:
                        time.sleep(min(delay, 5))  # Cap at 5 seconds
                
                st.success("✅ Replay completed!")
            else:
                st.info("👆 Kliknij 'Start Replay' aby odtworzyć sesję")
        
        with tab2:
            st.markdown("### 📊 Session Analysis")
            
            # Event type distribution
            if stats['event_types']:
                st.markdown("#### Event Types")
                event_df = pd.DataFrame(
                    list(stats['event_types'].items()),
                    columns=['Event Type', 'Count']
                )
                st.bar_chart(event_df.set_index('Event Type'))
            
            st.markdown("---")
            
            # Timeline
            st.markdown("#### Event Timeline")
            events_list = []
            for i, event in enumerate(session['events']):
                events_list.append({
                    'Index': i + 1,
                    'Time': event['timestamp'],
                    'Type': event['event_type'],
                    'Payload': event['payload'][:100] if event['payload'] else ''
                })
            
            timeline_df = pd.DataFrame(events_list)
            st.dataframe(timeline_df, use_container_width=True, height=400)
        
        with tab3:
            st.markdown("### 📄 Export Options")
            
            # Text export
            text_export = replay.export_session_to_text(selected_session_id)
            
            col_exp1, col_exp2 = st.columns(2)
            
            with col_exp1:
                st.download_button(
                    label="⬇️ Download as Text",
                    data=text_export,
                    file_name=f"session_{selected_session_id}.txt",
                    mime="text/plain",
                    use_container_width=True
                )
            
            with col_exp2:
                import json
                json_export = json.dumps(session, indent=2)
                st.download_button(
                    label="⬇️ Download as JSON",
                    data=json_export,
                    file_name=f"session_{selected_session_id}.json",
                    mime="application/json",
                    use_container_width=True
                )
            
            st.markdown("---")
            st.markdown("#### Preview")
            with st.expander("Show full session text"):
                st.text(text_export)
    else:
        st.error("❌ Could not load session details")
