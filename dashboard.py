import streamlit as st
import sqlite3
import pandas as pd
import time
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta
import json
import os

st.set_page_config(
    page_title="Advanced Honeypot Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

st.markdown("""
<style>
    .main-header {
        font-size: 48px;
        font-weight: bold;
        text-align: center;
        background: linear-gradient(90deg, #667eea 0%, #764ba2 100%);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
        padding: 20px 0;
    }
    .metric-card {
        background-color: #f0f2f6;
        padding: 20px;
        border-radius: 10px;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    .stMetric {
        background-color: #ffffff;
        padding: 15px;
        border-radius: 8px;
        box-shadow: 0 1px 3px rgba(0,0,0,0.12);
    }
</style>
""", unsafe_allow_html=True)

st.markdown('<p class="main-header">🛡️ Advanced Honeypot Security Dashboard</p>', unsafe_allow_html=True)

with st.sidebar:
    st.header("⚙️ Ustawienia")
    
    auto_refresh = st.checkbox("Auto-odświeżanie (30s)", value=False)
    
    st.markdown("---")
    st.header("🔍 Filtry")
    
    time_filter = st.selectbox(
        "Przedział czasowy",
        ["Ostatnia godzina", "Ostatnie 24h", "Ostatni tydzień", "Ostatni miesiąc", "Wszystko"]
    )
    
    st.markdown("---")
    if st.button('🔄 Odśwież dane', use_container_width=True):
        st.rerun()

@st.cache_data(ttl=5)
def load_data():
    try:
        IS_DOCKER = os.environ.get('IS_DOCKER', 'false').lower() == 'true'
        
        if IS_DOCKER:
            db_path = '/app/data/honeypot_events.db'
        else:
            db_path = 'data/honeypot_events.db'
            if not os.path.exists(db_path):
                if os.path.exists('honeypot_events.db'):
                    db_path = 'honeypot_events.db'
        
        if not os.path.exists(db_path):
            return pd.DataFrame()
            
        conn = sqlite3.connect(db_path)
        
        cursor = conn.cursor()
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='events'")
        if not cursor.fetchone():
            conn.close()
            return pd.DataFrame()
            
        query = "SELECT * FROM events ORDER BY id DESC LIMIT 10000"
        df = pd.read_sql_query(query, conn)
        conn.close()
        return df
    except Exception as e:
        print(f"Error loading data: {e}")
        return pd.DataFrame()

def filter_by_time(df, time_filter):
    if time_filter == "Wszystko":
        return df
    
    now = datetime.now()
    if time_filter == "Ostatnia godzina":
        start_time = now - timedelta(hours=1)
    elif time_filter == "Ostatnie 24h":
        start_time = now - timedelta(days=1)
    elif time_filter == "Ostatni tydzień":
        start_time = now - timedelta(weeks=1)
    elif time_filter == "Ostatni miesiąc":
        start_time = now - timedelta(days=30)
    else:
        return df
    
    return df[df['timestamp'] >= start_time]

if auto_refresh:
    time.sleep(30)
    st.rerun()

df = load_data()

if not df.empty:
    df['timestamp'] = pd.to_datetime(df['timestamp'])
    
    df = filter_by_time(df, time_filter)
    
    if df.empty:
        st.warning(f"Brak danych dla wybranego przedziału: {time_filter}")
        st.stop()

    st.markdown("### 📊 Kluczowe Metryki")
    col1, col2, col3, col4 = st.columns(4)
    
    with col1:
        st.metric("🎯 Całkowite zdarzenia", f"{len(df):,}")
    with col2:
        unique_ips = df['source_ip'].nunique()
        st.metric("🌐 Unikalne IP", unique_ips)
    with col3:
        high_threat = len(df[df['threat_level'] >= 3]) if 'threat_level' in df.columns else 0
        st.metric("⚠️ Wysokie zagrożenie", high_threat)
    with col4:
        last_event = df['timestamp'].max()
        minutes_ago = int((datetime.now() - last_event).total_seconds() / 60)
        st.metric("⏱️ Ostatni atak", f"{minutes_ago} min temu")

    st.markdown("---")

    col_chart1, col_chart2 = st.columns(2)

    with col_chart1:
        st.markdown("#### 📈 Ataki w czasie")
        if time_filter == "Ostatnia godzina":
            resample_period = '5min'
        elif time_filter == "Ostatnie 24h":
            resample_period = 'H'
        else:
            resample_period = 'D'
        
        timeline = df.set_index('timestamp').resample(resample_period).size()
        
        fig_timeline = px.line(
            x=timeline.index,
            y=timeline.values,
            labels={'x': 'Czas', 'y': 'Liczba ataków'},
            title=f'Ataki w czasie ({resample_period})'
        )
        fig_timeline.update_traces(line_color='#667eea', line_width=3)
        fig_timeline.update_layout(showlegend=False, height=350)
        st.plotly_chart(fig_timeline, use_container_width=True)

    with col_chart2:
        st.markdown("#### 🎭 Rozkład usług")
        service_counts = df['service_name'].value_counts()
        
        fig_services = px.pie(
            values=service_counts.values,
            names=service_counts.index,
            title='Ataki według usługi',
            color_discrete_sequence=px.colors.qualitative.Set3
        )
        fig_services.update_layout(height=350)
        st.plotly_chart(fig_services, use_container_width=True)

    st.markdown("---")

    col_analysis1, col_analysis2 = st.columns(2)

    with col_analysis1:
        st.markdown("#### 🏆 Top 10 Atakujących IP")
        top_ips = df['source_ip'].value_counts().head(10).reset_index()
        top_ips.columns = ['IP Address', 'Attacks']
        
        fig_top_ips = px.bar(
            top_ips,
            x='Attacks',
            y='IP Address',
            orientation='h',
            title='Najbardziej aktywne IP',
            color='Attacks',
            color_continuous_scale='Reds'
        )
        fig_top_ips.update_layout(height=400, showlegend=False)
        st.plotly_chart(fig_top_ips, use_container_width=True)

    with col_analysis2:
        if 'threat_level' in df.columns:
            st.markdown("#### ⚠️ Poziomy Zagrożenia")
            threat_dist = df['threat_level'].value_counts().sort_index()
            threat_labels = {0: 'Brak', 1: 'Bardzo niski', 2: 'Niski', 3: 'Średni', 4: 'Wysoki', 5: 'Krytyczny'}
            
            fig_threat = go.Figure(data=[go.Bar(
                x=[threat_labels.get(i, f'Level {i}') for i in threat_dist.index],
                y=threat_dist.values,
                marker_color=['#28a745', '#6c757d', '#ffc107', '#fd7e14', '#dc3545', '#6f2c91'][:len(threat_dist)]
            )])
            fig_threat.update_layout(title='Rozkład poziomów zagrożenia', height=400)
            st.plotly_chart(fig_threat, use_container_width=True)

    st.markdown("---")

    st.markdown("### 📋 Szczegółowe Logi")
    
    col_search1, col_search2 = st.columns([3, 1])
    with col_search1:
        search_ip = st.text_input("🔍 Wyszukaj po IP", "")
    with col_search2:
        limit = st.selectbox("Pokaż wierszy", [50, 100, 200, 500], index=0)
    
    display_df = df.copy()
    if search_ip:
        display_df = display_df[display_df['source_ip'].str.contains(search_ip, case=False)]
    
    display_columns = ['timestamp', 'service_name', 'source_ip', 'event_type']
    if 'threat_level' in display_df.columns:
        display_columns.append('threat_level')
    display_columns.append('payload')
    
    display_columns = [col for col in display_columns if col in display_df.columns]
    
    st.dataframe(
        display_df[display_columns].head(limit),
        use_container_width=True,
        height=400
    )
    
    st.markdown("#### 📥 Eksport Danych")
    col_export1, col_export2 = st.columns(2)
    
    with col_export1:
        csv = display_df.head(limit).to_csv(index=False)
        st.download_button(
            label="⬇️ Pobierz CSV",
            data=csv,
            file_name=f"honeypot_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv",
            mime="text/csv"
        )
    
    with col_export2:
        json_data = display_df.head(limit).to_json(orient='records', date_format='iso')
        st.download_button(
            label="⬇️ Pobierz JSON",
            data=json_data,
            file_name=f"honeypot_logs_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json"
        )

else:
    st.warning("⚠️ Brak danych w bazie. Uruchom honeypot i poczekaj na ataki!")
    st.info("💡 Wskazówka: Użyj pliku attacker.py do symulacji ataków")
    
    with st.expander("🚀 Jak rozpocząć"):
        st.code("""
# 1. Uruchom honeypot
python main.py

# 2. W nowym terminalu uruchom dashboard
streamlit run dashboard.py

# 3. Symuluj ataki
python attacker.py
        """, language="bash")
