import streamlit as st
import sqlite3
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta

st.set_page_config(
    page_title="Advanced Statistics",
    page_icon="📊",
    layout="wide"
)

st.title("📊 Advanced Statistics & Analytics")

from db_paths import resolve_db_uri_readonly


@st.cache_data(ttl=60)
def load_data():
    try:
        conn = sqlite3.connect(resolve_db_uri_readonly(), uri=True, timeout=10, check_same_thread=False)
        conn.execute('PRAGMA busy_timeout=5000;')
        query = "SELECT * FROM events ORDER BY timestamp DESC"
        df = pd.read_sql_query(query, conn)
        conn.close()
        return df
    except Exception as e:
        st.error(f"Error loading data: {e}")
        return pd.DataFrame()

df = load_data()

if df.empty:
    st.warning("⚠️ No data available")
    st.stop()

df['timestamp'] = pd.to_datetime(df['timestamp'])

# Time range selector
st.sidebar.header("⚙️ Settings")
time_range = st.sidebar.selectbox(
    "Time Range",
    ["Last Hour", "Last 24 Hours", "Last Week", "Last Month", "All Time"]
)

# Filter data
now = datetime.now()
if time_range == "Last Hour":
    df = df[df['timestamp'] >= now - timedelta(hours=1)]
elif time_range == "Last 24 Hours":
    df = df[df['timestamp'] >= now - timedelta(days=1)]
elif time_range == "Last Week":
    df = df[df['timestamp'] >= now - timedelta(weeks=1)]
elif time_range == "Last Month":
    df = df[df['timestamp'] >= now - timedelta(days=30)]

# Main metrics
col1, col2, col3, col4 = st.columns(4)

with col1:
    st.metric("Total Events", f"{len(df):,}")
with col2:
    st.metric("Unique IPs", df['source_ip'].nunique())
with col3:
    if 'country' in df.columns:
        st.metric("Countries", df['country'].nunique())
with col4:
    if 'threat_level' in df.columns:
        high_threat = len(df[df['threat_level'] >= 3])
        st.metric("High Threats", high_threat)

st.markdown("---")

# Attack patterns over time
st.markdown("### 📈 Attack Patterns Over Time")

# Hourly distribution
df['hour'] = df['timestamp'].dt.hour
hourly_dist = df.groupby('hour').size()

fig_hourly = px.bar(
    x=hourly_dist.index,
    y=hourly_dist.values,
    labels={'x': 'Hour of Day', 'y': 'Number of Attacks'},
    title='Attack Distribution by Hour'
)
fig_hourly.update_traces(marker_color='#667eea')
st.plotly_chart(fig_hourly, use_container_width=True)

st.markdown("---")

# Service analysis
col_serv1, col_serv2 = st.columns(2)

with col_serv1:
    st.markdown("### 🛠️ Service Analysis")
    service_stats = df.groupby('service_name').agg({
        'source_ip': 'count',
        'session_id': 'nunique'
    }).rename(columns={'source_ip': 'Total Events', 'session_id': 'Unique Sessions'})
    
    st.dataframe(service_stats, use_container_width=True)

with col_serv2:
    st.markdown("### 📊 Service Distribution")
    service_counts = df['service_name'].value_counts()
    
    fig_services = px.bar(
        x=service_counts.values,
        y=service_counts.index,
        orientation='h',
        labels={'x': 'Events', 'y': 'Service'},
        color=service_counts.values,
        color_continuous_scale='Viridis'
    )
    st.plotly_chart(fig_services, use_container_width=True)

st.markdown("---")

# Geographic analysis
if 'country' in df.columns and 'latitude' in df.columns:
    st.markdown("### 🌍 Geographic Analysis")
    
    col_geo1, col_geo2 = st.columns(2)
    
    with col_geo1:
        st.markdown("#### Top 20 Countries")
        country_stats = df['country'].value_counts().head(20)
        
        fig_countries = px.bar(
            x=country_stats.values,
            y=country_stats.index,
            orientation='h',
            labels={'x': 'Attacks', 'y': 'Country'},
            color=country_stats.values,
            color_continuous_scale='Reds'
        )
        st.plotly_chart(fig_countries, use_container_width=True)
    
    with col_geo2:
        st.markdown("#### Top 20 Cities")
        if 'city' in df.columns:
            city_stats = df['city'].value_counts().head(20)
            
            fig_cities = px.bar(
                x=city_stats.values,
                y=city_stats.index,
                orientation='h',
                labels={'x': 'Attacks', 'y': 'City'},
                color=city_stats.values,
                color_continuous_scale='Blues'
            )
            st.plotly_chart(fig_cities, use_container_width=True)

st.markdown("---")

# Threat analysis
if 'threat_level' in df.columns:
    st.markdown("### ⚠️ Threat Intelligence")
    
    col_threat1, col_threat2, col_threat3 = st.columns(3)
    
    with col_threat1:
        st.markdown("#### Threat Level Distribution")
        threat_counts = df['threat_level'].value_counts().sort_index()
        
        fig_threat = px.pie(
            values=threat_counts.values,
            names=threat_counts.index,
            title='Threat Levels',
            color_discrete_sequence=px.colors.sequential.Reds
        )
        st.plotly_chart(fig_threat, use_container_width=True)
    
    with col_threat2:
        st.markdown("#### High-Risk IPs")
        high_risk = df[df['threat_level'] >= 3]['source_ip'].value_counts().head(10)
        
        st.dataframe(high_risk, use_container_width=True)
    
    with col_threat3:
        st.markdown("#### Threat Score Over Time")
        if 'threat_score' in df.columns:
            threat_timeline = df.set_index('timestamp')['threat_score'].resample('H').mean()
            
            fig_threat_time = px.line(
                x=threat_timeline.index,
                y=threat_timeline.values,
                labels={'x': 'Time', 'y': 'Average Threat Score'}
            )
            fig_threat_time.update_traces(line_color='#dc3545')
            st.plotly_chart(fig_threat_time, use_container_width=True)

st.markdown("---")

# Payload analysis
st.markdown("### 🔍 Payload Analysis")

if 'payload' in df.columns:
    # Most common payloads
    common_payloads = df['payload'].value_counts().head(20)
    
    st.markdown("#### Most Common Payloads")
    for i, (payload, count) in enumerate(common_payloads.items(), 1):
        with st.expander(f"{i}. {payload[:100]}... ({count} times)"):
            st.code(payload, language='text')

st.markdown("---")

# Activity heatmap
st.markdown("### 🔥 Activity Heatmap")

df['day_of_week'] = df['timestamp'].dt.day_name()
df['hour_of_day'] = df['timestamp'].dt.hour

heatmap_data = df.groupby(['day_of_week', 'hour_of_day']).size().reset_index(name='count')

# Order days correctly
day_order = ['Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday', 'Sunday']
heatmap_pivot = heatmap_data.pivot(index='day_of_week', columns='hour_of_day', values='count')
heatmap_pivot = heatmap_pivot.reindex(day_order)

fig_heatmap = px.imshow(
    heatmap_pivot,
    labels=dict(x="Hour of Day", y="Day of Week", color="Attacks"),
    color_continuous_scale="Reds",
    aspect="auto"
)
st.plotly_chart(fig_heatmap, use_container_width=True)
