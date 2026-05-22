# dashboard.py
import streamlit as st
import sqlite3
import json
import os
import pandas as pd
from core.remediation import get_remediations_for_headers
import database

DB_FILE = "archon_data.db"

# Page config
st.set_page_config(
    page_title="Archon Command Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for rich aesthetics and dark/neon theme styling
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&display=swap');
    
    html, body, [class*="css"] {
        font-family: 'Outfit', sans-serif;
    }
    
    .main {
        background-color: #07090e;
    }
    
    /* Neon border panel */
    div[data-testid="stMetric"] {
        background: rgba(14, 20, 35, 0.65);
        border: 1px solid rgba(0, 255, 208, 0.2);
        box-shadow: 0 4px 15px rgba(0, 255, 208, 0.05);
        border-radius: 12px;
        padding: 15px 20px;
        transition: all 0.3s ease;
    }
    
    div[data-testid="stMetric"]:hover {
        border-color: rgba(0, 255, 208, 0.6);
        box-shadow: 0 4px 20px rgba(0, 255, 208, 0.15);
        transform: translateY(-2px);
    }

    /* Streamlit sidebar overrides */
    section[data-testid="stSidebar"] {
        background-color: #0b0f19;
        border-right: 1px solid rgba(255, 255, 255, 0.05);
    }
    
    .stAlert {
        border-radius: 10px;
        background-color: rgba(14, 20, 35, 0.85);
        border: 1px solid rgba(255, 75, 75, 0.2);
    }
</style>
""", unsafe_allow_html=True)

def load_data():
    if not os.path.exists(DB_FILE):
        return []
    with sqlite3.connect(DB_FILE) as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT target, connector, data, timestamp FROM scan_findings")
        rows = cursor.fetchall()
    return rows

def parse_findings(rows):
    findings = {}
    for target, connector, data_str, timestamp in rows:
        try:
            data = json.loads(data_str)
        except Exception:
            data = data_str

        if target not in findings:
            findings[target] = {"scout": None, "eyes": None, "shodan": None, "censys": None}
        
        if connector == "ArchonScout":
            findings[target]["scout"] = data
        elif connector == "ArchonEyes":
            findings[target]["eyes"] = data
        elif connector == "Shodan":
            findings[target]["shodan"] = data
        elif connector == "Censys":
            findings[target]["censys"] = data
    return findings

# Title Block
st.sidebar.title("🛡️ ARCHON SYSTEM")
st.sidebar.markdown("*Command Center v2.0*")
st.sidebar.markdown("---")

menu = st.sidebar.radio(
    "Navigation System",
    ["Overview Dashboard", "Threat Intel Explorer", "Remediation Engine", "Active Alert Console"]
)

# Load data once
rows = load_data()
findings = parse_findings(rows)
alerts = database.get_alerts()

if menu == "Overview Dashboard":
    st.title("🌐 Unified Perimeter Overview")
    st.markdown("Real-time network security parameters and active vulnerability gaps.")
    
    # Calculate KPIs
    total_assets = len(findings)
    total_ports = 0
    total_gaps = 0
    critical_gaps = 0
    
    port_distribution = {}
    
    for target, mods in findings.items():
        if mods["eyes"]:
            ports = mods["eyes"].get("exposed_ports", {})
            for p, svc in ports.items():
                total_ports += 1
                port_distribution[p] = port_distribution.get(p, 0) + 1
            
            gaps = mods["eyes"].get("vulnerabilities_detected", [])
            for g in gaps:
                total_gaps += 1
                if g.get("severity") == "High":
                    critical_gaps += 1

    # Render Cards
    kpi1, kpi2, kpi3, kpi4 = st.columns(4)
    kpi1.metric(label="Tracked Assets", value=total_assets)
    kpi2.metric(label="Exposed Ports", value=total_ports)
    kpi3.metric(label="Total Gaps", value=total_gaps)
    kpi4.metric(label="Critical Remediations", value=critical_gaps)

    st.markdown("### Asset Inventory Status")
    
    # Convert inventory to dataframe
    asset_data = []
    for target, mods in findings.items():
        ports_str = "None Detected"
        status = "Offline"
        gap_cnt = 0
        
        if mods["eyes"]:
            eyes = mods["eyes"]
            status = eyes.get("status", "Offline")
            exposed = list(eyes.get("exposed_ports", {}).keys())
            if exposed:
                ports_str = ", ".join(exposed)
            gap_cnt = len(eyes.get("vulnerabilities_detected", []))
            
        asset_data.append({
            "Target Asset": target,
            "Scan Status": status,
            "Open Ports": ports_str,
            "Security Gaps": gap_cnt
        })
        
    if asset_data:
        df = pd.DataFrame(asset_data)
        st.dataframe(df, use_container_width=True, hide_index=True)
    else:
        st.info("No assets scanned yet. Run standard scan first.")

    # Charts Column Block
    if port_distribution:
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("#### Open Ports Distribution")
            chart_df = pd.DataFrame({
                "Port": list(port_distribution.keys()),
                "Occurrences": list(port_distribution.values())
            })
            st.bar_chart(chart_df.set_index("Port"), color="#00ffd0")
        with col2:
            st.markdown("#### Gap Severity Breakdown")
            high_count = critical_gaps
            med_count = total_gaps - critical_gaps
            sev_df = pd.DataFrame({
                "Severity": ["High", "Medium"],
                "Count": [high_count, med_count]
            })
            st.bar_chart(sev_df.set_index("Severity"), color="#ff4b4b")

elif menu == "Threat Intel Explorer":
    st.title("🔍 Passive Threat Intelligence Explorer")
    st.markdown("Passive lookups aggregated from Shodan and Censys APIs.")
    
    intel_targets = [t for t, m in findings.items() if m["shodan"] or m["censys"]]
    
    if not intel_targets:
        st.info("No passive threat intelligence records stored in the database.")
    else:
        selected_ip = st.selectbox("Select Target IP Address", intel_targets)
        target_mods = findings[selected_ip]
        
        col1, col2 = st.columns(2)
        with col1:
            st.subheader("Shodan Intel")
            shodan = target_mods["shodan"]
            if not shodan:
                st.write("No Shodan records.")
            elif "error" in shodan:
                st.error(f"Shodan Error: {shodan['error']}")
            else:
                st.json(shodan)
        with col2:
            st.subheader("Censys Intel")
            censys = target_mods["censys"]
            if not censys:
                st.write("No Censys records.")
            elif "error" in censys:
                st.error(f"Censys Error: {censys['error']}")
            else:
                st.json(censys)

elif menu == "Remediation Engine":
    st.title("🛠️ Active Defense Remediation Engine")
    st.markdown("Automatically generated web server configurations targeting exposed perimeter gaps.")
    
    # Filter targets with Eyes gaps
    remedy_targets = []
    for target, mods in findings.items():
        if mods["eyes"] and mods["eyes"].get("vulnerabilities_detected"):
            remedy_targets.append(target)
            
    if not remedy_targets:
        st.success("🎉 Zero security gaps found! No remediations required.")
    else:
        target = st.selectbox("Select Vulnerable Asset", remedy_targets)
        vulnerabilities = findings[target]["eyes"]["vulnerabilities_detected"]
        
        # Display identified vulnerabilities
        st.markdown(f"#### Active Gaps on `{target}`")
        for v in vulnerabilities:
            severity = v.get("severity", "Medium")
            threat = v.get("vulnerability", "Unknown")
            desc = v.get("threat_impact", "")
            
            if severity == "High":
                st.error(f"**{threat}** — *{desc}*")
            else:
                st.warning(f"**{threat}** — *{desc}*")
                
        # Generate configs
        missing_headers = [v["vulnerability"].replace("Missing ", "") for v in vulnerabilities]
        configs = get_remediations_for_headers(missing_headers)
        
        st.markdown("#### Hardening Configurations")
        tab1, tab2, tab3 = st.tabs(["Nginx", "Apache", "Caddy"])
        
        with tab1:
            st.code(configs["nginx"], language="nginx")
        with tab2:
            st.code(configs["apache"], language="apache")
        with tab3:
            st.code(configs["caddy"], language="caddy")

elif menu == "Active Alert Console":
    st.title("🚨 Active Alert Console")
    st.markdown("Live notifications triggered by the background SSL & Subdomain Watcher daemon.")
    
    if not alerts:
        st.success("✅ System Secure. No watcher alerts triggered.")
    else:
        for a in alerts:
            alert_type = a["type"]
            target = a["target"]
            message = a["message"]
            timestamp = a["timestamp"]
            
            with st.container():
                st.markdown(f"**[{alert_type}]** `{target}` — *{message}* (Logged: {timestamp})")
                st.markdown("---")
