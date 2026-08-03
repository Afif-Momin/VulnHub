import platform
import requests
import pandas as pd
import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
from typing import Dict, Any, List

# Page Setup & Aesthetic Styling
st.set_page_config(
    page_title="Vulnerability Assessment Dashboard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom Premium CSS for layout alignment
st.markdown("""
<style>
    .main {
        background-color: #0F172A;
        color: #F8FAFC;
    }
    .stTabs [data-baseweb="tab-list"] {
        gap: 24px;
    }
    .stTabs [data-baseweb="tab"] {
        height: 50px;
        white-space: pre-wrap;
        background-color: #1E293B;
        border-radius: 4px;
        color: #94A3B8;
        padding-left: 20px;
        padding-right: 20px;
        border: 1px solid #334155;
    }
    .stTabs [aria-selected="true"] {
        background-color: #2563EB;
        color: white;
        border: 1px solid #3B82F6;
    }
</style>
""", unsafe_allow_html=True)

# App Title & Subtitle
st.title("🛡️ Centralized Vulnerability Dashboard")
st.markdown("---")

# Settings & Connection sidebar
st.sidebar.header("⚙️ Settings & Configuration")
backend_url = st.sidebar.text_input("Backend API Server", "http://localhost:8000")

# Fetch Backend Health
@st.cache_data(ttl=3)
def get_health(url: str) -> Dict[str, Any]:
    try:
        response = requests.get(f"{url}/health", timeout=2)
        if response.status_code == 200:
            return response.json()
    except Exception:
        pass
    return {"status": "offline"}

health_data = get_health(backend_url)
is_online = health_data.get("status") == "healthy"

if is_online:
    st.sidebar.success("🟢 Connected to Backend")
else:
    st.sidebar.error("🔴 Backend Offline (Start FastAPI server)")

# Diagnose scanner installations
st.sidebar.subheader("🔍 Local Scanner Diagnostics")
system_os = platform.system()
st.sidebar.caption(f"Host OS: **{system_os}**")

if is_online:
    scanners = health_data.get("scanners", {})
    
    # Nmap Info
    nmap_info = scanners.get("nmap", {})
    if nmap_info.get("available", False):
        st.sidebar.markdown("✔️ **Nmap:** Available")
    else:
        st.sidebar.markdown("❌ **Nmap:** Not Found")
        if system_os == "Windows":
            st.sidebar.info("👉 Install from [nmap.org](https://nmap.org/download.html) and add to system PATH.")
        else:
            st.sidebar.info("👉 Install with: `sudo apt install nmap`")

    # ZAP Info
    zap_info = scanners.get("zap", {})
    st.sidebar.markdown("⚠️ **OWASP ZAP:** API Agent Ready")
    st.sidebar.caption("Requires local ZAP daemon running in API Mode.")
    
    # OpenVAS Info
    openvas_info = scanners.get("openvas", {})
    if system_os == "Windows":
        st.sidebar.warning("ℹ️ **OpenVAS (Local):** Not Supported")
        st.sidebar.caption("OpenVAS is Linux-only. Use connection details below to query remote GVM in Docker/WSL2.")
    else:
        st.sidebar.markdown("✔️ **OpenVAS:** Ready")
else:
    st.sidebar.caption("Unable to load scanner states.")

# Sidebar Report Downloads
st.sidebar.markdown("---")
st.sidebar.subheader("📥 Export Scan Reports")
if is_online:
    # Technical PDF Download
    try:
        pdf_tech_response = requests.get(f"{backend_url}/reports/pdf?mode=technical", timeout=5)
        if pdf_tech_response.status_code == 200:
            st.sidebar.download_button(
                label="📄 Download Technical PDF",
                data=pdf_tech_response.content,
                file_name="vulnerability_technical_report.pdf",
                mime="application/pdf"
            )
    except Exception:
        st.sidebar.caption("Could not load Technical PDF button")

    # Executive PDF Download
    try:
        pdf_exec_response = requests.get(f"{backend_url}/reports/pdf?mode=executive", timeout=5)
        if pdf_exec_response.status_code == 200:
            st.sidebar.download_button(
                label="📊 Download Executive PDF",
                data=pdf_exec_response.content,
                file_name="vulnerability_executive_summary.pdf",
                mime="application/pdf"
            )
    except Exception:
        st.sidebar.caption("Could not load Executive PDF button")

    # JSON Report Download
    try:
        json_response = requests.get(f"{backend_url}/reports/json", timeout=5)
        if json_response.status_code == 200:
            import json
            st.sidebar.download_button(
                label="⚙️ Download Report JSON",
                data=json.dumps(json_response.json(), indent=2),
                file_name="vulnerability_report.json",
                mime="application/json"
            )
    except Exception:
        st.sidebar.caption("Could not load JSON report button")
else:
    st.sidebar.caption("Connect backend to enable report generation.")

# Tab setup
tab_dash, tab_scan, tab_import = st.tabs([
    "📊 Analytics Dashboard", 
    "🚀 Scan Console", 
    "📥 Ingest Center"
])

with tab_dash:
    # Load Findings
    findings: List[Dict[str, Any]] = []
    if is_online:
        try:
            res = requests.get(f"{backend_url}/findings")
            if res.status_code == 200:
                findings = res.json()
        except Exception as e:
            st.error(f"Failed to fetch findings: {e}")

    if not findings:
        st.info("No findings found in the database. Head to 'Scan Console' or 'Ingest Center' to add scan records.")
    else:
        df = pd.DataFrame(findings)

        # 1. Metric Cards Row
        st.subheader("Vulnerability Metrics Overview")
        col_c, col_h, col_m, col_l, col_i = st.columns(5)
        
        counts = df["severity"].value_counts()
        
        c_count = counts.get("Critical", 0)
        h_count = counts.get("High", 0)
        m_count = counts.get("Medium", 0)
        l_count = counts.get("Low", 0)
        i_count = counts.get("Info", 0)
        
        col_c.metric("Critical 🔴", c_count)
        col_h.metric("High 🟠", h_count)
        col_m.metric("Medium 🟡", m_count)
        col_l.metric("Low 🔵", l_count)
        col_i.metric("Info ⚪", i_count)

        st.markdown("---")

        # 2. Charts Row
        st.subheader("Data Visualizations")
        chart_col1, chart_col2 = st.columns(2)

        with chart_col1:
            # Severity distribution
            fig_sev = px.pie(
                df, 
                names="severity", 
                title="Vulnerabilities by Severity",
                color="severity",
                color_discrete_map={
                    "Critical": "#DC2626",
                    "High": "#EA580C",
                    "Medium": "#EAB308",
                    "Low": "#3B82F6",
                    "Info": "#94A3B8"
                }
            )
            st.plotly_chart(fig_sev, use_container_width=True)

        with chart_col2:
            # Scanner distribution
            fig_tool = px.bar(
                df.groupby(["source_tool", "severity"]).size().reset_index(name="counts"),
                x="source_tool",
                y="counts",
                color="severity",
                title="Findings Ingested per Scanner Tool",
                barmode="group",
                color_discrete_map={
                    "Critical": "#DC2626",
                    "High": "#EA580C",
                    "Medium": "#EAB308",
                    "Low": "#3B82F6",
                    "Info": "#94A3B8"
                }
            )
            st.plotly_chart(fig_tool, use_container_width=True)

        st.markdown("---")

        # 3. Findings Table and Details
        st.subheader("📋 Findings Inspector Table")
        
        # Filtering Controls
        f_col1, f_col2, f_col3 = st.columns(3)
        with f_col1:
            sel_severity = st.multiselect("Severity Filters", options=["Critical", "High", "Medium", "Low", "Info"])
        with f_col2:
            sel_tool = st.multiselect("Source Tool Filters", options=list(df["source_tool"].unique()))
        with f_col3:
            sel_host = st.text_input("Host Filter Search")

        filtered_df = df.copy()
        if sel_severity:
            filtered_df = filtered_df[filtered_df["severity"].isin(sel_severity)]
        if sel_tool:
            filtered_df = filtered_df[filtered_df["source_tool"].isin(sel_tool)]
        if sel_host:
            filtered_df = filtered_df[filtered_df["host"].str.contains(sel_host, case=False, na=False)]

        st.dataframe(
            filtered_df[["host", "port", "protocol", "service", "title", "severity", "cve", "cvss", "source_tool"]],
            use_container_width=True
        )

        # Reset button
        if st.button("🗑️ Clear Database Records"):
            if is_online:
                res = requests.delete(f"{backend_url}/findings")
                if res.status_code == 200:
                    st.success("Database cleared!")
                    st.rerun()

        st.markdown("---")

        # 4. Detailed Inspector
        st.subheader("🔍 Finding Inspector Detail Panel")
        if not filtered_df.empty:
            finding_options = filtered_df.apply(
                lambda r: f"[{r['severity']}] {r['host']}:{r['port'] or ''} - {r['title']}", axis=1
            ).tolist()
            
            selected_finding_idx = st.selectbox(
                "Choose a finding to inspect detailed description & solution",
                range(len(finding_options)),
                format_func=lambda x: finding_options[x]
            )
            
            f = filtered_df.iloc[selected_finding_idx]
            det1, det2 = st.columns(2)
            
            with det1:
                st.markdown(f"### **{f['title']}**")
                st.markdown(f"**Host:** `{f['host']}` | **Port:** `{f['port'] or 'N/A'}/{f['protocol'] or 'N/A'}`")
                st.markdown(f"**CVE:** `{f['cve'] or 'N/A'}` | **CVSS:** `{f['cvss'] or 'N/A'}`")
                st.markdown(f"**Scanner Source:** `{f['source_tool']}`")
                st.write("**Description:**")
                st.info(f["description"])

            with det2:
                st.markdown("### Actionable Remediation Guidance")
                if f.get("remediation_text"):
                    st.success(f["remediation_text"])
                else:
                    st.warning("No remediation text mapped for this finding type.")

                st.markdown("### Raw Evidence Details")
                st.code(f["raw_evidence"] or "No raw payload context provided.")

with tab_scan:
    st.header("Execute Live Security Scans")
    st.markdown("Select a scanner and trigger target assessment. Make sure target authorization is acknowledged.")

    # Authorization Checkbox
    st.error("🚨 **Target Scanning Authorization Confirmation**")
    authorized = st.checkbox(
        "I explicitly confirm that I am authorized to scan and probe this target scope. "
        "I understand that unauthorized scanning might violate local laws or policies."
    )

    scan_type = st.selectbox("Scanner Selection", ["Nmap Port Scan", "OWASP ZAP Web Scan", "OpenVAS Network Scan"])

    if scan_type == "Nmap Port Scan":
        st.subheader("Nmap Scan Arguments")
        target_nmap = st.text_input("Target Host/IP Address", "127.0.0.1")
        extra_args_nmap = st.text_input("Additional Arguments", "-sT -F")
        
        if st.button("Trigger Nmap Scan"):
            if not authorized:
                st.error("Cannot proceed without scan authorization confirmation.")
            elif not target_nmap.strip():
                st.error("Target Host/IP is required.")
            elif not is_online:
                st.error("FastAPI Backend Server is unreachable.")
            else:
                with st.spinner("Nmap scanner is profiling target..."):
                    try:
                        args_list = extra_args_nmap.split() if extra_args_nmap.strip() else []
                        res = requests.post(
                            f"{backend_url}/scan/nmap",
                            json={"target": target_nmap, "authorized": authorized, "extra_args": args_list}
                        )
                        if res.status_code == 200:
                            st.success(f"Nmap Scan Finished! Loaded {len(res.json())} findings.")
                            st.rerun()
                        else:
                            st.error(f"Scan failed: {res.json().get('detail', res.text)}")
                    except Exception as e:
                        st.error(f"Request failed: {e}")

    elif scan_type == "OWASP ZAP Web Scan":
        st.subheader("ZAP Active Scan Details")
        target_zap = st.text_input("Target Base URL (e.g., http://localhost)", "http://localhost")
        zap_api_url = st.text_input("ZAP API Endpoint", "http://localhost:8080")
        zap_api_key = st.text_input("ZAP API Key (Optional)", type="password")

        if st.button("Trigger ZAP Scan"):
            if not authorized:
                st.error("Cannot proceed without scan authorization confirmation.")
            elif not target_zap.strip():
                st.error("Target URL is required.")
            elif not is_online:
                st.error("FastAPI Backend Server is unreachable.")
            else:
                with st.spinner("ZAP is running spider and active scanner tasks (this takes longer)..."):
                    try:
                        res = requests.post(
                            f"{backend_url}/scan/zap?api_url={zap_api_url}&api_key={zap_api_key}",
                            json={"target": target_zap, "authorized": authorized}
                        )
                        if res.status_code == 200:
                            st.success(f"ZAP Scan Finished! Ingested {len(res.json())} findings.")
                            st.rerun()
                        else:
                            st.error(f"Scan failed: {res.json().get('detail', res.text)}")
                    except Exception as e:
                        st.error(f"Request failed: {e}")

    elif scan_type == "OpenVAS Network Scan":
        st.subheader("OpenVAS GVM API Connection")
        target_gvm = st.text_input("Target Host/IP", "127.0.0.1")
        
        # Connect options
        use_socket = st.checkbox("Connect via Unix Socket (Linux GVM service only)")
        
        if use_socket:
            socket_path = st.text_input("GVM Unix Socket Path", "/run/gvmd/gvmd.sock")
            host_gvm, port_gvm, username_gvm, password_gvm = "", 9390, "", ""
        else:
            host_gvm = st.text_input("Remote GVM Hostname/IP", "127.0.0.1")
            port_gvm = st.number_input("GVM Port (GMP TLS)", value=9390)
            username_gvm = st.text_input("GVM API Username", "admin")
            password_gvm = st.text_input("GVM API Password", type="password")
            socket_path = ""

        if system_os == "Windows" and use_socket:
            st.warning("⚠️ Unix Sockets are not supported on Windows. Please configure remote GVM TLS credentials.")

        if st.button("Trigger OpenVAS Sync"):
            if not authorized:
                st.error("Cannot proceed without scan authorization confirmation.")
            elif not target_gvm.strip():
                st.error("Target Host/IP is required.")
            elif not is_online:
                st.error("FastAPI Backend Server is unreachable.")
            else:
                with st.spinner("Connecting and running OpenVAS/GVM tasks..."):
                    try:
                        payload = {
                            "req": {"target": target_gvm, "authorized": authorized},
                            "host": host_gvm,
                            "port": port_gvm,
                            "username": username_gvm,
                            "password": password_gvm,
                            "use_socket": use_socket,
                            "socket_path": socket_path
                        }
                        # We pass configuration parameters
                        url = (
                            f"{backend_url}/scan/openvas"
                            f"?use_socket={use_socket}"
                        )
                        if host_gvm: url += f"&host={host_gvm}&port={port_gvm}&username={username_gvm}&password={password_gvm}"
                        if socket_path: url += f"&socket_path={socket_path}"
                        
                        res = requests.post(url, json={"target": target_gvm, "authorized": authorized})
                        
                        if res.status_code == 200:
                            st.success(f"OpenVAS Ingestion Complete! Loaded {len(res.json())} findings.")
                            st.rerun()
                        else:
                            st.error(f"OpenVAS Sync failed: {res.json().get('detail', res.text)}")
                    except Exception as e:
                        st.error(f"Request failed: {e}")

with tab_import:
    st.header("Import Pre-existing Reports")
    st.markdown("Ingest raw scanner reports directly. Useful for Windows/WSL setups without local daemon instances.")

    import_type = st.selectbox("Select Report Type to Upload", [
        "Nmap XML (-oX file)", 
        "OWASP ZAP JSON Alerts", 
        "OpenVAS GVM XML Results"
    ])

    uploaded_file = st.file_uploader("Upload Scan File", type=["xml", "json"])

    if uploaded_file is not None:
        if st.button("📥 Import Scan Record"):
            if not is_online:
                st.error("FastAPI backend is offline.")
            else:
                with st.spinner("Processing report parser..."):
                    try:
                        if import_type == "Nmap XML (-oX file)":
                            files = {"file": (uploaded_file.name, uploaded_file.getvalue(), "application/xml")}
                            res = requests.post(f"{backend_url}/import/nmap", files=files)
                        elif import_type == "OWASP ZAP JSON Alerts":
                            files = {"file": (uploaded_file.name, uploaded_file.getvalue(), "application/json")}
                            res = requests.post(f"{backend_url}/import/zap", files=files)
                        else:
                            files = {"file": (uploaded_file.name, uploaded_file.getvalue(), "application/xml")}
                            res = requests.post(f"{backend_url}/import/openvas", files=files)

                        if res.status_code == 200:
                            st.success(f"Successfully normalized and saved {len(res.json())} findings!")
                            st.rerun()
                        else:
                            st.error(f"Upload processing failed: {res.json().get('detail', res.text)}")
                    except Exception as e:
                        st.error(f"Upload failed: {e}")
