import streamlit as st

# Streamlit requires configuration definitions to be called at the absolute top
st.set_page_config(
    page_title="Advanced Cyber Security Scanner",
    page_icon="🛡️",
    layout="wide"
)

import json
from port_scanner import scan_ports
from vulnerability_scanner import run_vulnerability_scan
from pentest_module import run_pentest_simulation
from framework_mapper import calculate_risk_level, map_findings
from report_generator import generate_text_report, create_scan_record

# Inject custom CSS styles for a beautiful cyber dashboard look
st.markdown("""
    <style>
    .stApp { background-color: #020617; color: #e5f4ff; }
    h1, h2, h3 { color: #38bdf8 !important; font-family: 'Segoe UI', sans-serif; }
    .stTextInput>div>div>input {
        background-color: #071426 !important; color: #e5f4ff !important;
        border: 1px solid #1e3a56 !important;
    }
    .stButton>button {
        background-color: #0891b2 !important; color: white !important;
        border: none !important; font-weight: bold !important; width: 100%;
        padding: 10px 0px !important;
    }
    .stButton>button:hover { background-color: #0e7490 !important; }
    .risk-box { padding: 15px; border-radius: 6px; text-align: center; font-size: 22px; font-weight: bold; margin-bottom: 20px; }
    .risk-HIGH { background-color: rgba(255, 107, 107, 0.15); border: 2px solid #ff6b6b; color: #ff6b6b; }
    .risk-MEDIUM { background-color: rgba(251, 191, 36, 0.15); border: 2px solid #fbbf24; color: #fbbf24; }
    .risk-LOW { background-color: rgba(52, 211, 153, 0.15); border: 2px solid #34d399; color: #34d399; }
    </style>
""", unsafe_allow_html=True)

st.title("🛡️ Advanced Cyber Security Scanner")
st.markdown("##### Vulnerability Assessment | Pentesting Simulation | Audit Report | Framework Mapping")
st.markdown("---")

# Domain Target Input Bar
target_input = st.text_input("Target Hostname or URL Destination", value="monkeytype.com")

if st.button("Execute Core Scanning Pipeline"):
    target_clean = target_input.strip()
    if not target_clean:
        st.error("The network target domain address field cannot be left blank.")
    elif any(char in target_clean for char in [" ", "\\", "<", ">", '"']):
        st.error("Target address parameter contains structurally invalid string characters.")
    else:
        with st.spinner("⚡ Initializing scanner micro-engines... Auditing live target..."):
            try:
                # Trigger back-end core scripts
                port_scan = scan_ports(target_clean)
                
                if port_scan.get("error"):
                    st.error(f"Target Diagnostic Error: {port_scan['error']}")
                else:
                    vulnerabilities = run_vulnerability_scan(target_clean, port_scan)
                    pentest_results = run_pentest_simulation(target_clean)
                    mappings = map_findings(vulnerabilities, pentest_results)
                    risk_level = calculate_risk_level(vulnerabilities, pentest_results)
                    
                    # Generate record objects matching your original schema templates
                    scan_data = create_scan_record(target_clean, port_scan, vulnerabilities, pentest_results, mappings, risk_level)
                    text_report = generate_text_report(scan_data)
                    
                    # Output Metrics UI Layout Grid
                    st.subheader("📊 Live Risk Metric Assessment")
                    if risk_level == "HIGH":
                        st.markdown('<div class="risk-box risk-HIGH">⚠️ CRITICAL THREAT ENVIRONMENT: HIGH RISK PROFILE</div>', unsafe_allow_html=True)
                    elif risk_level == "MEDIUM":
                        st.markdown('<div class="risk-box risk-MEDIUM">❗ HARDENING CONFIGURATIONS RECOMMENDED: MEDIUM RISK WARNING</div>', unsafe_allow_html=True)
                    else:
                        st.markdown('<div class="risk-box risk-LOW">✅ IMMUNE NODE ENVIROMENT: LOW RISK SECURITY MATRIX</div>', unsafe_allow_html=True)
                    
                    col1, col2, col3 = st.columns(3)
                    col1.metric("Resolved Destination IP", port_scan.get("ip") or "N/A")
                    col2.metric("Discovered Open Network Ports", len(port_scan.get("open_ports", [])))
                    col3.metric("Framework Vulnerability Mappings", len(mappings))
                    
                    # Render Plain-Text Audit Console Logs
                    st.subheader("📋 Core Diagnostic Terminal Output Logs")
                    st.code(text_report, language="text")
                    
                    # Downloader Asset Controls
                    st.markdown("### 📥 Download Security Assets")
                    d_col1, d_col2 = st.columns(2)
                    d_col1.download_button("Download Report (.txt)", data=text_report, file_name=f"cyber_report_{target_clean}.txt", mime="text/plain")
                    d_col2.download_button("Export Scan JSON (.json)", data=json.dumps(scan_data, indent=2), file_name=f"cyber_report_{target_clean}.json", mime="application/json")
                    
            except Exception as system_ex:
                st.error(f"Internal Diagnostic Micro-Engine Exception Failure: {str(system_ex)}")