import os
import sys

# Route execution lookups up to the root folder level
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from flask import Flask, request, jsonify
from port_scanner import scan_ports
from vulnerability_scanner import run_vulnerability_scan
from pentest_module import run_pentest_simulation
from framework_mapper import calculate_risk_level, map_findings
from report_generator import create_scan_record

app = Flask(__name__)

@app.route('/')
def index():
    return "Advanced Cyber Security Scanner API Engine is operational. Query endpoint via /api/scan?target=yourdomain.com"

@app.route('/api/scan', methods=['GET'])
def api_scan_pipeline():
    target = request.args.get('target')
    if not target:
        return jsonify({"success": False, "error": "Missing parameter string 'target'."}), 400
        
    try:
        port_scan = scan_ports(target.strip())
        if port_scan.get("error"):
            return jsonify({"success": False, "error": port_scan["error"]}), 400
            
        vulnerabilities = run_vulnerability_scan(target, port_scan)
        pentest_results = run_pentest_simulation(target)
        mappings = map_findings(vulnerabilities, pentest_results)
        risk_level = calculate_risk_level(vulnerabilities, pentest_results)
        
        scan_record = create_scan_record(target, port_scan, vulnerabilities, pentest_results, mappings, risk_level)
        return jsonify({"success": True, "scan_results": scan_record}), 200
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500