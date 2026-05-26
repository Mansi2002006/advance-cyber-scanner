import datetime
import json


def _line(title=""):
    if title:
        return "\n==== %s ====\n" % title
    return "\n" + ("=" * 70) + "\n"


def generate_text_report(scan_data):
    timestamp = scan_data["timestamp"]
    target = scan_data["target"]
    risk_level = scan_data["risk_level"]
    port_scan = scan_data["port_scan"]
    vulnerabilities = scan_data["vulnerabilities"]
    pentest_results = scan_data["pentest_results"]
    mappings = scan_data["framework_mappings"]

    report = []
    report.append("ADVANCED CYBER SECURITY SCANNER REPORT")
    report.append("Generated: %s" % timestamp)
    report.append("Target: %s" % target)
    report.append("Resolved IP: %s" % (port_scan.get("ip") or "N/A"))
    report.append("Final Risk Level: %s" % risk_level)

    report.append(_line("OPEN PORTS"))
    if port_scan.get("open_ports"):
        for item in port_scan["open_ports"]:
            report.append(
                "[OPEN] Port %s (%s) - %s"
                % (item["port"], item["service"], item["severity"])
            )
    else:
        report.append("[INFO] No configured ports were detected as open.")

    report.append(_line("VULNERABILITIES FOUND"))
    if vulnerabilities:
        for finding in vulnerabilities:
            report.append("[%s] %s" % (finding["severity"], finding["title"]))
            report.append("Evidence: %s" % finding["evidence"])
            report.append("Impact: %s" % finding["impact"])
            report.append("Recommendation: %s" % finding["recommendation"])
            report.append("")
    else:
        report.append("[INFO] No vulnerabilities were identified by configured checks.")

    report.append(_line("PENTESTING SIMULATION RESULTS"))
    for result in pentest_results:
        report.append("[%s] %s" % (result["severity"], result["test"]))
        report.append("Status: %s" % result["status"])
        report.append("Payload: %s" % result["payload"])
        report.append("Evidence: %s" % result["evidence"])
        report.append("Recommendation: %s" % result["recommendation"])
        report.append("")

    report.append(_line("SECURITY FRAMEWORK MAPPING"))
    for mapping in mappings:
        report.append("Finding: %s" % mapping["source"])
        report.append("Severity: %s" % mapping["severity"])
        report.append("Category: %s" % mapping["category"])
        report.append("CIA Triad: %s" % ", ".join(mapping["cia"]))
        report.append("OWASP Top 10: %s" % mapping["owasp"])
        report.append("Impact: %s" % mapping["impact"])
        report.append("")

    report.append(_line("FINAL RISK SUMMARY"))
    report.append(
        "Overall risk is %s based on open services, missing controls, and simulated attack signals."
        % risk_level
    )

    return "\n".join(report)


def save_text_report(scan_data, file_path="report.txt"):
    content = generate_text_report(scan_data)
    with open(file_path, "w", encoding="utf-8") as report_file:
        report_file.write(content)
    return file_path


def save_json_report(scan_data, file_path="report.json"):
    with open(file_path, "w", encoding="utf-8") as report_file:
        json.dump(scan_data, report_file, indent=2)
    return file_path


def create_scan_record(target, port_scan, vulnerabilities, pentest_results, mappings, risk_level):
    return {
        "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "target": target,
        "port_scan": port_scan,
        "vulnerabilities": vulnerabilities,
        "pentest_results": pentest_results,
        "framework_mappings": mappings,
        "risk_level": risk_level,
    }
