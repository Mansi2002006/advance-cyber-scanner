CIA_RULES = {
    "Injection": ["Confidentiality", "Integrity"],
    "Open Port Risk": ["Confidentiality", "Availability"],
    "Weak Headers": ["Confidentiality", "Integrity"],
    "Connectivity": ["Availability"],
    "Scanner Configuration": ["Availability"],
}


OWASP_RULES = {
    "Injection": "Injection",
    "Open Port Risk": "Security Misconfiguration",
    "Weak Headers": "Security Misconfiguration",
    "Connectivity": "Security Misconfiguration",
    "Scanner Configuration": "Security Misconfiguration",
}


def _map_category(category):
    cia = CIA_RULES.get(category, ["Confidentiality"])
    owasp = OWASP_RULES.get(category, "Security Misconfiguration")
    return cia, owasp


def map_vulnerability_finding(finding):
    cia, owasp = _map_category(finding.get("category", "Security Misconfiguration"))
    return {
        "source": finding.get("title", "Unknown finding"),
        "impact": finding.get("impact", "Security impact requires review."),
        "category": finding.get("category", "Security Misconfiguration"),
        "severity": finding.get("severity", "LOW"),
        "cia": cia,
        "owasp": owasp,
    }


def map_pentest_result(result):
    category = "Injection" if "SQL" in result.get("test", "") else "Weak Headers"
    cia, owasp = _map_category(category)
    return {
        "source": result.get("test", "Pentest simulation"),
        "impact": result.get("evidence", "Simulation result requires review."),
        "category": category,
        "severity": result.get("severity", "LOW"),
        "cia": cia,
        "owasp": owasp,
    }


def map_findings(vulnerabilities, pentest_results):
    mappings = [map_vulnerability_finding(item) for item in vulnerabilities]
    mappings.extend(map_pentest_result(item) for item in pentest_results)
    return mappings


def calculate_risk_level(vulnerabilities, pentest_results):
    severities = [item.get("severity", "LOW") for item in vulnerabilities]
    severities.extend(item.get("severity", "LOW") for item in pentest_results)

    if "HIGH" in severities:
        return "HIGH"
    if "MEDIUM" in severities:
        return "MEDIUM"
    return "LOW"
