import socket


DEFAULT_PORTS = [21, 22, 23, 80, 443, 8080]


PORT_RISKS = {
    21: ("FTP", "HIGH", "FTP often sends credentials in clear text."),
    22: ("SSH", "MEDIUM", "SSH should be patched and protected with strong authentication."),
    23: ("Telnet", "HIGH", "Telnet is insecure because it sends data in clear text."),
    80: ("HTTP", "MEDIUM", "HTTP traffic is unencrypted unless redirected to HTTPS."),
    443: ("HTTPS", "LOW", "HTTPS is expected for secure web services."),
    8080: ("HTTP Alternate", "MEDIUM", "Alternate web ports often expose admin or test services."),
}


def resolve_target(host):
    """Resolve a hostname to an IP address with a friendly error result."""
    try:
        ip_address = socket.gethostbyname(host)
        return {"success": True, "host": host, "ip": ip_address, "error": None}
    except socket.gaierror:
        return {
            "success": False,
            "host": host,
            "ip": None,
            "error": "Invalid host or DNS lookup failed.",
        }


def scan_port(host, port, timeout=1.0):
    service, severity, description = PORT_RISKS.get(
        port, ("Unknown", "LOW", "Unknown service exposure.")
    )

    result = {
        "port": port,
        "service": service,
        "state": "closed",
        "severity": severity,
        "description": description,
    }

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            status = sock.connect_ex((host, port))
            if status == 0:
                result["state"] = "open"
    except socket.timeout:
        result["state"] = "filtered"
    except OSError as exc:
        result["state"] = "error"
        result["description"] = str(exc)

    return result


def scan_ports(host, ports=None, timeout=1.0):
    """Scan the selected TCP ports and return structured results."""
    ports = ports or DEFAULT_PORTS
    resolution = resolve_target(host)

    if not resolution["success"]:
        return {
            "target": host,
            "ip": None,
            "open_ports": [],
            "ports": [],
            "error": resolution["error"],
        }

    port_results = [scan_port(resolution["ip"], port, timeout) for port in ports]
    open_ports = [item for item in port_results if item["state"] == "open"]

    return {
        "target": host,
        "ip": resolution["ip"],
        "open_ports": open_ports,
        "ports": port_results,
        "error": None,
    }
