import pytest
from pathlib import Path
from backend.scanners.nmap_scanner import NmapScanner

def test_nmap_scanner_parse_xml():
    # Setup paths
    fixture_path = Path(__file__).resolve().parent / "fixtures" / "nmap_sample.xml"
    
    scanner = NmapScanner()
    findings = scanner.parse_xml_file(fixture_path)
    
    # Assert findings count (expecting 3 open ports: ssh, http, telnet)
    assert len(findings) == 3
    
    # Assert mapping details for SSH
    ssh_finding = next(f for f in findings if f.port == 22)
    assert ssh_finding.host == "127.0.0.1"
    assert ssh_finding.protocol == "tcp"
    assert ssh_finding.service == "ssh"
    assert ssh_finding.severity == "Info"
    assert ssh_finding.source_tool == "Nmap"
    assert "OpenSSH" in ssh_finding.description
    
    # Assert mapping details for HTTP
    http_finding = next(f for f in findings if f.port == 80)
    assert http_finding.host == "127.0.0.1"
    assert http_finding.protocol == "tcp"
    assert http_finding.service == "http"
    assert http_finding.severity == "Info"
    assert "Apache httpd" in http_finding.description

    # Assert mapping details for Telnet (which has Medium severity)
    telnet_finding = next(f for f in findings if f.port == 23)
    assert telnet_finding.host == "127.0.0.1"
    assert telnet_finding.protocol == "tcp"
    assert telnet_finding.service == "telnet"
    assert telnet_finding.severity == "Medium"
    assert "telnetd" in telnet_finding.description
    assert "transmits data in plaintext" in telnet_finding.remediation_text

def test_zap_scanner_parse_json():
    import json
    fixture_path = Path(__file__).resolve().parent / "fixtures" / "zap_sample.json"
    with open(fixture_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    from backend.scanners.zap_scanner import ZapScanner
    scanner = ZapScanner()
    findings = scanner.parse_alerts(data)

    assert len(findings) == 2

    # SQL Injection alert check
    sqli = next(f for f in findings if f.title == "SQL Injection")
    assert sqli.host == "127.0.0.1"
    assert sqli.port == 8080
    assert sqli.severity == "High"
    assert sqli.source_tool == "ZAP"
    assert "SQL Injection may be possible" in sqli.description
    assert "Use parameterized queries" in sqli.remediation_text
    assert "OWASP_Injection" in sqli.remediation_text or "attacks/SQL_Injection" in sqli.remediation_text

    # XSS alert check
    xss = next(f for f in findings if "Cross-Site Scripting" in f.title)
    assert xss.host == "127.0.0.1"
    assert xss.port == 8080
    assert xss.severity == "Medium"
    assert xss.source_tool == "ZAP"
    assert "Sanitize user inputs" in xss.remediation_text

def test_openvas_scanner_parse_xml():
    fixture_path = Path(__file__).resolve().parent / "fixtures" / "openvas_sample.xml"
    
    from backend.scanners.openvas_scanner import OpenvasScanner
    scanner = OpenvasScanner()
    findings = scanner.parse_xml_file(fixture_path)
    
    assert len(findings) == 2
    
    # Bound9 advisory check (Threat: High, CVSS: 7.5)
    bind = next(f for f in findings if "DSA-4890-1" in f.title)
    assert bind.host == "192.168.1.50"
    assert bind.port is None
    assert bind.protocol == "tcp"
    assert bind.severity == "High"
    assert bind.cvss == 7.5
    assert bind.cve == "CVE-2021-25215"
    assert bind.source_tool == "OpenVAS"
    assert "denial of service" in bind.description
    
    # HTTP Server Type and Version (Threat: Log, CVSS: 0.0)
    banner = next(f for f in findings if "HTTP Server" in f.title)
    assert banner.host == "192.168.1.50"
    assert banner.port == 80
    assert banner.protocol == "tcp"
    assert banner.severity == "Info"
    assert banner.cvss is None
    assert banner.cve is None
    assert banner.source_tool == "OpenVAS"
    assert "Apache/2.4.41" in banner.description

def test_remediation_engine():
    from backend.models.finding import Finding
    from backend.remediation.guidance import RemediationEngine
    
    # Create test finding
    f = Finding(
        host="127.0.0.1",
        port=80,
        protocol="tcp",
        service="http",
        title="Found SQL Injection in Login page",
        description="The login username field is vulnerable to SQL injection.",
        severity="Low",
        source_tool="Manual"
    )
    
    engine = RemediationEngine()
    enriched = engine.enrich_finding(f)
    
    # Verify severity upgraded and remediation added
    assert enriched.severity == "Critical"
    assert "parameterized queries" in enriched.remediation_text

def test_report_builder():
    from backend.models.finding import Finding
    from backend.reports.report_builder import ReportBuilder
    
    findings = [
        Finding(
            host="192.168.1.10",
            port=80,
            protocol="tcp",
            service="http",
            title="Outdated HTTP Server",
            description="The web server banner exposes detailed version details.",
            severity="Info",
            source_tool="Nmap"
        ),
        Finding(
            host="192.168.1.20",
            port=443,
            protocol="tcp",
            service="https",
            title="SQL Injection on Search API",
            description="The search parameter query is vulnerable.",
            severity="High",
            source_tool="ZAP"
        )
    ]
    
    builder = ReportBuilder(findings)
    
    # 1. JSON Report check
    json_rep = builder.generate_json_report()
    assert json_rep["summary"]["total_findings"] == 2
    assert json_rep["summary"]["severities"]["High"] == 1
    assert json_rep["summary"]["severities"]["Info"] == 1
    assert json_rep["summary"]["scanners"]["Nmap"] == 1
    assert len(json_rep["findings"]) == 2
    
    # 2. PDF Report check
    pdf_tech = builder.generate_pdf_report(mode="technical")
    assert pdf_tech.startswith(b"%PDF")
    
    pdf_exec = builder.generate_pdf_report(mode="executive")
    assert pdf_exec.startswith(b"%PDF")




