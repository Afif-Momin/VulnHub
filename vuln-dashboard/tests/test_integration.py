import pytest
import json
from pathlib import Path
from backend.models.finding import Finding
from backend.storage.db import init_db, save_findings, get_findings, clear_db
from backend.scanners.nmap_scanner import NmapScanner
from backend.scanners.zap_scanner import ZapScanner
from backend.scanners.openvas_scanner import OpenvasScanner
from backend.remediation.guidance import RemediationEngine
from backend.reports.report_builder import ReportBuilder

def test_full_pipeline_integration(tmp_path):
    # 1. Setup temporary database file
    db_path = tmp_path / "test_integration.db"
    init_db(db_path)
    
    # 2. Setup paths to fixtures
    fixtures_dir = Path(__file__).resolve().parent / "fixtures"
    nmap_fixture = fixtures_dir / "nmap_sample.xml"
    zap_fixture = fixtures_dir / "zap_sample.json"
    openvas_fixture = fixtures_dir / "openvas_sample.xml"
    
    # 3. Parse Nmap fixture
    nmap_scanner = NmapScanner()
    nmap_findings = nmap_scanner.parse_xml_file(nmap_fixture)
    assert len(nmap_findings) == 3
    
    # 4. Parse ZAP fixture
    zap_scanner = ZapScanner()
    with open(zap_fixture, "r", encoding="utf-8") as f:
        zap_data = json.load(f)
    zap_findings = zap_scanner.parse_alerts(zap_data)
    assert len(zap_findings) == 2
    
    # 5. Parse OpenVAS fixture
    openvas_scanner = OpenvasScanner()
    openvas_findings = openvas_scanner.parse_xml_file(openvas_fixture)
    assert len(openvas_findings) == 2
    
    # Combine findings
    all_findings = nmap_findings + zap_findings + openvas_findings
    assert len(all_findings) == 7
    
    # 6. Apply Remediation Guidance Engine
    engine = RemediationEngine()
    enriched_findings = engine.enrich_findings(all_findings)
    
    # Save to temporary database
    save_findings(enriched_findings, db_path)
    
    # 7. Query from DB and verify normalization + persistence
    db_findings = get_findings(db_path)
    assert len(db_findings) == 7
    
    # Verify Nmap Telnet finding severity is Medium
    nmap_telnet = next(f for f in db_findings if f.source_tool == "Nmap" and f.service == "telnet")
    assert nmap_telnet.severity == "Medium"
    
    # Verify ZAP SQL Injection finding severity is Critical (Upgraded from High via RemediationEngine rules)
    zap_sqli = next(f for f in db_findings if f.source_tool == "ZAP" and f.title == "SQL Injection")
    assert zap_sqli.severity == "Critical"
    assert "parameterized queries" in zap_sqli.remediation_text
    
    # Verify OpenVAS DSA-4890-1 finding is High
    gvm_bind = next(f for f in db_findings if f.source_tool == "OpenVAS" and "DSA-4890-1" in f.title)
    assert gvm_bind.severity == "High"
    assert gvm_bind.cvss == 7.5
    assert gvm_bind.cve == "CVE-2021-25215"
    
    # 8. Verify Report Generation
    builder = ReportBuilder(db_findings)
    json_report = builder.generate_json_report()
    assert json_report["summary"]["total_findings"] == 7
    assert json_report["summary"]["severities"]["Critical"] == 1
    assert json_report["summary"]["severities"]["High"] == 2
    assert json_report["summary"]["severities"]["Medium"] == 1
    assert json_report["summary"]["severities"]["Info"] == 3
    
    pdf_report = builder.generate_pdf_report(mode="technical")
    assert pdf_report.startswith(b"%PDF")
    
    # Clear database
    clear_db(db_path)
    assert len(get_findings(db_path)) == 0
