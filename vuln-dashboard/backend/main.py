import os
from pathlib import Path
from typing import List, Optional
from fastapi import FastAPI, HTTPException, UploadFile, File, Query, Response
from pydantic import BaseModel, Field

from backend.models.finding import Finding
from backend.storage.db import init_db, save_findings, get_findings, clear_db
from backend.reports.report_builder import ReportBuilder
from backend.scanners.nmap_scanner import NmapScanner
from backend.scanners.zap_scanner import ZapScanner
from backend.scanners.openvas_scanner import OpenvasScanner
from backend.remediation.guidance import RemediationEngine

app = FastAPI(title="Vulnerability Assessment Dashboard API", version="1.0.0")

# Database Path setup
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "vuln_dashboard.db"

# Initialize DB on start
@app.on_event("startup")
def startup_event():
    init_db(DB_PATH)

def save_and_enrich_findings(findings: List[Finding]) -> List[Finding]:
    engine = RemediationEngine()
    enriched = engine.enrich_findings(findings)
    save_findings(enriched, DB_PATH)
    return enriched

class ScanRequest(BaseModel):
    target: str = Field(..., description="Target hostname, IP, or URL")
    authorized: bool = Field(
        ..., 
        description="Explicit confirmation that the caller owns or has authorization to scan this target."
    )
    extra_args: Optional[List[str]] = Field(None, description="Optional command-line arguments (for Nmap)")

@app.get("/health")
def health_check():
    """Verify backend health and determine availability of external security scanners."""
    nmap = NmapScanner()
    
    return {
        "status": "healthy",
        "scanners": {
            "nmap": {
                "available": nmap.is_available(),
                "path": nmap.binary_path or "Not found in PATH"
            },
            "zap": {
                "available": False,
                "info": "Requires running ZAP daemon — use Scan Console to connect"
            },
            "openvas": {
                "available": False,
                "info": "Requires GVM/Greenbone service (Linux only natively; remote connection on Windows)"
            }
        }
    }

@app.post("/scan/nmap", response_model=List[Finding])
def run_nmap_scan(req: ScanRequest):
    """Trigger a live Nmap scan against the specified target. Authorization check is required."""
    if not req.authorized:
        raise HTTPException(
            status_code=400,
            detail="Access Denied. You must have explicit authorization to scan the target."
        )
    
    scanner = NmapScanner()
    if not scanner.is_available():
        raise HTTPException(
            status_code=503,
            detail="Nmap scanner is not available on this system host."
        )
        
    try:
        findings = scanner.scan(req.target, req.extra_args)
        return save_and_enrich_findings(findings)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/import/nmap", response_model=List[Finding])
async def import_nmap_xml(file: UploadFile = File(...)):
    """Upload and ingest an existing Nmap XML report file."""
    scanner = NmapScanner()
    try:
        xml_content = await file.read()
        findings = scanner.parse_xml_string(xml_content.decode("utf-8"))
        return save_and_enrich_findings(findings)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse uploaded Nmap XML: {str(e)}")

@app.post("/scan/zap", response_model=List[Finding])
def run_zap_scan(req: ScanRequest, api_url: str = "http://localhost:8080", api_key: Optional[str] = None):
    """Trigger a spider and active scan against a target URL using OWASP ZAP."""
    if not req.authorized:
        raise HTTPException(
            status_code=400,
            detail="Access Denied. You must have explicit authorization to scan the target."
        )
    
    scanner = ZapScanner(api_url=api_url, api_key=api_key)
    if not scanner.is_available():
        raise HTTPException(
            status_code=503,
            detail=f"OWASP ZAP service is not reachable at {api_url}."
        )
    try:
        findings = scanner.scan(req.target)
        return save_and_enrich_findings(findings)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/import/zap", response_model=List[Finding])
async def import_zap_json(file: UploadFile = File(...)):
    """Upload and ingest an existing ZAP alerts JSON file."""
    import json
    scanner = ZapScanner()
    try:
        content = await file.read()
        data = json.loads(content.decode("utf-8"))
        findings = scanner.parse_alerts(data)
        return save_and_enrich_findings(findings)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse uploaded ZAP JSON: {str(e)}")

@app.post("/scan/openvas", response_model=List[Finding])
def run_openvas_scan(
    req: ScanRequest, 
    host: Optional[str] = None, 
    port: Optional[int] = None, 
    username: Optional[str] = None, 
    password: Optional[str] = None,
    use_socket: bool = False,
    socket_path: Optional[str] = None
):
    """Trigger an OpenVAS scan task or retrieve reports from a GVM instance."""
    if not req.authorized:
        raise HTTPException(
            status_code=400,
            detail="Access Denied. You must have explicit authorization to scan the target."
        )
    
    config = {}
    if host: config["host"] = host
    if port: config["port"] = port
    if username: config["username"] = username
    if password: config["password"] = password
    if use_socket: config["use_socket"] = use_socket
    if socket_path: config["socket_path"] = socket_path

    scanner = OpenvasScanner(connection_config=config)
    if not scanner.is_available():
        raise HTTPException(
            status_code=503,
            detail="OpenVAS/GVM connection could not be established. Ensure settings are correct."
        )
    try:
        findings = scanner.scan(req.target)
        return save_and_enrich_findings(findings)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/import/openvas", response_model=List[Finding])
async def import_openvas_xml(file: UploadFile = File(...)):
    """Upload and ingest an existing OpenVAS GVM XML report file."""
    scanner = OpenvasScanner()
    try:
        content = await file.read()
        findings = scanner.parse_gvm_xml(content.decode("utf-8"))
        return save_and_enrich_findings(findings)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse uploaded OpenVAS XML: {str(e)}")


@app.get("/findings", response_model=List[Finding])
def list_findings(
    severity: Optional[str] = Query(None, description="Filter by severity level (Critical, High, Medium, Low, Info)"),
    source_tool: Optional[str] = Query(None, description="Filter by tool (Nmap, ZAP, OpenVAS)"),
    host: Optional[str] = Query(None, description="Filter by host IP or hostname")
):
    """Retrieve normalized findings stored in the database."""
    try:
        return get_findings(DB_PATH, severity=severity, source_tool=source_tool, host=host)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.delete("/findings")
def delete_all_findings():
    """Clear all findings from the SQLite database."""
    try:
        clear_db(DB_PATH)
        return {"status": "success", "message": "All findings deleted."}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/reports/pdf")
def get_pdf_report(mode: str = Query("technical", description="Report mode: 'technical' or 'executive'")):
    """Generate and download a PDF scan report."""
    try:
        findings = get_findings(DB_PATH)
        builder = ReportBuilder(findings)
        pdf_bytes = builder.generate_pdf_report(mode=mode)
        
        filename = f"vuln_report_{mode}.pdf"
        headers = {
            "Content-Disposition": f"attachment; filename={filename}"
        }
        return Response(content=pdf_bytes, media_type="application/pdf", headers=headers)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate PDF report: {str(e)}")

@app.get("/reports/json")
def get_json_report():
    """Generate and retrieve a JSON scan report."""
    try:
        findings = get_findings(DB_PATH)
        builder = ReportBuilder(findings)
        return builder.generate_json_report()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to generate JSON report: {str(e)}")

