import sqlite3
from pathlib import Path
from typing import List, Optional
from backend.models.finding import Finding

def get_db_connection(db_path: Path) -> sqlite3.Connection:
    """Establish and return a connection to the SQLite database, enabling dictionary access."""
    # Ensure directory exists
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn

def init_db(db_path: Path) -> None:
    """Initialize SQLite database tables if they do not exist."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            host TEXT NOT NULL,
            port INTEGER,
            protocol TEXT,
            service TEXT,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            severity TEXT NOT NULL,
            cve TEXT,
            cvss REAL,
            source_tool TEXT NOT NULL,
            raw_evidence TEXT,
            remediation_text TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()

def save_findings(findings: List[Finding], db_path: Path) -> None:
    """Save a list of Finding objects to the database."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    
    for f in findings:
        cursor.execute("""
            INSERT INTO findings (
                host, port, protocol, service, title, description, 
                severity, cve, cvss, source_tool, raw_evidence, remediation_text
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            f.host, f.port, f.protocol, f.service, f.title, f.description,
            f.severity, f.cve, f.cvss, f.source_tool, f.raw_evidence, f.remediation_text
        ))
    
    conn.commit()
    conn.close()

def get_findings(
    db_path: Path, 
    severity: Optional[str] = None, 
    source_tool: Optional[str] = None,
    host: Optional[str] = None
) -> List[Finding]:
    """Retrieve filtered findings from the database."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    
    query = "SELECT * FROM findings WHERE 1=1"
    params = []
    
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    if source_tool:
        query += " AND source_tool = ?"
        params.append(source_tool)
    if host:
        query += " AND host LIKE ?"
        params.append(f"%{host}%")
        
    query += " ORDER BY id DESC"
    
    cursor.execute(query, params)
    rows = cursor.fetchall()
    
    findings = []
    for r in rows:
        findings.append(Finding(
            host=r["host"],
            port=r["port"],
            protocol=r["protocol"],
            service=r["service"],
            title=r["title"],
            description=r["description"],
            severity=r["severity"],
            cve=r["cve"],
            cvss=r["cvss"],
            source_tool=r["source_tool"],
            raw_evidence=r["raw_evidence"],
            remediation_text=r["remediation_text"]
        ))
        
    conn.close()
    return findings

def clear_db(db_path: Path) -> None:
    """Clear all records from findings table."""
    conn = get_db_connection(db_path)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM findings")
    conn.commit()
    conn.close()
