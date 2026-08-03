from typing import Optional, Dict, Any
from pydantic import BaseModel, Field

class Finding(BaseModel):
    """
    Normalized data model representing a single vulnerability or scan finding.
    All scanners must map their output onto this unified structure.
    """
    host: str = Field(..., description="Target hostname or IP address")
    port: Optional[int] = Field(None, description="Port number associated with the finding")
    protocol: Optional[str] = Field(None, description="Protocol used (e.g., tcp, udp)")
    service: Optional[str] = Field(None, description="Service name if available (e.g., http, ssh)")
    title: str = Field(..., description="Short summary/title of the finding")
    description: str = Field(..., description="Detailed description of the finding")
    severity: str = Field(..., description="Severity level: Critical, High, Medium, Low, or Info")
    cve: Optional[str] = Field(None, description="Associated CVE ID (e.g., CVE-2023-1234)")
    cvss: Optional[float] = Field(None, description="CVSS base score if available (0.0 to 10.0)")
    source_tool: str = Field(..., description="The tool that generated this finding (e.g., Nmap, ZAP, OpenVAS)")
    raw_evidence: Optional[str] = Field(None, description="Raw details, output, or payload from the scanner")
    remediation_text: Optional[str] = Field(None, description="Actionable advice for fixing the finding")
