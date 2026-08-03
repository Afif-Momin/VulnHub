import shutil
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import List, Optional
from backend.models.finding import Finding

class NmapScanner:
    """
    Nmap scanner integration.
    Supports executing a live scan using cross-platform safe subprocess calls
    or parsing an existing XML output file.
    """

    def __init__(self, binary_path: Optional[str] = None):
        # Resolve binary path safely
        if binary_path:
            self.binary_path = binary_path
        else:
            self.binary_path = shutil.which("nmap")

    def is_available(self) -> bool:
        """Check if the nmap binary is available on the system PATH."""
        return self.binary_path is not None

    def scan(self, target: str, args: Optional[List[str]] = None) -> List[Finding]:
        """
        Execute Nmap scan on the target and return normalized findings.
        Raises RuntimeError if Nmap is not installed.
        """
        if not self.is_available():
            raise RuntimeError(
                "Nmap binary not found on system PATH. "
                "Please install Nmap from https://nmap.org/ (Windows) "
                "or run 'sudo apt install nmap' (Ubuntu)."
            )

        if not args:
            # -sT is TCP connect scan (does not require administrator/root privileges)
            # -F is fast scan (top 100 ports)
            args = ["-sT", "-F"]

        # Build cross-platform execution list
        cmd = [self.binary_path] + args + ["-oX", "-", target]

        try:
            # Run subprocess without Unix shell dependency
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                check=True
            )
            return self.parse_xml_string(result.stdout)
        except subprocess.CalledProcessError as e:
            error_msg = e.stderr or e.stdout or str(e)
            raise RuntimeError(f"Nmap scan failed: {error_msg}")
        except Exception as e:
            raise RuntimeError(f"An error occurred executing Nmap: {str(e)}")

    def parse_xml_file(self, file_path: Path) -> List[Finding]:
        """Parse an existing Nmap XML report file into normalized Finding objects."""
        if not file_path.exists():
            raise FileNotFoundError(f"Nmap XML file not found at: {file_path}")
        
        with open(file_path, "r", encoding="utf-8") as f:
            xml_content = f.read()
        return self.parse_xml_string(xml_content)

    def parse_xml_string(self, xml_content: str) -> List[Finding]:
        """Parse Nmap XML string into normalized Finding objects."""
        findings: List[Finding] = []
        if not xml_content.strip():
            return findings

        try:
            root = ET.fromstring(xml_content)
        except ET.ParseError as e:
            raise ValueError(f"Failed to parse Nmap XML content: {e}")

        # Iterate over each <host> element
        for host_elem in root.findall("host"):
            # Determine host address
            address_elem = host_elem.find("address")
            host_ip = address_elem.get("addr") if address_elem is not None else "Unknown"

            # Check hostnames
            hostnames_elem = host_elem.find("hostnames")
            hostname = host_ip
            if hostnames_elem is not None:
                name_elem = hostnames_elem.find("hostname")
                if name_elem is not None:
                    hostname = name_elem.get("name")

            # Status check (up/down)
            status_elem = host_elem.find("status")
            status = status_elem.get("state") if status_elem is not None else "unknown"
            if status != "up":
                continue

            # Iterate over open ports
            ports_elem = host_elem.find("ports")
            if ports_elem is not None:
                for port_elem in ports_elem.findall("port"):
                    state_elem = port_elem.find("state")
                    state = state_elem.get("state") if state_elem is not None else "unknown"
                    
                    # We only care about open ports/services
                    if state != "open":
                        continue

                    port_id = int(port_elem.get("portid"))
                    protocol = port_elem.get("protocol")

                    service_elem = port_elem.find("service")
                    service_name = service_elem.get("name") if service_elem is not None else "unknown"
                    product = service_elem.get("product") if service_elem is not None else ""
                    version = service_elem.get("version") if service_elem is not None else ""
                    
                    service_details = f"{service_name}"
                    if product:
                        service_details += f" ({product} {version})".strip()

                    title = f"Open Port Detected: {port_id}/{protocol} ({service_name})"
                    description = (
                        f"The port {port_id}/{protocol} is open on target host {hostname} ({host_ip}) "
                        f"running service '{service_details}'."
                    )
                    
                    # Default severity logic based on port classification
                    severity = "Info"
                    remediation = "Close this port if the service is not required for business operations. Secure the service with authentication and encryption."
                    
                    # Basic rule mapping directly in scanner for default Nmap info
                    unsafe_services = {
                        "telnet": ("Medium", "Telnet transmits data in plaintext. Replace with SSH."),
                        "ftp": ("Low", "FTP transmits credentials in cleartext. Upgrade to SFTP/FTPS or restrict access."),
                        "http": ("Info", "Ensure SSL/TLS is enabled (HTTPS) on port 443 instead of HTTP on port 80 where applicable."),
                    }
                    
                    if service_name in unsafe_services:
                        severity, remediation = unsafe_services[service_name]

                    findings.append(Finding(
                        host=host_ip,
                        port=port_id,
                        protocol=protocol,
                        service=service_name,
                        title=title,
                        description=description,
                        severity=severity,
                        source_tool="Nmap",
                        raw_evidence=ET.tostring(port_elem, encoding="utf-8").decode("utf-8"),
                        remediation_text=remediation
                    ))

        return findings
