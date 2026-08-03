import time
import requests
from urllib.parse import urlparse
from typing import List, Optional, Dict, Any
from backend.models.finding import Finding

class ZapScanner:
    """
    OWASP ZAP scanner integration.
    Communicates with the ZAP daemon REST API over HTTP.
    """

    def __init__(self, api_url: str = "http://localhost:8080", api_key: Optional[str] = None):
        self.api_url = api_url.rstrip("/")
        self.api_key = api_key or ""

    def _get_headers(self) -> Dict[str, str]:
        headers = {}
        if self.api_key:
            headers["X-ZAP-API-Key"] = self.api_key
        return headers

    def _get_params(self, extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        params = {}
        if self.api_key:
            params["apikey"] = self.api_key
        if extra:
            params.update(extra)
        return params

    def is_available(self) -> bool:
        """Check if ZAP is running and reachable."""
        try:
            # Call a simple view endpoint
            res = requests.get(
                f"{self.api_url}/JSON/core/view/version/", 
                params=self._get_params(), 
                headers=self._get_headers(),
                timeout=2
            )
            return res.status_code == 200
        except Exception:
            return False

    def scan(self, target_url: str) -> List[Finding]:
        """
        Run a quick Spider scan, then an Active scan, and fetch findings.
        This blocks until the scan is fully complete.
        """
        if not self.is_available():
            raise RuntimeError(
                f"OWASP ZAP is not reachable at {self.api_url}. "
                "Ensure the ZAP daemon is running and settings are correct."
            )

        # 1. Access target to populate site tree
        try:
            requests.get(target_url, timeout=10)
        except Exception as e:
            raise RuntimeError(f"Failed to connect to target URL: {e}")

        # 2. Trigger Spider scan
        spider_id = self.start_spider(target_url)
        while True:
            progress = self.get_spider_status(spider_id)
            if progress >= 100:
                break
            time.sleep(2)

        # 3. Trigger Active Scan
        ascan_id = self.start_active_scan(target_url)
        while True:
            progress = self.get_active_scan_status(ascan_id)
            if progress >= 100:
                break
            time.sleep(5)

        # 4. Fetch and map alerts
        return self.get_alerts(target_url)

    def start_spider(self, target_url: str) -> str:
        """Start spider scan and return the scan ID."""
        url = f"{self.api_url}/JSON/spider/action/scan/"
        params = self._get_params({"url": target_url})
        res = requests.get(url, params=params, headers=self._get_headers())
        res.raise_for_status()
        return res.json().get("scan", "")

    def get_spider_status(self, scan_id: str) -> int:
        """Get spider scan progress as an integer percentage."""
        url = f"{self.api_url}/JSON/spider/view/status/"
        params = self._get_params({"scanId": scan_id})
        res = requests.get(url, params=params, headers=self._get_headers())
        res.raise_for_status()
        return int(res.json().get("status", 0))

    def start_active_scan(self, target_url: str) -> str:
        """Start active scan and return the scan ID."""
        url = f"{self.api_url}/JSON/ascan/action/scan/"
        params = self._get_params({"url": target_url, "recurse": "true"})
        res = requests.get(url, params=params, headers=self._get_headers())
        res.raise_for_status()
        return res.json().get("scan", "")

    def get_active_scan_status(self, scan_id: str) -> int:
        """Get active scan progress as an integer percentage."""
        url = f"{self.api_url}/JSON/ascan/view/status/"
        params = self._get_params({"scanId": scan_id})
        res = requests.get(url, params=params, headers=self._get_headers())
        res.raise_for_status()
        return int(res.json().get("status", 0))

    def get_alerts(self, target_url: Optional[str] = None) -> List[Finding]:
        """Fetch findings (alerts) from ZAP, optionally filtered by target base URL."""
        url = f"{self.api_url}/JSON/core/view/alerts/"
        params = self._get_params()
        if target_url:
            params["baseurl"] = target_url
            
        res = requests.get(url, params=params, headers=self._get_headers())
        res.raise_for_status()
        
        # ZAP API returns alerts under {"alerts": [...]}
        alerts_data = res.json()
        return self.parse_alerts(alerts_data)

    def parse_alerts(self, alerts_data: Dict[str, Any]) -> List[Finding]:
        """Map ZAP raw alert response to normalized Finding objects."""
        findings: List[Finding] = []
        alerts = alerts_data.get("alerts", [])
        if not alerts:
            # Sometimes ZAP returns a list directly depending on endpoint
            if isinstance(alerts_data, list):
                alerts = alerts_data
            else:
                return findings

        for alert in alerts:
            vuln_url = alert.get("url", "")
            parsed_url = urlparse(vuln_url)
            
            host = parsed_url.hostname or "Unknown"
            
            # Determine port from URL
            port = parsed_url.port
            if not port:
                if parsed_url.scheme == "https":
                    port = 443
                elif parsed_url.scheme == "http":
                    port = 80
                    
            # Map ZAP risk levels to unified severity
            # ZAP has: Informational, Low, Medium, High
            zap_risk = alert.get("risk", "Informational")
            severity_map = {
                "Informational": "Info",
                "Low": "Low",
                "Medium": "Medium",
                "High": "High"
            }
            severity = severity_map.get(zap_risk, "Info")

            # Extract CVE
            cve = None
            reference = alert.get("reference", "")
            # Simple heuristic search for CVE-XXXX-XXXX
            import re
            cve_match = re.search(r"CVE-\d{4}-\d{4,}", reference)
            if cve_match:
                cve = cve_match.group(0)

            title = alert.get("name", "Vulnerability Alert")
            description = (
                f"{alert.get('description', '')}\n\n"
                f"**Vulnerable URL:** {vuln_url}\n"
                f"**Confidence:** {alert.get('confidence', '')}\n"
                f"**CWE ID:** {alert.get('cweid', 'N/A')}"
            )
            
            evidence = (
                f"Evidence: {alert.get('evidence', '')}\n"
                f"Parameter: {alert.get('param', '')}\n"
                f"Attack: {alert.get('attack', '')}\n"
                f"Other Info: {alert.get('other', '')}"
            )

            remediation = f"{alert.get('solution', '')}\nReference: {reference}".strip()

            findings.append(Finding(
                host=host,
                port=port,
                protocol=parsed_url.scheme,
                service="http",
                title=title,
                description=description,
                severity=severity,
                cve=cve,
                cvss=None, # ZAP doesn't provide standard CVSS base scores natively
                source_tool="ZAP",
                raw_evidence=evidence,
                remediation_text=remediation
            ))

        return findings
