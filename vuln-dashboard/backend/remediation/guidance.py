import json
from pathlib import Path
from typing import List, Dict, Any, Optional
from backend.models.finding import Finding

class RemediationEngine:
    """
    Data-driven categorization and remediation engine.
    Loads classification rules from a JSON config file and normalizes findings.
    """

    def __init__(self, rules_path: Optional[Path] = None):
        if not rules_path:
            rules_path = Path(__file__).resolve().parent / "rules.json"
        
        self.rules_path = rules_path
        self.rules: List[Dict[str, Any]] = []
        self.load_rules()

    def load_rules(self) -> None:
        """Load rules list from rules.json."""
        if not self.rules_path.exists():
            # Fallback to default rules if file is missing
            self.rules = []
            return
        
        try:
            with open(self.rules_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                self.rules = data.get("rules", [])
        except Exception:
            self.rules = []

    def enrich_finding(self, finding: Finding) -> Finding:
        """
        Apply matching rules to enrich or override severity and remediation text.
        Returns the modified Finding object.
        """
        title_lower = finding.title.lower()
        desc_lower = finding.description.lower()

        # Find matching pattern
        for rule in self.rules:
            pattern = rule.get("pattern", "").lower()
            if not pattern:
                continue

            if pattern in title_lower or pattern in desc_lower:
                # Update severity if rule has a higher priority or we want to standardize
                rule_severity = rule.get("severity")
                if rule_severity:
                    # Severity priority ranking: Critical > High > Medium > Low > Info
                    priority = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Info": 1}
                    current_pri = priority.get(finding.severity, 0)
                    rule_pri = priority.get(rule_severity, 0)
                    
                    # If rule defines higher severity, upgrade it
                    if rule_pri > current_pri:
                        finding.severity = rule_severity
                
                # Standardize or override remediation text
                rule_remediation = rule.get("remediation")
                if rule_remediation:
                    finding.remediation_text = rule_remediation
                
                # Stop at first match or keep checking? Usually first match is good.
                break

        return finding

    def enrich_findings(self, findings: List[Finding]) -> List[Finding]:
        """Enrich a list of findings in place."""
        return [self.enrich_finding(f) for f in findings]
