"""
Findings analyzer.

Deduplicates, normalizes, scores, and enriches findings
from all scanner phases.
"""


class Analyzer:
    """Phase 4: Analyze, deduplicate, and score all findings."""

    RISK_LEVELS = {
        "CRITICAL": {"likelihood": 5, "impact": 5, "min_score": 20},
        "HIGH": {"likelihood": 4, "impact": 4, "min_score": 12},
        "MEDIUM": {"likelihood": 3, "impact": 3, "min_score": 6},
        "LOW": {"likelihood": 2, "impact": 2, "min_score": 2},
        "INFORMATIONAL": {"likelihood": 1, "impact": 1, "min_score": 1},
    }

    OWASP_MAPPING = {
        "OTG-AUTHZ": "A01:2021 Broken Access Control",
        "OTG-CRYPST": "A02:2021 Cryptographic Failures",
        "OTG-INPVAL": "A03:2021 Injection",
        "OTG-CONFIG": "A05:2021 Security Misconfiguration",
        "DEP-NPM": "A06:2021 Vulnerable and Outdated Components",
        "DEP-PIP": "A06:2021 Vulnerable and Outdated Components",
        "DEP-TRIVY": "A06:2021 Vulnerable and Outdated Components",
        "OTG-AUTHN": "A07:2021 Identification and Authentication Failures",
        "OTG-IDENT": "A07:2021 Identification and Authentication Failures",
        "SAST-SEMGREP": "A03:2021 Injection",
        "SAST-LINT": "A03:2021 Injection",
        "OTG-SESS": "A07:2021 Identification and Authentication Failures",
        "OTG-ERR": "A05:2021 Security Misconfiguration",
        "OTG-CLIENT": "A03:2021 Injection",
        "OTG-INFO": "A05:2021 Security Misconfiguration",
        "OTG-BUSLOGIC": "A04:2021 Insecure Design",
        "NEMO-PIR": "AI Safety: Prompt Injection",
        "NEMO-JBR": "AI Safety: Jailbreak Resistance",
        "NEMO-TBD": "AI Safety: Toxicity/Bias",
        "NEMO-TBE": "AI Safety: Topic Boundaries",
        "NEMO-PII": "AI Safety: PII Leakage",
        "NEMO-HAL": "AI Safety: Hallucination",
    }

    def analyze(self, findings: list) -> list:
        """Deduplicate, enrich, and score all findings."""
        deduped = self._deduplicate(findings)

        for finding in deduped:
            self._enrich(finding)

        # Sort by severity
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}
        deduped.sort(key=lambda f: severity_order.get(f.get("severity", "INFORMATIONAL"), 5))

        return deduped

    def _deduplicate(self, findings: list) -> list:
        """Remove duplicate findings (same file + line + rule)."""
        seen = set()
        unique = []

        for f in findings:
            key = (
                f.get("file", ""),
                f.get("line", 0),
                f.get("rule_id", ""),
                f.get("title", ""),
            )
            if key not in seen:
                seen.add(key)
                unique.append(f)

        return unique

    def _enrich(self, finding: dict):
        """Add risk score, OWASP mapping, and normalize fields."""
        sev = finding.get("severity", "INFORMATIONAL")
        risk_info = self.RISK_LEVELS.get(sev, self.RISK_LEVELS["INFORMATIONAL"])

        finding["likelihood"] = risk_info["likelihood"]
        finding["impact"] = risk_info["impact"]
        finding["risk_score"] = risk_info["likelihood"] * risk_info["impact"]

        # OWASP Top 10 mapping
        category = finding.get("category", "")
        finding["owasp_category"] = self.OWASP_MAPPING.get(category, "Uncategorized")

        # Ensure all required fields exist
        finding.setdefault("remediation", "")
        finding.setdefault("file", "")
        finding.setdefault("line", 0)
        finding.setdefault("description", "")
        finding.setdefault("status", "FAIL" if sev != "INFORMATIONAL" else "INFO")

    def count_by_severity(self, findings: list) -> dict:
        """Count findings by severity level."""
        counts = {}
        for f in findings:
            sev = f.get("severity", "INFORMATIONAL")
            # Skip N/A entries
            if f.get("status") == "N/A":
                continue
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    def overall_posture(self, severity_counts: dict) -> str:
        """Determine overall security posture rating."""
        if severity_counts.get("CRITICAL", 0) > 0:
            return "CRITICAL"
        if severity_counts.get("HIGH", 0) >= 3:
            return "HIGH RISK"
        if severity_counts.get("HIGH", 0) > 0:
            return "MODERATE RISK"
        if severity_counts.get("MEDIUM", 0) > 3:
            return "MODERATE RISK"
        if severity_counts.get("MEDIUM", 0) > 0:
            return "LOW RISK"
        return "STRONG"
