"""
Report generator.

Produces attestation reports in Markdown, JSON, and JUnit XML formats.
"""

import json
import os
from datetime import datetime
from pathlib import Path
from xml.etree.ElementTree import Element, SubElement, tostring
from xml.dom.minidom import parseString


class Reporter:
    """Phase 5: Generate attestation report documents."""

    def __init__(self, output_dir: str, project_info: dict, scan_mode: str, elapsed_seconds: float,
                 fix_mode: bool = False, before_counts: dict = None, after_counts: dict = None):
        self.output_dir = Path(output_dir)
        self.project_info = project_info
        self.scan_mode = scan_mode
        self.elapsed = elapsed_seconds
        self.fix_mode = fix_mode
        self.before_counts = before_counts
        self.after_counts = after_counts
        self.timestamp = datetime.now()
        self.date_str = self.timestamp.strftime("%Y-%m-%d")

        # Determine version (increment for same-day scans)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        existing = list(self.output_dir.glob(f"{self.date_str}-v*.md"))
        self.version = len(existing) + 1
        self.base_name = f"{self.date_str}-v{self.version}"

    def generate_markdown(self, findings: list, severity_counts: dict) -> str:
        """Generate the full markdown attestation report."""
        path = self.output_dir / f"{self.base_name}.md"
        lines = []

        # Header
        lines.append("# Security Attestation Report")
        lines.append("")
        lines.append(f"> **Application:** {self.project_info['name']}")
        lines.append(f"> **Generated:** {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"> **Attestation Version:** v{self.version}")
        lines.append(f"> **Scan Mode:** {self.scan_mode}")
        lines.append(f"> **Auditor:** scan-it (automated security attestation)")
        lines.append(f"> **AI Features Present:** {'YES' if self.project_info['ai_features'] else 'NO'}")
        lines.append("")
        lines.append("---")
        lines.append("")

        # Executive Summary
        lines.append("## Executive Summary")
        lines.append("")
        posture = self._posture(severity_counts)
        total = sum(severity_counts.values())
        lines.append(f"**Overall Risk Posture:** {posture}")
        lines.append("")
        lines.append(f"This scan identified **{total}** findings across the project.")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Total findings | {total} |")
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
            lines.append(f"| {sev.capitalize()} | {severity_counts.get(sev, 0)} |")
        lines.append(f"| Scan duration | {self.elapsed:.1f}s |")
        lines.append("")
        lines.append("---")
        lines.append("")

        # Fix-It Before/After Comparison (when --fix-it was used)
        if self.fix_mode and self.before_counts and self.after_counts:
            lines.append("## Fix-It: Before / After Comparison")
            lines.append("")
            lines.append("| Severity | Before | After | Fixed | Remaining |")
            lines.append("|----------|--------|-------|-------|-----------|")
            total_before = 0
            total_after = 0
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
                before = self.before_counts.get(sev, 0)
                after = self.after_counts.get(sev, 0)
                fixed = before - after
                total_before += before
                total_after += after
                lines.append(f"| {sev} | {before} | {after} | {fixed} | {after} |")
            lines.append(f"| **TOTAL** | **{total_before}** | **{total_after}** | "
                         f"**{total_before - total_after}** | **{total_after}** |")
            lines.append("")
            lines.append("---")
            lines.append("")

        # Scan Coverage
        lines.append("## Scan Coverage")
        lines.append("")
        lines.append("| Phase | Status | Findings |")
        lines.append("|-------|--------|----------|")

        phase_counts = self._count_by_phase(findings)
        phases = [
            ("Static Analysis (SAST)", ["SAST-SEMGREP", "SAST-LINT"], self.scan_mode in ("full", "sast")),
            ("Dependency Scanning", ["DEP-NPM", "DEP-PIP", "DEP-TRIVY"], self.scan_mode in ("full", "deps")),
            ("OWASP Testing Guide", ["OTG-INFO", "OTG-CONFIG", "OTG-IDENT", "OTG-AUTHN", "OTG-AUTHZ",
                                      "OTG-SESS", "OTG-INPVAL", "OTG-ERR", "OTG-CRYPST", "OTG-BUSLOGIC",
                                      "OTG-CLIENT"], self.scan_mode in ("full", "owasp")),
            ("AI Safety (NeMo)", ["NEMO-PIR", "NEMO-JBR", "NEMO-TBD", "NEMO-TBE", "NEMO-PII", "NEMO-HAL"],
             self.scan_mode in ("full", "guardrails")),
        ]
        for name, cats, ran in phases:
            count = sum(phase_counts.get(c, 0) for c in cats)
            status = "Completed" if ran else "Skipped"
            lines.append(f"| {name} | {status} | {count} |")

        lines.append("")
        lines.append(f"**Languages:** {', '.join(self.project_info['languages']) or 'unknown'}")
        lines.append(f"**Frameworks:** {', '.join(self.project_info['frameworks']) or 'none detected'}")
        lines.append("")
        lines.append("---")
        lines.append("")

        # OWASP Top 10 Mapping
        lines.append("## OWASP Top 10 (2021) Coverage")
        lines.append("")
        owasp_map = self._owasp_top10_coverage(findings)
        lines.append("| Category | Findings | Status |")
        lines.append("|----------|----------|--------|")
        for cat, info in owasp_map.items():
            status = "FAIL" if info["count"] > 0 else "PASS"
            lines.append(f"| {cat} | {info['count']} | {status} |")
        lines.append("")
        lines.append("---")
        lines.append("")

        # Summary Dashboard
        lines.append("## Category Dashboard")
        lines.append("")
        lines.append("| # | Suite | Category | ID | Status | Findings | Highest |")
        lines.append("|---|-------|----------|----|--------|----------|---------|")

        dashboard_rows = self._build_dashboard(findings)
        for i, row in enumerate(dashboard_rows, 1):
            lines.append(f"| {i} | {row['suite']} | {row['category']} | {row['id']} | {row['status']} | {row['count']} | {row['highest']} |")

        lines.append("")
        lines.append("---")
        lines.append("")

        # Findings by severity
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
            sev_findings = [f for f in findings if f.get("severity") == sev and f.get("status") != "N/A"]
            if not sev_findings:
                continue

            lines.append(f"## {sev.capitalize()} Findings")
            lines.append("")

            for f in sev_findings:
                lines.append(f"### {f.get('rule_id', 'N/A')}: {f['title']}")
                lines.append("")
                lines.append(f"- **Severity:** {f['severity']}")
                lines.append(f"- **Tool:** {f.get('tool', 'N/A')}")
                lines.append(f"- **Category:** {f.get('category', 'N/A')}")
                if f.get("file"):
                    loc = f['file']
                    if f.get("line"):
                        loc += f":{f['line']}"
                    lines.append(f"- **Location:** `{loc}`")
                lines.append(f"- **OWASP:** {f.get('owasp_category', 'N/A')}")
                lines.append(f"- **Risk Score:** {f.get('risk_score', 'N/A')} "
                            f"(Likelihood: {f.get('likelihood', 'N/A')} x Impact: {f.get('impact', 'N/A')})")
                lines.append("")
                lines.append(f"**What:** {f.get('description', 'N/A')}")
                lines.append("")

                # AI Validation section (populated by Phase 4.5)
                if f.get("validation"):
                    v = f["validation"]
                    lines.append("**Validation:**")
                    lines.append("")
                    lines.append(f"- **Assessment:** True Positive "
                                 f"(confidence: {v.get('confidence', 'N/A')})")
                    lines.append(f"- **Reasoning:** {v.get('reasoning', 'N/A')}")
                    lines.append(f"- **What to Test:** {v.get('validation_request', 'N/A')}")
                    lines.append(f"- **Expected Result:** {v.get('validation_result', 'N/A')}")
                    if v.get("developer_instructions"):
                        lines.append("")
                        lines.append("**Developer Verification Steps:**")
                        lines.append("")
                        lines.append("```bash")
                        lines.append(v["developer_instructions"])
                        lines.append("```")
                    lines.append("")

                # Fix Info section (populated by Phase 4.7)
                if f.get("fix_info"):
                    fi = f["fix_info"]
                    if fi.get("status") != "skipped":
                        lines.append("**Fix:**")
                        lines.append("")
                        lines.append(f"- **Classification:** {fi.get('classification', 'N/A')}")
                        lines.append(f"- **Status:** {fi.get('status', 'N/A')}")
                        lines.append(f"- **Fix Type:** {fi.get('fix_type', 'N/A')}")
                        lines.append(f"- **Explanation:** {fi.get('explanation', 'N/A')}")
                        if fi.get("diff"):
                            lines.append("")
                            lines.append("**Patch:**")
                            lines.append("")
                            lines.append("```diff")
                            lines.append(fi["diff"])
                            lines.append("```")
                        if fi.get("guidance"):
                            lines.append("")
                            lines.append(f"**Guidance:** {fi['guidance']}")
                        lines.append("")

                if f.get("remediation"):
                    lines.append(f"**Remediation:** {f['remediation']}")
                    lines.append("")
                lines.append("---")
                lines.append("")

        # AI Safety Assessment
        lines.append("## AI Safety Assessment")
        lines.append("")
        if self.project_info["ai_features"]:
            nemo_findings = [f for f in findings if f.get("category", "").startswith("NEMO-")]
            if nemo_findings:
                lines.append("| Category | Status | Findings |")
                lines.append("|----------|--------|----------|")
                nemo_cats = {
                    "NEMO-PIR": "Prompt Injection Resistance",
                    "NEMO-JBR": "Jailbreak Resistance",
                    "NEMO-TBD": "Toxicity / Bias Detection",
                    "NEMO-TBE": "Topic Boundary Enforcement",
                    "NEMO-PII": "PII Leakage Prevention",
                    "NEMO-HAL": "Hallucination Detection",
                }
                for cat_id, cat_name in nemo_cats.items():
                    cat_findings = [f for f in nemo_findings if f["category"] == cat_id and f.get("status") != "N/A"]
                    count = len(cat_findings)
                    status = "FAIL" if count > 0 else "PASS"
                    lines.append(f"| {cat_name} | {status} | {count} |")
                lines.append("")
            else:
                lines.append("All NeMo Guardrails categories passed.")
                lines.append("")
        else:
            lines.append("No AI features detected. All NeMo Guardrails categories marked N/A.")
            lines.append("")

        lines.append("---")
        lines.append("")

        # Recommendations
        lines.append("## Recommendations")
        lines.append("")
        critical_high = [f for f in findings if f["severity"] in ("CRITICAL", "HIGH") and f.get("status") != "N/A"]
        medium = [f for f in findings if f["severity"] == "MEDIUM" and f.get("status") != "N/A"]

        if critical_high:
            lines.append("### Immediate (Critical/High)")
            lines.append("")
            for f in critical_high[:10]:
                lines.append(f"1. **{f['title']}** ({f['severity']})")
                if f.get("remediation"):
                    lines.append(f"   - {f['remediation'][:200]}")
            lines.append("")

        if medium:
            lines.append("### Short-term (Medium)")
            lines.append("")
            for f in medium[:10]:
                lines.append(f"1. **{f['title']}** ({f['severity']})")
                if f.get("remediation"):
                    lines.append(f"   - {f['remediation'][:200]}")
            lines.append("")

        lines.append("---")
        lines.append("")

        # Metadata
        lines.append("## Attestation Metadata")
        lines.append("")
        lines.append(f"- Scan completed: {self.timestamp.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append(f"- Duration: {self.elapsed:.1f}s")
        lines.append(f"- Scan mode: {self.scan_mode}")
        lines.append("- Safe testing constraints: All tests were non-destructive. No exploits were executed.")
        lines.append("")
        lines.append("---")
        lines.append("")
        lines.append("*This attestation is informational only. It is intended to support GRC oversight "
                     "and continuous risk monitoring.*")
        lines.append("")
        lines.append("*Generated by scan-it v1.0.0*")

        path.write_text("\n".join(lines))
        return str(path)

    def generate_json(self, findings: list, severity_counts: dict) -> str:
        """Generate JSON attestation report."""
        path = self.output_dir / f"{self.base_name}.json"

        report = {
            "meta": {
                "application": self.project_info["name"],
                "generated": self.timestamp.isoformat(),
                "version": f"v{self.version}",
                "scan_mode": self.scan_mode,
                "auditor": "scan-it",
                "duration_seconds": round(self.elapsed, 1),
                "ai_features": self.project_info["ai_features"],
                "languages": self.project_info["languages"],
                "frameworks": self.project_info["frameworks"],
            },
            "summary": {
                "posture": self._posture(severity_counts),
                "total_findings": sum(severity_counts.values()),
                "severity_counts": severity_counts,
            },
            "findings": [
                {
                    "id": f.get("rule_id", ""),
                    "title": f.get("title", ""),
                    "severity": f.get("severity", ""),
                    "category": f.get("category", ""),
                    "owasp_category": f.get("owasp_category", ""),
                    "tool": f.get("tool", ""),
                    "file": f.get("file", ""),
                    "line": f.get("line", 0),
                    "description": f.get("description", ""),
                    "remediation": f.get("remediation", ""),
                    "risk_score": f.get("risk_score", 0),
                    "likelihood": f.get("likelihood", 0),
                    "impact": f.get("impact", 0),
                    "status": f.get("status", ""),
                    "validation": f.get("validation", None),
                    "fix_info": f.get("fix_info", None),
                }
                for f in findings
                if f.get("status") != "N/A"
            ],
        }

        path.write_text(json.dumps(report, indent=2))
        return str(path)

    def generate_junit(self, findings: list, severity_counts: dict) -> str:
        """Generate JUnit XML for CI/CD integration."""
        path = self.output_dir / f"{self.base_name}-junit.xml"

        testsuites = Element("testsuites")
        testsuites.set("name", f"scan-it: {self.project_info['name']}")
        testsuites.set("time", f"{self.elapsed:.1f}")

        # Group findings by category
        categories = {}
        for f in findings:
            if f.get("status") == "N/A":
                continue
            cat = f.get("category", "uncategorized")
            categories.setdefault(cat, []).append(f)

        for cat_name, cat_findings in categories.items():
            testsuite = SubElement(testsuites, "testsuite")
            testsuite.set("name", cat_name)
            testsuite.set("tests", str(len(cat_findings)))

            failures = [f for f in cat_findings if f.get("severity") in ("CRITICAL", "HIGH", "MEDIUM")]
            testsuite.set("failures", str(len(failures)))

            for f in cat_findings:
                testcase = SubElement(testsuite, "testcase")
                testcase.set("name", f.get("title", "Unknown"))
                testcase.set("classname", f.get("category", ""))

                if f.get("severity") in ("CRITICAL", "HIGH", "MEDIUM"):
                    failure = SubElement(testcase, "failure")
                    failure.set("type", f.get("severity", ""))
                    failure.set("message", f.get("description", "")[:500])
                    failure.text = f"File: {f.get('file', 'N/A')}:{f.get('line', 0)}\n" \
                                  f"Remediation: {f.get('remediation', 'N/A')}"

        xml_str = tostring(testsuites, encoding="unicode")
        pretty = parseString(xml_str).toprettyxml(indent="  ")
        path.write_text(pretty)
        return str(path)

    # ---- Helpers ----

    def _posture(self, severity_counts: dict) -> str:
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

    def _count_by_phase(self, findings: list) -> dict:
        counts = {}
        for f in findings:
            if f.get("status") == "N/A":
                continue
            cat = f.get("category", "")
            counts[cat] = counts.get(cat, 0) + 1
        return counts

    def _owasp_top10_coverage(self, findings: list) -> dict:
        owasp = {
            "A01:2021 Broken Access Control": {"count": 0},
            "A02:2021 Cryptographic Failures": {"count": 0},
            "A03:2021 Injection": {"count": 0},
            "A04:2021 Insecure Design": {"count": 0},
            "A05:2021 Security Misconfiguration": {"count": 0},
            "A06:2021 Vulnerable and Outdated Components": {"count": 0},
            "A07:2021 Identification and Authentication Failures": {"count": 0},
            "A08:2021 Software and Data Integrity Failures": {"count": 0},
            "A09:2021 Security Logging and Monitoring Failures": {"count": 0},
            "A10:2021 Server-Side Request Forgery": {"count": 0},
        }

        for f in findings:
            if f.get("status") == "N/A":
                continue
            owasp_cat = f.get("owasp_category", "")
            if owasp_cat in owasp:
                owasp[owasp_cat]["count"] += 1

        return owasp

    def _build_dashboard(self, findings: list) -> list:
        """Build the 22-category dashboard."""
        dashboard_defs = [
            ("NeMo Guardrails AI Safety", "Prompt Injection Resistance", "NEMO-PIR"),
            ("NeMo Guardrails AI Safety", "Jailbreak Resistance", "NEMO-JBR"),
            ("NeMo Guardrails AI Safety", "Toxicity / Bias Detection", "NEMO-TBD"),
            ("NeMo Guardrails AI Safety", "Topic Boundary Enforcement", "NEMO-TBE"),
            ("NeMo Guardrails AI Safety", "PII Leakage Prevention", "NEMO-PII"),
            ("NeMo Guardrails AI Safety", "Hallucination Detection", "NEMO-HAL"),
            ("OWASP Testing Guide", "Information Gathering", "OTG-INFO"),
            ("OWASP Testing Guide", "Configuration & Deployment", "OTG-CONFIG"),
            ("OWASP Testing Guide", "Identity Management", "OTG-IDENT"),
            ("OWASP Testing Guide", "Authentication", "OTG-AUTHN"),
            ("OWASP Testing Guide", "Authorization", "OTG-AUTHZ"),
            ("OWASP Testing Guide", "Session Management", "OTG-SESS"),
            ("OWASP Testing Guide", "Input Validation", "OTG-INPVAL"),
            ("OWASP Testing Guide", "Error Handling", "OTG-ERR"),
            ("OWASP Testing Guide", "Cryptography", "OTG-CRYPST"),
            ("OWASP Testing Guide", "Business Logic", "OTG-BUSLOGIC"),
            ("OWASP Testing Guide", "Client-Side", "OTG-CLIENT"),
            ("Dependency & Container", "npm audit", "DEP-NPM"),
            ("Dependency & Container", "pip-audit", "DEP-PIP"),
            ("Dependency & Container", "Trivy Container Scan", "DEP-TRIVY"),
            ("Static Analysis", "Semgrep", "SAST-SEMGREP"),
            ("Static Analysis", "Bandit / ESLint Security", "SAST-LINT"),
        ]

        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFORMATIONAL": 4}
        rows = []

        for suite, category, cat_id in dashboard_defs:
            cat_findings = [f for f in findings if f.get("category") == cat_id]
            non_na = [f for f in cat_findings if f.get("status") != "N/A"]
            na_only = len(cat_findings) > 0 and len(non_na) == 0

            count = len(non_na)
            if na_only:
                status = "N/A"
                highest = "N/A"
            elif count > 0:
                status = "FAIL"
                highest = min(
                    (f.get("severity", "INFORMATIONAL") for f in non_na),
                    key=lambda s: severity_order.get(s, 5),
                )
            else:
                status = "PASS"
                highest = "-"

            rows.append({
                "suite": suite,
                "category": category,
                "id": cat_id,
                "status": status,
                "count": count,
                "highest": highest,
            })

        return rows
