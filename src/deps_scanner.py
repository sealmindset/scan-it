"""
Dependency and container scanning.

Runs npm audit, pip-audit, and Trivy for known vulnerabilities
in project dependencies and container images.
"""

import json
import os
import subprocess
from pathlib import Path


class DepsScanner:
    """Phase 1.5: Dependency and container vulnerability scanning."""

    def __init__(self, target_dir: str, project_info: dict):
        self.target = Path(target_dir)
        self.project_info = project_info

    def run(self) -> list:
        findings = []

        if self.project_info.get("has_node"):
            findings.extend(self._run_npm_audit())

        if self.project_info.get("has_python"):
            findings.extend(self._run_pip_audit())

        findings.extend(self._run_trivy())

        return findings

    def _run_npm_audit(self) -> list:
        """Run npm audit for Node.js dependency vulnerabilities."""
        findings = []
        output_file = "/tmp/scan-it-npm-audit.json"

        try:
            cmd = ["npm", "audit", "--json"]
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=120,
                cwd=str(self.target),
            )

            data = json.loads(result.stdout) if result.stdout else {}

            # npm audit v7+ format
            vulns = data.get("vulnerabilities", {})
            for name, info in vulns.items():
                sev = info.get("severity", "low").upper()
                severity = self._normalize_npm_severity(sev)
                via = info.get("via", [])
                desc_parts = []
                cve_ids = []

                for v in via:
                    if isinstance(v, dict):
                        desc_parts.append(v.get("title", ""))
                        if v.get("cve"):
                            cve_ids.append(v["cve"])
                    elif isinstance(v, str):
                        desc_parts.append(f"via {v}")

                findings.append({
                    "tool": "npm-audit",
                    "category": "DEP-NPM",
                    "title": f"Vulnerable package: {name}@{info.get('range', 'unknown')}",
                    "severity": severity,
                    "file": "package-lock.json",
                    "line": 0,
                    "description": "; ".join(desc_parts) or f"Known vulnerability in {name}",
                    "rule_id": ", ".join(cve_ids) or f"npm-{name}",
                    "package": name,
                    "fix_available": info.get("fixAvailable", False),
                    "remediation": f"Run 'npm audit fix' or upgrade {name} to a patched version.",
                })

        except FileNotFoundError:
            print("  WARNING: npm not found, skipping npm audit")
        except json.JSONDecodeError:
            print("  WARNING: npm audit returned invalid JSON")
        except Exception as e:
            print(f"  WARNING: npm audit error: {e}")

        print(f"  npm audit: {len(findings)} findings")
        return findings

    def _run_pip_audit(self) -> list:
        """Run pip-audit for Python dependency vulnerabilities."""
        findings = []
        output_file = "/tmp/scan-it-pip-audit.json"

        # Find requirements file
        req_files = ["requirements.txt", "pyproject.toml", "setup.py"]
        req_path = None
        for rf in req_files:
            if (self.target / rf).exists():
                req_path = rf
                break

        if not req_path:
            print("  pip-audit: no requirements file found, skipping")
            return findings

        try:
            cmd = ["pip-audit", "--format=json", f"--output={output_file}"]
            if req_path == "requirements.txt":
                cmd.extend(["--requirement", str(self.target / req_path)])
            subprocess.run(cmd, capture_output=True, timeout=120, cwd=str(self.target))

            if os.path.exists(output_file):
                with open(output_file) as f:
                    data = json.load(f)

                deps = data if isinstance(data, list) else data.get("dependencies", [])
                for dep in deps:
                    for vuln in dep.get("vulns", []):
                        fix_versions = vuln.get("fix_versions", [])
                        fix_str = ", ".join(fix_versions) if fix_versions else "no fix available"
                        findings.append({
                            "tool": "pip-audit",
                            "category": "DEP-PIP",
                            "title": f"Vulnerable package: {dep['name']}=={dep['version']}",
                            "severity": "HIGH",
                            "file": req_path,
                            "line": 0,
                            "description": f"{vuln['id']}: vulnerability in {dep['name']} {dep['version']}",
                            "rule_id": vuln["id"],
                            "package": dep["name"],
                            "remediation": f"Upgrade {dep['name']} to {fix_str}.",
                        })

        except FileNotFoundError:
            print("  WARNING: pip-audit not found, skipping")
        except Exception as e:
            print(f"  WARNING: pip-audit error: {e}")

        print(f"  pip-audit: {len(findings)} findings")
        return findings

    def _run_trivy(self) -> list:
        """Run Trivy for filesystem and container scanning."""
        findings = []

        # Filesystem scan
        findings.extend(self._trivy_fs_scan())

        # Dockerfile config scan
        if (self.target / "Dockerfile").exists():
            findings.extend(self._trivy_config_scan())

        return findings

    def _trivy_fs_scan(self) -> list:
        """Trivy filesystem dependency scan."""
        findings = []
        output_file = "/tmp/scan-it-trivy-fs.json"

        try:
            cmd = [
                "trivy", "fs",
                "--format", "json",
                "--output", output_file,
                "--severity", "CRITICAL,HIGH,MEDIUM",
                "--skip-dirs", "node_modules",
                "--skip-dirs", ".venv",
                "--skip-dirs", "venv",
                str(self.target),
            ]
            subprocess.run(cmd, capture_output=True, timeout=180)

            if os.path.exists(output_file):
                findings.extend(self._parse_trivy_results(output_file, "DEP-TRIVY"))

        except FileNotFoundError:
            print("  WARNING: trivy not found, skipping filesystem scan")
        except Exception as e:
            print(f"  WARNING: Trivy fs error: {e}")

        print(f"  Trivy filesystem: {len(findings)} findings")
        return findings

    def _trivy_config_scan(self) -> list:
        """Trivy Dockerfile configuration scan."""
        findings = []
        output_file = "/tmp/scan-it-trivy-config.json"

        try:
            cmd = [
                "trivy", "config",
                "--format", "json",
                "--output", output_file,
                str(self.target / "Dockerfile"),
            ]
            subprocess.run(cmd, capture_output=True, timeout=60)

            if os.path.exists(output_file):
                with open(output_file) as f:
                    data = json.load(f)

                for result in data.get("Results", []):
                    for misconfig in result.get("Misconfigurations", []):
                        severity = misconfig.get("Severity", "MEDIUM").upper()
                        findings.append({
                            "tool": "trivy-config",
                            "category": "DEP-TRIVY",
                            "title": misconfig.get("Title", "Dockerfile misconfiguration"),
                            "severity": severity,
                            "file": "Dockerfile",
                            "line": misconfig.get("CauseMetadata", {}).get("StartLine", 0),
                            "description": misconfig.get("Description", ""),
                            "rule_id": misconfig.get("ID", ""),
                            "remediation": misconfig.get("Resolution", ""),
                        })

        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"  WARNING: Trivy config error: {e}")

        if findings:
            print(f"  Trivy config: {len(findings)} findings")
        return findings

    def _parse_trivy_results(self, filepath: str, category: str) -> list:
        """Parse Trivy JSON output into findings."""
        findings = []
        try:
            with open(filepath) as f:
                data = json.load(f)

            for result in data.get("Results", []):
                target = result.get("Target", "")
                for vuln in result.get("Vulnerabilities", []):
                    severity = vuln.get("Severity", "MEDIUM").upper()
                    fix_ver = vuln.get("FixedVersion", "no fix available")
                    findings.append({
                        "tool": "trivy",
                        "category": category,
                        "title": f"{vuln.get('VulnerabilityID', 'Unknown')}: {vuln.get('PkgName', '')}",
                        "severity": severity,
                        "file": target,
                        "line": 0,
                        "description": vuln.get("Description", "")[:300],
                        "rule_id": vuln.get("VulnerabilityID", ""),
                        "package": vuln.get("PkgName", ""),
                        "installed_version": vuln.get("InstalledVersion", ""),
                        "fixed_version": fix_ver,
                        "remediation": f"Upgrade {vuln.get('PkgName', '')} to {fix_ver}.",
                    })
        except Exception:
            pass
        return findings

    def _normalize_npm_severity(self, sev: str) -> str:
        mapping = {
            "CRITICAL": "CRITICAL",
            "HIGH": "HIGH",
            "MODERATE": "MEDIUM",
            "LOW": "LOW",
            "INFO": "INFORMATIONAL",
        }
        return mapping.get(sev, "MEDIUM")
