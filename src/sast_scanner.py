"""
Static Analysis (SAST) scanner.

Runs semgrep, bandit (Python), eslint-security (JS/TS), and
manual pattern checks for common vulnerability patterns.
"""

import json
import os
import re
import subprocess
from pathlib import Path


class SASTScanner:
    """Phase 1: Static analysis without a running application."""

    EXCLUDE_DIRS = [
        "node_modules", ".venv", "venv", "__pycache__",
        ".git", "dist", "build", ".next", "coverage",
    ]

    # Patterns for manual code-level checks
    SECRET_PATTERNS = [
        (r'(?:password|passwd|pwd)\s*[=:]\s*["\'][^"\']{4,}["\']', "Hardcoded password"),
        (r'(?:api_key|apikey|api_secret)\s*[=:]\s*["\'][^"\']{4,}["\']', "Hardcoded API key"),
        (r'(?:secret|token)\s*[=:]\s*["\'][^"\']{8,}["\']', "Hardcoded secret/token"),
        (r'AKIA[0-9A-Z]{16}', "AWS Access Key ID"),
        (r'ghp_[a-zA-Z0-9]{36}', "GitHub Personal Access Token"),
        (r'sk-[a-zA-Z0-9]{20,}', "OpenAI/Stripe Secret Key pattern"),
        (r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----', "Private key in source"),
    ]

    # SQL keyword group used across patterns (whole-word match to avoid
    # false positives on words like "selected", "inserted", "deleted", etc.)
    _SQL_KW = r'(?:SELECT|INSERT\s+INTO|UPDATE\s+\S+\s+SET|DELETE\s+FROM|DROP\s+TABLE|ALTER\s+TABLE|CREATE\s+TABLE)\b'

    SQLI_PATTERNS = [
        (rf'f"[^"]*{_SQL_KW}[^"]*\{{', "Python f-string SQL injection"),
        (rf"f'[^']*{_SQL_KW}[^']*\{{", "Python f-string SQL injection"),
        (rf'`[^`]*{_SQL_KW}[^`]*\$\{{', "JS template literal SQL injection"),
        (rf'["\'].*{_SQL_KW}.*["\']\s*\+', "String concat SQL injection"),
        (rf'\.format\(.*{_SQL_KW}', "Python .format() SQL injection"),
        (rf'%s.*{_SQL_KW}|{_SQL_KW}.*%s', "Python % format SQL"),
    ]

    # ── Context-aware false-positive filters ──────────────────────────
    # Lines matching these are non-exploitable contexts shared across
    # multiple vulnerability categories (logging, UI messages, etc.)
    SAFE_DISPLAY_CONTEXTS = re.compile(
        r'\b(?:flash|log(?:ging)?\.(?:debug|info|warning|error|critical|exception)'
        r'|print|raise\s+\w+|\.add_message|messages\.(?:success|info|warning|error)'
        r'|render_template|jsonify|abort|redirect)\s*\(',
        re.IGNORECASE,
    )

    # Lines that are string-only assignments (no executable sink)
    SAFE_STRING_ASSIGNMENT = re.compile(
        r'^\s*(?:#|//|/\*|\*|"""|\'{3})',  # comments / docstrings
    )

    # Configuration / example / placeholder files that commonly contain
    # dummy secrets and should not be flagged.
    SECRET_SAFE_FILES = re.compile(
        r'(?:\.example|\.sample|\.template|\.dist|\.defaults'
        r'|\.env\.example|docker-compose\.override'
        r'|fixtures|seeds|factories|__mocks__)',
        re.IGNORECASE,
    )
    SECRET_PLACEHOLDER_VALUES = re.compile(
        r'["\'](?:changeme|CHANGEME|xxxx|your[_-]?(?:password|key|secret|token)[_-]?here'
        r'|replace[_-]?me|TODO|FIXME|placeholder|example|test|dummy|fake|sample'
        r'|password|secret|<[^>]+>|\*{3,}|\.{3,})["\']',
        re.IGNORECASE,
    )

    XSS_PATTERNS = [
        (r'dangerouslySetInnerHTML', "React dangerouslySetInnerHTML usage"),
        (r'\.innerHTML\s*=', "Direct innerHTML assignment"),
        (r'document\.write\s*\(', "document.write usage"),
        (r'v-html\s*=', "Vue v-html directive"),
        (r'\.outerHTML\s*=', "Direct outerHTML assignment"),
        (r'\|\s*safe\b', "Django/Jinja2 |safe filter (bypasses escaping)"),
    ]
    # XSS patterns in sanitized/safe wrappers are not exploitable
    XSS_SAFE_CONTEXTS = re.compile(
        r'\b(?:DOMPurify\.sanitize|sanitize[_]?html|escape|markupsafe\.escape'
        r'|bleach\.clean|xss_clean|html\.escape|cgi\.escape'
        r'|encodeURIComponent|textContent\s*=)\s*\(',
        re.IGNORECASE,
    )

    DESER_PATTERNS = [
        (r'pickle\.load(?!s\b)', "Insecure pickle deserialization"),
        (r'yaml\.load\s*\([^)]*$', "PyYAML unsafe load (missing Loader)"),
        (r'yaml\.load\s*\([^)]*\)(?!.*Loader)', "PyYAML unsafe load (missing Loader)"),
        (r'yaml\.unsafe_load', "PyYAML explicit unsafe_load"),
        (r'(?<!\w)eval\s*\(\s*(?:request|req\b|self\.request|input\s*\(|sys\.stdin'
         r'|f["\']|[a-zA-Z_]\w*\s*[\+%])', "eval() with dynamic/user input"),
        (r'unserialize\s*\(\s*\$', "PHP unserialize with variable input"),
        (r'JSON\.parse\s*\(\s*(?:req|request)\b', "Unvalidated JSON parse from request"),
    ]
    # Safe deserialization wrappers
    DESER_SAFE_CONTEXTS = re.compile(
        r'\byaml\.(?:safe_load|CSafeLoader|SafeLoader)'
        r'|pickle\.loads?\s*\(.*(?:hmac|signature|verify)',
        re.IGNORECASE,
    )

    CMD_INJECTION_PATTERNS = [
        (r'os\.system\s*\(', "os.system() usage"),
        (r'subprocess.*shell\s*=\s*True', "subprocess with shell=True"),
        (r'child_process\.exec\s*\(', "Node child_process.exec"),
        (r'child_process\.execSync\s*\(', "Node child_process.execSync"),
    ]
    # Command injection with only hardcoded string args is low-risk
    CMD_SAFE_CONTEXTS = re.compile(
        r'os\.system\s*\(\s*["\'][^"\']*["\']\s*\)'
        r'|subprocess\.\w+\s*\(\s*\[["\']'
        r'|child_process\.exec(?:Sync)?\s*\(\s*["\'][^"\']*["\']\s*\)',
    )

    SCANNABLE_EXTENSIONS = {
        ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs",
        ".java", ".rb", ".php", ".vue", ".svelte",
    }

    def __init__(self, target_dir: str, project_info: dict):
        self.target = Path(target_dir)
        self.project_info = project_info

    def run(self) -> list:
        """Execute all SAST checks and return findings."""
        findings = []

        # 1. Semgrep
        findings.extend(self._run_semgrep())

        # 2. Bandit (Python)
        if self.project_info.get("has_python"):
            findings.extend(self._run_bandit())

        # 3. ESLint security (JS/TS)
        if self.project_info.get("has_node"):
            findings.extend(self._run_eslint_security())

        # 4. Manual pattern checks
        findings.extend(self._run_pattern_checks())

        return findings

    def _run_semgrep(self) -> list:
        """Run semgrep with OWASP and security rulesets."""
        findings = []
        output_file = "/tmp/scan-it-semgrep.json"
        exclude_args = []
        for d in self.EXCLUDE_DIRS:
            exclude_args.extend(["--exclude", d])

        try:
            cmd = [
                "semgrep", "scan",
                "--config", "p/owasp-top-ten",
                "--config", "p/security-audit",
                "--json", "--output", output_file,
                *exclude_args,
                str(self.target),
            ]
            subprocess.run(cmd, capture_output=True, timeout=300)

            if os.path.exists(output_file):
                with open(output_file) as f:
                    data = json.load(f)

                for result in data.get("results", []):
                    sev = result.get("extra", {}).get("severity", "WARNING")
                    severity = self._normalize_severity(sev)
                    findings.append({
                        "tool": "semgrep",
                        "category": "SAST-SEMGREP",
                        "title": result.get("check_id", "Unknown rule"),
                        "severity": severity,
                        "file": result.get("path", ""),
                        "line": result.get("start", {}).get("line", 0),
                        "description": result.get("extra", {}).get("message", ""),
                        "rule_id": result.get("check_id", ""),
                        "remediation": result.get("extra", {}).get("fix", ""),
                    })
        except subprocess.TimeoutExpired:
            print("  WARNING: Semgrep timed out after 300s")
        except FileNotFoundError:
            print("  WARNING: semgrep not found, skipping")
        except Exception as e:
            print(f"  WARNING: Semgrep error: {e}")

        print(f"  Semgrep: {len(findings)} findings")
        return findings

    def _run_bandit(self) -> list:
        """Run Bandit for Python-specific security issues."""
        findings = []
        output_file = "/tmp/scan-it-bandit.json"
        exclude_str = ",".join(self.EXCLUDE_DIRS)

        try:
            cmd = [
                "bandit", "-r", str(self.target),
                "-f", "json", "-o", output_file,
                f"--exclude={exclude_str}",
            ]
            subprocess.run(cmd, capture_output=True, timeout=120)

            if os.path.exists(output_file):
                with open(output_file) as f:
                    data = json.load(f)

                for result in data.get("results", []):
                    severity = self._normalize_severity(
                        result.get("issue_severity", "LOW")
                    )
                    findings.append({
                        "tool": "bandit",
                        "category": "SAST-LINT",
                        "title": result.get("test_name", "Unknown"),
                        "severity": severity,
                        "file": result.get("filename", ""),
                        "line": result.get("line_number", 0),
                        "description": result.get("issue_text", ""),
                        "rule_id": result.get("test_id", ""),
                        "confidence": result.get("issue_confidence", ""),
                        "remediation": "",
                    })
        except FileNotFoundError:
            print("  WARNING: bandit not found, skipping")
        except Exception as e:
            print(f"  WARNING: Bandit error: {e}")

        print(f"  Bandit: {len(findings)} findings")
        return findings

    def _run_eslint_security(self) -> list:
        """Run ESLint with security plugin for JS/TS issues."""
        findings = []
        output_file = "/tmp/scan-it-eslint.json"

        try:
            cmd = [
                "npx", "eslint",
                "--no-eslintrc",
                "--plugin", "security",
                "--rule", json.dumps({
                    "security/detect-object-injection": "warn",
                    "security/detect-non-literal-regexp": "warn",
                    "security/detect-unsafe-regex": "warn",
                    "security/detect-buffer-noassert": "warn",
                    "security/detect-eval-with-expression": "warn",
                    "security/detect-no-csrf-before-method-override": "warn",
                    "security/detect-possible-timing-attacks": "warn",
                    "security/detect-pseudoRandomBytes": "warn",
                }),
                "--format", "json",
                "--output-file", output_file,
                "--ext", ".js,.jsx,.ts,.tsx",
                "--ignore-pattern", "node_modules/**",
                "--ignore-pattern", "dist/**",
                "--ignore-pattern", ".next/**",
                str(self.target),
            ]
            subprocess.run(cmd, capture_output=True, timeout=120)

            if os.path.exists(output_file):
                with open(output_file) as f:
                    data = json.load(f)

                for file_result in data:
                    for msg in file_result.get("messages", []):
                        if msg.get("ruleId", "").startswith("security/"):
                            severity = "MEDIUM" if msg.get("severity", 1) >= 2 else "LOW"
                            findings.append({
                                "tool": "eslint-security",
                                "category": "SAST-LINT",
                                "title": msg.get("ruleId", "Unknown"),
                                "severity": severity,
                                "file": file_result.get("filePath", ""),
                                "line": msg.get("line", 0),
                                "description": msg.get("message", ""),
                                "rule_id": msg.get("ruleId", ""),
                                "remediation": "",
                            })
        except FileNotFoundError:
            print("  WARNING: eslint not found, skipping")
        except Exception as e:
            print(f"  WARNING: ESLint error: {e}")

        print(f"  ESLint security: {len(findings)} findings")
        return findings

    def _run_pattern_checks(self) -> list:
        """Manual regex pattern checks for common vulnerabilities."""
        findings = []
        all_patterns = [
            (self.SECRET_PATTERNS, "Hardcoded Secrets", "HIGH", "OTG-CONFIG"),
            (self.SQLI_PATTERNS, "SQL Injection", "CRITICAL", "OTG-INPVAL"),
            (self.XSS_PATTERNS, "Cross-Site Scripting (XSS)", "HIGH", "OTG-INPVAL"),
            (self.DESER_PATTERNS, "Insecure Deserialization", "HIGH", "OTG-INPVAL"),
            (self.CMD_INJECTION_PATTERNS, "Command Injection", "CRITICAL", "OTG-INPVAL"),
        ]

        for root, dirs, files in os.walk(self.target):
            dirs[:] = [d for d in dirs if d not in self.EXCLUDE_DIRS]

            for fname in files:
                fpath = Path(root) / fname
                if fpath.suffix not in self.SCANNABLE_EXTENSIONS:
                    continue

                try:
                    content = fpath.read_text(errors="ignore")
                except Exception:
                    continue

                rel_path = str(fpath.relative_to(self.target))

                for patterns, group_name, default_sev, category in all_patterns:
                    for pattern, desc in patterns:
                        for i, line in enumerate(content.splitlines(), 1):
                            # Skip test files and comments
                            if "/test" in rel_path.lower() or "test_" in fname.lower():
                                continue
                            if line.strip().startswith("#") or line.strip().startswith("//"):
                                continue

                            # ── Context-aware false-positive filtering ──
                            if self._is_safe_context(group_name, line, rel_path):
                                continue

                            if re.search(pattern, line, re.IGNORECASE):
                                findings.append({
                                    "tool": "pattern-check",
                                    "category": category,
                                    "title": desc,
                                    "severity": default_sev,
                                    "file": rel_path,
                                    "line": i,
                                    "description": f"{group_name}: {desc} detected in source code",
                                    "rule_id": f"PATTERN-{group_name.upper().replace(' ', '-')}",
                                    "remediation": self._get_pattern_remediation(group_name),
                                })

        print(f"  Pattern checks: {len(findings)} findings")
        return findings

    def _is_safe_context(self, group_name: str, line: str, rel_path: str) -> bool:
        """Return True if the line is a known-safe context for the given
        vulnerability group, suppressing the finding as a false positive."""

        if group_name == "SQL Injection":
            # f-strings / format strings in flash, logging, print, etc.
            return bool(self.SAFE_DISPLAY_CONTEXTS.search(line))

        if group_name == "Hardcoded Secrets":
            # Example / template / fixture files with placeholder values
            if self.SECRET_SAFE_FILES.search(rel_path):
                return True
            if self.SECRET_PLACEHOLDER_VALUES.search(line):
                return True
            return False

        if group_name == "Cross-Site Scripting (XSS)":
            # Output inside a sanitizer wrapper is not exploitable
            if self.XSS_SAFE_CONTEXTS.search(line):
                return True
            # innerHTML/outerHTML in logging or flash is not DOM access
            if self.SAFE_DISPLAY_CONTEXTS.search(line):
                return True
            return False

        if group_name == "Insecure Deserialization":
            # yaml.safe_load or verified-signature pickle is fine
            if self.DESER_SAFE_CONTEXTS.search(line):
                return True
            return False

        if group_name == "Command Injection":
            # Hardcoded-string-only commands are low-risk
            if self.CMD_SAFE_CONTEXTS.search(line):
                return True
            # Command strings in flash/logging/print are not executed
            if self.SAFE_DISPLAY_CONTEXTS.search(line):
                return True
            return False

        return False

    def _normalize_severity(self, sev: str) -> str:
        """Normalize tool-specific severity labels."""
        sev = sev.upper()
        mapping = {
            "ERROR": "HIGH",
            "WARNING": "MEDIUM",
            "INFO": "LOW",
            "NOTE": "INFORMATIONAL",
            "SEVERITY-4": "CRITICAL",
            "SEVERITY-3": "HIGH",
            "SEVERITY-2": "MEDIUM",
            "SEVERITY-1": "LOW",
            "SEVERITY-0": "INFORMATIONAL",
        }
        return mapping.get(sev, sev) if sev not in (
            "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"
        ) else sev

    def _get_pattern_remediation(self, group: str) -> str:
        remediations = {
            "Hardcoded Secrets": "Move secrets to environment variables or a secrets manager. Never commit credentials to source control.",
            "SQL Injection": "Use parameterized queries or an ORM. Never concatenate user input into SQL strings.",
            "Cross-Site Scripting (XSS)": "Use framework-provided escaping. Avoid innerHTML and dangerouslySetInnerHTML. Implement Content-Security-Policy headers.",
            "Insecure Deserialization": "Use safe deserialization methods (e.g., yaml.safe_load, JSON instead of pickle). Validate input before deserialization.",
            "Command Injection": "Avoid shell=True. Use subprocess with argument lists. Validate and sanitize all inputs passed to system commands.",
        }
        return remediations.get(group, "Review and fix the identified pattern.")
