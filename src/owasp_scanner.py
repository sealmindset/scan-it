"""
OWASP Testing Guide scanner.

Implements static/configuration-based checks from OWASP Testing Guide v4.
Dynamic tests (ZAP, Playwright, pytest) are noted but require a running app,
which is outside the scope of this containerized scanner.

This module focuses on checks that can be performed via source code and
configuration analysis without a running application.
"""

import json
import os
import re
from pathlib import Path


class OWASPScanner:
    """Phase 2: OWASP Testing Guide configuration and source-level checks."""

    EXCLUDE_DIRS = {
        "node_modules", ".venv", "venv", "__pycache__", ".git",
        "dist", "build", ".next", "coverage",
    }

    def __init__(self, target_dir: str, project_info: dict):
        self.target = Path(target_dir)
        self.project_info = project_info

    def run(self) -> list:
        findings = []
        findings.extend(self._check_security_headers())
        findings.extend(self._check_cors_config())
        findings.extend(self._check_cookie_security())
        findings.extend(self._check_error_handling())
        findings.extend(self._check_crypto())
        findings.extend(self._check_auth_patterns())
        findings.extend(self._check_session_management())
        findings.extend(self._check_input_validation())
        findings.extend(self._check_client_side())
        findings.extend(self._check_info_leakage())
        return findings

    def _scan_files(self, extensions=None, callback=None):
        """Walk source files calling callback(rel_path, content, line_num, line)."""
        if extensions is None:
            extensions = {".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".java", ".rb", ".php"}
        findings = []
        for root, dirs, files in os.walk(self.target):
            dirs[:] = [d for d in dirs if d not in self.EXCLUDE_DIRS]
            for fname in files:
                fpath = Path(root) / fname
                if fpath.suffix not in extensions:
                    continue
                try:
                    content = fpath.read_text(errors="ignore")
                    rel_path = str(fpath.relative_to(self.target))
                    if callback:
                        results = callback(rel_path, content)
                        if results:
                            findings.extend(results)
                except Exception:
                    continue
        return findings

    # ---- OTG-CONFIG: Security Headers ----

    def _check_security_headers(self) -> list:
        """Check for security header configuration in source."""
        findings = []

        # Check if helmet/security middleware is used
        helmet_found = False
        csp_found = False
        hsts_found = False

        def check(rel_path, content):
            nonlocal helmet_found, csp_found, hsts_found
            results = []
            lower = content.lower()

            if "helmet" in lower or "security-headers" in lower:
                helmet_found = True
            if "content-security-policy" in lower or "csp" in lower:
                csp_found = True
            if "strict-transport-security" in lower or "hsts" in lower:
                hsts_found = True

            return results

        self._scan_files(callback=check)

        # Also check config files
        config_exts = {".yaml", ".yml", ".json", ".toml", ".conf", ".cfg", ".ini", ".env"}
        self._scan_files(extensions=config_exts, callback=check)

        if not helmet_found:
            findings.append(self._make_finding(
                "OTG-CONFIG", "CONFIG-01",
                "Missing security headers middleware",
                "MEDIUM",
                "No security headers middleware (e.g., helmet for Express, secure-headers for Python) detected. "
                "This means responses may lack X-Content-Type-Options, X-Frame-Options, and other protective headers.",
                "Add a security headers middleware to your application. For Express: use helmet(). "
                "For Python/Django: use django-secure or SecurityMiddleware. For FastAPI: add middleware.",
            ))

        if not csp_found:
            findings.append(self._make_finding(
                "OTG-CONFIG", "CONFIG-08",
                "No Content-Security-Policy configuration found",
                "MEDIUM",
                "Content-Security-Policy (CSP) header is not configured. CSP prevents XSS by controlling "
                "which scripts, styles, and resources the browser is allowed to load.",
                "Configure a Content-Security-Policy header. Start with a restrictive policy and loosen as needed. "
                "Avoid 'unsafe-inline' and 'unsafe-eval'.",
            ))

        if not hsts_found:
            findings.append(self._make_finding(
                "OTG-CONFIG", "CONFIG-03",
                "No HSTS (Strict-Transport-Security) configuration found",
                "LOW",
                "Strict-Transport-Security header is not configured. This header tells browsers to always "
                "use HTTPS, preventing downgrade attacks.",
                "Add Strict-Transport-Security header with max-age of at least 31536000 (1 year). "
                "Include includeSubDomains and preload if applicable.",
            ))

        return findings

    # ---- OTG-CONFIG: CORS ----

    def _check_cors_config(self) -> list:
        findings = []

        def check(rel_path, content):
            results = []
            lines = content.splitlines()
            for i, line in enumerate(lines, 1):
                # Wildcard CORS
                if re.search(r'Access-Control-Allow-Origin.*\*', line) or \
                   re.search(r"cors\s*\(\s*\)", line, re.IGNORECASE) or \
                   re.search(r'origin\s*:\s*["\']?\*', line):
                    results.append(self._make_finding(
                        "OTG-CONFIG", "CONFIG-02",
                        "CORS wildcard origin detected",
                        "MEDIUM",
                        f"Found wildcard CORS configuration at {rel_path}:{i}. "
                        "This allows any website to make requests to your API, which could lead to data theft.",
                        "Restrict CORS origins to specific trusted domains instead of using wildcard '*'.",
                        file=rel_path, line=i,
                    ))
            return results

        findings.extend(self._scan_files(callback=check))
        return findings

    # ---- OTG-SESS: Cookie Security ----

    def _check_cookie_security(self) -> list:
        findings = []

        def check(rel_path, content):
            results = []
            lines = content.splitlines()
            for i, line in enumerate(lines, 1):
                # Cookie without secure flags
                if re.search(r'set.?cookie|cookie\s*=|setCookie', line, re.IGNORECASE):
                    if "httponly" not in content[max(0, content.find(line)-200):content.find(line)+200].lower():
                        results.append(self._make_finding(
                            "OTG-SESS", "SESS-03",
                            "Cookie may lack HttpOnly attribute",
                            "MEDIUM",
                            f"Cookie set at {rel_path}:{i} may not have HttpOnly flag. "
                            "Without HttpOnly, JavaScript can access the cookie, enabling XSS-based session theft.",
                            "Set HttpOnly=true on all session cookies to prevent JavaScript access.",
                            file=rel_path, line=i,
                        ))
                        break  # One finding per file
            return results

        findings.extend(self._scan_files(callback=check))
        return findings

    # ---- OTG-ERR: Error Handling ----

    def _check_error_handling(self) -> list:
        findings = []

        def check(rel_path, content):
            results = []
            lines = content.splitlines()
            for i, line in enumerate(lines, 1):
                # Debug mode enabled
                if re.search(r'DEBUG\s*=\s*True', line) and "test" not in rel_path.lower():
                    results.append(self._make_finding(
                        "OTG-ERR", "ERR-04",
                        "Debug mode enabled",
                        "HIGH",
                        f"Debug mode is enabled at {rel_path}:{i}. Debug mode exposes detailed error "
                        "information including stack traces, variable values, and internal paths to attackers.",
                        "Ensure DEBUG=False in production. Use environment variables to control debug mode.",
                        file=rel_path, line=i,
                    ))

                # Empty exception handlers
                if re.search(r'except\s*:', line) and not re.search(r'except\s+\w', line):
                    # Check if next non-empty line is just pass
                    remaining = lines[i:i+3] if i < len(lines) else []
                    for next_line in remaining:
                        stripped = next_line.strip()
                        if stripped == "pass" or stripped == "...":
                            results.append(self._make_finding(
                                "OTG-ERR", "ERR-06",
                                "Empty/bare exception handler",
                                "LOW",
                                f"Bare except with pass at {rel_path}:{i}. This silently swallows all errors "
                                "including security-relevant ones, making issues harder to detect and debug.",
                                "Catch specific exceptions and log them appropriately. Never use bare except:pass.",
                                file=rel_path, line=i,
                            ))
                            break
                        if stripped and not stripped.startswith("#"):
                            break

                # Stack trace in responses
                if re.search(r'traceback\.format_exc|traceback\.print_exc', line):
                    results.append(self._make_finding(
                        "OTG-ERR", "ERR-01",
                        "Stack trace potentially exposed in response",
                        "MEDIUM",
                        f"Stack trace formatting at {rel_path}:{i}. If this output reaches the client, "
                        "it reveals internal paths, code structure, and potentially sensitive data to attackers.",
                        "Log stack traces server-side only. Return generic error messages to clients.",
                        file=rel_path, line=i,
                    ))

            return results

        findings.extend(self._scan_files(callback=check))
        return findings

    # ---- OTG-CRYPST: Cryptography ----

    def _check_crypto(self) -> list:
        findings = []
        weak_algos = [
            (r'\bmd5\b', "MD5", "MD5 is cryptographically broken. Use SHA-256 or SHA-3 for hashing."),
            (r'\bsha1\b', "SHA-1", "SHA-1 is deprecated for security. Use SHA-256 or SHA-3."),
            (r'\bdes\b', "DES", "DES has a 56-bit key and is trivially breakable. Use AES-256."),
            (r'\brc4\b', "RC4", "RC4 has known biases and vulnerabilities. Use AES-GCM."),
            (r'\becb\b', "ECB mode", "ECB mode does not provide semantic security. Use CBC or GCM mode."),
        ]

        def check(rel_path, content):
            results = []
            # Skip test files
            if "test" in rel_path.lower():
                return results

            lines = content.splitlines()
            for i, line in enumerate(lines, 1):
                if line.strip().startswith("#") or line.strip().startswith("//"):
                    continue
                for pattern, name, fix in weak_algos:
                    if re.search(pattern, line, re.IGNORECASE):
                        # Avoid false positives in comments and imports
                        if "import" in line.lower() or "require" in line.lower():
                            continue
                        results.append(self._make_finding(
                            "OTG-CRYPST", f"CRYPST-04",
                            f"Weak cryptographic algorithm: {name}",
                            "MEDIUM",
                            f"Use of {name} detected at {rel_path}:{i}. {name} is considered weak or broken "
                            "for security purposes.",
                            fix,
                            file=rel_path, line=i,
                        ))
            return results

        findings.extend(self._scan_files(callback=check))
        return findings

    # ---- OTG-AUTHN: Authentication ----

    def _check_auth_patterns(self) -> list:
        findings = []

        def check(rel_path, content):
            results = []
            lines = content.splitlines()
            for i, line in enumerate(lines, 1):
                # JWT alg:none or HS256 misuse
                if re.search(r'algorithm.*none|alg.*none|verify\s*=\s*False', line, re.IGNORECASE):
                    results.append(self._make_finding(
                        "OTG-AUTHN", "AUTHN-JWT",
                        "JWT verification may be disabled or use 'none' algorithm",
                        "CRITICAL",
                        f"JWT configuration at {rel_path}:{i} may allow 'none' algorithm or skip verification. "
                        "An attacker could forge tokens.",
                        "Always verify JWT signatures. Explicitly set allowed algorithms (e.g., RS256). "
                        "Never accept alg:none.",
                        file=rel_path, line=i,
                    ))

                # Hardcoded JWT secret
                if re.search(r'jwt.*secret\s*[=:]\s*["\'][^"\']{4,}', line, re.IGNORECASE):
                    results.append(self._make_finding(
                        "OTG-AUTHN", "AUTHN-08",
                        "Hardcoded JWT secret",
                        "HIGH",
                        f"Hardcoded JWT secret at {rel_path}:{i}. If an attacker finds this value, "
                        "they can forge authentication tokens for any user.",
                        "Store JWT secrets in environment variables or a secrets manager.",
                        file=rel_path, line=i,
                    ))
            return results

        findings.extend(self._scan_files(callback=check))
        return findings

    # ---- OTG-SESS: Session Management ----

    def _check_session_management(self) -> list:
        findings = []

        def check(rel_path, content):
            results = []
            # Check for CSRF protection
            lower = content.lower()
            if ("csrf" not in lower and "csrftoken" not in lower and
                "x-csrf" not in lower and "csrfmiddleware" not in lower):
                # Only flag if this looks like a web app with forms
                if re.search(r'<form|app\.(post|put|patch|delete)', content, re.IGNORECASE):
                    results.append(self._make_finding(
                        "OTG-SESS", "SESS-07",
                        "No CSRF protection detected",
                        "MEDIUM",
                        f"No CSRF token usage found in {rel_path}. Without CSRF protection, attackers "
                        "can trick authenticated users into performing unwanted actions.",
                        "Implement CSRF tokens on all state-changing forms and API endpoints. "
                        "Use SameSite=Strict cookies as defense-in-depth.",
                        file=rel_path,
                    ))
            return results

        findings.extend(self._scan_files(callback=check))
        return findings

    # ---- OTG-INPVAL: Input Validation ----

    def _check_input_validation(self) -> list:
        findings = []

        def check(rel_path, content):
            results = []
            lines = content.splitlines()
            for i, line in enumerate(lines, 1):
                # Path traversal
                if re.search(r'open\s*\(.*(?:request|req|params|query|args)', line, re.IGNORECASE):
                    if "sanitize" not in line.lower() and "validate" not in line.lower():
                        results.append(self._make_finding(
                            "OTG-INPVAL", "AUTHZ-03",
                            "Potential path traversal via user input in file operations",
                            "HIGH",
                            f"User input used in file operation at {rel_path}:{i}. Without path sanitization, "
                            "an attacker could read arbitrary files using '../' sequences.",
                            "Validate and sanitize file paths. Use os.path.realpath() and verify the resolved "
                            "path is within the allowed directory.",
                            file=rel_path, line=i,
                        ))

                # SSRF patterns
                if re.search(r'requests?\.(get|post|put|delete|head|patch)\s*\(.*(?:request|req|params|query|args)', line, re.IGNORECASE):
                    results.append(self._make_finding(
                        "OTG-INPVAL", "SSRF-01",
                        "Potential SSRF via user-controlled URL",
                        "HIGH",
                        f"HTTP request with user-controlled URL at {rel_path}:{i}. An attacker could make "
                        "the server request internal services, cloud metadata endpoints, or other sensitive resources.",
                        "Validate and whitelist allowed URLs/hosts. Block requests to internal IP ranges "
                        "(10.x, 172.16-31.x, 192.168.x, 169.254.x).",
                        file=rel_path, line=i,
                    ))
            return results

        findings.extend(self._scan_files(callback=check))
        return findings

    # ---- OTG-CLIENT: Client-Side ----

    def _check_client_side(self) -> list:
        findings = []

        def check(rel_path, content):
            results = []
            lines = content.splitlines()
            for i, line in enumerate(lines, 1):
                # postMessage without origin check
                if re.search(r'addEventListener\s*\(\s*["\']message', line):
                    # Check surrounding lines for origin validation
                    context = "\n".join(lines[max(0, i-3):i+5])
                    if "origin" not in context.lower():
                        results.append(self._make_finding(
                            "OTG-CLIENT", "CLIENT-03",
                            "postMessage handler without origin validation",
                            "MEDIUM",
                            f"postMessage listener at {rel_path}:{i} does not check event.origin. "
                            "Any website could send messages to this handler.",
                            "Always validate event.origin against a whitelist of trusted origins before "
                            "processing postMessage data.",
                            file=rel_path, line=i,
                        ))

                # window.location from user input
                if re.search(r'window\.location\s*=.*(?:location\.hash|location\.search|document\.referrer)', line):
                    results.append(self._make_finding(
                        "OTG-CLIENT", "CLIENT-06",
                        "Potential open redirect via client-side redirect",
                        "MEDIUM",
                        f"Client-side redirect using user-controlled input at {rel_path}:{i}. "
                        "An attacker could craft a URL that redirects users to a malicious site.",
                        "Validate redirect targets against a whitelist of allowed URLs. "
                        "Never redirect based on unvalidated user input.",
                        file=rel_path, line=i,
                    ))
            return results

        js_exts = {".js", ".ts", ".tsx", ".jsx", ".vue", ".svelte"}
        findings.extend(self._scan_files(extensions=js_exts, callback=check))
        return findings

    # ---- OTG-INFO: Information Leakage ----

    def _check_info_leakage(self) -> list:
        findings = []

        # Check for robots.txt with sensitive paths
        robots = self.target / "robots.txt"
        if robots.exists():
            try:
                content = robots.read_text()
                if re.search(r'Disallow:.*(?:admin|api|internal|private|secret|config|backup)', content, re.IGNORECASE):
                    findings.append(self._make_finding(
                        "OTG-INFO", "INFO-03",
                        "robots.txt reveals sensitive paths",
                        "LOW",
                        "robots.txt contains Disallow entries that reveal the existence of sensitive paths "
                        "(admin, API, internal). Attackers use robots.txt for reconnaissance.",
                        "Consider whether revealing path names in robots.txt helps or hurts. "
                        "Authentication and authorization are the real controls, not obscurity.",
                        file="robots.txt",
                    ))
            except Exception:
                pass

        # Check for .env files that shouldn't be in the project
        env_files = list(self.target.glob(".env*"))
        for ef in env_files:
            if ef.name in (".env.example", ".env.template", ".env.sample"):
                continue
            try:
                content = ef.read_text(errors="ignore")
                if re.search(r'(?:PASSWORD|SECRET|KEY|TOKEN)\s*=\s*\S+', content, re.IGNORECASE):
                    findings.append(self._make_finding(
                        "OTG-INFO", "INFO-ENV",
                        f"Environment file with secrets: {ef.name}",
                        "HIGH",
                        f"{ef.name} contains what appear to be real credentials. If committed to version control, "
                        "these secrets are exposed to anyone with repository access.",
                        "Add .env to .gitignore. Rotate any exposed credentials immediately. "
                        "Use a secrets manager for production credentials.",
                        file=ef.name,
                    ))
            except Exception:
                pass

        return findings

    def _make_finding(self, category, test_id, title, severity, description, remediation, file="", line=0):
        return {
            "tool": "owasp-check",
            "category": category,
            "title": title,
            "severity": severity,
            "file": file,
            "line": line,
            "description": description,
            "rule_id": test_id,
            "remediation": remediation,
        }
