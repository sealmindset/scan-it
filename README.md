# scan-it

Dockerized security scanner that combines **NeMo Guardrails AI safety testing** + **OWASP Testing Guide** + **dependency scanning** + **static analysis** into a single container. No Claude Code required.

## Quick Start

```bash
# Clone
git clone https://github.com/sealmindset/scan-it.git

# Build the image (run from the scan-it directory)
cd scan-it
docker build -t scan-it .

# Scan any project (from anywhere)
./scan-it.sh /path/to/your/project
```

Or with Docker directly:

```bash
# Build (must be run from the scan-it directory, not your target project)
cd /path/to/scan-it
docker build -t scan-it .

# Then scan your target project
docker run --rm -v /path/to/your/project:/app:ro -v ./reports:/output scan-it
```

**Important:** `docker build` must be run from the `scan-it/` directory (where the Dockerfile lives), not from your target project.

## Scan Modes

| Mode | Command | What It Scans |
|------|---------|---------------|
| **Full** | `./scan-it.sh /app` | Everything below |
| **SAST** | `./scan-it.sh /app sast` | Semgrep, Bandit, ESLint security, pattern checks |
| **Deps** | `./scan-it.sh /app deps` | npm audit, pip-audit, Trivy |
| **OWASP** | `./scan-it.sh /app owasp` | OWASP Testing Guide config/code checks |
| **Guardrails** | `./scan-it.sh /app guardrails` | NeMo AI safety checks (if AI features detected) |

## Output Formats

Markdown attestation is always generated. Optionally add JSON or JUnit XML:

```bash
./scan-it.sh /app full --format json    # Markdown + JSON
./scan-it.sh /app full --format junit   # Markdown + JUnit XML (for CI/CD)
```

Reports are saved to `<project>/scan-it-reports/`.

## What Gets Scanned

### Static Analysis (SAST)
- **Semgrep** with OWASP Top 10 and security-audit rulesets
- **Bandit** for Python-specific security issues
- **ESLint security plugin** for JavaScript/TypeScript
- **Pattern checks** for hardcoded secrets, SQL injection, XSS sinks, insecure deserialization, command injection

### Dependency Scanning
- **npm audit** for Node.js vulnerabilities
- **pip-audit** for Python vulnerabilities
- **Trivy** for filesystem dependencies and Dockerfile misconfigurations

### OWASP Testing Guide (Code/Config Level)
- Security headers (HSTS, CSP, X-Frame-Options)
- CORS configuration
- Cookie security attributes
- Error handling and debug mode
- Weak cryptographic algorithms
- Authentication patterns (JWT misuse, hardcoded secrets)
- Session management (CSRF protection)
- Input validation (path traversal, SSRF)
- Client-side security (postMessage, open redirects)
- Information leakage (.env files, robots.txt)

### NeMo Guardrails AI Safety (6 Categories)
Only runs when AI/LLM features are detected in your project:

| Category | What It Checks |
|----------|----------------|
| Prompt Injection Resistance | Input sanitization, delimiter tags, direct concatenation |
| Jailbreak Resistance | NeMo config, output validation rails |
| Toxicity / Bias Detection | Content moderation filters |
| Topic Boundary Enforcement | System prompt boundaries |
| PII Leakage Prevention | PII masking, conversation logging |
| Hallucination Detection | RAG/grounding, confidence scoring |

## Attestation Report

The generated report includes:

- **Executive Summary** with overall risk posture rating
- **22-category dashboard** (6 NeMo + 11 OWASP + 3 Dependency + 2 SAST)
- **OWASP Top 10 (2021) mapping**
- **Every finding** with severity, location, description, risk score, and remediation
- **Prioritized recommendations** (Critical/High first)
- **AI safety assessment** (if applicable)

## Docker Compose

```bash
cd /path/to/your/project

# Set target and run
SCAN_TARGET=. docker compose -f /path/to/scan-it/docker-compose.yml run --rm scan-it
```

## CI/CD Integration

### GitHub Actions

```yaml
- name: Security Scan
  run: |
    docker run --rm \
      -v ${{ github.workspace }}:/app:ro \
      -v ./reports:/output \
      scan-it full --format junit

- name: Upload Results
  uses: actions/upload-artifact@v4
  with:
    name: security-report
    path: reports/
```

### GitLab CI

```yaml
security-scan:
  image: scan-it:latest
  script:
    - python3 /opt/scan-it/src/scanner.py --target . --output ./reports --format junit
  artifacts:
    reports:
      junit: reports/*-junit.xml
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No critical or high findings |
| 1 | High-severity findings detected |
| 2 | Critical-severity findings detected |

## Safety Guarantees

- **Non-destructive**: All scans are read-only analysis. No code is modified.
- **No network probing**: This scanner does static/config analysis only. No active DAST.
- **No data exfiltration**: All findings stay local in the output directory.
- **Deterministic**: Same input produces same output. No external API calls during scanning.

## Tools Bundled in the Container

| Tool | Purpose |
|------|---------|
| Semgrep | Cross-language static analysis |
| Bandit | Python security linter |
| ESLint + security plugin | JavaScript/TypeScript security |
| Trivy | Dependency and container scanning |
| npm audit | Node.js dependency vulnerabilities |
| pip-audit | Python dependency vulnerabilities |

## Project Structure

```
scan-it/
├── Dockerfile              # Container with all scanning tools
├── docker-compose.yml      # Easy Docker Compose usage
├── scan-it.sh              # Convenience wrapper script
├── entrypoint.sh           # Container entrypoint
├── config/
│   └── scan-config.yml     # Default scan configuration
├── src/
│   ├── scanner.py          # Main orchestrator
│   ├── detectors.py        # Project type detection
│   ├── sast_scanner.py     # Static analysis (semgrep, bandit, eslint)
│   ├── deps_scanner.py     # Dependency scanning (npm, pip, trivy)
│   ├── owasp_scanner.py    # OWASP Testing Guide checks
│   ├── guardrails_scanner.py  # NeMo AI safety checks
│   ├── analyzer.py         # Finding dedup, scoring, enrichment
│   └── reporter.py         # Report generation (MD, JSON, JUnit)
├── templates/              # Report templates
├── VERSION                 # Version tracking
├── LICENSE                 # CC0 1.0 Universal
└── README.md
```

## Relationship to nemo-it

**scan-it** is the Docker-based standalone version of [nemo-it](https://github.com/sealmindset/nemo-it). The key differences:

| | nemo-it | scan-it |
|---|---------|---------|
| **Runs via** | Claude Code skill (`/nemo-it`) | Docker container |
| **Requires** | Claude Code CLI | Docker only |
| **Dynamic testing** | Yes (ZAP, Playwright, pytest) | No (static/config analysis only) |
| **AI safety testing** | Runtime tests against live AI endpoints | Source code analysis for AI safety patterns |
| **Interactive** | Yes (asks questions, shows progress) | No (batch mode, CI/CD friendly) |
| **Output** | Same attestation format | Same attestation format |

## License

CC0 1.0 Universal -- Public Domain
