#!/usr/bin/env python3
"""
scan-it: Main scanner orchestrator.

Runs security scans in phases:
  0. Preflight  - Detect project type, AI features, validate environment
  1. SAST       - Static analysis (semgrep, bandit, eslint-security, pattern checks)
  1.5 Deps      - Dependency scanning (npm audit, pip-audit, trivy)
  2. OWASP      - OWASP Testing Guide checks (static + config analysis)
  3. Guardrails - NeMo AI safety testing (if AI features detected)
  4. Analysis   - Deduplicate, score, generate remediation
  5. Report     - Generate attestation documents
"""

import argparse
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path

from detectors import ProjectDetector
from sast_scanner import SASTScanner
from deps_scanner import DepsScanner
from owasp_scanner import OWASPScanner
from guardrails_scanner import GuardrailsScanner
from analyzer import Analyzer
from reporter import Reporter


def parse_args():
    parser = argparse.ArgumentParser(
        description="scan-it: Security attestation scanner"
    )
    parser.add_argument(
        "--mode",
        choices=["full", "sast", "deps", "owasp", "guardrails"],
        default="full",
        help="Scan mode (default: full)",
    )
    parser.add_argument(
        "--target",
        default="/app",
        help="Target directory to scan (default: /app)",
    )
    parser.add_argument(
        "--output",
        default="/output",
        help="Output directory for reports (default: /output)",
    )
    parser.add_argument(
        "--format",
        choices=["json", "junit"],
        default=None,
        help="Additional output format (markdown is always generated)",
    )
    parser.add_argument(
        "--config",
        default=None,
        help="Path to custom config file",
    )
    parser.add_argument(
        "--ai-validate",
        action="store_true",
        default=False,
        help="Enable AI-powered finding validation (requires AI provider credentials)",
    )
    parser.add_argument(
        "--fix-it",
        nargs="?",
        const="default",
        default=None,
        metavar="SCOPE",
        help="Fix validated findings. Default: CRITICAL+HIGH. Use '--fix-it all' for all severities. Implies --ai-validate.",
    )
    return parser.parse_args()


def print_banner(mode, target):
    print("=" * 60)
    print("  scan-it Security Attestation Scanner v1.0.0")
    print(f"  Mode: {mode}")
    print(f"  Target: {target}")
    print(f"  Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print("=" * 60)
    print()


def print_phase(name, description):
    print()
    print(f"--- Phase: {name} ---")
    print(f"    {description}")
    print()


def main():
    args = parse_args()
    start_time = time.time()

    # --fix-it implies --ai-validate
    if args.fix_it is not None:
        args.ai_validate = True

    print_banner(args.mode, args.target)

    target = Path(args.target)
    if not target.exists():
        print(f"ERROR: Target directory does not exist: {target}")
        sys.exit(1)

    # Load config
    config_path = args.config or os.path.join(
        os.environ.get("SCAN_IT_HOME", "/opt/scan-it"), "config", "scan-config.yml"
    )

    all_findings = []

    # ----------------------------------------------------------------
    # Phase 0: Preflight
    # ----------------------------------------------------------------
    print_phase("PREFLIGHT", "Detecting project type, tech stack, and AI features...")

    detector = ProjectDetector(str(target))
    project_info = detector.detect()

    print(f"  Project type: {', '.join(project_info['languages']) or 'unknown'}")
    print(f"  Frameworks: {', '.join(project_info['frameworks']) or 'none detected'}")
    print(f"  AI features: {'YES' if project_info['ai_features'] else 'NO'}")
    print(f"  Has Dockerfile: {'YES' if project_info['has_docker'] else 'NO'}")
    print()

    # ----------------------------------------------------------------
    # Phase 1: Static Analysis
    # ----------------------------------------------------------------
    if args.mode in ("full", "sast"):
        print_phase("STATIC ANALYSIS (SAST)", "Scanning source code for security issues...")

        sast = SASTScanner(str(target), project_info)
        sast_findings = sast.run()
        all_findings.extend(sast_findings)

        print(f"  SAST findings: {len(sast_findings)}")

    # ----------------------------------------------------------------
    # Phase 1.5: Dependency Scanning
    # ----------------------------------------------------------------
    if args.mode in ("full", "deps"):
        print_phase("DEPENDENCY SCANNING", "Checking dependencies for known vulnerabilities...")

        deps = DepsScanner(str(target), project_info)
        deps_findings = deps.run()
        all_findings.extend(deps_findings)

        print(f"  Dependency findings: {len(deps_findings)}")

    # ----------------------------------------------------------------
    # Phase 2: OWASP Checks
    # ----------------------------------------------------------------
    if args.mode in ("full", "owasp"):
        print_phase(
            "OWASP TESTING GUIDE",
            "Running OWASP configuration and code-level checks...",
        )

        owasp = OWASPScanner(str(target), project_info)
        owasp_findings = owasp.run()
        all_findings.extend(owasp_findings)

        print(f"  OWASP findings: {len(owasp_findings)}")

    # ----------------------------------------------------------------
    # Phase 3: AI Safety (NeMo Guardrails)
    # ----------------------------------------------------------------
    if args.mode in ("full", "guardrails"):
        print_phase(
            "AI SAFETY (NeMo Guardrails)",
            "Checking AI/LLM integration safety...",
        )

        guardrails = GuardrailsScanner(str(target), project_info)
        guardrails_findings = guardrails.run()
        all_findings.extend(guardrails_findings)

        if project_info["ai_features"]:
            print(f"  AI safety findings: {len(guardrails_findings)}")
        else:
            print("  No AI features detected -- all NeMo categories marked N/A")

    # ----------------------------------------------------------------
    # Phase 4: Analysis
    # ----------------------------------------------------------------
    print_phase("ANALYSIS", "Deduplicating, scoring, and generating remediation guidance...")

    analyzer = Analyzer()
    analyzed = analyzer.analyze(all_findings)

    severity_counts = analyzer.count_by_severity(analyzed)
    print(f"  Total unique findings: {len(analyzed)}")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
        count = severity_counts.get(sev, 0)
        if count:
            print(f"    {sev}: {count}")

    # ----------------------------------------------------------------
    # Phase 4.5: AI Validation (optional)
    # ----------------------------------------------------------------
    if args.ai_validate:
        print_phase("AI VALIDATION", "Validating findings with AI analysis of source code...")

        from ai_validator import AIValidator

        validator = AIValidator(str(target))
        analyzed = validator.validate_findings(analyzed)
        validator.print_summary()

        # Recount after false-positive removal
        severity_counts = analyzer.count_by_severity(analyzed)
        print(f"  Findings after AI validation: {len(analyzed)}")

    # ----------------------------------------------------------------
    # Phase 4.7: AI Fix Generation (optional, requires --fix-it)
    # ----------------------------------------------------------------
    before_severity_counts = None
    after_severity_counts = None

    if args.fix_it is not None:
        print_phase("AI FIX GENERATION", "Generating and applying fixes for validated findings...")

        from ai_fixer import AIFixer

        # Determine severity scope
        if args.fix_it == "all":
            fix_scope = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]
        else:
            fix_scope = ["CRITICAL", "HIGH"]

        # Save "before" snapshot
        before_severity_counts = dict(severity_counts)

        fixer = AIFixer(str(target), fix_scope)
        analyzed = fixer.fix_findings(analyzed)
        fixer.print_summary()

        # Verification re-scan
        print_phase("VERIFICATION RE-SCAN", "Re-scanning to verify applied fixes...")

        rescan_findings = []
        if args.mode in ("full", "sast"):
            rescan_findings.extend(SASTScanner(str(target), project_info).run())
        if args.mode in ("full", "deps"):
            rescan_findings.extend(DepsScanner(str(target), project_info).run())
        if args.mode in ("full", "owasp"):
            rescan_findings.extend(OWASPScanner(str(target), project_info).run())
        if args.mode in ("full", "guardrails"):
            rescan_findings.extend(GuardrailsScanner(str(target), project_info).run())

        rescan_analyzer = Analyzer()
        after_analyzed = rescan_analyzer.analyze(rescan_findings)
        after_severity_counts = rescan_analyzer.count_by_severity(after_analyzed)

        before_total = sum(v for k, v in before_severity_counts.items() if k != "INFORMATIONAL")
        after_total = sum(v for k, v in after_severity_counts.items() if k != "INFORMATIONAL")
        print(f"  Before fixes: {before_total} findings")
        print(f"  After fixes:  {after_total} findings")
        print(f"  Fixed:        {before_total - after_total}")

    # ----------------------------------------------------------------
    # Phase 5: Reporting
    # ----------------------------------------------------------------
    print_phase("REPORTING", "Generating attestation documents...")

    elapsed = time.time() - start_time
    reporter = Reporter(
        output_dir=args.output,
        project_info=project_info,
        scan_mode=args.mode,
        elapsed_seconds=elapsed,
        fix_mode=args.fix_it is not None,
        before_counts=before_severity_counts,
        after_counts=after_severity_counts,
    )

    # Always generate markdown
    md_path = reporter.generate_markdown(analyzed, severity_counts)
    print(f"  Markdown: {md_path}")

    # Optional formats
    if args.format == "json":
        json_path = reporter.generate_json(analyzed, severity_counts)
        print(f"  JSON: {json_path}")

    if args.format == "junit":
        junit_path = reporter.generate_junit(analyzed, severity_counts)
        print(f"  JUnit XML: {junit_path}")

    # ----------------------------------------------------------------
    # Summary
    # ----------------------------------------------------------------
    print()
    print("=" * 60)
    print("  SCAN COMPLETE")
    print("=" * 60)
    print()

    posture = analyzer.overall_posture(severity_counts)
    print(f"  Overall Security Posture: {posture}")
    print(f"  Duration: {elapsed:.1f}s")
    print()
    print(f"  Findings:")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
        count = severity_counts.get(sev, 0)
        print(f"    {sev}: {count}")
    print()

    # Top recommendations
    top_findings = [f for f in analyzed if f["severity"] in ("CRITICAL", "HIGH")][:3]
    if top_findings:
        print("  Top actions:")
        for i, f in enumerate(top_findings, 1):
            print(f"    {i}. [{f['severity']}] {f['title']}")
            if f.get("remediation"):
                print(f"       Fix: {f['remediation'][:100]}")
        print()

    print(f"  Reports saved to: {args.output}/")
    print()

    # Exit with non-zero if critical findings
    if severity_counts.get("CRITICAL", 0) > 0:
        sys.exit(2)
    elif severity_counts.get("HIGH", 0) > 0:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
