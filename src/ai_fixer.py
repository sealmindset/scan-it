#!/usr/bin/env python3
"""
AI Fix Generation Phase (Phase 4.7).

Classifies validated findings as AUTO / SEMI_AUTO / MANUAL, generates code
patches via AI, applies AUTO fixes directly, stores SEMI_AUTO diffs for
developer review, and records MANUAL guidance.

Opt-in via --fix-it flag (implies --ai-validate).
"""

import difflib
import json
import logging
import os
from pathlib import Path
from typing import Optional

from ai_validator import get_llm_provider, read_source_context

logger = logging.getLogger(__name__)


# ── Classification Rules ─────────────────────────────────────────────
# Decision tree from make-it fix-strategies.md

CLASSIFICATION_RULES = [
    # Dependency CVEs -> AUTO (npm audit fix / pip install)
    (lambda f: f.get("category", "").startswith("DEP-"), "AUTO"),
    # SSL verify=False -> AUTO
    (lambda f: "verify=false" in f.get("title", "").lower(), "AUTO"),
    # Missing request timeouts -> AUTO
    (lambda f: "timeout" in f.get("title", "").lower(), "AUTO"),
    # Weak crypto (MD5/SHA1) -> AUTO
    (lambda f: any(k in f.get("title", "").lower() for k in ("md5", "sha1", "weak hash", "weak crypto")), "AUTO"),
    # Temp file issues -> AUTO
    (lambda f: any(k in f.get("title", "").lower() for k in ("temp file", "mktemp", "tempfile")), "AUTO"),
    # SQL injection -> SEMI_AUTO
    (lambda f: "sql injection" in f.get("title", "").lower(), "SEMI_AUTO"),
    # XSS / HTML injection -> SEMI_AUTO
    (lambda f: any(k in f.get("title", "").lower() for k in ("xss", "cross-site", "innerhtml", "html injection")), "SEMI_AUTO"),
    # Pickle / deserialization -> SEMI_AUTO
    (lambda f: any(k in f.get("title", "").lower() for k in ("pickle", "deserialization", "deserialize")), "SEMI_AUTO"),
    # Hardcoded secrets -> SEMI_AUTO
    (lambda f: any(k in f.get("title", "").lower() for k in ("hardcoded", "secret in source", "api key", "password")), "SEMI_AUTO"),
    # Config fixes (permissions, bind address) -> SEMI_AUTO
    (lambda f: any(k in f.get("title", "").lower() for k in ("permission", "0.0.0.0", "bind address")), "SEMI_AUTO"),
    # AI safety / NeMo -> MANUAL
    (lambda f: f.get("category", "").startswith("NEMO-"), "MANUAL"),
    # Rate limiting -> MANUAL
    (lambda f: "rate limit" in f.get("title", "").lower(), "MANUAL"),
]


def classify_finding(finding: dict) -> str:
    """Classify a finding as AUTO, SEMI_AUTO, or MANUAL."""
    for check, classification in CLASSIFICATION_RULES:
        try:
            if check(finding):
                return classification
        except Exception:
            continue
    return "MANUAL"


# ── Fix Prompt Template ──────────────────────────────────────────────

FIX_SYSTEM_PROMPT = """\
You are a senior application security engineer. Your job is to generate \
precise, minimal code fixes for security vulnerabilities.

You must respond with valid JSON only. No markdown fences, no explanation \
outside the JSON.

JSON schema:
{
    "fix_type": "short description of the fix strategy applied",
    "original_code": "exact verbatim code to be replaced (whitespace-sensitive)",
    "fixed_code": "the corrected replacement code",
    "explanation": "1-3 sentences explaining what changed and why",
    "file_path": "relative path to the file being fixed",
    "line_start": integer,
    "line_end": integer,
    "cannot_fix": false
}

Rules:
- original_code MUST be an EXACT substring of the source file (whitespace-sensitive). \
  Copy it verbatim from the source context provided.
- fixed_code should be a minimal, drop-in replacement. Change only what is needed.
- Do NOT change unrelated code. Preserve indentation, coding style, and variable names.
- For dependency issues with no source code, set original_code and fixed_code to "" \
  and put the fix command (npm audit fix, pip install, etc.) in explanation.
- If you cannot produce a safe automated fix, set "cannot_fix": true and put \
  guidance in explanation instead.
"""


def build_fix_prompt(finding: dict, source_context: Optional[str], classification: str) -> str:
    """Build the user message for fix generation."""
    parts = [
        "## Finding to Fix",
        "",
        f"- **Rule:** {finding.get('rule_id', 'N/A')}",
        f"- **Title:** {finding.get('title', 'N/A')}",
        f"- **Severity:** {finding.get('severity', 'N/A')}",
        f"- **Category:** {finding.get('category', 'N/A')}",
        f"- **File:** {finding.get('file', 'N/A')}:{finding.get('line', 0)}",
        f"- **Tool:** {finding.get('tool', 'N/A')}",
        f"- **Description:** {finding.get('description', 'N/A')}",
        f"- **Remediation hint:** {finding.get('remediation', 'N/A')}",
        f"- **Pre-classification:** {classification}",
        "",
        "## Source Code Context",
        "",
    ]

    if source_context:
        parts.append("```")
        parts.append(source_context)
        parts.append("```")
    else:
        parts.append("No source code available (dependency or configuration-level issue).")

    parts.append("")
    parts.append("Generate the minimal fix. Return JSON only.")
    return "\n".join(parts)


# ── AI Fixer ─────────────────────────────────────────────────────────


class AIFixer:
    """Phase 4.7: AI-powered fix generation and application."""

    CONTEXT_LINES = 30  # More context than validator (which uses 10)

    def __init__(self, target_dir: str, severity_scope: list):
        self.target_dir = target_dir
        self.severity_scope = severity_scope
        self.provider = get_llm_provider()
        self.stats = {
            "total_in_scope": 0,
            "auto_applied": 0,
            "auto_downgraded": 0,
            "semi_auto_generated": 0,
            "manual_guidance": 0,
            "errors": 0,
            "skipped": 0,
            "tokens_used": 0,
        }

    def fix_findings(self, findings: list) -> list:
        """Process all findings. Applies AUTO fixes, generates SEMI_AUTO diffs,
        records MANUAL guidance. Returns the enriched findings list."""

        for finding in findings:
            # Skip N/A findings
            if finding.get("status") == "N/A":
                finding["fix_info"] = {
                    "classification": "SKIP",
                    "status": "skipped",
                    "fix_type": "N/A",
                    "explanation": "Finding is N/A — no fix needed.",
                    "diff": None,
                    "guidance": None,
                }
                self.stats["skipped"] += 1
                continue

            # Skip findings outside severity scope
            if finding.get("severity", "") not in self.severity_scope:
                finding["fix_info"] = {
                    "classification": "SKIP",
                    "status": "skipped",
                    "fix_type": "Out of scope",
                    "explanation": f"Severity {finding.get('severity')} not in fix scope.",
                    "diff": None,
                    "guidance": None,
                }
                self.stats["skipped"] += 1
                continue

            self.stats["total_in_scope"] += 1
            classification = classify_finding(finding)

            if classification == "MANUAL":
                finding["fix_info"] = {
                    "classification": "MANUAL",
                    "status": "guidance_only",
                    "fix_type": "Manual intervention required",
                    "explanation": finding.get("remediation", "Review and fix manually."),
                    "diff": None,
                    "guidance": finding.get("remediation", ""),
                }
                self.stats["manual_guidance"] += 1
                print(f"    ▸ MANUAL: {finding.get('rule_id', '?')} — {finding['title']}")
                continue

            # AUTO or SEMI_AUTO — ask AI for a patch
            result = self._fix_single(finding, classification)

            if result is None or result.get("cannot_fix"):
                # AI couldn't generate fix — downgrade to manual
                explanation = "AI could not generate a safe fix."
                if result and result.get("explanation"):
                    explanation = result["explanation"]
                finding["fix_info"] = {
                    "classification": "MANUAL",
                    "status": "guidance_only",
                    "fix_type": "AI fix generation failed",
                    "explanation": explanation,
                    "diff": None,
                    "guidance": finding.get("remediation", ""),
                }
                self.stats["errors"] += 1
                print(f"    ▸ MANUAL (AI unable): {finding.get('rule_id', '?')} — {finding['title']}")
                continue

            original = result.get("original_code", "")
            fixed = result.get("fixed_code", "")
            file_path = result.get("file_path", finding.get("file", ""))

            if classification == "AUTO" and original and fixed:
                applied = self._apply_fix(file_path, original, fixed)
                if applied:
                    diff_text = self._generate_diff(original, fixed, file_path)
                    finding["fix_info"] = {
                        "classification": "AUTO",
                        "status": "applied",
                        "fix_type": result.get("fix_type", ""),
                        "explanation": result.get("explanation", ""),
                        "diff": diff_text,
                        "guidance": None,
                    }
                    self.stats["auto_applied"] += 1
                    print(f"    ✓ AUTO (applied): {finding.get('rule_id', '?')} — {finding['title']}")
                else:
                    # Downgrade to SEMI_AUTO
                    diff_text = self._generate_diff(original, fixed, file_path)
                    finding["fix_info"] = {
                        "classification": "SEMI_AUTO",
                        "status": "patch_generated",
                        "fix_type": result.get("fix_type", ""),
                        "explanation": result.get("explanation", "") + " (Auto-apply failed; review patch manually.)",
                        "diff": diff_text,
                        "guidance": None,
                    }
                    self.stats["auto_downgraded"] += 1
                    print(f"    ~ SEMI-AUTO (downgraded): {finding.get('rule_id', '?')} — {finding['title']}")
            else:
                # SEMI_AUTO or no original/fixed code (dependency fix)
                diff_text = self._generate_diff(original, fixed, file_path) if original and fixed else None
                finding["fix_info"] = {
                    "classification": classification,
                    "status": "patch_generated" if diff_text else "guidance_only",
                    "fix_type": result.get("fix_type", ""),
                    "explanation": result.get("explanation", ""),
                    "diff": diff_text,
                    "guidance": None if diff_text else result.get("explanation", ""),
                }
                if diff_text:
                    self.stats["semi_auto_generated"] += 1
                    print(f"    ~ SEMI-AUTO (patch): {finding.get('rule_id', '?')} — {finding['title']}")
                else:
                    self.stats["manual_guidance"] += 1
                    print(f"    ▸ GUIDANCE: {finding.get('rule_id', '?')} — {finding['title']}")

        return findings

    def _fix_single(self, finding: dict, classification: str) -> Optional[dict]:
        """Generate a fix for a single finding via AI."""
        source_context = read_source_context(
            self.target_dir,
            finding.get("file", ""),
            finding.get("line", 0),
            context_lines=self.CONTEXT_LINES,
        )
        user_message = build_fix_prompt(finding, source_context, classification)

        try:
            response = self.provider.create_message(
                messages=[{"role": "user", "content": user_message}],
                system=FIX_SYSTEM_PROMPT,
                max_tokens=2048,
                temperature=0.2,
            )
            self.stats["tokens_used"] += response.get("tokens_used", 0)

            content = response["content"].strip()
            if content.startswith("```"):
                content = content.split("\n", 1)[1]
                if content.endswith("```"):
                    content = content.rsplit("```", 1)[0]

            return json.loads(content.strip())

        except json.JSONDecodeError as e:
            logger.warning(f"AI returned invalid JSON for fix {finding.get('rule_id', '?')}: {e}")
            return None
        except Exception as e:
            logger.warning(f"AI fix generation failed for {finding.get('rule_id', '?')}: {e}")
            return None

    def _apply_fix(self, file_path: str, original_code: str, fixed_code: str) -> bool:
        """Apply an AUTO fix via exact string replacement. Returns True on success."""
        # Resolve file path
        fpath = Path(self.target_dir) / file_path
        if not fpath.is_file():
            # Try stripping /app/ prefix
            if file_path.startswith("/app/"):
                fpath = Path(self.target_dir) / file_path[5:]
            if not fpath.is_file():
                logger.warning(f"Cannot apply fix: file not found: {file_path}")
                return False

        try:
            content = fpath.read_text(errors="ignore")
        except Exception as e:
            logger.warning(f"Cannot read file for fix: {e}")
            return False

        # Safety: original_code must appear exactly once
        count = content.count(original_code)
        if count == 0:
            logger.warning(f"Cannot apply fix: original_code not found in {file_path}")
            return False
        if count > 1:
            logger.warning(f"Cannot apply fix: original_code appears {count} times in {file_path}")
            return False

        new_content = content.replace(original_code, fixed_code, 1)

        try:
            fpath.write_text(new_content)
            return True
        except Exception as e:
            logger.warning(f"Cannot write fixed file: {e}")
            return False

    def _generate_diff(self, original_code: str, fixed_code: str, file_path: str) -> str:
        """Generate a unified diff string."""
        original_lines = original_code.splitlines(keepends=True)
        fixed_lines = fixed_code.splitlines(keepends=True)
        diff = difflib.unified_diff(
            original_lines,
            fixed_lines,
            fromfile=f"a/{file_path}",
            tofile=f"b/{file_path}",
        )
        return "".join(diff)

    def print_summary(self):
        """Print Phase 4.7 summary."""
        s = self.stats
        print(f"  AI model: {self.provider.get_model_name()}")
        print(f"  Findings in scope: {s['total_in_scope']}")
        print(f"    AUTO applied: {s['auto_applied']}")
        if s["auto_downgraded"]:
            print(f"    AUTO downgraded to SEMI-AUTO: {s['auto_downgraded']}")
        print(f"    SEMI-AUTO patches: {s['semi_auto_generated']}")
        print(f"    MANUAL guidance: {s['manual_guidance']}")
        if s["errors"]:
            print(f"    Errors: {s['errors']}")
        if s["skipped"]:
            print(f"    Skipped (out of scope/N/A): {s['skipped']}")
        if s["tokens_used"]:
            print(f"  Tokens used: {s['tokens_used']:,}")
