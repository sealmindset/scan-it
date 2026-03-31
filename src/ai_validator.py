#!/usr/bin/env python3
"""
AI Validation Phase (Phase 4.5).

Validates scanner findings using LLM analysis of source code context.
False positives (confidence > 0.8) are removed from the final report.
True positives are enriched with developer validation instructions.

Opt-in via --ai-validate flag. Requires AI provider credentials.
"""

import json
import logging
import os
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)


# ── LLM Provider Abstraction ────────────────────────────────────────
# Pattern from auditgithub/src/services/llm_provider.py


class LLMProvider(ABC):
    """Abstract base class for LLM providers."""

    def create_message(
        self,
        messages: List[Dict[str, str]],
        system: str,
        max_tokens: int = 4096,
        temperature: float = 0.3,
    ) -> Dict[str, Any]:
        return self._call_provider(messages, system, max_tokens, temperature)

    @abstractmethod
    def _call_provider(
        self,
        messages: List[Dict[str, str]],
        system: str,
        max_tokens: int,
        temperature: float,
    ) -> Dict[str, Any]:
        pass

    @abstractmethod
    def get_model_name(self) -> str:
        pass


class AnthropicFoundryProvider(LLMProvider):
    """Azure AI Foundry provider (Anthropic via Azure) — default."""

    def __init__(self):
        import anthropic

        self.client = anthropic.Anthropic(
            api_key=os.getenv("ANTHROPIC_FOUNDRY_API_KEY"),
            base_url=os.getenv("ANTHROPIC_FOUNDRY_BASE_URL"),
        )
        self.model = os.getenv(
            "ANTHROPIC_DEFAULT_SONNET_MODEL",
            "cogdep-aifoundry-dev-eus2-claude-sonnet-4-5",
        )
        logger.info(f"AI Validator using Azure AI Foundry: {self.model}")

    def _call_provider(self, messages, system, max_tokens=4096, temperature=0.3):
        response = self.client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            temperature=temperature,
            system=system,
            messages=messages,
        )
        return {
            "content": response.content[0].text,
            "tokens_used": response.usage.input_tokens + response.usage.output_tokens,
            "model": self.model,
        }

    def get_model_name(self) -> str:
        return self.model


class AnthropicProvider(LLMProvider):
    """Direct Anthropic API provider."""

    def __init__(self):
        import anthropic

        self.client = anthropic.Anthropic(
            api_key=os.getenv("ANTHROPIC_API_KEY"),
        )
        self.model = os.getenv("ANTHROPIC_MODEL", "claude-sonnet-4-20250514")
        logger.info(f"AI Validator using Anthropic Direct: {self.model}")

    def _call_provider(self, messages, system, max_tokens=4096, temperature=0.3):
        response = self.client.messages.create(
            model=self.model,
            max_tokens=max_tokens,
            temperature=temperature,
            system=system,
            messages=messages,
        )
        return {
            "content": response.content[0].text,
            "tokens_used": response.usage.input_tokens + response.usage.output_tokens,
            "model": self.model,
        }

    def get_model_name(self) -> str:
        return self.model


def get_llm_provider() -> LLMProvider:
    """Factory: select provider via AI_PROVIDER env var (default: anthropic_foundry)."""
    provider = os.getenv("AI_PROVIDER", "anthropic_foundry").lower()

    if provider == "anthropic_foundry":
        return AnthropicFoundryProvider()
    elif provider in ("anthropic", "claude"):
        return AnthropicProvider()
    else:
        logger.warning(f"Unknown AI_PROVIDER '{provider}', falling back to anthropic_foundry")
        return AnthropicFoundryProvider()


# ── Source Code Reader ───────────────────────────────────────────────


def read_source_context(
    target_dir: str, file_path: str, line: int, context_lines: int = 10
) -> Optional[str]:
    """Read ~21 lines of source around the finding for LLM context."""
    if not file_path or line <= 0:
        return None

    # Try relative, then strip leading /app/ prefix
    candidates = [
        Path(target_dir) / file_path,
        Path(target_dir) / file_path.lstrip("/"),
    ]
    if file_path.startswith("/app/"):
        candidates.append(Path(target_dir) / file_path[5:])

    fpath = None
    for c in candidates:
        if c.is_file():
            fpath = c
            break
    if fpath is None:
        return None

    try:
        all_lines = fpath.read_text(errors="ignore").splitlines()
    except Exception:
        return None

    start = max(0, line - context_lines - 1)
    end = min(len(all_lines), line + context_lines)
    numbered = []
    for i, text in enumerate(all_lines[start:end], start=start + 1):
        marker = " >>>" if i == line else "    "
        numbered.append(f"{marker} {i:4d} | {text}")
    return "\n".join(numbered)


# ── Prompt Template ──────────────────────────────────────────────────

VALIDATION_SYSTEM_PROMPT = """\
You are a senior application security engineer performing triage on automated \
scanner findings. Your job is to analyze each finding against the actual source \
code and determine whether it is a true positive or false positive.

You must respond with valid JSON only. No markdown fences, no explanation \
outside the JSON.

JSON schema:
{
    "is_false_positive": boolean,
    "confidence": float (0.0 to 1.0),
    "reasoning": "1-2 sentences explaining your assessment",
    "validation_request": "what a developer should test to confirm this finding",
    "validation_result": "what the test result would show if the finding is valid",
    "developer_instructions": "specific commands: curl, grep, test scripts, etc."
}

Rules:
- If the code clearly handles the concern (parameterized queries, input \
  validation, sanitization, safe wrappers), mark as false positive.
- If the finding is about a dependency CVE or configuration issue with no \
  source code context, lean toward true positive unless obviously benign.
- For true positives, provide concrete developer_instructions: curl commands \
  to test endpoints, grep commands to locate related patterns, or minimal \
  test scripts to reproduce the issue.
- Set confidence high (>0.8) only when you are very sure.
- Moderate confidence (0.5-0.8) when context is ambiguous.
"""


def build_validation_prompt(finding: dict, source_context: Optional[str]) -> str:
    """Build the user message for a single finding validation."""
    parts = [
        "## Finding to Validate",
        "",
        f"- **Rule:** {finding.get('rule_id', 'N/A')}",
        f"- **Title:** {finding.get('title', 'N/A')}",
        f"- **Severity:** {finding.get('severity', 'N/A')}",
        f"- **Category:** {finding.get('category', 'N/A')}",
        f"- **File:** {finding.get('file', 'N/A')}:{finding.get('line', 0)}",
        f"- **Tool:** {finding.get('tool', 'N/A')}",
        f"- **Description:** {finding.get('description', 'N/A')}",
        f"- **OWASP:** {finding.get('owasp_category', 'N/A')}",
        "",
        "## Source Code Context",
        "",
    ]

    if source_context:
        parts.append("```")
        parts.append(source_context)
        parts.append("```")
    else:
        parts.append("No source code available for this finding (dependency/config-level issue).")

    parts.append("")
    parts.append("Analyze this finding and return your JSON assessment.")
    return "\n".join(parts)


# ── AI Validator ─────────────────────────────────────────────────────


class AIValidator:
    """Phase 4.5: AI-powered finding validation."""

    FALSE_POSITIVE_THRESHOLD = 0.8

    def __init__(self, target_dir: str):
        self.target_dir = target_dir
        self.provider = get_llm_provider()
        self.stats = {
            "total": 0,
            "true_positives": 0,
            "false_positives": 0,
            "errors": 0,
            "skipped": 0,
            "tokens_used": 0,
        }

    def validate_findings(self, findings: list) -> list:
        """Validate all findings. Returns filtered list with false positives removed."""
        validated = []

        for finding in findings:
            # Skip N/A findings (guardrails placeholders)
            if finding.get("status") == "N/A":
                validated.append(finding)
                self.stats["skipped"] += 1
                continue

            self.stats["total"] += 1
            result = self._validate_single(finding)

            if result is None:
                # AI call failed — keep finding as-is
                validated.append(finding)
                self.stats["errors"] += 1
                continue

            if result.get("is_false_positive") and result.get("confidence", 0) > self.FALSE_POSITIVE_THRESHOLD:
                self.stats["false_positives"] += 1
                print(f"    ✕ FALSE POSITIVE ({result['confidence']:.0%}): {finding.get('rule_id', '?')} — {finding['title']}")
                continue  # excluded from report

            # True positive — enrich with validation data
            finding["validation"] = {
                "is_false_positive": result.get("is_false_positive", False),
                "confidence": result.get("confidence", 0),
                "reasoning": result.get("reasoning", ""),
                "validation_request": result.get("validation_request", ""),
                "validation_result": result.get("validation_result", ""),
                "developer_instructions": result.get("developer_instructions", ""),
            }
            validated.append(finding)
            self.stats["true_positives"] += 1
            print(f"    ✓ TRUE POSITIVE ({result.get('confidence', 0):.0%}): {finding.get('rule_id', '?')} — {finding['title']}")

        return validated

    def _validate_single(self, finding: dict) -> Optional[dict]:
        """Validate a single finding via AI. Returns parsed JSON or None on error."""
        source_context = read_source_context(
            self.target_dir,
            finding.get("file", ""),
            finding.get("line", 0),
        )
        user_message = build_validation_prompt(finding, source_context)

        try:
            response = self.provider.create_message(
                messages=[{"role": "user", "content": user_message}],
                system=VALIDATION_SYSTEM_PROMPT,
                max_tokens=1024,
                temperature=0.2,
            )
            self.stats["tokens_used"] += response.get("tokens_used", 0)

            content = response["content"].strip()
            # Strip markdown fences if the LLM wraps its response
            if content.startswith("```"):
                content = content.split("\n", 1)[1]
                if content.endswith("```"):
                    content = content.rsplit("```", 1)[0]

            return json.loads(content.strip())

        except json.JSONDecodeError as e:
            logger.warning(f"AI returned invalid JSON for {finding.get('rule_id', '?')}: {e}")
            return None
        except Exception as e:
            logger.warning(f"AI validation failed for {finding.get('rule_id', '?')}: {e}")
            return None

    def print_summary(self):
        """Print Phase 4.5 summary."""
        s = self.stats
        print(f"  AI model: {self.provider.get_model_name()}")
        print(f"  Findings validated: {s['total']}")
        print(f"    True positives: {s['true_positives']}")
        print(f"    False positives removed: {s['false_positives']}")
        if s["errors"]:
            print(f"    Errors (kept as-is): {s['errors']}")
        if s["skipped"]:
            print(f"    Skipped (N/A): {s['skipped']}")
        if s["tokens_used"]:
            print(f"  Tokens used: {s['tokens_used']:,}")
