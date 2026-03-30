"""
NeMo Guardrails AI Safety scanner.

Checks AI/LLM integrations for safety issues through static analysis.
Since this runs in Docker without a live AI endpoint, the checks are
code-level: looking for missing input sanitization, output validation,
PII handling, prompt hardening, and safety guardrails.
"""

import os
import re
from pathlib import Path


class GuardrailsScanner:
    """Phase 3: AI safety analysis for LLM-integrated applications."""

    EXCLUDE_DIRS = {
        "node_modules", ".venv", "venv", "__pycache__", ".git",
        "dist", "build", ".next", "coverage",
    }

    SCANNABLE_EXTENSIONS = {
        ".py", ".js", ".ts", ".tsx", ".jsx", ".yaml", ".yml",
        ".json", ".toml",
    }

    def __init__(self, target_dir: str, project_info: dict):
        self.target = Path(target_dir)
        self.project_info = project_info

    def run(self) -> list:
        if not self.project_info.get("ai_features"):
            return self._all_na()

        findings = []
        findings.extend(self._check_prompt_injection_resistance())
        findings.extend(self._check_jailbreak_resistance())
        findings.extend(self._check_toxicity_bias())
        findings.extend(self._check_topic_boundaries())
        findings.extend(self._check_pii_leakage())
        findings.extend(self._check_hallucination())
        findings.extend(self._check_ai_rate_limiting())
        findings.extend(self._check_system_prompt_security())
        return findings

    def _all_na(self) -> list:
        """Return N/A markers for all NeMo categories when no AI features detected."""
        categories = [
            ("NEMO-PIR", "Prompt Injection Resistance"),
            ("NEMO-JBR", "Jailbreak Resistance"),
            ("NEMO-TBD", "Toxicity / Bias Detection"),
            ("NEMO-TBE", "Topic Boundary Enforcement"),
            ("NEMO-PII", "PII Leakage Prevention"),
            ("NEMO-HAL", "Hallucination Detection"),
        ]
        return [{
            "tool": "nemo-guardrails",
            "category": cat_id,
            "title": f"{cat_name} -- N/A (no AI features detected)",
            "severity": "INFORMATIONAL",
            "file": "",
            "line": 0,
            "description": "No AI/LLM features detected in this project. This category is not applicable.",
            "rule_id": f"{cat_id}-NA",
            "remediation": "",
            "status": "N/A",
        } for cat_id, cat_name in categories]

    def _scan_ai_files(self, callback):
        """Scan files known to contain AI features."""
        findings = []
        ai_files = self.project_info.get("ai_files", []) + self.project_info.get("ai_endpoints", [])
        scanned = set()

        # Also scan all source files for AI-related patterns
        for root, dirs, files in os.walk(self.target):
            dirs[:] = [d for d in dirs if d not in self.EXCLUDE_DIRS]
            for fname in files:
                fpath = Path(root) / fname
                if fpath.suffix not in self.SCANNABLE_EXTENSIONS:
                    continue
                rel_path = str(fpath.relative_to(self.target))
                if rel_path in scanned:
                    continue
                scanned.add(rel_path)

                try:
                    content = fpath.read_text(errors="ignore")
                    results = callback(rel_path, content)
                    if results:
                        findings.extend(results)
                except Exception:
                    continue

        return findings

    # ---- NEMO-PIR: Prompt Injection Resistance ----

    def _check_prompt_injection_resistance(self) -> list:
        findings = []

        sanitize_found = False
        delimiter_found = False

        def check(rel_path, content):
            nonlocal sanitize_found, delimiter_found
            results = []

            # Check for prompt input sanitization
            if re.search(r'sanitize.*prompt|prompt.*sanitize|clean.*input.*ai|filter.*prompt', content, re.IGNORECASE):
                sanitize_found = True

            # Check for delimiter tags around user input
            if re.search(r'<user_input>|<human>|```user|<\|user\|>', content):
                delimiter_found = True

            # Check for direct user input concatenation into prompts
            lines = content.splitlines()
            for i, line in enumerate(lines, 1):
                if re.search(r'(?:prompt|message|content)\s*[=+].*(?:request|req\.|params|query|body|input|user)', line, re.IGNORECASE):
                    if not re.search(r'sanitize|escape|filter|validate|clean', line, re.IGNORECASE):
                        results.append(self._make_finding(
                            "NEMO-PIR", "PIR-CONCAT",
                            "User input concatenated directly into AI prompt",
                            "HIGH",
                            f"At {rel_path}:{i}, user input appears to be directly included in an AI prompt "
                            "without sanitization. An attacker could inject instructions that override the "
                            "system prompt and change the AI's behavior.",
                            "Sanitize all user input before including in prompts. Use delimiter tags "
                            "(e.g., <user_input>...</user_input>) to separate user content from instructions. "
                            "Implement input length limits.",
                            file=rel_path, line=i,
                        ))
            return results

        findings.extend(self._scan_ai_files(check))

        if not sanitize_found and self.project_info.get("ai_features"):
            findings.append(self._make_finding(
                "NEMO-PIR", "PIR-NO-SANITIZE",
                "No prompt input sanitization detected",
                "HIGH",
                "No prompt sanitization function found in the codebase. Without input sanitization, "
                "the AI is vulnerable to prompt injection attacks where users craft inputs that override "
                "system instructions.",
                "Implement a sanitizePromptInput() function that strips instruction-like patterns, "
                "enforces length limits, and escapes special characters before including user input in prompts.",
            ))

        if not delimiter_found and self.project_info.get("ai_features"):
            findings.append(self._make_finding(
                "NEMO-PIR", "PIR-NO-DELIMITER",
                "No delimiter tags used for user input in prompts",
                "MEDIUM",
                "User input is not wrapped in delimiter tags when passed to the AI model. "
                "Delimiters help the model distinguish between instructions and user content.",
                "Wrap user input in clear delimiter tags (e.g., <user_input>content</user_input>) "
                "in all prompts.",
            ))

        return findings

    # ---- NEMO-JBR: Jailbreak Resistance ----

    def _check_jailbreak_resistance(self) -> list:
        findings = []

        nemo_config_found = False
        output_rail_found = False

        def check(rel_path, content):
            nonlocal nemo_config_found, output_rail_found
            lower = content.lower()

            if "nemoguardrails" in lower or ".colang" in rel_path:
                nemo_config_found = True

            if re.search(r'output.*rail|output.*filter|output.*guard|validate.*output|check.*response', lower):
                output_rail_found = True

            return []

        self._scan_ai_files(check)

        if not nemo_config_found:
            findings.append(self._make_finding(
                "NEMO-JBR", "JBR-NO-GUARDRAILS",
                "No NeMo Guardrails or equivalent safety framework detected",
                "MEDIUM",
                "No NeMo Guardrails configuration (.colang files, guardrails config) or equivalent "
                "safety framework found. Without runtime guardrails, the AI may be susceptible to "
                "jailbreak attempts that convince it to ignore its instructions.",
                "Implement NeMo Guardrails or an equivalent runtime safety layer. Define input and output "
                "rails that detect and block jailbreak attempts.",
            ))

        if not output_rail_found:
            findings.append(self._make_finding(
                "NEMO-JBR", "JBR-NO-OUTPUT-RAIL",
                "No AI output validation detected",
                "MEDIUM",
                "No output validation or filtering for AI responses found. Without output rails, "
                "jailbreak attempts that succeed will produce unfiltered responses.",
                "Implement output validation that checks AI responses for policy violations before "
                "sending to the user. Use content classification, regex patterns, and semantic checks.",
            ))

        return findings

    # ---- NEMO-TBD: Toxicity / Bias Detection ----

    def _check_toxicity_bias(self) -> list:
        findings = []

        content_filter_found = False

        def check(rel_path, content):
            nonlocal content_filter_found
            lower = content.lower()

            if re.search(r'content.*filter|moderat|toxic|bias.*detect|safe.*content|content.*policy', lower):
                content_filter_found = True

            return []

        self._scan_ai_files(check)

        if not content_filter_found:
            findings.append(self._make_finding(
                "NEMO-TBD", "TBD-NO-FILTER",
                "No content moderation or toxicity filtering detected",
                "MEDIUM",
                "No content moderation, toxicity detection, or bias filtering found for AI outputs. "
                "The AI could generate harmful, biased, or inappropriate content.",
                "Implement content moderation on AI outputs. Use OpenAI's moderation API, "
                "Perspective API, or custom classifiers to detect and filter toxic content.",
            ))

        return findings

    # ---- NEMO-TBE: Topic Boundary Enforcement ----

    def _check_topic_boundaries(self) -> list:
        findings = []

        system_prompt_found = False
        topic_restriction_found = False

        def check(rel_path, content):
            nonlocal system_prompt_found, topic_restriction_found
            lower = content.lower()

            if re.search(r'system.*prompt|system.*message|role.*system', lower):
                system_prompt_found = True

            if re.search(r'(?:only|must|should).*(?:answer|respond|help).*(?:about|regarding|related)', lower):
                topic_restriction_found = True
            if re.search(r'do not.*(?:answer|respond|help).*(?:about|regarding|unrelated)', lower):
                topic_restriction_found = True

            return []

        self._scan_ai_files(check)

        if system_prompt_found and not topic_restriction_found:
            findings.append(self._make_finding(
                "NEMO-TBE", "TBE-NO-BOUNDARY",
                "System prompt lacks explicit topic boundaries",
                "LOW",
                "A system prompt exists but does not include explicit topic boundary instructions. "
                "Without boundaries, the AI may respond to any topic, including inappropriate ones.",
                "Add explicit topic restrictions to the system prompt: define what the AI should and "
                "should not discuss. Include graceful refusal messages for out-of-scope requests.",
            ))

        return findings

    # ---- NEMO-PII: PII Leakage Prevention ----

    def _check_pii_leakage(self) -> list:
        findings = []

        pii_masking_found = False
        logging_ai_found = False

        def check(rel_path, content):
            nonlocal pii_masking_found, logging_ai_found
            lower = content.lower()

            if re.search(r'mask.*pii|pii.*mask|anonymize|pseudonym|redact.*pii|pii.*redact', lower):
                pii_masking_found = True

            # Check if AI conversations are logged without PII filtering
            if re.search(r'log.*(prompt|completion|response|chat|message)', lower):
                if not re.search(r'mask|redact|anonymize|filter.*pii', lower):
                    logging_ai_found = True

            return []

        self._scan_ai_files(check)

        if not pii_masking_found:
            findings.append(self._make_finding(
                "NEMO-PII", "PII-NO-MASKING",
                "No PII masking before AI submission",
                "HIGH",
                "No PII masking or redaction found before sending data to AI models. "
                "User PII (names, emails, phone numbers, addresses) may be sent to external "
                "AI providers, creating privacy and compliance risks.",
                "Implement PII detection and masking (e.g., regex-based or NER-based) before "
                "sending any user data to AI models. Replace PII with pseudonyms and unmask "
                "in responses if needed.",
            ))

        if logging_ai_found:
            findings.append(self._make_finding(
                "NEMO-PII", "PII-LOG-LEAK",
                "AI conversations logged without PII filtering",
                "MEDIUM",
                "AI prompts or responses are logged without PII filtering. This could store "
                "sensitive user data in log files accessible to operations staff.",
                "Filter or mask PII in all AI-related log entries. Ensure conversation logs "
                "are subject to the same data retention policies as user data.",
            ))

        return findings

    # ---- NEMO-HAL: Hallucination Detection ----

    def _check_hallucination(self) -> list:
        findings = []

        grounding_found = False
        confidence_found = False

        def check(rel_path, content):
            nonlocal grounding_found, confidence_found
            lower = content.lower()

            if re.search(r'ground.*truth|fact.*check|knowledge.*base|retrieval.*augment|rag\b', lower):
                grounding_found = True

            if re.search(r'confidence.*score|certainty|uncertainty|calibrat', lower):
                confidence_found = True

            return []

        self._scan_ai_files(check)

        if not grounding_found:
            findings.append(self._make_finding(
                "NEMO-HAL", "HAL-NO-GROUNDING",
                "No fact-grounding or RAG implementation detected",
                "MEDIUM",
                "No retrieval-augmented generation (RAG), knowledge base grounding, or fact-checking "
                "mechanism found. The AI may generate plausible but incorrect information (hallucinations).",
                "Implement RAG with a verified knowledge base. Ground AI responses in factual data. "
                "Add citation requirements so users can verify claims.",
            ))

        if not confidence_found:
            findings.append(self._make_finding(
                "NEMO-HAL", "HAL-NO-CONFIDENCE",
                "No confidence scoring for AI responses",
                "LOW",
                "No confidence scoring or uncertainty quantification found for AI responses. "
                "Users cannot distinguish high-confidence answers from uncertain ones.",
                "Add confidence scoring to AI responses. Flag low-confidence outputs with disclaimers. "
                "Consider requiring human review for responses below a confidence threshold.",
            ))

        return findings

    # ---- Additional AI Safety Checks ----

    def _check_ai_rate_limiting(self) -> list:
        findings = []

        rate_limit_found = False

        def check(rel_path, content):
            nonlocal rate_limit_found
            lower = content.lower()

            if re.search(r'rate.*limit.*ai|ai.*rate.*limit|throttl.*ai|ai.*throttl', lower):
                rate_limit_found = True
            # Generic rate limiting on AI endpoints
            if re.search(r'rate.*limit', lower) and re.search(r'ai|chat|completion|generate', lower):
                rate_limit_found = True

            return []

        self._scan_ai_files(check)

        if not rate_limit_found:
            findings.append(self._make_finding(
                "NEMO-PIR", "PIR-NO-RATE-LIMIT",
                "No rate limiting on AI endpoints",
                "MEDIUM",
                "No rate limiting specific to AI endpoints found. Without rate limiting, attackers "
                "can make rapid automated requests to probe for vulnerabilities or exhaust AI API quotas.",
                "Implement per-user rate limiting on all AI endpoints. Consider stricter limits than "
                "standard API endpoints due to higher cost per request.",
            ))

        return findings

    def _check_system_prompt_security(self) -> list:
        findings = []

        def check(rel_path, content):
            results = []
            lines = content.splitlines()
            for i, line in enumerate(lines, 1):
                # System prompt in client-side code
                if rel_path.endswith((".jsx", ".tsx", ".vue", ".svelte")):
                    if re.search(r'system.*prompt|role.*system.*content', line, re.IGNORECASE):
                        results.append(self._make_finding(
                            "NEMO-PIR", "PIR-CLIENT-PROMPT",
                            "System prompt exposed in client-side code",
                            "HIGH",
                            f"System prompt found in client-side file {rel_path}:{i}. Users can see the "
                            "system prompt in browser dev tools, revealing instructions meant to be hidden.",
                            "Move system prompts to server-side code. Never include system prompts in "
                            "client-side JavaScript or HTML.",
                            file=rel_path, line=i,
                        ))
            return results

        findings.extend(self._scan_ai_files(check))
        return findings

    def _make_finding(self, category, rule_id, title, severity, description, remediation, file="", line=0):
        return {
            "tool": "nemo-guardrails",
            "category": category,
            "title": title,
            "severity": severity,
            "file": file,
            "line": line,
            "description": description,
            "rule_id": rule_id,
            "remediation": remediation,
        }
