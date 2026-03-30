"""
Project type and feature detection.

Detects languages, frameworks, AI/LLM features, Docker presence,
and running services without modifying the target project.
"""

import os
import re
from pathlib import Path


class ProjectDetector:
    """Detect project characteristics by examining files and structure."""

    AI_IMPORT_PATTERNS = [
        r"openai", r"anthropic", r"langchain", r"llama",
        r"transformers", r"nemoguardrails", r"huggingface",
        r"azure.*openai", r"azure.*ai", r"ollama", r"mistral",
        r"cohere", r"gemini", r"google\.generativeai",
    ]

    AI_ENDPOINT_PATTERNS = [
        r"/api/ai", r"/api/chat", r"/api/completion",
        r"/api/generate", r"/api/embed", r"/v1/chat",
        r"/v1/completion",
    ]

    SCANNABLE_EXTENSIONS = {
        ".py", ".js", ".ts", ".tsx", ".jsx", ".go", ".rs",
        ".java", ".rb", ".php", ".yaml", ".yml", ".json",
        ".toml", ".env", ".cfg", ".ini", ".conf",
    }

    EXCLUDE_DIRS = {
        "node_modules", ".venv", "venv", "__pycache__", ".git",
        "dist", "build", ".next", "coverage", ".tox", ".mypy_cache",
        "vendor", "target",
    }

    def __init__(self, target_dir: str):
        self.target = Path(target_dir)

    def detect(self) -> dict:
        """Run all detection routines and return project info."""
        info = {
            "name": self.target.name,
            "path": str(self.target),
            "languages": [],
            "frameworks": [],
            "ai_features": False,
            "ai_files": [],
            "ai_endpoints": [],
            "has_docker": False,
            "has_node": False,
            "has_python": False,
            "has_go": False,
            "has_rust": False,
        }

        self._detect_languages(info)
        self._detect_frameworks(info)
        self._detect_ai_features(info)
        self._detect_docker(info)

        return info

    def _detect_languages(self, info: dict):
        if (self.target / "package.json").exists():
            info["languages"].append("javascript")
            info["has_node"] = True

        # Check for TypeScript
        if (self.target / "tsconfig.json").exists():
            if "typescript" not in info["languages"]:
                info["languages"].append("typescript")

        py_markers = ["requirements.txt", "setup.py", "pyproject.toml", "Pipfile"]
        if any((self.target / m).exists() for m in py_markers):
            info["languages"].append("python")
            info["has_python"] = True

        if (self.target / "go.mod").exists():
            info["languages"].append("go")
            info["has_go"] = True

        if (self.target / "Cargo.toml").exists():
            info["languages"].append("rust")
            info["has_rust"] = True

    def _detect_frameworks(self, info: dict):
        pkg_json = self.target / "package.json"
        if pkg_json.exists():
            try:
                content = pkg_json.read_text()
                frameworks_map = {
                    "next": "nextjs",
                    "react": "react",
                    "vue": "vue",
                    "angular": "angular",
                    "express": "express",
                    "fastify": "fastify",
                    "koa": "koa",
                    "nest": "nestjs",
                }
                for key, name in frameworks_map.items():
                    if f'"{key}' in content.lower():
                        info["frameworks"].append(name)
            except Exception:
                pass

        py_files = ["requirements.txt", "pyproject.toml", "setup.py", "Pipfile"]
        for pf in py_files:
            fpath = self.target / pf
            if fpath.exists():
                try:
                    content = fpath.read_text().lower()
                    py_frameworks = {
                        "fastapi": "fastapi",
                        "django": "django",
                        "flask": "flask",
                        "starlette": "starlette",
                        "tornado": "tornado",
                        "aiohttp": "aiohttp",
                    }
                    for key, name in py_frameworks.items():
                        if key in content and name not in info["frameworks"]:
                            info["frameworks"].append(name)
                except Exception:
                    pass

    def _detect_ai_features(self, info: dict):
        """Scan source files for AI/LLM imports and endpoint patterns."""
        ai_import_re = re.compile("|".join(self.AI_IMPORT_PATTERNS), re.IGNORECASE)
        ai_endpoint_re = re.compile("|".join(self.AI_ENDPOINT_PATTERNS), re.IGNORECASE)

        for root, dirs, files in os.walk(self.target):
            # Prune excluded directories
            dirs[:] = [d for d in dirs if d not in self.EXCLUDE_DIRS]

            for fname in files:
                fpath = Path(root) / fname
                if fpath.suffix not in self.SCANNABLE_EXTENSIONS:
                    continue
                try:
                    content = fpath.read_text(errors="ignore")
                except Exception:
                    continue

                if ai_import_re.search(content):
                    rel = str(fpath.relative_to(self.target))
                    if rel not in info["ai_files"]:
                        info["ai_files"].append(rel)
                        info["ai_features"] = True

                if ai_endpoint_re.search(content):
                    rel = str(fpath.relative_to(self.target))
                    if rel not in info["ai_endpoints"]:
                        info["ai_endpoints"].append(rel)
                        info["ai_features"] = True

        # Check for NeMo / guardrails config files
        nemo_markers = ["colang", "guardrails"]
        for marker in nemo_markers:
            if (self.target / marker).is_dir():
                info["ai_features"] = True

        for fpath in self.target.glob("*.colang"):
            info["ai_features"] = True
            break

    def _detect_docker(self, info: dict):
        docker_files = ["Dockerfile", "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"]
        info["has_docker"] = any((self.target / f).exists() for f in docker_files)
