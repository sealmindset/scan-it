# scan-it: Dockerized security scanner
# Combines NeMo AI safety + OWASP Testing Guide + Dependency scanning + SAST
# Usage: docker run -v $(pwd):/app scan-it [mode] [--format json|junit]

FROM python:3.12-slim AS base

LABEL maintainer="sealmindset"
LABEL description="Standalone security scanner with NeMo + OWASP coverage"
LABEL version="1.0.0"

# Prevent interactive prompts
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV SCAN_IT_HOME=/opt/scan-it

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    git \
    jq \
    nodejs \
    npm \
    wget \
    unzip \
    && rm -rf /var/lib/apt/lists/*

# Install Trivy
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Install Python security tools
RUN pip install --no-cache-dir \
    semgrep \
    bandit \
    pip-audit \
    pyyaml \
    jinja2 \
    rich \
    anthropic

# Install Node.js security tools
RUN npm install -g \
    eslint \
    eslint-plugin-security \
    @eslint/js

# Create application directory
WORKDIR ${SCAN_IT_HOME}

# Copy source code
COPY src/ ./src/
COPY templates/ ./templates/
COPY config/ ./config/
COPY entrypoint.sh ./entrypoint.sh
COPY VERSION ./VERSION

RUN chmod +x ./entrypoint.sh

# Create output directory mount point
RUN mkdir -p /app /output /tmp/scan-it

ENTRYPOINT ["./entrypoint.sh"]
CMD ["full"]
