#!/usr/bin/env bash
# scan-it: Convenience wrapper for running the Docker scanner
#
# Usage:
#   ./scan-it.sh /path/to/project [mode] [--format json|junit]
#
# Examples:
#   ./scan-it.sh .                          # Full scan of current directory
#   ./scan-it.sh /my/app sast               # SAST only
#   ./scan-it.sh /my/app full --format json  # Full scan + JSON output
#   ./scan-it.sh /my/app deps               # Dependency scan only

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="scan-it:latest"

# Parse arguments
TARGET="${1:-.}"
shift || true
MODE="${1:-full}"
shift || true

# Check for --ai-validate flag in remaining args
AI_VALIDATE=""
EXTRA_ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ai-validate)
            AI_VALIDATE="--ai-validate"
            shift
            ;;
        *)
            EXTRA_ARGS+=("$1")
            shift
            ;;
    esac
done

# Resolve target to absolute path
TARGET="$(cd "$TARGET" 2>/dev/null && pwd || echo "$TARGET")"

if [ ! -d "$TARGET" ]; then
    echo "ERROR: Target directory does not exist: $TARGET"
    exit 1
fi

# Create output directory
OUTPUT_DIR="${TARGET}/scan-it-reports"
mkdir -p "$OUTPUT_DIR"

# Build image if needed
if ! docker image inspect "$IMAGE_NAME" &>/dev/null; then
    echo "Building scan-it Docker image..."
    docker build -t "$IMAGE_NAME" "$SCRIPT_DIR"
    echo ""
fi

# Run the scanner
echo "Scanning: $TARGET"
echo "Mode: $MODE"
echo "Output: $OUTPUT_DIR"
echo ""

# Load .env file if present (for AI provider credentials, etc.)
ENV_FILE_FLAG=""
if [ -f "${SCRIPT_DIR}/.env" ]; then
    ENV_FILE_FLAG="--env-file ${SCRIPT_DIR}/.env"
elif [ -f "${TARGET}/.env" ]; then
    ENV_FILE_FLAG="--env-file ${TARGET}/.env"
fi

docker run --rm \
    -v "$TARGET":/app:ro \
    -v "$OUTPUT_DIR":/output \
    ${ENV_FILE_FLAG:+$ENV_FILE_FLAG} \
    "$IMAGE_NAME" \
    "$MODE" ${AI_VALIDATE:+$AI_VALIDATE} "${EXTRA_ARGS[@]}"

echo ""
echo "Reports saved to: $OUTPUT_DIR/"
