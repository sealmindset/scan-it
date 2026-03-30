#!/usr/bin/env bash
set -euo pipefail

SCAN_MODE="${1:-full}"
FORMAT_FLAG=""
TARGET_DIR="/app"
OUTPUT_DIR="/output"

# Parse arguments
shift || true
while [[ $# -gt 0 ]]; do
    case "$1" in
        --format)
            FORMAT_FLAG="$2"
            shift 2
            ;;
        --target)
            TARGET_DIR="$2"
            shift 2
            ;;
        --output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        *)
            shift
            ;;
    esac
done

# Ensure output directory exists
mkdir -p "$OUTPUT_DIR"

echo "============================================"
echo "  scan-it: Security Attestation Scanner"
echo "  Mode: $SCAN_MODE"
echo "  Target: $TARGET_DIR"
echo "  Output: $OUTPUT_DIR"
echo "============================================"
echo ""

# Run the scanner
exec python3 "${SCAN_IT_HOME}/src/scanner.py" \
    --mode "$SCAN_MODE" \
    --target "$TARGET_DIR" \
    --output "$OUTPUT_DIR" \
    ${FORMAT_FLAG:+--format "$FORMAT_FLAG"}
