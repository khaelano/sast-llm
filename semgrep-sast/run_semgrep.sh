#!/usr/bin/env bash
# =============================================================
# Semgrep SAST Scanner
# Menjalankan scan menggunakan Semgrep dengan berbagai ruleset
# =============================================================

set -euo pipefail

# Get script directory and project root (works regardless of where script is run from)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color
BOLD='\033[1m'

# Default values
TARGET_DIR="${PROJECT_ROOT}/vulnerable-samples"
OUTPUT_DIR="${PROJECT_ROOT}/results"
CUSTOM_RULES_DIR="${SCRIPT_DIR}/rules"
OUTPUT_FORMAT="json"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

print_banner() {
    echo -e "${BOLD}${BLUE}"
    echo "╔══════════════════════════════════════════════════════╗"
    echo "║           SEMGREP SAST SCANNER                       ║"
    echo "║  Static Application Security Testing with Semgrep    ║"
    echo "╚══════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

check_semgrep() {
    if ! command -v semgrep &> /dev/null; then
        echo -e "${RED}Error: Semgrep tidak ditemukan!${NC}"
        echo ""
        echo "Install Semgrep:"
        echo "  pip install semgrep"
        echo "  atau"
        echo "  brew install semgrep"
        exit 1
    fi
    
    SEMGREP_VERSION=$(semgrep --version 2>&1 | head -1)
    echo -e "${GREEN}✓ Semgrep ditemukan: ${SEMGREP_VERSION}${NC}"
}

run_scan() {
    local scan_name=$1
    local rules=$2
    local output_file=$3
    local extra_args=${4:-""}
    
    echo -e "\n${CYAN}[Scan] ${scan_name}${NC}"
    echo -e "  Rules   : ${rules}"
    echo -e "  Target  : ${TARGET_DIR}"
    echo -e "  Output  : ${output_file}"
    echo ""
    
    # Jalankan semgrep
    if semgrep \
        --config "${rules}" \
        --json \
        --output "${output_file}" \
        ${extra_args} \
        "${TARGET_DIR}" 2>&1 | grep -v "^$"; then
        
        # Hitung findings
        if [ -f "${output_file}" ]; then
            FINDING_COUNT=$(python3 -c "
import json
with open('${output_file}') as f:
    data = json.load(f)
results = data.get('results', [])
print(len(results))
" 2>/dev/null || echo "?")
            echo -e "${GREEN}  ✓ Selesai: ${FINDING_COUNT} findings${NC}"
        fi
    else
        echo -e "${YELLOW}  ! Scan selesai dengan warning${NC}"
    fi
}

# =============================================================
# MAIN
# =============================================================

print_banner
check_semgrep

# Buat direktori output
mkdir -p "${OUTPUT_DIR}"

echo -e "\n${BOLD}Target: ${TARGET_DIR}${NC}"
echo -e "${BOLD}Output: ${OUTPUT_DIR}${NC}"
echo ""
echo -e "${YELLOW}Memulai scan...${NC}"
echo "─────────────────────────────────────────────────────────"

# ------------------------------------------------------------
# Scan 1: OWASP Top 10 (Ruleset Resmi Semgrep)
# ------------------------------------------------------------
run_scan \
    "OWASP Top 10 (Official Semgrep Rules)" \
    "p/owasp-top-ten" \
    "${OUTPUT_DIR}/semgrep_owasp_top10.json"

# ------------------------------------------------------------
# Scan 2: Python Security Rules
# ------------------------------------------------------------
run_scan \
    "Python Security (Official)" \
    "p/python" \
    "${OUTPUT_DIR}/semgrep_python.json"

# ------------------------------------------------------------
# Scan 3: JavaScript/Node.js Security
# ------------------------------------------------------------
run_scan \
    "JavaScript Security (Official)" \
    "p/javascript" \
    "${OUTPUT_DIR}/semgrep_javascript.json"

# ------------------------------------------------------------
# Scan 4: Secrets Detection
# ------------------------------------------------------------
run_scan \
    "Secrets Detection" \
    "p/secrets" \
    "${OUTPUT_DIR}/semgrep_secrets.json"

# ------------------------------------------------------------
# Scan 5: Custom Rules (buatan sendiri)
# ------------------------------------------------------------
if [ -d "${CUSTOM_RULES_DIR}" ]; then
    run_scan \
        "Custom Security Rules" \
        "${CUSTOM_RULES_DIR}" \
        "${OUTPUT_DIR}/semgrep_custom.json"
fi

# ------------------------------------------------------------
# Scan 6: Full Scan - Gabungan semua rules
# ------------------------------------------------------------
echo -e "\n${CYAN}[Scan] Full Scan (Semua Rules Digabung)${NC}"
echo -e "  Output: ${OUTPUT_DIR}/semgrep_full_results.json"

semgrep \
    --config "p/owasp-top-ten" \
    --config "p/python" \
    --config "p/javascript" \
    --config "p/secrets" \
    --config "${CUSTOM_RULES_DIR}" \
    --json \
    --output "${OUTPUT_DIR}/semgrep_full_results.json" \
    --metrics=off \
    "${TARGET_DIR}" 2>&1 | grep -E "(Found|Ran|Error)" || true

TOTAL_FINDINGS=$(python3 -c "
import json
with open('${OUTPUT_DIR}/semgrep_full_results.json') as f:
    data = json.load(f)
results = data.get('results', [])
print(len(results))
" 2>/dev/null || echo "?")

echo -e "${GREEN}  ✓ Total findings: ${TOTAL_FINDINGS}${NC}"

# ------------------------------------------------------------
# Buat Summary Report
# ------------------------------------------------------------
echo ""
echo "─────────────────────────────────────────────────────────"
echo -e "${BOLD}Membuat summary report...${NC}"

python3 - << 'PYEOF'
import json
import os
from collections import defaultdict

output_dir = os.environ.get("OUTPUT_DIR", "../results")
report_file = f"{output_dir}/semgrep_summary.txt"

try:
    with open(f"{output_dir}/semgrep_full_results.json") as f:
        data = json.load(f)
except FileNotFoundError:
    print("File hasil tidak ditemukan")
    exit(1)

results = data.get('results', [])
errors = data.get('errors', [])

# Hitung severity
severity_counts = defaultdict(int)
rule_counts = defaultdict(int)
file_counts = defaultdict(int)
categories = defaultdict(int)

for r in results:
    severity = r.get('extra', {}).get('severity', 'WARNING').upper()
    rule_id = r.get('check_id', 'unknown')
    filepath = r.get('path', 'unknown')
    
    severity_counts[severity] += 1
    rule_counts[rule_id] += 1
    file_counts[os.path.basename(filepath)] += 1

# Generate report
lines = []
lines.append("=" * 60)
lines.append("SEMGREP SAST SCAN SUMMARY")
lines.append("=" * 60)
lines.append(f"Total Findings : {len(results)}")
lines.append(f"Total Errors   : {len(errors)}")
lines.append("")

lines.append("Distribusi Severity:")
for sev in ['ERROR', 'WARNING', 'INFO']:
    count = severity_counts.get(sev, 0)
    bar = "█" * min(count, 40)
    lines.append(f"  {sev:<10} : {count:3d}  {bar}")

lines.append("")
lines.append("Top Rules Triggered:")
for rule, count in sorted(rule_counts.items(), key=lambda x: x[1], reverse=True)[:10]:
    short_rule = rule.split('.')[-1] if '.' in rule else rule
    lines.append(f"  {count:3d}x  {short_rule}")

lines.append("")
lines.append("Files dengan Vulnerabilities:")
for fname, count in sorted(file_counts.items(), key=lambda x: x[1], reverse=True):
    lines.append(f"  {count:3d}  {fname}")

lines.append("")
lines.append("Detail Findings:")
for r in results:
    path = r.get('path', '')
    start_line = r.get('start', {}).get('line', 0)
    rule_id = r.get('check_id', '').split('.')[-1]
    severity = r.get('extra', {}).get('severity', 'WARNING')
    message = r.get('extra', {}).get('message', '')[:80]
    lines.append(f"  [{severity}] {os.path.basename(path)}:{start_line}  {rule_id}")

report_content = '\n'.join(lines)
print(report_content)

with open(report_file, 'w') as f:
    f.write(report_content)
    
print(f"\nReport disimpan ke: {report_file}")
PYEOF

echo ""
echo -e "${BOLD}${GREEN}✓ Semua scan selesai!${NC}"
echo ""
echo "File hasil:"
ls -la "${OUTPUT_DIR}"/semgrep_*.json 2>/dev/null | awk '{print "  " $NF}' || echo "  Tidak ada file hasil"
echo ""
echo "Untuk melihat hasil secara visual:"
echo "  semgrep --config p/owasp-top-ten --output findings.html --html ${TARGET_DIR}"
