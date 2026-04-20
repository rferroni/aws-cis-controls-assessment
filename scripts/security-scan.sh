#!/bin/bash
# Comprehensive security scanning script

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Running comprehensive security scans...${NC}"

# Create reports directory
mkdir -p security-reports

# 1. Dependency vulnerability scanning with Safety
echo -e "${GREEN}1. Running Safety dependency scan...${NC}"
if command -v safety &> /dev/null; then
    safety check --json --output security-reports/safety-report.json || true
    safety check --short-report
else
    echo -e "${YELLOW}Safety not found, installing...${NC}"
    pip install safety
    safety check --json --output security-reports/safety-report.json || true
    safety check --short-report
fi

# 2. Static code analysis with Bandit
echo -e "${GREEN}2. Running Bandit static analysis...${NC}"
if command -v bandit &> /dev/null; then
    bandit -r aws_cis_assessment -f json -o security-reports/bandit-report.json || true
    bandit -r aws_cis_assessment -ll
else
    echo -e "${YELLOW}Bandit not found, installing...${NC}"
    pip install bandit[toml]
    bandit -r aws_cis_assessment -f json -o security-reports/bandit-report.json || true
    bandit -r aws_cis_assessment -ll
fi

# 3. License compliance check
echo -e "${GREEN}3. Running license compliance check...${NC}"
if command -v pip-licenses &> /dev/null; then
    pip-licenses --format=json --output-file=security-reports/licenses-report.json
    pip-licenses --format=plain-vertical
else
    echo -e "${YELLOW}pip-licenses not found, installing...${NC}"
    pip install pip-licenses
    pip-licenses --format=json --output-file=security-reports/licenses-report.json
    pip-licenses --format=plain-vertical
fi

# 4. Secrets detection (if truffleHog is available)
echo -e "${GREEN}4. Running secrets detection...${NC}"
if command -v trufflehog &> /dev/null; then
    trufflehog filesystem . --json > security-reports/secrets-report.json || true
    echo "Secrets scan completed"
else
    echo -e "${YELLOW}TruffleHog not found, skipping secrets scan${NC}"
    echo "Install with: curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin"
fi

# 5. Additional security checks with pip-audit (if available)
echo -e "${GREEN}5. Running pip-audit scan...${NC}"
if command -v pip-audit &> /dev/null; then
    pip-audit --format=json --output=security-reports/pip-audit-report.json || true
    pip-audit --desc
else
    echo -e "${YELLOW}pip-audit not found, installing...${NC}"
    pip install pip-audit
    pip-audit --format=json --output=security-reports/pip-audit-report.json || true
    pip-audit --desc
fi

# Generate summary report
echo -e "${GREEN}Generating security summary...${NC}"
cat > security-reports/security-summary.md << EOF
# Security Scan Summary

Generated on: $(date)

## Scans Performed

1. **Dependency Vulnerability Scan (Safety)**
   - Report: safety-report.json
   - Scans Python dependencies for known vulnerabilities

2. **Static Code Analysis (Bandit)**
   - Report: bandit-report.json
   - Analyzes Python code for security issues

3. **License Compliance Check**
   - Report: licenses-report.json
   - Lists all dependency licenses

4. **Secrets Detection (TruffleHog)**
   - Report: secrets-report.json
   - Scans for accidentally committed secrets

5. **Additional Dependency Audit (pip-audit)**
   - Report: pip-audit-report.json
   - Alternative dependency vulnerability scanner

## Report Files

EOF

# List all generated reports
ls -la security-reports/ >> security-reports/security-summary.md

echo -e "${GREEN}Security scanning completed!${NC}"
echo -e "${YELLOW}Reports generated in: security-reports/${NC}"
echo -e "${YELLOW}Summary available at: security-reports/security-summary.md${NC}"

# Check if any critical issues were found
if grep -q '"severity": "HIGH"' security-reports/*.json 2>/dev/null; then
    echo -e "${RED}WARNING: High severity security issues found!${NC}"
    echo "Please review the reports and address critical vulnerabilities."
    exit 1
else
    echo -e "${GREEN}No critical security issues detected.${NC}"
fi