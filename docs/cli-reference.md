# CLI Reference

Complete command-line interface reference for the AWS CIS Controls Compliance Assessment Framework - a production-ready enterprise solution with 149 implemented rules (133 CIS Controls + 9 bonus security enhancements + 7 audit logging controls).

## Table of Contents

1. [Global Options](#global-options)
2. [Commands Overview](#commands-overview)
3. [assess Command](#assess-command)
4. [list-controls Command](#list-controls-command)
5. [list-regions Command](#list-regions-command)
6. [show-stats Command](#show-stats-command)
7. [validate-credentials Command](#validate-credentials-command)
8. [validate-config Command](#validate-config-command)
9. [help-guide Command](#help-guide-command)
10. [benchmark Command](#benchmark-command)
11. [validate-accuracy Command](#validate-accuracy-command)
12. [Environment Variables](#environment-variables)
13. [Exit Codes](#exit-codes)

## Global Options

These options are available for all commands:

```bash
aws-cis-assess [GLOBAL_OPTIONS] COMMAND [COMMAND_OPTIONS]
```

| Option | Description |
|--------|-------------|
| `--version` | Show version information and exit |
| `--verbose, -v` | Enable verbose output |
| `--debug` | Enable debug logging |
| `--help` | Show help message and exit |

### Examples

```bash
# Show version
aws-cis-assess --version

# Enable verbose output for any command
aws-cis-assess --verbose assess

# Enable debug logging
aws-cis-assess --debug assess --log-file debug.log
```

## Commands Overview

| Command | Purpose |
|---------|---------|
| `assess` | Run CIS Controls compliance assessment |
| `list-controls` | List available CIS Controls and Config rules |
| `list-regions` | List available AWS regions |
| `show-stats` | Show assessment statistics and scope |
| `validate-credentials` | Test AWS credentials and permissions |
| `validate-config` | Validate CIS Controls configuration files |
| `help-guide` | Show detailed help and examples |
| `benchmark` | Run performance benchmarks |
| `validate-accuracy` | Validate assessment accuracy against AWS Config |

## assess Command

Run CIS Controls compliance assessment.

### Syntax

```bash
aws-cis-assess assess [OPTIONS]
```

### Options

#### Scope Options

| Option | Type | Description |
|--------|------|-------------|
| `--implementation-groups, -ig` | Choice | Implementation Groups to assess (IG1, IG2, IG3) |
| `--controls, -ctrl` | String | Comma-separated list of specific CIS Control IDs |
| `--exclude-controls` | String | Comma-separated list of CIS Control IDs to exclude |
| `--regions, -r` | String | Comma-separated list of AWS regions |
| `--exclude-regions` | String | Comma-separated list of AWS regions to exclude |

#### AWS Credentials Options

| Option | Type | Description |
|--------|------|-------------|
| `--aws-profile, -p` | String | AWS profile to use for credentials |
| `--aws-access-key-id` | String | AWS Access Key ID |
| `--aws-secret-access-key` | String | AWS Secret Access Key |
| `--aws-session-token` | String | AWS Session Token (for temporary credentials) |

#### Configuration Options

| Option | Type | Description |
|--------|------|-------------|
| `--config-path, -c` | Path | Path to CIS Controls configuration directory |

#### Output Options

| Option | Type | Description |
|--------|------|-------------|
| `--output-format, -f` | Choice | Output format(s): json, html, csv (can specify multiple) |
| `--output-file, -o` | String | Output file path (extension added based on format) |
| `--output-dir` | Path | Output directory for generated reports |

#### Performance Options

| Option | Type | Description |
|--------|------|-------------|
| `--max-workers, -w` | Integer | Maximum number of parallel workers (default: 4) |
| `--timeout` | Integer | Assessment timeout in seconds (default: 3600) |

#### Behavior Options

| Option | Type | Description |
|--------|------|-------------|
| `--enable-error-recovery` / `--disable-error-recovery` | Flag | Enable/disable error recovery mechanisms (default: enabled) |
| `--enable-audit-trail` / `--disable-audit-trail` | Flag | Enable/disable audit trail logging (default: enabled) |
| `--dry-run` | Flag | Validate configuration without running assessment |
| `--quiet, -q` | Flag | Suppress progress output |

#### Logging Options

| Option | Type | Description |
|--------|------|-------------|
| `--log-level` | Choice | Set logging level: DEBUG, INFO, WARNING, ERROR |
| `--log-file` | Path | Write logs to specified file |

### Examples

#### Basic Usage

```bash
# Run full assessment with default settings
aws-cis-assess assess

# Assess only IG1 controls
aws-cis-assess assess --implementation-groups IG1

# Assess specific controls
aws-cis-assess assess --controls 1.1,3.3,4.1

# Assess specific regions
aws-cis-assess assess --regions us-east-1,us-west-2
```

#### Output Formats

```bash
# Generate HTML report
aws-cis-assess assess --output-format html --output-file report.html

# Generate multiple formats
aws-cis-assess assess --output-format json,html,csv --output-dir ./reports/

# Quiet mode with JSON output
aws-cis-assess assess --quiet --output-format json --output-file results.json
```

#### AWS Credentials

```bash
# Use specific AWS profile
aws-cis-assess assess --aws-profile production

# Use short flag for profile
aws-cis-assess assess -p production

# Use access keys directly
aws-cis-assess assess --aws-access-key-id AKIA... --aws-secret-access-key ...

# Use temporary credentials
aws-cis-assess assess --aws-access-key-id AKIA... --aws-secret-access-key ... --aws-session-token ...
```

#### Advanced Options

```bash
# Custom configuration with detailed logging
aws-cis-assess assess --config-path ./config/ --log-level DEBUG --log-file assessment.log

# Performance tuning
aws-cis-assess assess --max-workers 2 --timeout 1800

# Dry run validation
aws-cis-assess assess --dry-run --verbose
```

## list-controls Command

List available CIS Controls and their Config rules.

### Syntax

```bash
aws-cis-assess list-controls [OPTIONS]
```

### Options

| Option | Type | Description |
|--------|------|-------------|
| `--config-path, -c` | Path | Path to CIS Controls configuration directory |
| `--output-format, -f` | Choice | Output format: table, json (default: table) |

### Examples

```bash
# List controls in table format
aws-cis-assess list-controls

# List controls in JSON format
aws-cis-assess list-controls --output-format json

# Use custom configuration
aws-cis-assess list-controls --config-path ./custom-config/
```

### Output Format

#### Table Format
```
IG1 - Essential Cyber Hygiene
================================================================================
Control ID | Title                                    | Config Rules
-----------|------------------------------------------|------------------
1.1        | Establish and Maintain Detailed...      | 5 Config rules
3.3        | Configure Data Access Control Lists     | 10 Config rules
4.1        | Establish and Maintain a Secure...      | 5 Config rules
```

#### JSON Format
```json
{
  "1.1": {
    "title": "Establish and Maintain Detailed Enterprise Asset Inventory",
    "implementation_group": "IG1",
    "weight": 1.0,
    "config_rules": [
      {
        "name": "eip-attached",
        "resource_types": ["AWS::EC2::EIP"],
        "description": "Ensures Elastic IPs are attached to EC2 instances or ENIs"
      }
    ]
  }
}
```

## list-regions Command

List available AWS regions.

### Syntax

```bash
aws-cis-assess list-regions [OPTIONS]
```

### Options

| Option | Type | Description |
|--------|------|-------------|
| `--aws-profile, -p` | String | AWS profile to use for credentials |
| `--output-format, -f` | Choice | Output format: table, json (default: table) |

### Examples

```bash
# List regions in table format
aws-cis-assess list-regions

# List regions in JSON format
aws-cis-assess list-regions --output-format json

# Use specific AWS profile
aws-cis-assess list-regions --aws-profile production
```

### Output Format

#### Table Format
```
📍 Available AWS Regions
==================================================
Region          | Default
----------------|--------
us-east-1       | ✓
us-west-2       | ✓
eu-west-1       | ✓
ap-southeast-1  |
```

#### JSON Format
```json
{
  "enabled_regions": [
    "us-east-1",
    "us-west-2",
    "eu-west-1",
    "ap-southeast-1"
  ],
  "default_regions": [
    "us-east-1",
    "us-west-2",
    "eu-west-1"
  ],
  "total_enabled": 4,
  "total_default": 3
}
```

## show-stats Command

Show assessment statistics and scope.

### Syntax

```bash
aws-cis-assess show-stats [OPTIONS]
```

### Options

| Option | Type | Description |
|--------|------|-------------|
| `--config-path, -c` | Path | Path to CIS Controls configuration directory |
| `--implementation-groups, -ig` | Choice | Implementation Groups to analyze |
| `--controls` | String | Comma-separated list of specific CIS Control IDs |
| `--regions, -r` | String | Comma-separated list of AWS regions |
| `--output-format, -f` | Choice | Output format: table, json (default: table) |

### Examples

```bash
# Show statistics for all controls
aws-cis-assess show-stats

# Show statistics for specific Implementation Groups
aws-cis-assess show-stats --implementation-groups IG1,IG2

# Show statistics for specific controls
aws-cis-assess show-stats --controls 1.1,3.3,4.1

# Show statistics in JSON format
aws-cis-assess show-stats --output-format json
```

### Output Format

```
📊 Assessment Statistics
==================================================
Total Controls: 15
Total Config Rules: 106
Total Regions: 3
Estimated Assessments: 318

By Implementation Group:
  IG1: 8 controls, 56 rules
  IG2: 5 controls, 30 rules
  IG3: 2 controls, 20 rules

By AWS Service:
  EC2: 45 assessments
  IAM: 32 assessments
  S3: 28 assessments
  ...
```

## validate-credentials Command

Test AWS credentials and permissions.

### Syntax

```bash
aws-cis-assess validate-credentials [OPTIONS]
```

### Options

| Option | Type | Description |
|--------|------|-------------|
| `--aws-profile, -p` | String | AWS profile to use for credentials |
| `--aws-access-key-id` | String | AWS Access Key ID |
| `--aws-secret-access-key` | String | AWS Secret Access Key |
| `--aws-session-token` | String | AWS Session Token |
| `--regions, -r` | String | Comma-separated list of AWS regions to validate |

### Examples

```bash
# Validate default credentials
aws-cis-assess validate-credentials

# Validate specific AWS profile
aws-cis-assess validate-credentials --aws-profile production

# Validate credentials for specific regions
aws-cis-assess validate-credentials --regions us-east-1,us-west-2

# Validate access keys directly
aws-cis-assess validate-credentials --aws-access-key-id AKIA... --aws-secret-access-key ...
```

### Output Format

```
🔧 Validating AWS credentials...
✅ AWS credentials are valid
   Account ID: 123456789012
   User/Role: arn:aws:iam::123456789012:user/assessment-user
   Regions: ['us-east-1', 'us-west-2', 'eu-west-1']
   Supported Services: ec2, iam, s3, rds, cloudtrail...
```

## validate-config Command

Validate CIS Controls configuration files.

### Syntax

```bash
aws-cis-assess validate-config [OPTIONS]
```

### Options

| Option | Type | Description |
|--------|------|-------------|
| `--config-path, -c` | Path | Path to CIS Controls configuration directory |

### Examples

```bash
# Validate default configuration
aws-cis-assess validate-config

# Validate custom configuration
aws-cis-assess validate-config --config-path ./custom-config/
```

### Output Format

```
🔧 Validating CIS Controls configuration...
✅ Configuration is valid

Configuration Summary:
  IG1: 56 Config rules
  IG2: 30 Config rules
  IG3: 20 Config rules
```

## help-guide Command

Show detailed help, examples, and troubleshooting guide.

### Syntax

```bash
aws-cis-assess help-guide [OPTIONS]
```

### Options

| Option | Type | Description |
|--------|------|-------------|
| `--topic, -t` | Choice | Specific help topic: examples, troubleshooting, best-practices |

### Examples

```bash
# Show all help topics
aws-cis-assess help-guide

# Show usage examples
aws-cis-assess help-guide --topic examples

# Show troubleshooting guide
aws-cis-assess help-guide --topic troubleshooting

# Show best practices
aws-cis-assess help-guide --topic best-practices
```

## benchmark Command

Run performance benchmarks for regression testing.

### Syntax

```bash
aws-cis-assess benchmark [OPTIONS]
```

### Options

| Option | Type | Description |
|--------|------|-------------|
| `--output-dir, -o` | Path | Output directory for benchmark results (default: benchmarks) |
| `--iterations, -i` | Integer | Number of iterations per benchmark test (default: 3) |
| `--baseline-file, -b` | Path | Baseline file for regression detection |
| `--regression-threshold` | Float | Performance regression threshold (default: 1.3) |
| `--verbose, -v` | Flag | Enable verbose output |

### Examples

```bash
# Run basic benchmark
aws-cis-assess benchmark

# Run with custom iterations and output directory
aws-cis-assess benchmark --iterations 5 --output-dir ./perf-results

# Run with baseline comparison
aws-cis-assess benchmark --baseline-file baseline.json --regression-threshold 1.2
```

## validate-accuracy Command

Validate assessment accuracy against AWS Config rule evaluations.

### Syntax

```bash
aws-cis-assess validate-accuracy [OPTIONS]
```

### Options

| Option | Type | Description |
|--------|------|-------------|
| `--aws-profile, -p` | String | AWS profile to use for credentials |
| `--aws-access-key-id` | String | AWS Access Key ID |
| `--aws-secret-access-key` | String | AWS Secret Access Key |
| `--aws-session-token` | String | AWS Session Token |
| `--regions, -r` | String | Comma-separated list of AWS regions to validate |
| `--config-rules` | String | Comma-separated list of specific Config rules to validate |
| `--output-file, -o` | Path | Output file for validation report |
| `--check-config-availability` | Flag | Check AWS Config service availability in regions |
| `--verbose, -v` | Flag | Enable verbose output |

### Examples

```bash
# Basic accuracy validation
aws-cis-assess validate-accuracy

# Validate specific regions
aws-cis-assess validate-accuracy --regions us-east-1,us-west-2

# Validate specific Config rules
aws-cis-assess validate-accuracy --config-rules eip-attached,iam-password-policy

# Check Config availability first
aws-cis-assess validate-accuracy --check-config-availability
```

## Environment Variables

The tool recognizes these environment variables:

| Variable | Description |
|----------|-------------|
| `AWS_ACCESS_KEY_ID` | AWS access key ID |
| `AWS_SECRET_ACCESS_KEY` | AWS secret access key |
| `AWS_SESSION_TOKEN` | AWS session token |
| `AWS_DEFAULT_REGION` | Default AWS region |
| `AWS_PROFILE` | AWS profile name |
| `AWS_CONFIG_FILE` | AWS config file path |
| `AWS_SHARED_CREDENTIALS_FILE` | AWS credentials file path |
| `HTTP_PROXY` | HTTP proxy URL |
| `HTTPS_PROXY` | HTTPS proxy URL |
| `NO_PROXY` | Comma-separated list of hosts to bypass proxy |

### Examples

```bash
# Set AWS credentials via environment variables
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=us-east-1

# Set proxy configuration
export HTTPS_PROXY=https://proxy.company.com:8080
export NO_PROXY=localhost,127.0.0.1,.company.com

# Run assessment
aws-cis-assess assess
```

## Exit Codes

The tool uses these exit codes:

| Code | Description |
|------|-------------|
| 0 | Success |
| 1 | General error |
| 2 | Configuration error |
| 3 | Credential error |
| 4 | Permission error |
| 5 | Network error |
| 130 | Interrupted by user (Ctrl+C) |

### Examples

```bash
# Check exit code in scripts
aws-cis-assess assess --quiet
if [ $? -eq 0 ]; then
    echo "Assessment completed successfully"
else
    echo "Assessment failed with exit code $?"
fi

# Handle specific error codes
case $? in
    0) echo "Success" ;;
    2) echo "Configuration error - check your config files" ;;
    3) echo "Credential error - check your AWS credentials" ;;
    4) echo "Permission error - check your IAM permissions" ;;
    *) echo "Unknown error" ;;
esac
```

## Common Usage Patterns

### CI/CD Integration

```bash
#!/bin/bash
# CI/CD pipeline script

# Validate credentials
aws-cis-assess validate-credentials --aws-profile ci-role || exit 1

# Run assessment
aws-cis-assess assess \
  --aws-profile ci-role \
  --implementation-groups IG1 \
  --quiet \
  --output-format json \
  --output-file ci-results.json || exit 1

# Check compliance threshold
COMPLIANCE=$(jq -r '.compliance_summary.ig1_compliance_percentage' ci-results.json)
if (( $(echo "$COMPLIANCE < 80" | bc -l) )); then
    echo "Compliance below threshold: $COMPLIANCE%"
    exit 1
fi
```

### Multi-Account Assessment

```bash
#!/bin/bash
# Multi-account assessment script

ACCOUNTS=("account1-prod" "account2-prod" "account3-prod")

for account in "${ACCOUNTS[@]}"; do
    echo "Assessing $account..."
    aws-cis-assess assess \
      --aws-profile "$account" \
      --output-format json \
      --output-file "${account}-results.json" \
      --quiet
done
```

### Scheduled Assessment

```bash
#!/bin/bash
# Cron job script for regular assessments

DATE=$(date +%Y%m%d_%H%M%S)
OUTPUT_DIR="/var/log/cis-assessments/$DATE"

mkdir -p "$OUTPUT_DIR"

aws-cis-assess assess \
  --output-format html,json \
  --output-dir "$OUTPUT_DIR" \
  --log-file "$OUTPUT_DIR/assessment.log" \
  --quiet

# Send notification if compliance drops
COMPLIANCE=$(jq -r '.compliance_summary.overall_compliance_percentage' "$OUTPUT_DIR"/*.json)
if (( $(echo "$COMPLIANCE < 85" | bc -l) )); then
    echo "Compliance alert: $COMPLIANCE%" | mail -s "CIS Compliance Alert" admin@company.com
fi
```