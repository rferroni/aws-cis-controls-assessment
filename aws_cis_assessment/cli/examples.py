"""Example usage and help content for the CLI."""

USAGE_EXAMPLES = {
    "basic": {
        "title": "Basic Assessment",
        "description": "Run a full CIS Controls assessment with default settings",
        "command": "aws-cis-assess assess",
        "explanation": "This will assess all Implementation Groups (IG1, IG2, IG3) in the default region (us-east-1) and generate a JSON report."
    },
    "default_region": {
        "title": "Default Region Assessment",
        "description": "Run assessment using the default region (us-east-1)",
        "command": "aws-cis-assess assess --implementation-groups IG1",
        "explanation": "When no --regions parameter is specified, the assessment runs only in us-east-1 for faster, focused results."
    },
    "specific_ig": {
        "title": "Specific Implementation Group",
        "description": "Assess only essential controls (IG1) in specific regions",
        "command": "aws-cis-assess assess --implementation-groups IG1 --regions us-east-1,us-west-2",
        "explanation": "This focuses on the most critical security controls. Without --regions, it would default to us-east-1 only."
    },
    "specific_controls": {
        "title": "Specific Controls Assessment",
        "description": "Assess only specific CIS Controls across all regions",
        "command": "aws-cis-assess assess --controls 1.1,3.3,4.1",
        "explanation": "This assesses only the specified controls (Asset Inventory, Data Access Control, Secure Configuration) across all regions."
    },
    "exclude_regions": {
        "title": "Exclude Regions",
        "description": "Assess all regions except government or restricted regions",
        "command": "aws-cis-assess assess --exclude-regions us-gov-east-1,us-gov-west-1,cn-north-1",
        "explanation": "This runs assessment on all enabled regions except the specified government and China regions."
    },
    "html_report": {
        "title": "HTML Report Generation",
        "description": "Generate an interactive HTML report with custom output directory",
        "command": "aws-cis-assess assess --output-format html --output-dir ./reports/",
        "explanation": "Creates an interactive web-based report in the specified directory with charts and drill-down capabilities."
    },
    "multiple_formats": {
        "title": "Multiple Output Formats",
        "description": "Generate reports in multiple formats with custom directory",
        "command": "aws-cis-assess assess --output-format json,html,csv --output-dir ./compliance-reports/",
        "explanation": "Creates three different report formats in the specified directory: JSON for automation, HTML for viewing, and CSV for analysis."
    },
    "custom_profile": {
        "title": "Custom AWS Profile with Logging",
        "description": "Use a specific AWS profile with custom configuration and detailed logging",
        "command": "aws-cis-assess assess --aws-profile production --config-path ./config/ --log-level DEBUG --log-file assessment.log",
        "explanation": "Uses the 'production' AWS profile, custom CIS Controls configuration, and saves detailed debug logs to a file."
    },
    "quiet_mode": {
        "title": "Quiet Mode Assessment",
        "description": "Run assessment with minimal output for automation",
        "command": "aws-cis-assess assess --quiet --output-format json --output-file results.json",
        "explanation": "Runs assessment with suppressed progress output, suitable for automated scripts and CI/CD pipelines."
    },
    "timeout_control": {
        "title": "Assessment with Timeout",
        "description": "Run assessment with custom timeout and worker limits",
        "command": "aws-cis-assess assess --timeout 1800 --max-workers 2",
        "explanation": "Runs assessment with 30-minute timeout and limited to 2 parallel workers to reduce API load."
    },
    "dry_run": {
        "title": "Dry Run Validation",
        "description": "Validate configuration and credentials without running assessment",
        "command": "aws-cis-assess assess --dry-run",
        "explanation": "Checks that everything is configured correctly before running the full assessment."
    },
    "list_controls": {
        "title": "List Available Controls",
        "description": "View all available CIS Controls and their Config rules",
        "command": "aws-cis-assess list-controls",
        "explanation": "Shows all CIS Controls organized by Implementation Group with their AWS Config rules."
    },
    "list_regions": {
        "title": "List Available Regions",
        "description": "View all available AWS regions for assessment",
        "command": "aws-cis-assess list-regions",
        "explanation": "Shows all AWS regions that can be used for assessment. Default region is us-east-1."
    },
    "show_stats": {
        "title": "Assessment Statistics",
        "description": "Show detailed statistics about assessment scope",
        "command": "aws-cis-assess show-stats --implementation-groups IG1,IG2",
        "explanation": "Displays statistics about controls, rules, and estimated assessments for the specified scope."
    },
    "validate_credentials": {
        "title": "Credential Validation",
        "description": "Test AWS credentials and permissions",
        "command": "aws-cis-assess validate-credentials --aws-profile production",
        "explanation": "Verifies that the specified AWS profile has the necessary permissions for assessment."
    }
}

TROUBLESHOOTING_GUIDE = {
    "credential_errors": {
        "title": "AWS Credential Issues",
        "problems": [
            "NoCredentialsError: Unable to locate credentials",
            "AccessDenied: User is not authorized to perform operation",
            "InvalidUserID.NotFound: The user ID does not exist"
        ],
        "solutions": [
            "Ensure AWS credentials are configured (aws configure or environment variables)",
            "Verify the AWS profile exists and is accessible",
            "Check that the user/role has necessary IAM permissions",
            "Try using --aws-profile to specify a different profile",
            "Use 'aws-cis-assess validate-credentials' to test credentials"
        ]
    },
    "permission_errors": {
        "title": "IAM Permission Issues",
        "problems": [
            "AccessDenied errors for specific AWS services",
            "Some controls show 'INSUFFICIENT_PERMISSIONS'",
            "Assessment completes but with many errors"
        ],
        "solutions": [
            "Ensure the user/role has ReadOnlyAccess or equivalent permissions",
            "Add specific service permissions (EC2, IAM, S3, etc.)",
            "Use --verbose flag to see detailed permission errors",
            "Consider using a role with broader read permissions",
            "Use --log-level DEBUG for detailed permission analysis"
        ]
    },
    "configuration_errors": {
        "title": "Configuration Issues",
        "problems": [
            "Configuration validation failed",
            "Missing configuration files",
            "Invalid YAML syntax in config files",
            "Specific controls not found"
        ],
        "solutions": [
            "Run 'aws-cis-assess validate-config' to check configuration",
            "Ensure all required YAML files are present in config directory",
            "Check YAML syntax and structure",
            "Use default configuration if custom config has issues",
            "Use 'aws-cis-assess list-controls' to see available controls",
            "Verify control IDs match exactly (case-sensitive)"
        ]
    },
    "network_errors": {
        "title": "Network and API Issues",
        "problems": [
            "Connection timeouts",
            "API throttling errors",
            "Service unavailable errors",
            "Assessment taking too long"
        ],
        "solutions": [
            "Check internet connectivity and AWS service status",
            "Reduce --max-workers to decrease API call rate",
            "Increase --timeout value for large assessments",
            "Retry the assessment after a few minutes",
            "Use --regions to limit assessment to specific regions",
            "Use --exclude-regions to skip problematic regions"
        ]
    },
    "scope_issues": {
        "title": "Assessment Scope Problems",
        "problems": [
            "Too many resources being assessed",
            "Assessment running out of memory",
            "Unexpected controls being assessed",
            "Missing expected controls"
        ],
        "solutions": [
            "Use --controls to assess only specific controls",
            "Use --implementation-groups to limit scope",
            "Use --exclude-controls to skip problematic controls",
            "Use 'aws-cis-assess show-stats' to preview assessment scope",
            "Reduce --max-workers to limit memory usage",
            "Use --regions to limit geographic scope"
        ]
    },
    "output_issues": {
        "title": "Output and Reporting Problems",
        "problems": [
            "Reports not generated in expected location",
            "Permission denied writing output files",
            "Output format not as expected",
            "Log files not created"
        ],
        "solutions": [
            "Use --output-dir to specify output directory",
            "Ensure write permissions for output directory",
            "Check disk space availability",
            "Use absolute paths for --output-file and --log-file",
            "Verify output format is supported (json, html, csv)",
            "Use --quiet to reduce console output if needed"
        ]
    }
}

BEST_PRACTICES = [
    {
        "title": "Start with IG1",
        "description": "Begin with IG1 (Essential Cyber Hygiene) controls as they provide the foundation for security.",
        "command": "aws-cis-assess assess --implementation-groups IG1"
    },
    {
        "title": "Use Dry Run First",
        "description": "Always validate your configuration before running a full assessment.",
        "command": "aws-cis-assess assess --dry-run"
    },
    {
        "title": "Preview Assessment Scope",
        "description": "Use show-stats to understand what will be assessed before running.",
        "command": "aws-cis-assess show-stats --implementation-groups IG1,IG2"
    },
    {
        "title": "Focus on Specific Controls",
        "description": "Start with critical controls to get faster, focused results.",
        "command": "aws-cis-assess assess --controls 1.1,3.3,5.2"
    },
    {
        "title": "Generate Multiple Formats",
        "description": "Create both HTML (for viewing) and JSON (for automation) reports.",
        "command": "aws-cis-assess assess --output-format html,json --output-dir ./reports/"
    },
    {
        "title": "Focus on Critical Regions",
        "description": "Expand beyond the default region (us-east-1) to include your most important regions.",
        "command": "aws-cis-assess assess --regions us-east-1,us-west-2"
    },
    {
        "title": "Exclude Problematic Regions",
        "description": "Skip regions with known issues or restrictions.",
        "command": "aws-cis-assess assess --exclude-regions us-gov-east-1,cn-north-1"
    },
    {
        "title": "Use Detailed Logging for Troubleshooting",
        "description": "Enable detailed logging when diagnosing issues.",
        "command": "aws-cis-assess assess --log-level DEBUG --log-file debug.log"
    },
    {
        "title": "Quiet Mode for Automation",
        "description": "Use quiet mode in scripts and CI/CD pipelines.",
        "command": "aws-cis-assess assess --quiet --output-format json"
    },
    {
        "title": "Control Resource Usage",
        "description": "Limit workers and set timeouts for large assessments.",
        "command": "aws-cis-assess assess --max-workers 2 --timeout 1800"
    },
    {
        "title": "Regular Assessments",
        "description": "Run assessments regularly to track compliance improvements over time.",
        "command": "# Set up a cron job or scheduled task"
    },
    {
        "title": "Validate Credentials First",
        "description": "Test credentials and permissions before running assessments.",
        "command": "aws-cis-assess validate-credentials --aws-profile production"
    }
]

def get_usage_example(example_name: str) -> dict:
    """Get a specific usage example by name."""
    return USAGE_EXAMPLES.get(example_name, {})

def get_all_examples() -> dict:
    """Get all usage examples."""
    return USAGE_EXAMPLES

def get_troubleshooting_guide() -> dict:
    """Get the troubleshooting guide."""
    return TROUBLESHOOTING_GUIDE

def get_best_practices() -> list:
    """Get best practices list."""
    return BEST_PRACTICES