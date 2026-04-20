# AWS CIS Controls Compliance Assessment Framework Documentation

Welcome to the comprehensive documentation for the AWS CIS Controls Compliance Assessment Framework. This production-ready, enterprise-grade framework evaluates AWS account security posture against CIS Controls Implementation Groups (IG1, IG2, IG3) using AWS Config rule specifications without requiring AWS Config to be enabled.

## 🆕 Latest Updates (Version 1.2.4)

### CIS Controls Overview Table
- New sortable/filterable table in HTML reports showing all assessed CIS Controls v8.1 safeguards
- Corrected rule counts: 199 unique assessment rules across 40 safeguards

## Documentation Structure

### User Documentation
- **[Installation Guide](installation.md)** - Complete installation and setup instructions
- **[User Guide](user-guide.md)** - Comprehensive usage guide with examples
- **[CLI Reference](cli-reference.md)** - Complete command-line interface reference
- **[Troubleshooting Guide](troubleshooting.md)** - Common issues and solutions

### Technical Documentation
- **[Developer Guide](developer-guide.md)** - Extending and customizing assessments
- **[Assessment Logic](assessment-logic.md)** - Detailed assessment logic documentation
- **[Config Rule Mappings](config-rule-mappings.md)** - Complete mapping of CIS Controls to AWS Config rules
- **[HTML Report Improvements](html-report-improvements.md)** - Enhanced HTML report features and customization
- **[AWS Backup Controls Guide](adding-aws-backup-controls.md)** - **NEW:** Comprehensive guide for AWS Backup service controls

## Quick Start

1. **Install the framework**: `pip install aws-cis-controls-assessment`
2. **Configure AWS credentials**: `aws configure` or set environment variables
3. **Run basic assessment**: `aws-cis-assess assess`
4. **View results**: Open the generated HTML report

## Key Features

- **✅ Complete Coverage**: 199 unique assessment rules across 40 CIS Controls v8.1 safeguards
- **✅ Production Ready**: Enterprise-tested with comprehensive error handling
- **✅ Performance Optimized**: Handles large-scale assessments efficiently
- **✅ Multiple Output Formats**: JSON, HTML, and CSV reports with detailed remediation guidance
- **✅ No AWS Config Required**: Direct AWS API calls based on Config rule specifications
- **✅ Enterprise Architecture**: Scalable, maintainable framework with audit trails
- **✅ AWS Backup Controls**: Comprehensive backup infrastructure assessment

## Implementation Groups Overview

### IG1 - Essential Cyber Hygiene (122 Rules, 24 Controls) ✅
Foundational safeguards for all enterprises:
- Asset Inventory and Management (6 rules)
- Identity and Access Management (15 rules)
- Data Protection and Encryption (8 rules)
- Network Security Controls (20 rules)
- Logging and Monitoring (13 rules)
- Backup and Recovery (14 rules) - **NEW: AWS Backup service controls**
- Security Services Integration (5 rules)
- Configuration Management (9 rules)
- Vulnerability Management (5 rules)

### IG2 - Enhanced Security (75 Rules, 12 Controls) ✅
Additional controls for regulated environments:
- Advanced Encryption at Rest (6 rules)
- Certificate Management (2 rules)
- Network High Availability (7 rules)
- Enhanced Monitoring (3 rules)
- CodeBuild Security (4 rules)
- Vulnerability Scanning (1 rule)
- Network Segmentation (5 rules)
- Auto-scaling Security (1 rule)
- Enhanced Access Controls (8 rules)

### IG3 - Advanced Security (13 Rules, 4 Controls) ✅
Sophisticated controls for high-risk environments:
- API Gateway WAF Integration (1 rule)
- Critical for preventing application-layer attacks
- Required for high-security environments

## Production Status

**✅ Ready for Enterprise Deployment**
- 199 unique assessment rules across 40 CIS Controls v8.1 safeguards
- Production-tested architecture with comprehensive error handling
- Enterprise-grade performance and scalability
- Comprehensive audit trails and logging
- Ready for immediate deployment in production environments

## Support and Contributing

- **Issues**: Report bugs and request features on GitHub
- **Contributing**: See the developer guide for contribution guidelines
- **Community**: Join our community discussions

## License

This project is licensed under the MIT License - see the [LICENSE](../LICENSE) file for details.