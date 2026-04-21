# AWS CIS Controls Compliance Assessment Framework

A security framework for evaluating AWS account configurations against CIS Controls Implementation Groups (IG1, IG2, IG3) using AWS Config rule specifications. **199 unique assessment rules across 40 CIS Controls v8.1 safeguards.**

> **Production Status**: This framework provides comprehensive point-in-time compliance assessments while we recommend [AWS Config](https://aws.amazon.com/config/) for ongoing continuous compliance monitoring and automated remediation.

## 🎯 Key Features

- **✅ 199 Unique Assessment Rules**: 122 IG1 + 75 IG2 + 13 IG3 rules (some shared across IGs) across 40 CIS Controls
- **✅ Cumulative Coverage**: IG1 24/56 (42.9%), IG2 27/74 (36.5%), IG3 30/153 (19.6%) safeguards
- **✅ Dual Scoring System**: Both weighted and AWS Config-style scoring methodologies
- **✅ Enhanced HTML Reports**: Sorted controls, hover tooltips, working search, improved remediation display
- **✅ Enterprise Ready**: Production-tested with enterprise-grade architecture
- **✅ Performance Optimized**: Handles large-scale assessments efficiently
- **✅ Multi-Format Reports**: JSON, HTML, and CSV with detailed remediation guidance
- **✅ No AWS Config Required**: Direct AWS API calls based on Config rule specifications
- **✅ Comprehensive Remediation**: Every rule includes CLI commands, console steps, best practices, and AWS documentation links

## 🚀 Quick Start

### Installation

```bash
# Install from PyPI (production-ready)
pip install aws-cis-controls-assessment

# Or install from source for development
git clone <repository-url>
cd aws-cis-controls-assessment
pip install -e .
```

### Basic Usage

```bash
# Run complete assessment (all 199 rules) - defaults to us-east-1
aws-cis-assess assess --aws-profile my-aws-profile

# Assess multiple regions
aws-cis-assess assess --aws-profile my-aws-profile --regions us-east-1,us-west-2

# Assess specific Implementation Group using short flag (defaults to us-east-1)
aws-cis-assess assess -p my-aws-profile --implementation-groups IG1 --output-format json

# Generate comprehensive HTML report (defaults to us-east-1)
aws-cis-assess assess --aws-profile production --output-format html --output-file compliance-report.html

# Enterprise multi-region assessment with multiple formats
aws-cis-assess assess -p security-audit --implementation-groups IG1,IG2,IG3 --regions all --output-format html,json --output-dir ./reports/

# Quick assessment with default profile and default region (us-east-1)
aws-cis-assess assess --output-format json
```

### Sample Output

```
🔧 Initializing assessment engine...
✅ Validating configuration...
📊 Assessment Summary:
   Implementation Groups: IG1, IG2, IG3
   Total Assessments: 199
   Regions: us-east-1
🚀 Starting compliance assessment...
[████████████████████] 100.0% - Complete

📈 Assessment Results:
   Overall Compliance: 72.4%
   IG1 Compliance: 78.3%
   IG2 Compliance: 68.1%
   IG3 Compliance: 65.7%
   Total Resources: 1,247
   Assessment Duration: 12m 34s

📄 Generating reports...
   ⏱️  Assessment Duration: 12m 34s
   ✅ JSON report: reports/cis_assessment_20260421_143022.json
   ✅ HTML report: reports/cis_assessment_20260421_143022.html
   📋 Log file: reports/cis_assessment_20260421_143022.log
✅ Assessment completed successfully!

🎯 Final Result: 72.4% overall compliance
```

A sample HTML report is available in [`examples/sample-report.html`](examples/sample-report.html) and a JSON report in [`examples/sample-report.json`](examples/sample-report.json) — open the HTML in your browser to see the interactive report with filters and pagination.

## 📊 Implementation Groups Coverage

### Coverage Summary (Cumulative)

| IG | Safeguards Covered | Total Safeguards | Coverage | Rules |
|----|-------------------|-----------------|----------|-------|
| IG1 | 24 | 56 | 42.9% | 122 |
| IG2 | 27 | 74 | 36.5% | 75 |
| IG3 | 30 | 153 | 19.6% | 13 |
| **Unique Total** | | | | **199** |

> Coverage is cumulative: IG2 includes all IG1 safeguards, IG3 includes all IG1+IG2 safeguards.
> Rule counts per IG reflect unique registered assessments. Some rules are shared across IGs and counted once in the unique total.

### IG1 - Essential Cyber Hygiene (122 Rules, 24 Controls)

| Control ID | Safeguard Name | Rules |
|-----------|---------------|-------|
| 1.1 | Establish and Maintain Detailed Enterprise Asset Inventory | 12 |
| 1.5 | Account Inventory | 1 |
| 2.2 | Ensure Authorized Software is Currently Supported | 5 |
| 2.2.1 | Software Inventory Process | 1 |
| 3.3 | Configure Data Access Control Lists | 4 |
| 3.4 | Enforce Data Retention | 2 |
| 3.11 | Encrypt Sensitive Data at Rest | 8 |
| 4.1 | Establish and Maintain a Secure Configuration Process | 14 |
| 4.6 | Securely Manage Enterprise Assets and Software | 3 |
| 5.3 | Disable Dormant Accounts | 6 |
| 6.2 | Establish an Access Revoking Process | 1 |
| 6.5 | Require MFA for Administrative Access | 3 |
| 8.2 | Collect Audit Logs | 7 |
| 8.5 | Collect Detailed Audit Logs | 1 |
| 8.8 | Audit Log Reviews | 1 |
| 9.1 | Ensure Only Fully Supported Browsers and Email Clients are Allowed | 3 |
| 10.1 | Deploy and Maintain Anti-Malware Software | 2 |
| 11.1 | Establish and Maintain a Data Recovery Process | 6 |
| 11.2 | Automated Backups | 8 |
| 12.2 | Network Infrastructure Management | 5 |
| 13.1 | Centralize Security Event Alerting | 5 |
| 14.6 | Train Workforce Members on Recognizing and Reporting Security Incidents | 5 |
| 15.3 | Classify Service Providers | 3 |
| 16.11 | Leverage Vetted Modules or Services for Application Security Components | 23 |

### IG2 - Enhanced Security (75 Rules, 12 Controls)

| Control ID | Safeguard Name | Rules |
|-----------|---------------|-------|
| 3.10 | Encrypt Sensitive Data in Transit | 7 |
| 3.11 | Encrypt Sensitive Data at Rest | 8 |
| 4.5 | Implement and Manage a Firewall on End-User Devices | 5 |
| 4.6 | Securely Manage Enterprise Assets and Software | 5 |
| 5.2 | Use Unique Passwords | 3 |
| 6.3 | Require MFA for Externally-Exposed Applications | 5 |
| 6.4 | Require MFA for Remote Network Access | 5 |
| 8.2 | Audit Log Management | 7 |
| 8.5 | Collect Detailed Audit Logs | 7 |
| 11.4 | Backup Restoration Testing | 6 |
| 12.2 | Network Infrastructure Management | 11 |
| 16.11 | Leverage Vetted Modules or Services for Application Security Components | 13 |

### IG3 - Advanced Security (13 Rules, 4 Controls)

| Control ID | Safeguard Name | Rules |
|-----------|---------------|-------|
| 3.10 | Encrypt Sensitive Data in Transit | 1 |
| 10.5 | Enable Anti-Exploitation Features | 3 |
| 13.8 | Deploy a Network Intrusion Prevention Solution | 3 |
| 16.12 | Implement Code-Level Security Checks | 6 |

## 🏗️ Production Architecture

### Core Components
- **Assessment Engine**: Orchestrates compliance evaluations across all AWS regions
- **Control Assessments**: 199 unique rule implementations with robust error handling
- **Scoring Engine**: Calculates compliance scores and generates executive metrics
- **Reporting System**: Multi-format output with detailed remediation guidance
- **Resource Management**: Optimized for enterprise-scale deployments with memory management

### Enterprise Features
- **Multi-threading**: Parallel execution for improved performance
- **Error Recovery**: Comprehensive error handling and retry mechanisms
- **Audit Trail**: Complete compliance audit and logging capabilities
- **Resource Monitoring**: Real-time performance and resource usage tracking
- **Scalable Architecture**: Handles assessments across hundreds of AWS accounts

## 📋 Requirements

- **Python**: 3.8+ (production tested on 3.8, 3.9, 3.10, 3.11)
- **AWS Credentials**: Configured via AWS CLI, environment variables, or IAM roles
- **Permissions**: Read-only access to AWS services being assessed
- **Memory**: Minimum 2GB RAM for large-scale assessments
- **Network**: Internet access for AWS API calls
- **Default Region**: Assessments default to `us-east-1` unless `--regions` is specified

## 📈 Business Value

### Immediate Benefits
- **Compliance Readiness**: Instant CIS Controls compliance assessment
- **Risk Reduction**: Identify and prioritize security vulnerabilities
- **Audit Support**: Generate comprehensive compliance reports
- **Cost Optimization**: Identify misconfigured and unused resources
- **Operational Efficiency**: Automate manual compliance checking

### Long-term Value
- **Continuous Improvement**: Track compliance posture over time
- **Regulatory Compliance**: Support for multiple compliance frameworks
- **Security Automation**: Foundation for automated remediation
- **Enterprise Integration**: Integrate with existing security tools
- **Future-Proof**: Extensible architecture for evolving requirements

## 🛡️ Security & Compliance

### Security Features
- **Read-Only Access**: Framework requires only read permissions
- **No Data Storage**: No sensitive data stored or transmitted
- **Audit Logging**: Complete audit trail of all assessments
- **Error Handling**: Secure error handling without data leakage

### Compliance Support
- **CIS Controls**: Coverage across Implementation Groups 1, 2, and 3 (199 unique rules, 40 safeguards)
- **AWS Well-Architected**: Aligned with security pillar best practices
- **Industry Standards**: Supports SOC 2, NIST, ISO 27001 mapping
- **Regulatory Requirements**: HIPAA, PCI DSS, FedRAMP compatible
- **Custom Frameworks**: Extensible for organization-specific requirements

## 📚 Documentation

### Core Documentation
- **[Installation Guide](docs/installation.md)**: Detailed installation instructions and requirements
- **[User Guide](docs/user-guide.md)**: Comprehensive user manual and best practices
- **[CLI Reference](docs/cli-reference.md)**: Complete command-line interface documentation
- **[Dual Scoring Guide](docs/dual-scoring-implementation.md)**: Weighted vs AWS Config scoring methodologies
- **[Scoring Methodology](docs/scoring-methodology.md)**: Detailed explanation of weighted scoring
- **[AWS Config Comparison](docs/scoring-comparison-aws-config.md)**: Comparison with AWS Config approach
- **[Troubleshooting Guide](docs/troubleshooting.md)**: Common issues and solutions
- **[Developer Guide](docs/developer-guide.md)**: Development and contribution guidelines

### Technical Documentation
- **[Assessment Logic](docs/assessment-logic.md)**: How compliance assessments work
- **[Config Rule Mappings](docs/config-rule-mappings.md)**: CIS Controls to AWS Config rule mappings
- **[HTML Report Improvements](docs/html-report-improvements.md)**: Enhanced HTML report features and customization

## 🤝 Support & Community

### Getting Help
- **Documentation**: Comprehensive guides and API documentation
- **GitHub Issues**: Bug reports and feature requests
- **Enterprise Support**: Commercial support available for enterprise deployments

### Contributing
- **Code Contributions**: Pull requests welcome with comprehensive tests
- **Documentation**: Help improve documentation and examples
- **Bug Reports**: Detailed bug reports with reproduction steps
- **Feature Requests**: Enhancement suggestions with business justification

## 📄 License

MIT License - see [LICENSE](LICENSE) file for details.

## 🏆 Project Status

**✅ Production Ready**: 199 unique rules across 40 CIS Controls v8.1 safeguards  
**✅ Enterprise Deployed**: Actively used in production environments  
**✅ Continuously Maintained**: Regular updates and security patches  
**✅ Community Supported**: Active development and community contributions  
**✅ Future-Proof**: Extensible architecture for evolving requirements

---

**Framework Version**: 1.2.4  
**CIS Controls v8.1 Coverage**: 199 unique rules across 40 safeguards (IG1: 122, IG2: 75, IG3: 13)  
**Production Status**: ✅ Ready for immediate enterprise deployment  
**Last Updated**: April 2026

## 🆕 What's New in Version 1.2.4

### CIS Controls Overview Table
- New dedicated section in HTML reports with a comprehensive, sortable, filterable table of all assessed CIS Controls v8.1 safeguards
- Summary cards showing total controls, average compliance, fully compliant count, and attention-needed count
- Filter bar with IG dropdown, Rules dropdown, and text search
- Click on Control ID to jump to corresponding Resource Details section

### Accuracy Fixes
- Fixed flaky property test for control display name format
- Updated CLI version assertion
- Removed hardcoded resource evaluation count from HTML report footer
- Corrected rule counts: 199 unique assessment rules (previously reported as 224 which double-counted cross-IG shared rules)

### Previous Highlights (1.2.0–1.2.3)
- Dynamic coverage metrics from YAML configs with cumulative IG logic
- HTML report controls sort numerically with hover tooltips
- 50 new IG1 rules across security services, logging, encryption, inventory, configuration management, and backup
- 14 IG2 access & configuration controls, 7 IG2 audit logging controls
- Dual scoring system, enhanced HTML reports, resource deduplication fixes

See [CHANGELOG.md](docs/CHANGELOG.md) for complete version history.