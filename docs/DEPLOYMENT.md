# AWS CIS Assessment Framework - Production Deployment Guide

This document provides comprehensive instructions for deploying the AWS CIS Assessment Framework. The framework implements 199 unique assessment rules across 40 CIS Controls v8.1 safeguards and is ready for enterprise deployment.

## 🎯 Framework Status

- **✅ Production Ready**: Complete implementation with 199 unique assessment rules
- **✅ Enterprise Tested**: Validated in large-scale environments
- **✅ Security Hardened**: Comprehensive security scanning and validation
- **✅ Performance Optimized**: Memory management and resource monitoring
- **✅ Fully Documented**: Complete deployment and operations documentation

## 🚀 Quick Production Deployment

### Option 1: PyPI Installation (Recommended)

```bash
# Install the production-ready package
pip install aws-cis-controls-assessment

# Run immediate assessment
aws-cis-assess assess --aws-profile production-profile --regions us-east-1,us-west-2
```

### Option 2: Install from Source (GitHub)

```bash
git clone <repository-url>
cd aws-cis-controls-assessment
pip install -e .

# Run assessment
aws-cis-assess assess --aws-profile production-profile
```

## Prerequisites

### System Requirements

- Python 3.8 or higher
- Git
- pip package manager

### Development Dependencies

```bash
# Install development dependencies
pip install -e .[dev]

# Or install from requirements
pip install -r requirements.txt
```

### Security Tools (Optional)

```bash
# Install security scanning tools
pip install bandit safety pip-audit pip-licenses

# Install secrets scanner
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin
```

## Local Development Setup

### 1. Clone and Setup

```bash
git clone <repository-url>
cd aws-cis-controls-assessment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -e .[dev]
```

### 2. Pre-commit Hooks (Recommended)

```bash
pip install pre-commit
pre-commit install
pre-commit run --all-files  # Test all hooks
```

### 3. Run Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=aws_cis_assessment --cov-report=html

# Run specific test types
pytest -m unit
pytest -m integration
pytest -m property
```

## Building the Package

### Automated Build

```bash
./scripts/build.sh
```

### Manual Build

```bash
# Clean previous builds
rm -rf build/ dist/ *.egg-info/

# Install build dependencies
pip install build twine

# Build the package
python -m build

# Verify the build
twine check dist/*
```

### Build Outputs

- `dist/*.whl` - Wheel distribution
- `dist/*.tar.gz` - Source distribution

## CI/CD Pipeline

### GitHub Actions Workflows

The project includes three main workflows:

1. **CI/CD Pipeline** (`.github/workflows/ci.yml`)
   - Runs on push/PR to main/develop
   - Tests across Python versions
   - Security scanning
   - Publishes on release

2. **Security Scanning** (`.github/workflows/security.yml`)
   - Daily security scans
   - Dependency vulnerability checks
   - Code analysis
   - Secrets detection

3. **Release Process** (`.github/workflows/release.yml`)
   - Triggered on version tags
   - Comprehensive testing
   - Builds artifacts
   - Creates GitHub releases
   - Publishes to PyPI

### Required Secrets

Configure these secrets in your GitHub repository:

```
PYPI_API_TOKEN          # PyPI publishing
AWS_ACCESS_KEY_ID       # Integration tests (optional)
AWS_SECRET_ACCESS_KEY   # Integration tests (optional)
```


### Branch Protection

Recommended branch protection rules for `main`:

- Require pull request reviews
- Require status checks to pass
- Require branches to be up to date
- Include administrators
- Restrict pushes

## Security Scanning

### Automated Security Scans

```bash
./scripts/security-scan.sh
```

### Manual Security Checks

```bash
# Dependency vulnerabilities
safety check
pip-audit

# Static code analysis
bandit -r aws_cis_assessment

# License compliance
pip-licenses

# Secrets detection
trufflehog filesystem .
```

### Security Reports

Security scan reports are generated in `security-reports/`:

- `safety-report.json` - Dependency vulnerabilities
- `bandit-report.json` - Static code analysis
- `licenses-report.json` - License information
- `secrets-report.json` - Secrets detection
- `pip-audit-report.json` - Additional dependency audit

## Release Process

### 1. Prepare Release

```bash
# Update version in aws_cis_assessment/__init__.py
# Update CHANGELOG.md
# Commit changes
git add .
git commit -m "Prepare release v1.2.4"
git push origin main
```

### 2. Create Release Tag

```bash
git tag v1.2.4
git push origin v1.2.4
```

### 3. Automated Release

The release workflow will automatically:

1. Validate the tag format
2. Run comprehensive tests
3. Build Python packages
4. Create GitHub release
5. Publish to PyPI

### 4. Manual Release (if needed)

```bash
python -m build
twine upload dist/*
```

## Package Distribution

### PyPI Package

```bash
pip install aws-cis-controls-assessment
```

### GitHub Repository

Clone and install from source:

```bash
git clone <repository-url>
cd aws-cis-controls-assessment
pip install -e .
```

## Troubleshooting

### Build Issues

**Problem**: Build fails with dependency conflicts
```bash
python -m venv fresh-venv
source fresh-venv/bin/activate
pip install -e .[dev]
```

**Problem**: Tests fail during build
```bash
pytest -v --tb=long
```

### Security Scan Issues

**Problem**: High severity vulnerabilities found
```bash
pip install --upgrade -r requirements.txt
```

**Problem**: False positive in security scan
```bash
# Add to ignore list in .bandit or .safety-policy.yml
# Document the reason for ignoring
```

### CI/CD Issues

**Problem**: GitHub Actions failing
```bash
# Check workflow logs and update actions versions
# Ensure all required secrets are configured
```

**Problem**: Release workflow not triggering
```bash
# Ensure tag format is correct (v1.2.4)
git tag -d v1.2.4
git push origin :refs/tags/v1.2.4
git tag v1.2.4
git push origin v1.2.4
```

## Security Considerations

- Never commit AWS credentials
- Use IAM roles when possible
- Regularly update dependencies
- Monitor security scan results
- Follow principle of least privilege
- Use secrets management for sensitive data
