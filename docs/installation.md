# Installation Guide

This guide covers the installation and initial setup of the AWS CIS Controls Compliance Assessment Framework - a production-ready, enterprise-grade solution for AWS security compliance assessment.

> **📦 Package Name Change**: Starting from version 1.0.4, this package is published as `aws-cis-controls-assessment` (previously `aws-cis-assessment`). If you have the old package installed, please uninstall it first: `pip uninstall aws-cis-assessment` then install the new package: `pip install aws-cis-controls-assessment`

## Production Status

**✅ Ready for Enterprise Deployment**
- Complete implementation with 199 unique AWS Config rule assessments
- CIS Controls coverage across all Implementation Groups
- Production-tested architecture with comprehensive error handling
- Enterprise-grade performance and scalability

## System Requirements

### Python Requirements
- **Python 3.8 or higher** (Python 3.9+ recommended)
- **pip** package manager
- **Virtual environment** (recommended)

### AWS Requirements
- **AWS Account** with appropriate permissions
- **AWS CLI** configured (optional but recommended)
- **Read-only access** to AWS services being assessed

### Operating System Support
- **Linux** (Ubuntu 18.04+, CentOS 7+, Amazon Linux 2)
- **macOS** (10.14+)
- **Windows** (Windows 10, Windows Server 2016+)

## Installation Methods

### Method 1: Install from PyPI (Recommended)

```bash
# Install the latest production version
pip install aws-cis-controls-assessment

# Verify installation
aws-cis-assess --version
```

### Method 2: Install from Source

```bash
# Clone the repository
git clone https://github.com/rferroni/aws-cis-controls-assessment.git
cd aws-cis-controls-assessment

# Create virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .

# Verify installation
aws-cis-assess --version
```



## AWS Credentials Setup

The tool supports multiple methods for AWS credential configuration:

### Method 1: AWS SSO (Recommended)

```bash
# Configure AWS SSO
aws configure sso

# Use SSO profile
aws-cis-assess assess --aws-profile my-sso-profile
```

### Method 2: AWS CLI Configuration

```bash
# Install AWS CLI if not already installed
pip install awscli

# Configure credentials
aws configure
```

This creates `~/.aws/credentials` and `~/.aws/config` files.

### Method 3: IAM Roles (EC2/ECS/Lambda)

When running on AWS services, the tool automatically uses IAM roles attached to the service.

### Method 4: Environment Variables (Not Recommended)

> ⚠️ **Avoid using long-lived access keys.** Environment variables with permanent credentials are a security risk — they can leak through logs, shell history, or process listings. Prefer SSO, IAM roles, or short-lived session credentials instead.

```bash
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_SESSION_TOKEN=your_session_token
export AWS_DEFAULT_REGION=us-east-1
```

## Required IAM Permissions

The tool requires read-only permissions for various AWS services. Here's a comprehensive IAM policy that covers all 199 assessments:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "access-analyzer:Get*",
                "access-analyzer:List*",
                "acm:Describe*",
                "acm:Get*",
                "acm:List*",
                "apigateway:GET",
                "application-autoscaling:Describe*",
                "autoscaling:Describe*",
                "backup:Describe*",
                "backup:Get*",
                "backup:List*",
                "cloudfront:Get*",
                "cloudfront:List*",
                "cloudtrail:Describe*",
                "cloudtrail:Get*",
                "cloudtrail:List*",
                "codebuild:BatchGetProjects",
                "codebuild:ListProjects",
                "cognito-idp:Describe*",
                "cognito-idp:Get*",
                "cognito-idp:List*",
                "config:Describe*",
                "config:Get*",
                "config:List*",
                "dynamodb:Describe*",
                "dynamodb:List*",
                "ec2:Describe*",
                "ecr:Describe*",
                "ecr:Get*",
                "ecr:List*",
                "ecs:Describe*",
                "ecs:List*",
                "elasticfilesystem:Describe*",
                "elasticache:Describe*",
                "elasticache:List*",
                "elasticbeanstalk:Describe*",
                "elasticbeanstalk:List*",
                "elasticloadbalancing:Describe*",
                "elasticmapreduce:Describe*",
                "elasticmapreduce:List*",
                "es:Describe*",
                "es:List*",
                "guardduty:Get*",
                "guardduty:List*",
                "iam:Get*",
                "iam:List*",
                "inspector2:BatchGet*",
                "inspector2:List*",
                "kinesis:Describe*",
                "kinesis:List*",
                "lambda:Get*",
                "lambda:List*",
                "logs:Describe*",
                "macie2:Get*",
                "macie2:List*",
                "network-firewall:Describe*",
                "network-firewall:List*",
                "opensearch:Describe*",
                "opensearch:List*",
                "organizations:Describe*",
                "organizations:List*",
                "rds:Describe*",
                "redshift:Describe*",
                "route53:Get*",
                "route53:List*",
                "route53resolver:Get*",
                "route53resolver:List*",
                "s3:GetBucket*",
                "s3:GetAccountPublicAccessBlock",
                "s3:GetEncryptionConfiguration",
                "s3:ListBucket*",
                "s3:ListAllMyBuckets",
                "sagemaker:Describe*",
                "sagemaker:List*",
                "secretsmanager:Describe*",
                "secretsmanager:List*",
                "securityhub:Describe*",
                "securityhub:Get*",
                "securityhub:List*",
                "sns:Get*",
                "sns:List*",
                "sqs:Get*",
                "sqs:List*",
                "sso:Describe*",
                "sso:Get*",
                "sso:List*",
                "ssm:Describe*",
                "ssm:Get*",
                "ssm:List*",
                "sts:GetCallerIdentity",
                "wafv2:Get*",
                "wafv2:List*"
            ],
            "Resource": "*"
        }
    ]
}
```

### Services Covered

This policy includes permissions for all AWS services assessed by the tool:

**Identity & Security:** IAM, SSO/Identity Center, IAM Access Analyzer, GuardDuty, Security Hub, Macie, Inspector, Secrets Manager, ACM, Cognito  
**Compute:** EC2, Auto Scaling, ECS, ECR, Lambda, Elastic Beanstalk, EMR, SageMaker  
**Storage:** S3, EFS, Backup  
**Database:** RDS, DynamoDB, Redshift, ElastiCache, OpenSearch/Elasticsearch, Kinesis  
**Networking:** VPC (via EC2), ELB/ALB/NLB, API Gateway, CloudFront, Route 53, Route 53 Resolver, Network Firewall, WAFv2  
**Monitoring:** CloudTrail, CloudWatch Logs, Config  
**Messaging:** SNS, SQS  
**Management:** SSM, Organizations, STS  
**DevOps:** CodeBuild

### Minimal Permissions for Testing

For initial testing, you can use the AWS managed `ReadOnlyAccess` policy:

```bash
# Attach ReadOnlyAccess to your IAM user/role
aws iam attach-user-policy --user-name <user> --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
```

## Verification

### Test Installation

```bash
# Check version
aws-cis-assess --version

# List available commands
aws-cis-assess --help

# Test AWS credentials
aws-cis-assess validate-credentials

# List available regions
aws-cis-assess list-regions

# Show assessment statistics
aws-cis-assess show-stats
```

### Run Sample Assessment

```bash
# Run a quick IG1 assessment
aws-cis-assess assess --implementation-groups IG1 --regions us-east-1

# Run dry run to validate configuration
aws-cis-assess assess --dry-run
```


## Troubleshooting Installation

### Common Issues

#### Python Version Issues
```bash
# Check Python version
python --version

# Use specific Python version
python3.9 -m pip install aws-cis-controls-assessment
```

#### Permission Issues
```bash
# Install for current user only
pip install --user aws-cis-controls-assessment

# Use virtual environment
python -m venv aws-cis-env
source aws-cis-env/bin/activate
pip install aws-cis-controls-assessment
```

#### AWS Credential Issues
```bash
# Test AWS credentials
aws sts get-caller-identity

# Validate with the tool
aws-cis-assess validate-credentials --verbose

# If using temporary credentials (recommended over permanent keys)
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_SESSION_TOKEN=your_session_token
export AWS_DEFAULT_REGION=us-east-1
```

#### Network/Proxy Issues
```bash
# Install with proxy
pip install --proxy http://proxy.company.com:8080 aws-cis-controls-assessment

# Configure AWS CLI with proxy
aws configure set proxy.http http://proxy.company.com:8080
aws configure set proxy.https https://proxy.company.com:8080
```

### Getting Help

If you encounter issues during installation:

1. **Check the troubleshooting guide**: `docs/troubleshooting.md`
2. **Enable verbose logging**: Add `--verbose` to commands
3. **Check system requirements**: Ensure Python 3.8+ and proper AWS access
4. **Review AWS permissions**: Verify IAM permissions are sufficient
5. **Report issues**: Create an issue on GitHub with detailed error information

## Next Steps

After successful installation:

1. **Read the User Guide**: `docs/user-guide.md`
2. **Review Configuration Options**: `docs/configuration.md`
3. **Run Your First Assessment**: Follow the quick start in the user guide
4. **Explore CLI Commands**: `docs/cli-reference.md`

### Upgrading

### Upgrade from PyPI
```bash
pip install --upgrade aws-cis-controls-assessment
```

### Upgrade from Source
```bash
cd aws-cis-controls-assessment
git pull origin main
pip install -e .
```

### Check for Updates
```bash
# Check current version
aws-cis-assess --version

# Check for available updates
pip list --outdated | grep aws-cis-controls-assessment
```