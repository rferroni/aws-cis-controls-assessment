# Troubleshooting Guide

This guide helps you diagnose and resolve common issues with the AWS CIS Controls Compliance Assessment Framework - a production-ready, enterprise-grade solution with 199 unique assessment rules.

## Production Framework Status

**✅ Enterprise-Ready Solution**
- Complete implementation with 199 unique assessment rules across 40 CIS Controls v8.1 safeguards
- Production-tested with comprehensive error handling
- Optimized for large-scale enterprise deployments
- Robust error recovery and retry mechanisms

## Table of Contents

1. [General Troubleshooting Steps](#general-troubleshooting-steps)
2. [AWS Credential Issues](#aws-credential-issues)
3. [IAM Permission Issues](#iam-permission-issues)
4. [Configuration Issues](#configuration-issues)
5. [Network and API Issues](#network-and-api-issues)
6. [Assessment Scope Issues](#assessment-scope-issues)
7. [Output and Reporting Issues](#output-and-reporting-issues)
8. [Performance Issues](#performance-issues)
9. [Error Codes Reference](#error-codes-reference)
10. [Getting Additional Help](#getting-additional-help)

## General Troubleshooting Steps

### 1. Enable Verbose Logging

Always start with verbose logging to get detailed information:

```bash
aws-cis-assess assess --verbose --log-level DEBUG --log-file debug.log
```

### 2. Validate Your Setup

Run basic validation commands:

```bash
# Check tool version
aws-cis-assess --version

# Validate AWS credentials
aws-cis-assess validate-credentials --verbose

# Validate configuration
aws-cis-assess validate-config --verbose

# Test with dry run
aws-cis-assess assess --dry-run --verbose
```

### 3. Start with Minimal Scope

Reduce scope to isolate issues:

```bash
# Single control, single region
aws-cis-assess assess --controls 1.1 --regions us-east-1 --verbose
```

### 4. Check System Resources

Ensure adequate system resources:

```bash
# Check available memory
free -h

# Check disk space
df -h

# Check Python version
python --version
```

## AWS Credential Issues

### Problem: NoCredentialsError

**Error Message:**
```
NoCredentialsError: Unable to locate credentials
```

**Solutions:**

1. **Configure AWS CLI:**
   ```bash
   aws configure
   ```

2. **Set environment variables:**
   ```bash
   export AWS_ACCESS_KEY_ID=your_access_key
   export AWS_SECRET_ACCESS_KEY=your_secret_key
   export AWS_DEFAULT_REGION=us-east-1
   ```

3. **Use specific profile:**
   ```bash
   aws-cis-assess assess --aws-profile your-profile
   ```

4. **Verify credentials:**
   ```bash
   aws sts get-caller-identity
   ```

### Problem: InvalidUserID.NotFound

**Error Message:**
```
InvalidUserID.NotFound: The user ID does not exist
```

**Solutions:**

1. **Check user/role exists:**
   ```bash
   aws iam get-user
   # or
   aws sts get-caller-identity
   ```

2. **Verify profile configuration:**
   ```bash
   cat ~/.aws/credentials
   cat ~/.aws/config
   ```

3. **Test with different profile:**
   ```bash
   aws-cis-assess validate-credentials --aws-profile different-profile
   ```

### Problem: Token Expired

**Error Message:**
```
TokenRefreshError: The AWS Access Token has expired
```

**Solutions:**

1. **Refresh SSO token:**
   ```bash
   aws sso login --profile your-sso-profile
   ```

2. **Re-authenticate:**
   ```bash
   aws configure sso
   ```

3. **Use long-term credentials for automation:**
   ```bash
   # Create service account with access keys
   aws iam create-access-key --user-name service-account
   ```

## IAM Permission Issues

### Problem: AccessDenied Errors

**Error Message:**
```
AccessDenied: User: arn:aws:iam::123456789012:user/username is not authorized to perform: ec2:DescribeInstances
```

**Solutions:**

1. **Use ReadOnlyAccess policy:**
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": "ReadOnlyAccess",
         "Resource": "*"
       }
     ]
   }
   ```

2. **Add specific permissions:**
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [
       {
         "Effect": "Allow",
         "Action": [
           "ec2:Describe*",
           "iam:Get*",
           "iam:List*",
           "s3:GetBucket*",
           "s3:ListBucket*"
         ],
         "Resource": "*"
       }
     ]
   }
   ```

3. **Check current permissions:**
   ```bash
   aws iam simulate-principal-policy \
     --policy-source-arn arn:aws:iam::123456789012:user/username \
     --action-names ec2:DescribeInstances \
     --resource-arns "*"
   ```

### Problem: Partial Assessment Results

**Symptoms:**
- Some controls show "INSUFFICIENT_PERMISSIONS"
- Assessment completes but with many errors
- Missing results for certain services

**Solutions:**

1. **Review permission errors:**
   ```bash
   aws-cis-assess assess --verbose 2>&1 | grep -i "access.*denied"
   ```

2. **Add missing service permissions:**
   ```bash
   # Example: Add CloudTrail permissions
   aws iam attach-user-policy \
     --user-name your-user \
     --policy-arn arn:aws:iam::aws:policy/CloudTrailReadOnlyAccess
   ```

3. **Use broader permissions for comprehensive assessment:**
   ```bash
   aws iam attach-user-policy \
     --user-name your-user \
     --policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
   ```

## Configuration Issues

### Problem: Configuration Validation Failed

**Error Message:**
```
Configuration validation failed:
  • Missing required field 'resource_types' in control 1.1
  • Invalid YAML syntax in cis_controls_ig1.yaml
```

**Solutions:**

1. **Use default configuration:**
   ```bash
   aws-cis-assess assess  # Uses built-in configuration
   ```

2. **Validate custom configuration:**
   ```bash
   aws-cis-assess validate-config --config-path ./custom-config/
   ```

3. **Check YAML syntax:**
   ```bash
   python -c "import yaml; yaml.safe_load(open('config.yaml'))"
   ```

4. **Reset to defaults:**
   ```bash
   # Remove custom config to use defaults
   rm -rf ~/.aws-cis-assessment/config/
   ```

### Problem: Controls Not Found

**Error Message:**
```
Control '1.1' not found in configuration
```

**Solutions:**

1. **List available controls:**
   ```bash
   aws-cis-assess list-controls
   ```

2. **Check control ID format:**
   ```bash
   # Correct format
   aws-cis-assess assess --controls 1.1,3.3,4.1
   
   # Incorrect format
   aws-cis-assess assess --controls 1-1,3-3,4-1
   ```

3. **Verify Implementation Group:**
   ```bash
   aws-cis-assess list-controls | grep "1.1"
   ```

## Network and API Issues

### Problem: Connection Timeouts

**Error Message:**
```
ConnectTimeoutError: Connect timeout on endpoint URL
```

**Solutions:**

1. **Check internet connectivity:**
   ```bash
   ping aws.amazon.com
   curl -I https://ec2.us-east-1.amazonaws.com
   ```

2. **Configure proxy settings:**
   ```bash
   export HTTP_PROXY=http://proxy.company.com:8080
   export HTTPS_PROXY=https://proxy.company.com:8080
   
   # Or in AWS CLI config
   aws configure set proxy.http http://proxy.company.com:8080
   aws configure set proxy.https https://proxy.company.com:8080
   ```

3. **Increase timeout:**
   ```bash
   aws-cis-assess assess --timeout 3600  # 1 hour
   ```

### Problem: API Throttling

**Error Message:**
```
ThrottlingException: Rate exceeded
```

**Solutions:**

1. **Reduce parallel workers:**
   ```bash
   aws-cis-assess assess --max-workers 1
   ```

2. **Add delays between calls:**
   ```bash
   # The tool automatically implements exponential backoff
   # Just retry the assessment
   aws-cis-assess assess --verbose
   ```

3. **Assess fewer regions:**
   ```bash
   aws-cis-assess assess --regions us-east-1,us-west-2
   ```

### Problem: Service Unavailable

**Error Message:**
```
ServiceUnavailableException: Service is temporarily unavailable
```

**Solutions:**

1. **Check AWS service status:**
   - Visit https://status.aws.amazon.com/
   - Check specific service status

2. **Retry after delay:**
   ```bash
   sleep 300  # Wait 5 minutes
   aws-cis-assess assess --verbose
   ```

3. **Exclude problematic regions:**
   ```bash
   aws-cis-assess assess --exclude-regions us-west-1
   ```

## Assessment Scope Issues

### Problem: Too Many Resources

**Symptoms:**
- Assessment runs out of memory
- Assessment takes too long
- System becomes unresponsive

**Solutions:**

1. **Limit scope:**
   ```bash
   # Assess only IG1
   aws-cis-assess assess --implementation-groups IG1
   
   # Assess specific controls
   aws-cis-assess assess --controls 1.1,3.3
   
   # Limit regions
   aws-cis-assess assess --regions us-east-1
   ```

2. **Reduce workers:**
   ```bash
   aws-cis-assess assess --max-workers 1
   ```

3. **Preview scope:**
   ```bash
   aws-cis-assess show-stats --implementation-groups IG1,IG2
   ```

### Problem: Unexpected Controls Being Assessed

**Solutions:**

1. **Check Implementation Group hierarchy:**
   - IG2 includes all IG1 controls
   - IG3 includes all IG1 and IG2 controls

2. **Use specific controls:**
   ```bash
   aws-cis-assess assess --controls 1.1,3.3  # Only these controls
   ```

3. **Exclude unwanted controls:**
   ```bash
   aws-cis-assess assess --exclude-controls 7.1,12.8
   ```

## Output and Reporting Issues

### Problem: Reports Not Generated

**Error Message:**
```
Permission denied: cannot write to /path/to/output.html
```

**Solutions:**

1. **Check write permissions:**
   ```bash
   ls -la /path/to/output/directory/
   chmod 755 /path/to/output/directory/
   ```

2. **Use different output directory:**
   ```bash
   aws-cis-assess assess --output-dir ~/reports/
   ```

3. **Use absolute paths:**
   ```bash
   aws-cis-assess assess --output-file /home/user/reports/assessment.html
   ```

### Problem: Corrupted or Empty Reports

**Solutions:**

1. **Check disk space:**
   ```bash
   df -h
   ```

2. **Verify assessment completed:**
   ```bash
   aws-cis-assess assess --verbose 2>&1 | tail -20
   ```

3. **Try different format:**
   ```bash
   aws-cis-assess assess --output-format json  # Simpler format
   ```

### Problem: Log Files Not Created

**Solutions:**

1. **Check log file permissions:**
   ```bash
   touch /path/to/logfile.log
   ls -la /path/to/logfile.log
   ```

2. **Use relative path:**
   ```bash
   aws-cis-assess assess --log-file ./assessment.log
   ```

3. **Check parent directory exists:**
   ```bash
   mkdir -p /path/to/logs/
   aws-cis-assess assess --log-file /path/to/logs/assessment.log
   ```

## Performance Issues

### Problem: Assessment Takes Too Long

**Solutions:**

1. **Reduce scope:**
   ```bash
   # Start with IG1 only
   aws-cis-assess assess --implementation-groups IG1
   
   # Limit regions
   aws-cis-assess assess --regions us-east-1,us-west-2
   ```

2. **Increase workers (if system can handle it):**
   ```bash
   aws-cis-assess assess --max-workers 8
   ```

3. **Set reasonable timeout:**
   ```bash
   aws-cis-assess assess --timeout 1800  # 30 minutes
   ```

### Problem: High Memory Usage

**Solutions:**

1. **Reduce workers:**
   ```bash
   aws-cis-assess assess --max-workers 1
   ```

2. **Limit scope:**
   ```bash
   aws-cis-assess assess --controls 1.1,3.3,4.1
   ```

3. **Monitor system resources:**
   ```bash
   # Run in background and monitor
   aws-cis-assess assess --quiet &
   top -p $!
   ```

## Error Codes Reference

### Common Exit Codes

- **0**: Success
- **1**: General error
- **2**: Configuration error
- **3**: Credential error
- **4**: Permission error
- **5**: Network error
- **130**: Interrupted by user (Ctrl+C)

### AWS API Error Codes

- **AccessDenied**: Insufficient IAM permissions
- **InvalidUserID.NotFound**: User/role doesn't exist
- **TokenRefreshError**: Expired credentials
- **ThrottlingException**: API rate limit exceeded
- **ServiceUnavailableException**: AWS service temporarily unavailable
- **NoCredentialsError**: No AWS credentials found

## Getting Additional Help

### Enable Debug Mode

```bash
aws-cis-assess assess --debug --verbose --log-file full-debug.log
```

### Collect System Information

```bash
# System info
uname -a
python --version
pip list | grep aws

# AWS info
aws --version
aws sts get-caller-identity
aws configure list

# Tool info
aws-cis-assess --version
aws-cis-assess validate-credentials --verbose
```

### Create Minimal Reproduction

```bash
# Minimal command that reproduces the issue
aws-cis-assess assess \
  --controls 1.1 \
  --regions us-east-1 \
  --verbose \
  --log-file minimal-repro.log
```

### Report Issues

When reporting issues, include:

1. **Command used**: Full command line
2. **Error message**: Complete error output
3. **Log files**: Debug logs if available
4. **Environment**: OS, Python version, tool version
5. **AWS setup**: Region, account type, permissions
6. **Expected vs actual behavior**: What you expected vs what happened

### Community Resources

- **GitHub Issues**: Report bugs and request features
- **Documentation**: Check latest documentation
- **AWS Forums**: AWS-specific questions
- **Stack Overflow**: General troubleshooting

### Professional Support

For enterprise users:
- **AWS Support**: For AWS service-related issues
- **Professional Services**: For implementation assistance
- **Training**: For team education and best practices


## AWS Backup Controls Issues

### Problem: Backup Plan Assessment Failures

**Error Message:**
```
AccessDenied: User is not authorized to perform: backup:ListBackupPlans
```

**Solutions:**

1. **Add Backup permissions:**
   ```bash
   # Ensure IAM policy includes Backup permissions
   aws iam attach-user-policy \
     --user-name your-user \
     --policy-arn arn:aws:iam::aws:policy/AWSBackupReadOnlyAccess
   ```

2. **Verify Backup service availability:**
   ```bash
   # Check if Backup service is available in region
   aws backup list-backup-plans --region us-east-1
   ```

3. **Check for Backup plans:**
   ```bash
   # List existing backup plans
   aws backup list-backup-plans --query 'BackupPlansList[*].[BackupPlanName,BackupPlanId]' --output table
   ```

### Problem: Backup Vault Access Policy Check Failures

**Error Message:**
```
ResourceNotFoundException: Backup vault not found
```

**Solutions:**

1. **Verify backup vaults exist:**
   ```bash
   # List backup vaults in region
   aws backup list-backup-vaults --region us-east-1
   ```

2. **Check vault access policy:**
   ```bash
   # Get vault access policy
   aws backup get-backup-vault-access-policy --backup-vault-name MyVault
   ```

3. **Create backup vault if needed:**
   ```bash
   # Create a backup vault
   aws backup create-backup-vault --backup-vault-name MyVault
   ```

### Problem: Backup Plan Frequency/Retention Validation

**Symptoms:**
- Backup plans marked as non-compliant
- Frequency or retention requirements not met
- Assessment shows "Backup plan does not meet minimum requirements"

**Solutions:**

1. **Review backup plan rules:**
   ```bash
   # Get backup plan details
   aws backup get-backup-plan --backup-plan-id <plan-id>
   ```

2. **Check schedule expression:**
   ```bash
   # Verify cron/rate expression meets requirements
   # Minimum daily frequency: cron(0 0 * * ? *) or rate(1 day)
   ```

3. **Verify retention settings:**
   ```bash
   # Ensure DeleteAfterDays >= 35 days (5 weeks)
   # Check lifecycle settings in backup plan rules
   ```

4. **Update backup plan:**
   ```bash
   # Update plan to meet requirements
   aws backup update-backup-plan \
     --backup-plan-id <plan-id> \
     --backup-plan file://updated-plan.json
   ```

### Problem: No Backup Resources Found

**Symptoms:**
- Assessment shows "No backup plans found"
- Zero backup-related resources discovered
- All backup controls show NOT_APPLICABLE

**Solutions:**

1. **Enable AWS Backup:**
   ```bash
   # Create your first backup plan
   aws backup create-backup-plan --backup-plan file://backup-plan.json
   ```

2. **Check region scope:**
   ```bash
   # Backup resources are regional
   # Ensure you're checking the correct regions
   aws-cis-assess assess --regions us-east-1,us-west-2 --verbose
   ```

3. **Verify service availability:**
   ```bash
   # Check if Backup service is enabled in your account
   aws backup describe-global-settings
   ```

### Problem: Backup Vault Policy Validation

**Symptoms:**
- Vault policy marked as non-compliant
- "Vault allows public access" or "Vault policy too permissive"
- Policy validation failures

**Solutions:**

1. **Review vault policy:**
   ```bash
   # Get current vault policy
   aws backup get-backup-vault-access-policy \
     --backup-vault-name MyVault \
     --query 'Policy' \
     --output text | jq .
   ```

2. **Check for overly permissive principals:**
   ```json
   {
     "Statement": [{
       "Principal": "*",  // ❌ Too permissive
       "Effect": "Allow",
       "Action": "backup:*"
     }]
   }
   ```

3. **Update vault policy:**
   ```bash
   # Apply restrictive policy
   aws backup put-backup-vault-access-policy \
     --backup-vault-name MyVault \
     --policy file://restrictive-policy.json
   ```

4. **Best practice policy example:**
   ```json
   {
     "Version": "2012-10-17",
     "Statement": [{
       "Effect": "Allow",
       "Principal": {
         "AWS": "arn:aws:iam::123456789012:role/BackupRole"
       },
       "Action": [
         "backup:DescribeBackupVault",
         "backup:ListRecoveryPointsByBackupVault"
       ],
       "Resource": "*"
     }]
   }
   ```

### Problem: Backup Assessment Performance

**Symptoms:**
- Backup control assessments take too long
- Timeout errors during backup plan evaluation
- High API call volume to Backup service

**Solutions:**

1. **Limit assessment scope:**
   ```bash
   # Assess only specific backup controls
   aws-cis-assess assess --controls 11.1,11.2 --regions us-east-1
   ```

2. **Reduce parallel workers:**
   ```bash
   # Lower concurrency for Backup API calls
   aws-cis-assess assess --max-workers 2
   ```

3. **Check for large number of backup plans:**
   ```bash
   # Count backup plans
   aws backup list-backup-plans --query 'length(BackupPlansList)'
   ```

4. **Optimize backup plan structure:**
   - Consolidate multiple small plans into fewer comprehensive plans
   - Use backup selections to target specific resources
   - Avoid creating excessive backup plans per region
