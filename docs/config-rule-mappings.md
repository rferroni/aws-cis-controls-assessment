# Config Rule Mappings

This document provides a comprehensive mapping of CIS Controls to AWS Config rules used by the assessment tool.

## Table of Contents

1. [Overview](#overview)
2. [IG1 - Essential Cyber Hygiene](#ig1---essential-cyber-hygiene)
3. [IG2 - Enhanced Security](#ig2---enhanced-security)
4. [IG3 - Advanced Security](#ig3---advanced-security)
5. [Config Rule Details](#config-rule-details)
6. [Resource Type Coverage](#resource-type-coverage)
7. [Assessment Logic](#assessment-logic)

## Overview

The AWS CIS Controls Compliance Assessment Framework uses AWS Config rule specifications as the foundation for evaluating compliance. Each CIS Control is mapped to one or more AWS Config rules that assess specific AWS resources and configurations.

**Production Status**: This framework implements 199 unique assessment rules across 40 CIS Controls v8.1 safeguards covering all Implementation Groups.

### Mapping Methodology

1. **Direct Mapping**: CIS Controls directly correspond to existing AWS Config rules
2. **Composite Mapping**: Multiple Config rules combine to assess a single CIS Control
3. **Custom Logic**: Additional assessment logic based on Config rule specifications
4. **Resource Coverage**: All applicable AWS resource types are evaluated

### Implementation Groups Hierarchy

- **IG1**: 96 Config rules covering essential cyber hygiene
- **IG2**: +74 Config rules for enhanced security (includes all IG1 rules)
- **IG3**: +1 Config rule for advanced security (includes all IG1+IG2 rules)
- **Bonus**: +9 additional security rules beyond CIS requirements
- **Total**: 163 Config rules implemented (151 CIS + 9 bonus + 7 audit logging)

## IG1 - Essential Cyber Hygiene

### Control 1.1: Establish and Maintain Detailed Enterprise Asset Inventory

**Purpose**: Maintain an accurate and up-to-date inventory of all enterprise assets.

| Config Rule | Resource Types | Description |
|-------------|----------------|-------------|
| `eip-attached` | AWS::EC2::EIP | Ensures Elastic IPs are attached to EC2 instances or ENIs |
| `ec2-stopped-instance` | AWS::EC2::Instance | Checks for EC2 instances stopped for more than allowed days |
| `vpc-network-acl-unused-check` | AWS::EC2::NetworkAcl | Ensures VPC network ACLs are in use |
| `ec2-instance-managed-by-systems-manager` | AWS::EC2::Instance, AWS::SSM::ManagedInstanceInventory | Ensures EC2 instances are managed by Systems Manager |
| `ec2-security-group-attached-to-eni` | AWS::EC2::SecurityGroup | Ensures security groups are attached to network interfaces |

**Assessment Logic**:
- Discovers all EC2 instances, EIPs, security groups, and network ACLs
- Validates that resources are properly managed and not orphaned
- Checks Systems Manager agent installation and registration

### Control 2.2: Ensure Authorized Software is Currently Supported

**Purpose**: Ensure that only authorized and supported software is installed and running.

| Config Rule | Resource Types | Description |
|-------------|----------------|-------------|
| `elastic-beanstalk-managed-updates-enabled` | AWS::ElasticBeanstalk::Environment | Ensures Elastic Beanstalk environments have managed updates enabled |
| `lambda-function-settings-check` | AWS::Lambda::Function | Validates Lambda function runtime and configuration settings |
| `ec2-imdsv2-check` | AWS::EC2::Instance | Ensures EC2 instances use IMDSv2 for metadata access |

**Assessment Logic**:
- Validates that compute services use supported and current software versions
- Checks for automatic update mechanisms where available
- Ensures secure configuration of runtime environments

### Control 3.3: Configure Data Access Control Lists

**Purpose**: Configure data access control lists on network shares and databases.

| Config Rule | Resource Types | Description |
|-------------|----------------|-------------|
| `iam-password-policy` | AWS::IAM::AccountPasswordPolicy | Ensures IAM password policy meets security requirements |
| `iam-user-mfa-enabled` | AWS::IAM::User | Ensures IAM users have MFA enabled |
| `iam-root-access-key-check` | AWS::IAM::User | Ensures root account access keys are not present |
| `s3-bucket-public-read-prohibited` | AWS::S3::Bucket | Ensures S3 buckets do not allow public read access |
| `s3-bucket-public-write-prohibited` | AWS::S3::Bucket | Ensures S3 buckets do not allow public write access |
| `ec2-instance-no-public-ip` | AWS::EC2::Instance | Ensures EC2 instances do not have public IP addresses |
| `rds-instance-public-access-check` | AWS::RDS::DBInstance | Ensures RDS instances are not publicly accessible |
| `redshift-cluster-public-access-check` | AWS::Redshift::Cluster | Ensures Redshift clusters are not publicly accessible |
| `dms-replication-not-public` | AWS::DMS::ReplicationInstance | Ensures DMS replication instances are not public |
| `ec2-instance-profile-attached` | AWS::EC2::Instance | Ensures EC2 instances have IAM instance profiles attached |

**Assessment Logic**:
- Evaluates IAM policies and access controls
- Checks for public accessibility of data stores
- Validates proper authentication and authorization mechanisms

### Control 4.1: Establish and Maintain a Secure Configuration Process

**Purpose**: Establish and maintain a secure configuration process for enterprise assets.

| Config Rule | Resource Types | Description |
|-------------|----------------|-------------|
| `account-part-of-organizations` | AWS::Organizations::Account | Ensures AWS account is part of AWS Organizations |
| `ec2-volume-inuse-check` | AWS::EC2::Volume | Ensures EBS volumes are attached to EC2 instances |
| `redshift-cluster-maintenancesettings-check` | AWS::Redshift::Cluster | Validates Redshift cluster maintenance settings |
| `secretsmanager-rotation-enabled-check` | AWS::SecretsManager::Secret | Ensures Secrets Manager secrets have rotation enabled |
| `rds-automatic-minor-version-upgrade-enabled` | AWS::RDS::DBInstance | Ensures RDS instances have automatic minor version upgrades |

**Assessment Logic**:
- Validates organizational governance structures
- Checks for proper resource utilization and maintenance
- Ensures automatic security updates and rotation policies

### Control 11.1: Establish and Maintain a Data Recovery Process

**Purpose**: Establish and maintain a data recovery process for enterprise data.

| Config Rule | Resource Types | Description |
|-------------|----------------|-------------|
| `backup-recovery-point-encrypted` | AWS::Backup::RecoveryPoint | Ensures backup recovery points are encrypted |
| `backup-recovery-point-minimum-retention-check` | AWS::Backup::RecoveryPoint | Validates recovery point retention periods |
| `backup-recovery-point-manual-deletion-disabled` | AWS::Backup::RecoveryPoint | Ensures manual deletion is disabled for recovery points |
| `backup-plan-min-frequency-and-min-retention-check` | AWS::Backup::BackupPlan | Validates backup plan frequency and retention policies |
| `backup-vault-access-policy-check` | AWS::Backup::BackupVault | Checks backup vault access policies for security |
| `backup-selection-resource-coverage-check` | AWS::Backup::BackupPlan | Ensures backup plans cover critical resources |
| `db-instance-backup-enabled` | AWS::RDS::DBInstance | Ensures RDS instances have automated backups enabled |
| `dynamodb-pitr-enabled` | AWS::DynamoDB::Table | Ensures DynamoDB tables have point-in-time recovery |
| `elasticache-redis-cluster-automatic-backup-check` | AWS::ElastiCache::CacheCluster | Validates ElastiCache Redis backup configuration |
| `redshift-backup-enabled` | AWS::Redshift::Cluster | Ensures Redshift clusters have automated backups |
| `aurora-resources-protected-by-backup-plan` | AWS::RDS::DBCluster | Ensures Aurora clusters are protected by backup plans |
| `rds-resources-protected-by-backup-plan` | AWS::RDS::DBInstance | Ensures RDS instances are protected by backup plans |
| `dynamodb-resources-protected-by-backup-plan` | AWS::DynamoDB::Table | Ensures DynamoDB tables are protected by backup plans |
| `ebs-resources-protected-by-backup-plan` | AWS::EC2::Volume | Ensures EBS volumes are protected by backup plans |
| `efs-resources-protected-by-backup-plan` | AWS::EFS::FileSystem | Ensures EFS file systems are protected by backup plans |

**Assessment Logic**:
- Validates backup plan configuration and policies
- Checks backup vault security and access controls
- Ensures recovery points meet retention requirements
- Validates encryption of backup data
- Confirms resources are protected by backup plans
- Checks automated backup configuration across services
- Validates backup selections cover critical resources

**Service-Level Controls (IG1)**:
- `backup-plan-min-frequency-and-min-retention-check`: Evaluates backup plans to ensure they have rules with minimum frequency and retention
- `backup-vault-access-policy-check`: Validates backup vault access policies don't allow overly permissive access (wildcard principals or actions)
- `backup-selection-resource-coverage-check`: Ensures backup plans have selections that target resources (not empty plans)

**Service-Level Controls (IG2)**:
- `backup-vault-lock-check`: Verifies vault lock is enabled for ransomware protection (immutable backups)
- `backup-report-plan-exists-check`: Validates backup compliance reporting is configured
- `backup-restore-testing-plan-exists-check`: Ensures backup recoverability is validated through restore testing

### Control 5.2: Use Unique Passwords

**Purpose**: Use unique passwords for all enterprise assets.

| Config Rule | Resource Types | Description |
|-------------|----------------|-------------|
| `iam-password-policy` | AWS::IAM::AccountPasswordPolicy | Enhanced password policy validation |
| `mfa-enabled-for-iam-console-access` | AWS::IAM::User | Ensures MFA is enabled for console access |
| `root-account-mfa-enabled` | AWS::IAM::User | Ensures root account has MFA enabled |
| `iam-user-unused-credentials-check` | AWS::IAM::User | Identifies unused IAM user credentials |

**Assessment Logic**:
- Validates password complexity requirements
- Checks for MFA enforcement
- Identifies stale or unused credentials

## IG2 - Enhanced Security

### Control 4: Secure Configuration of Enterprise Assets and Software

**Purpose**: Establish and maintain the secure configuration of enterprise assets and software.

#### Control 4.1: IAM Role Session Duration Validation

| Config Rule | Resource Types | Description |
|-------------|----------------|-------------|
| `iam-max-session-duration-check` | AWS::IAM::Role | Validates IAM role session duration does not exceed 12 hours |

**Assessment Logic**:
- Discovers all IAM roles (global service, evaluated in us-east-1)
- Checks MaxSessionDuration property on each role
- COMPLIANT if MaxSessionDuration ≤ 43200 seconds (12 hours)
- NON_COMPLIANT if MaxSessionDuration > 43200 seconds
- Limits credential exposure window for temporary credentials

**Remediation Guidance**:
```bash
# Update IAM role to limit session duration
aws iam update-role --role-name <role-name> --max-session-duration 43200
```

#### Control 4.2: Default Security Group Restriction

| Config Rule | Resource Types | Description |
|-------------|----------------|-------------|
| `security-group-default-rules-check` | AWS::EC2::SecurityGroup | Ensures default security groups have no inbound or outbound rules |

**Assessment Logic**:
- Discovers all security groups with GroupName='default' (regional service)
- Checks IpPermissions (inbound rules) and IpPermissionsEgress (outbound rules)
- COMPLIANT if both rule lists are empty
- NON_COMPLIANT if any rules exist
- Prevents unintended access through default security groups

**Remediation Guidance**:
```bash
# Remove all inbound rules from default security group
aws ec2 revoke-security-group-ingress --group-id <sg-id> --ip-permissions <permissions>

# Remove all outbound rules from default security group
aws ec2 revoke-security-group-egress --group-id <sg-id> --ip-permissions <permissions>
```

#### Control 4.3: VPC DNS Configuration Validation

| Config Rule | Resource Types | Description |
|-------------|----------------|-------------|
| `vpc-dns-resolution-enabled` | AWS::EC2::VPC | Validates VPC DNS settings (enableDnsHostnames and enableDnsSupport) |

**Assessment Logic**:
- Discovers all VPCs (regional service)
- Checks enableDnsHostnames attribute via describe_vpc_attribute
- Checks enableDnsSupport attribute via describe_vpc_attribute
- COMPLIANT if both attributes are True
- NON_COMPLIANT if either attribute is False
- Required for many AWS services to function correctly

**Remediation Guidance**:
```bash
# Enable DNS resolution for VPC
aws ec2 modify-vpc-attribute --vpc-id <vpc-id> --enable-dns-support

# Enable DNS hostnames for VPC
aws ec2 modify-vpc-attribute --vpc-id <vpc-id> --enable-dns-hostnames
```

#### Control 4.4: RDS Default Admin Username Check

| Config Rule | Resource Types | Description |
|-------------|----------------|-------------|
| `rds-default-admin-check` | AWS::RDS::DBInstance | Ensures RDS instances don't use default admin usernames |

**Assessment Logic**:
- Discovers all RDS instances (regional service)
- Checks MasterUsername against default list (case-insensitive): postgres, admin, root, mysql, administrator, sa
- COMPLIANT if MasterUsername is not a default value
- NON_COMPLIANT if MasterUsername matches default list
- Reduces risk of credential guessing attacks

**Remediation Guidance**:
```bash
# RDS master username cannot be changed after creation
# Remediation requires snapshot and restore:
aws rds create-db-snapshot --db-instance-identifier <old-instance> --db-snapshot-identifier <snapshot-name>
aws rds restore-db-instance-from-db-snapshot --db-instance-identifier <new-instance> --db-snapshot-identifier <snapshot-name> --master-username <custom-username>

# Note: This is a disruptive change requiring downtime
```

#### Control 4.5: EC2 Instance Profile Least Privilege Validation

| Config Rule | Resource Types | Description |
|-------------|----------------|-------------|
| `ec2-instance-profile-least-privilege` | AWS::EC2::Instance | Validates EC2 instance profile permissions follow least privilege |

**Assessment Logic**:
- Discovers all EC2 instances with instance profiles (regional service)
- Gets IAM role from instance profile (IAM is global, queried in us-east-1)
- Lists attached managed policies and inline policies
- Checks for overly permissive policies:
  - AdministratorAccess or PowerUserAccess managed policies
  - Policies with Action: "*" and Resource: "*"
- COMPLIANT if no overly permissive policies found
- NON_COMPLIANT if overly permissive policies detected

**Remediation Guidance**:
```bash
# Create specific policy with limited permissions
aws iam create-policy --policy-name <specific-policy> --policy-document file://policy.json

# Attach specific policy to role
aws iam attach-role-policy --role-name <role-name> --policy-arn <specific-policy-arn>

# Detach overly permissive policy
aws iam detach-role-policy --role-name <role-name> --policy-arn <broad-policy-arn>
```

### Control 5: Account Management

**Purpose**: Use processes and tools to assign and manage authorization to credentials for user accounts, including administrator accounts, as well as service accounts, to enterprise assets and software.

#### Control 5.1: Service Account Documentation Verification

| Config Rule | Resource Types | Description |
|-------------|----------------|-------------|
| `iam-service-account-inventory-check` | AWS::IAM::User, AWS::IAM::Role | Validates service accounts have required documentation tags |

**Assessment Logic**:
- Discovers all IAM users and roles (global service, evaluated in us-east-1)
- Identifies service accounts by:
  - Naming convention (contains "service", "app", "application")
  - ServiceAccount=true tag
- Checks for required tags: Purpose, Owner, LastReviewed
- COMPLIANT if all three tags present with non-empty values
- NON_COMPLIANT if any required tag missing or empty
- Supports compliance and access review processes

**Remediation Guidance**:
```bash
# Add required documentation tags to service account
aws iam tag-user --user-name <service-account> --tags \
  Key=Purpose,Value="API access for application" \
  Key=Owner,Value="platform-team" \
  Key=LastReviewed,Value="2024-01-15"

# For roles
aws iam tag-role --role-name <service-role> --tags \
  Key=Purpose,Value="Lambda execution" \
  Key=Owner,Value="dev-team" \
  Key=LastReviewed,Value="2024-01-15"
```

#### Control 5.2: Administrative Policy Attachment Validation

| Config Rule | Resource Types | Description |
|-------------|----------------|-------------|
| `iam-admin-policy-attached-to-role-check` | AWS::IAM::User | Ensures administrative policies are attached to roles, not users |

**Assessment Logic**:
- Discovers all IAM users (global service, evaluated in us-east-1)
- Lists attached managed policies and inline policies
- Checks for administrative policies:
  - AdministratorAccess (arn:aws:iam::aws:policy/AdministratorAccess)
  - PowerUserAccess
  - Inline policies with Action: "*" and Resource: "*"
- COMPLIANT if no admin policies attached to user
- NON_COMPLIANT if admin policies found on user
- Encourages role-based access with temporary credentials

**Remediation Guidance**:
```bash
# Create admin role
aws iam create-role --role-name AdminRole --assume-role-policy-document file://trust-policy.json

# Attach admin policy to role
aws iam attach-role-policy --role-name AdminRole --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# Remove admin policy from user
aws iam detach-user-policy --user-name <user> --policy-arn arn:aws:iam::aws:policy/AdministratorAccess

# User assumes role for admin access
aws sts assume-role --role-arn arn:aws:iam::<account>:role/AdminRole --role-session-name admin-session
```

#### Control 5.3: AWS IAM Identity Center (SSO) Enablement Check

| Config Rule | Resource Types | Description |
|-------------|----------------|-------------|
| `sso-enabled-check` | AWS::::Account | Validates AWS IAM Identity Center is configured and enabled |

**Assessment Logic**:
- Account-level check (global service, evaluated in us-east-1)
- Calls sso-admin.list_instances() to check for SSO instances
- COMPLIANT if at least one SSO instance exists
- NON_COMPLIANT if no SSO instances found
- Encourages centralized identity management

**Remediation Guidance**:
```bash
# SSO must be enabled through console or Organizations API
# After enabling, configure permission sets:
aws sso-admin create-permission-set --instance-arn <instance-arn> --name ReadOnlyAccess

aws sso-admin attach-managed-policy-to-permission-set \
  --instance-arn <instance-arn> \
  --permission-set-arn <ps-arn> \
  --managed-policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess
```

#### Control 5.4: IAM User Inline Policy Restriction

| Config Rule | Resource Types | Description |
|-------------|----------------|-------------|
| `iam-user-no-inline-policies` | AWS::IAM::User | Ensures IAM users don't have inline policies |

**Assessment Logic**:
- Discovers all IAM users (global service, evaluated in us-east-1)
- Lists inline policies attached to each user
- COMPLIANT if inline policy list is empty
- NON_COMPLIANT if any inline policies exist
- Encourages use of managed policies for reusability

**Remediation Guidance**:
```bash
# Get inline policy document
aws iam get-user-policy --user-name <user> --policy-name <inline-policy> > policy.json

# Create managed policy from document
aws iam create-policy --policy-name <policy-name> --policy-document file://policy.json

# Attach managed policy to user
aws iam attach-user-policy --user-name <user> --policy-arn <policy-arn>

# Delete inline policy
aws iam delete-user-policy --user-name <user> --policy-name <inline-policy>
```

### Control 6: Access Control Management

**Purpose**: Use processes and tools to create, assign, manage, and revoke access credentials and privileges for user, administrator, and service accounts for enterprise assets and software.

#### Control 6.1: IAM Access Analyzer Enablement Verification

| Config Rule | Resource Types | Description |
|-------------|----------------|-------------|
| `iam-access-analyzer-enabled` | AWS::AccessAnalyzer::Analyzer | Validates IAM Access Analyzer is enabled in all active regions |

**Assessment Logic**:
- Regional service, evaluated in all active regions
- Lists analyzers in each region
- Checks for at least one analyzer with status='ACTIVE'
- COMPLIANT if active analyzer found in region
- NON_COMPLIANT if no active analyzers in region
- Detects resources shared with external entities

**Remediation Guidance**:
```bash
# Create analyzer in each region
aws accessanalyzer create-analyzer --analyzer-name account-analyzer --type ACCOUNT --region <region>

# Create in all regions
for region in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do
  aws accessanalyzer create-analyzer --analyzer-name account-analyzer --type ACCOUNT --region $region
done
```

#### Control 6.2: Permission Boundary Configuration Validation

| Config Rule | Resource Types | Description |
|-------------|----------------|-------------|
| `iam-permission-boundaries-check` | AWS::IAM::Role | Ensures permission boundaries are configured for roles with elevated privileges |

**Assessment Logic**:
- Discovers all IAM roles (global service, evaluated in us-east-1)
- Identifies roles with elevated privileges:
  - Roles with AdministratorAccess or PowerUserAccess
  - Roles with policies containing Action: "*"
  - Roles with AssumeRole permissions
- Checks if PermissionsBoundary field is set
- COMPLIANT if permission boundary configured for elevated privilege roles
- NON_COMPLIANT if no permission boundary on elevated privilege roles
- Prevents privilege escalation in delegated administration

**Remediation Guidance**:
```bash
# Create permission boundary policy
aws iam create-policy --policy-name DelegatedAdminBoundary --policy-document file://boundary.json

# Attach boundary to role
aws iam put-role-permissions-boundary --role-name <role> --permissions-boundary arn:aws:iam::<account>:policy/DelegatedAdminBoundary
```

#### Control 6.3: Service Control Policy Enablement Check

| Config Rule | Resource Types | Description |
|-------------|----------------|-------------|
| `organizations-scp-enabled-check` | AWS::::Account | Validates AWS Organizations Service Control Policies are enabled and in use |

**Assessment Logic**:
- Account-level check (global service, evaluated in us-east-1)
- Calls organizations.describe_organization() to check if account is in organization
- Checks if FeatureSet includes ALL or SERVICE_CONTROL_POLICY
- Lists SCPs to verify custom SCPs exist (beyond default FullAWSAccess)
- COMPLIANT if organization exists, SCPs enabled, and custom SCPs in use
- NON_COMPLIANT if not in organization, SCPs not enabled, or only default SCP
- Enforces organizational policies and guardrails

**Remediation Guidance**:
```bash
# Enable all features in Organizations
aws organizations enable-all-features

# Create custom SCP
aws organizations create-policy --name DenyRootUser --type SERVICE_CONTROL_POLICY --content file://scp.json

# Attach SCP to OU
aws organizations attach-policy --policy-id <policy-id> --target-id <ou-id>
```

#### Control 6.4: Cognito User Pool MFA Validation

| Config Rule | Resource Types | Description |
|-------------|----------------|-------------|
| `cognito-user-pool-mfa-enabled` | AWS::Cognito::UserPool | Ensures Cognito user pools have MFA enabled |

**Assessment Logic**:
- Discovers all Cognito user pools (regional service)
- Calls cognito-idp.describe_user_pool() to get MfaConfiguration
- COMPLIANT if MfaConfiguration is 'ON' or 'OPTIONAL'
- NON_COMPLIANT if MfaConfiguration is 'OFF'
- Enhances authentication security for applications

**Remediation Guidance**:
```bash
# Enable MFA for Cognito user pool
aws cognito-idp set-user-pool-mfa-config \
  --user-pool-id <pool-id> \
  --mfa-configuration ON \
  --software-token-mfa-configuration Enabled=true \
  --sms-mfa-configuration SmsConfiguration={SnsCallerArn=<sns-role-arn>}
```

#### Control 6.5: VPN Connection MFA Requirement Verification

| Config Rule | Resource Types | Description |
|-------------|----------------|-------------|
| `vpn-connection-mfa-enabled` | AWS::EC2::ClientVpnEndpoint | Validates Client VPN endpoints require MFA authentication |

**Assessment Logic**:
- Discovers all Client VPN endpoints (regional service)
- Checks AuthenticationOptions for MFA requirement
- Looks for:
  - directory-service-authentication with MFA
  - federated-authentication with MFA requirement
  - certificate-authentication with additional factor
- COMPLIANT if MFA is required for authentication
- NON_COMPLIANT if no MFA requirement found
- Ensures secure remote access to AWS resources

**Remediation Guidance**:
```bash
# Create Client VPN endpoint with AD authentication and MFA
aws ec2 create-client-vpn-endpoint \
  --client-cidr-block 10.0.0.0/16 \
  --server-certificate-arn <cert-arn> \
  --authentication-options Type=directory-service-authentication,ActiveDirectory={DirectoryId=<dir-id>} \
  --connection-log-options Enabled=true,CloudwatchLogGroup=<log-group>

# Note: MFA enforcement depends on authentication method (AD, SAML, or certificate)
```

### Control 3.10: Encrypt Sensitive Data in Transit

**Purpose**: Encrypt sensitive data in transit between network locations.

| Config Rule | Resource Types | Description |
|-------------|----------------|-------------|
| `api-gw-ssl-enabled` | AWS::ApiGateway::Stage | Ensures API Gateway stages use SSL/TLS |
| `alb-http-to-https-redirection-check` | AWS::ElasticLoadBalancingV2::LoadBalancer | Ensures ALB redirects HTTP to HTTPS |
| `elb-tls-https-listeners-only` | AWS::ElasticLoadBalancing::LoadBalancer | Ensures ELB uses only TLS/HTTPS listeners |
| `s3-bucket-ssl-requests-only` | AWS::S3::Bucket | Ensures S3 buckets require SSL requests |
| `redshift-require-tls-ssl` | AWS::Redshift::Cluster | Ensures Redshift requires TLS/SSL connections |
| `elasticsearch-https-required` | AWS::Elasticsearch::Domain | Ensures Elasticsearch domains require HTTPS |
| `cloudfront-viewer-policy-https` | AWS::CloudFront::Distribution | Ensures CloudFront uses HTTPS viewer policy |

**Assessment Logic**:
- Validates SSL/TLS configuration across all services
- Checks for proper certificate management
- Ensures encryption in transit for data flows

### Control 3.11: Encrypt Sensitive Data at Rest

**Purpose**: Encrypt sensitive data at rest on all enterprise assets.

| Config Rule | Resource Types | Description |
|-------------|----------------|-------------|
| `encrypted-volumes` | AWS::EC2::Volume | Ensures EBS volumes are encrypted |
| `rds-storage-encrypted` | AWS::RDS::DBInstance | Ensures RDS instances have encrypted storage |
| `s3-default-encryption-kms` | AWS::S3::Bucket | Ensures S3 buckets have default KMS encryption |
| `dynamodb-table-encrypted-kms` | AWS::DynamoDB::Table | Ensures DynamoDB tables are encrypted with KMS |
| `backup-recovery-point-encrypted` | AWS::Backup::RecoveryPoint | Ensures backup recovery points are encrypted |
| `elasticsearch-encrypted-at-rest` | AWS::Elasticsearch::Domain | Ensures Elasticsearch domains are encrypted at rest |
| `redshift-cluster-kms-enabled` | AWS::Redshift::Cluster | Ensures Redshift clusters use KMS encryption |
| `secretsmanager-secret-encrypted-with-kms-key` | AWS::SecretsManager::Secret | Ensures secrets are encrypted with KMS |

**Assessment Logic**:
- Validates encryption configuration for all data stores
- Checks for proper KMS key usage
- Ensures encryption at rest for backups and snapshots

### Control 7.1: Establish and Maintain a Vulnerability Management Process

**Purpose**: Establish and maintain a vulnerability management process.

| Config Rule | Resource Types | Description |
|-------------|----------------|-------------|
| `ecr-private-image-scanning-enabled` | AWS::ECR::Repository | Ensures ECR repositories have image scanning enabled |
| `guardduty-enabled-centralized` | AWS::GuardDuty::Detector | Ensures GuardDuty is enabled and centralized |
| `ec2-managedinstance-patch-compliance-status-check` | AWS::EC2::Instance | Ensures EC2 instances are compliant with patch management |
| `inspector-assessment-target-exists` | AWS::Inspector::AssessmentTarget | Ensures Inspector assessment targets exist |

**Assessment Logic**:
- Validates vulnerability scanning capabilities
- Checks for threat detection services
- Ensures patch management compliance

### Control 8.2: Collect Audit Logs

**Purpose**: Collect audit logs from enterprise assets and software to support security monitoring, incident response, and compliance requirements.

| Config Rule | Resource Types | Description |
|-------------|----------------|-------------|
| `route53-query-logging-enabled` | AWS::Route53::HostedZone | Validates Route 53 hosted zones have query logging enabled to track DNS queries for security investigations |
| `alb-access-logs-enabled` | AWS::ElasticLoadBalancingV2::LoadBalancer | Ensures Application Load Balancers have access logging enabled to analyze traffic patterns |
| `cloudfront-access-logs-enabled` | AWS::CloudFront::Distribution | Validates CloudFront distributions have access logging enabled to track content delivery requests |
| `cloudwatch-log-retention-check` | AWS::Logs::LogGroup | Ensures CloudWatch log groups have appropriate retention periods (minimum 90 days) for compliance |
| `cloudtrail-insights-enabled` | AWS::CloudTrail::Trail | Validates CloudTrail Insights is enabled for automatic anomaly detection of API activity |
| `config-recording-all-resources` | AWS::Config::ConfigurationRecorder | Ensures AWS Config records all resource types to track configuration changes |
| `waf-logging-enabled` | AWS::WAFv2::WebACL | Validates WAF web ACLs have logging enabled to capture web application firewall events |
| `elb-logging-enabled` | AWS::ElasticLoadBalancing::LoadBalancer | Ensures Classic Load Balancers have access logging enabled |
| `rds-logging-enabled` | AWS::RDS::DBInstance | Validates RDS instances have appropriate database logging enabled |
| `elasticsearch-logs-to-cloudwatch` | AWS::Elasticsearch::Domain | Ensures Elasticsearch domains send logs to CloudWatch |
| `codebuild-project-logging-enabled` | AWS::CodeBuild::Project | Validates CodeBuild projects capture build logs |
| `redshift-cluster-configuration-check` | AWS::Redshift::Cluster | Ensures Redshift clusters have audit logging enabled |
| `wafv2-logging-enabled` | AWS::WAFv2::WebACL | Ensures WAFv2 web ACLs have logging enabled |

**Assessment Logic**:
- **DNS Query Logging**: Validates Route 53 hosted zones have query logging configurations pointing to CloudWatch Logs
- **Load Balancer Logging**: Checks ALB and Classic ELB access_logs.s3.enabled attribute and validates S3 bucket configuration
- **CDN Logging**: Validates CloudFront distribution Logging.Enabled field and S3 bucket configuration
- **Log Retention**: Checks CloudWatch log groups have retentionInDays set to at least 90 days (configurable parameter)
- **CloudTrail Insights**: Validates at least one active trail has InsightSelectors configured for anomaly detection
- **Config Recording**: Ensures configuration recorders have allSupported=true and recording status is active
- **WAF Logging**: Validates WAF web ACLs (both REGIONAL and CLOUDFRONT scopes) have logging configurations with destination ARNs
- **Multi-Region Support**: Regional services (ALB, CloudWatch Logs, AWS Config, WAF) are evaluated in all active regions
- **Global Services**: Route 53 and CloudFront are evaluated in us-east-1 only

**Remediation Guidance**:
- Route 53: Create CloudWatch Logs log group and configure query logging for each hosted zone
- ALB/ELB: Enable access logs with S3 bucket destination and appropriate bucket policy
- CloudFront: Enable logging in distribution settings with S3 bucket and optional prefix
- CloudWatch Logs: Set retention policy using `put-retention-policy` API (recommended: 90-365 days)
- CloudTrail: Enable Insights using `put-insight-selectors` API (note: additional charges apply)
- AWS Config: Configure recorder with allSupported=true and start recording
- WAF: Create Kinesis Data Firehose delivery stream (prefix: "aws-waf-logs-") and configure logging

## IG3 - Advanced Security

### Control 3.14: Log Sensitive Data Access

**Purpose**: Log sensitive data access including modification and disposal.

| Config Rule | Resource Types | Description |
|-------------|----------------|-------------|
| `api-gw-execution-logging-enabled` | AWS::ApiGateway::Stage | Ensures API Gateway execution logging is enabled |
| `cloudtrail-s3-dataevents-enabled` | AWS::CloudTrail::Trail | Ensures CloudTrail logs S3 data events |
| `multi-region-cloudtrail-enabled` | AWS::CloudTrail::Trail | Ensures multi-region CloudTrail is enabled |
| `cloud-trail-cloud-watch-logs-enabled` | AWS::CloudTrail::Trail | Ensures CloudTrail sends logs to CloudWatch |
| `s3-bucket-logging-enabled` | AWS::S3::Bucket | Ensures S3 bucket access logging is enabled |
| `vpc-flow-logs-enabled` | AWS::EC2::VPC | Ensures VPC Flow Logs are enabled |

**Assessment Logic**:
- Validates comprehensive logging configuration
- Checks for data access event logging
- Ensures log centralization and retention

### Control 12.8: Establish and Maintain Network Segmentation

**Purpose**: Establish and maintain network segmentation for all enterprise assets.

| Config Rule | Resource Types | Description |
|-------------|----------------|-------------|
| `api-gw-associated-with-waf` | AWS::ApiGateway::Stage | Ensures API Gateway is associated with WAF |
| `vpc-sg-open-only-to-authorized-ports` | AWS::EC2::SecurityGroup | Ensures security groups open only authorized ports |
| `no-unrestricted-route-to-igw` | AWS::EC2::RouteTable | Ensures no unrestricted routes to Internet Gateway |
| `subnet-auto-assign-public-ip-disabled` | AWS::EC2::Subnet | Ensures subnets don't auto-assign public IPs |
| `nacl-no-unrestricted-ssh-rdp` | AWS::EC2::NetworkAcl | Ensures NACLs don't allow unrestricted SSH/RDP |

**Assessment Logic**:
- Validates network segmentation controls
- Checks for proper firewall configurations
- Ensures restricted network access patterns

### Control 13.1: Centralize Security Event Alerting

**Purpose**: Centralize security event alerting across the enterprise.

| Config Rule | Resource Types | Description |
|-------------|----------------|-------------|
| `restricted-incoming-traffic` | AWS::EC2::SecurityGroup | Ensures security groups restrict incoming traffic |
| `incoming-ssh-disabled` | AWS::EC2::SecurityGroup | Ensures SSH access is properly restricted |
| `guardduty-non-archived-findings` | AWS::GuardDuty::Detector | Ensures GuardDuty findings are not archived |
| `securityhub-enabled` | AWS::SecurityHub::Hub | Ensures Security Hub is enabled for centralization |

**Assessment Logic**:
- Validates centralized security monitoring
- Checks for proper alerting mechanisms
- Ensures security event correlation

## Bonus Security Rules

Beyond the core CIS Controls rules, the framework includes additional security enhancements:

### Enhanced Logging Security
| Config Rule | Resource Types | Description |
|-------------|----------------|-------------|
| `cloudwatch-log-group-encrypted` | AWS::Logs::LogGroup | Ensures CloudWatch log groups are encrypted |
| `route53-query-logging-enabled` | AWS::Route53::HostedZone | Validates Route 53 DNS query logging is enabled |
| `alb-access-logs-enabled` | AWS::ElasticLoadBalancingV2::LoadBalancer | Ensures ALB access logging is enabled |
| `cloudfront-access-logs-enabled` | AWS::CloudFront::Distribution | Validates CloudFront access logging is enabled |
| `waf-logging-enabled` | AWS::WAFv2::WebACL | Ensures WAF web ACL logging is enabled |

### Network Security Enhancements  
| Config Rule | Resource Types | Description |
|-------------|----------------|-------------|
| `incoming-ssh-disabled` | AWS::EC2::SecurityGroup | Enhanced SSH access restrictions |
| `restricted-incoming-traffic` | AWS::EC2::SecurityGroup | Advanced network access controls |

### Data Encryption Enhancements
| Config Rule | Resource Types | Description |
|-------------|----------------|-------------|
| `kinesis-stream-encrypted` | AWS::Kinesis::Stream | Ensures Kinesis streams are encrypted |
| `sqs-queue-encrypted-kms` | AWS::SQS::Queue | Ensures SQS queues use KMS encryption |

**Business Value**: These bonus rules provide additional security value beyond CIS Controls requirements, enhancing the overall security posture with minimal additional overhead. The audit logging rules (Control 8.2) provide comprehensive visibility across AWS services for security investigations and compliance.

## Config Rule Details

### Rule Parameters

Many Config rules accept parameters that customize their behavior:

```yaml
# Example: IAM Password Policy
iam-password-policy:
  parameters:
    RequireUppercaseCharacters: true
    RequireLowercaseCharacters: true
    RequireNumbers: true
    RequireSymbols: true
    MinimumPasswordLength: 14
    PasswordReusePrevention: 24
    MaxPasswordAge: 90
```

### Evaluation Triggers

Config rules are triggered by:
- **Configuration Changes**: When resource configurations change
- **Periodic**: At regular intervals (24 hours by default)
- **On-Demand**: When manually triggered

### Compliance Status

Each resource evaluation results in one of these statuses:
- **COMPLIANT**: Resource meets the rule requirements
- **NON_COMPLIANT**: Resource violates the rule requirements
- **NOT_APPLICABLE**: Rule doesn't apply to this resource
- **INSUFFICIENT_DATA**: Not enough information to evaluate

## Resource Type Coverage

### Compute Services
- **EC2**: Instances, volumes, security groups, network interfaces
- **Lambda**: Functions, layers, event source mappings
- **Elastic Beanstalk**: Applications, environments

### Storage Services
- **S3**: Buckets, bucket policies, access points
- **EBS**: Volumes, snapshots
- **EFS**: File systems, mount targets

### Database Services
- **RDS**: DB instances, clusters, snapshots
- **DynamoDB**: Tables, global tables
- **Redshift**: Clusters, parameter groups
- **ElastiCache**: Clusters, replication groups

### Networking Services
- **VPC**: VPCs, subnets, route tables, NACLs
- **ELB**: Classic load balancers, application load balancers
- **CloudFront**: Distributions, origins
- **API Gateway**: APIs, stages, deployments

### Security Services
- **IAM**: Users, roles, policies, groups
- **KMS**: Keys, aliases, grants
- **Secrets Manager**: Secrets, rotation configurations
- **GuardDuty**: Detectors, findings
- **Security Hub**: Hubs, standards subscriptions

### Management Services
- **CloudTrail**: Trails, event data stores
- **CloudWatch**: Alarms, log groups, metrics
- **Systems Manager**: Managed instances, patch compliance
- **Organizations**: Accounts, organizational units

## Assessment Logic

### Resource Discovery

For each Config rule, the assessment tool:

1. **Identifies Resource Types**: Determines which AWS resource types to evaluate
2. **Discovers Resources**: Uses AWS APIs to find all resources of the specified types
3. **Filters by Region**: Evaluates resources in the specified regions
4. **Applies Rule Logic**: Executes the Config rule evaluation logic

### Evaluation Process

```python
def evaluate_config_rule(rule_name, resource_type, region):
    # 1. Discover resources
    resources = discover_resources(resource_type, region)
    
    # 2. For each resource
    for resource in resources:
        # 3. Apply rule logic
        compliance_result = apply_rule_logic(rule_name, resource)
        
        # 4. Generate result
        yield ComplianceResult(
            resource_id=resource.id,
            resource_type=resource_type,
            compliance_status=compliance_result.status,
            evaluation_reason=compliance_result.reason,
            config_rule_name=rule_name,
            region=region,
            timestamp=datetime.now()
        )
```

### Scoring Calculation

Compliance scores are calculated as:

```
Control Score = (Compliant Resources / Total Resources) × 100
IG Score = Weighted Average of Control Scores
Overall Score = Weighted Average of IG Scores
```

### Error Handling

The assessment tool handles various error conditions:

- **Permission Errors**: Mark as "INSUFFICIENT_PERMISSIONS"
- **Service Unavailable**: Mark as "ERROR" with details
- **Resource Not Found**: Mark as "NOT_APPLICABLE"
- **API Throttling**: Implement exponential backoff and retry

### Remediation Guidance

Each non-compliant finding includes:

1. **Specific Steps**: Detailed remediation instructions
2. **AWS CLI Commands**: Ready-to-use command examples
3. **Console Links**: Direct links to AWS Console
4. **Documentation**: Links to relevant AWS documentation
5. **Priority**: Risk-based priority (HIGH, MEDIUM, LOW)

This comprehensive mapping ensures that the assessment tool provides accurate, actionable compliance evaluation based on AWS Config rule specifications while maintaining independence from the AWS Config service itself.