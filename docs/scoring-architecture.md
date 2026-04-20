# Rules, Checks & Scoring Architecture — Reusable Reference

This document captures the complete rules catalog, scoring logic, severity/weight system,
and priority determination used by the AWS CIS Assessment Framework. It is designed to be
used as a reference for reproducing a similar weighted compliance scoring system in another project.

---

## 1. Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                    YAML Config Files                            │
│  cis_controls_ig1.yaml (122 rules, 24 controls)                │
│  cis_controls_ig2.yaml (75 rules, 12 controls)                 │
│  cis_controls_ig3.yaml (13 rules, 4 controls)                  │
│  Total: 199 unique rules across 40 controls                    │
└──────────────┬──────────────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Scoring Engine                                │
│  - Control weights (per-control importance multiplier)          │
│  - IG weights (per-group importance multiplier)                 │
│  - Weighted average compliance calculation                      │
│  - Remediation priority determination                           │
└──────────────┬──────────────────────────────────────────────────┘
               │
               ▼
┌─────────────────────────────────────────────────────────────────┐
│                    Visual Severity Layer                         │
│  - Compliance grade (A/B/C/D/F)                                │
│  - Risk level (LOW/MEDIUM/HIGH/CRITICAL)                       │
│  - Status color (green/orange/dark-orange/red)                  │
│  - Severity badge (low/medium/high by finding count)            │
└─────────────────────────────────────────────────────────────────┘
```

---

## 2. Weight System

### 2.1 Control Weights

Each CIS control has a weight that reflects its security importance.
Default weight is `1.0`. Higher weights amplify the control's impact on the overall score.

```python
control_weights = {
    '1.1':  1.0,   # Asset Inventory — foundational
    '3.3':  1.5,   # Data Access Control — critical (highest weight)
    '3.10': 1.4,   # Encryption in Transit — critical
    '3.11': 1.4,   # Encryption at Rest — critical
    '3.14': 1.2,   # Sensitive Data Logging — important
    '4.1':  1.2,   # Secure Configuration — important
    '5.2':  1.3,   # Password Management — important
    '7.1':  1.1,   # Vulnerability Management — important
    '12.8': 1.3,   # Network Segmentation — important
    '13.1': 1.2,   # Network Monitoring — important
    # All other controls default to 1.0
}
```

Weight tiers:
| Weight | Tier | Controls |
|--------|------|----------|
| 1.5 | Critical | 3.3 (Data Access Control) |
| 1.4 | Critical | 3.10 (Encryption in Transit), 3.11 (Encryption at Rest) |
| 1.3 | Important | 5.2 (Password Mgmt), 12.8 (Network Segmentation) |
| 1.2 | Important | 4.1 (Secure Config), 3.14 (Sensitive Data Logging), 13.1 (Network Monitoring) |
| 1.1 | Important | 7.1 (Vulnerability Management) |
| 1.0 | Standard | All other controls (default) |

### 2.2 Implementation Group Weights

Higher IGs represent more advanced security and carry more weight in the overall score.

```python
ig_weights = {
    'IG1': 1.0,   # Essential cyber hygiene — baseline
    'IG2': 1.5,   # Enhanced security — regulatory compliance
    'IG3': 2.0,   # Advanced security — high-risk environments
}
```

### 2.3 How Weights Are Used

The scoring engine uses a **weighted average** at two levels:

1. **IG-level score** = weighted average of control scores within the IG
   ```
   IG_score = Σ(control_compliance% × control_weight) / Σ(control_weight)
   ```

2. **Overall score** = weighted average of IG scores
   ```
   Overall_score = Σ(IG_compliance% × IG_weight) / Σ(IG_weight)
   ```

3. **AWS Config style score** (unweighted alternative) = simple ratio
   ```
   Config_score = total_compliant_resources / total_resources × 100
   ```

---

## 3. Scoring Formulas

### 3.1 Control Score

```python
def calculate_control_score(control_id, rule_results):
    # Filter out ERROR results (only score COMPLIANT, NON_COMPLIANT, NOT_APPLICABLE)
    scorable = [r for r in rule_results if r.status in [COMPLIANT, NON_COMPLIANT, NOT_APPLICABLE]]
    
    total = len(scorable)
    compliant = count(r for r in scorable if r.status == COMPLIANT)
    
    compliance_pct = (compliant / total) * 100 if total > 0 else 0.0
    
    # A control is considered "compliant" if >= 80%
    is_compliant = compliance_pct >= 80.0
```

### 3.2 IG Score (Weighted)

```python
def calculate_ig_score(ig_name, control_scores):
    total_weighted = 0.0
    total_weight = 0.0
    
    for control_id, score in control_scores.items():
        weight = control_weights.get(control_id, 1.0)
        total_weighted += score.compliance_pct * weight
        total_weight += weight
    
    ig_pct = total_weighted / total_weight if total_weight > 0 else 0.0
```

### 3.3 Overall Score (Weighted)

```python
def calculate_overall_score(ig_scores):
    total_weighted = 0.0
    total_weight = 0.0
    
    for ig_name, ig_score in ig_scores.items():
        weight = ig_weights.get(ig_name, 1.0)  # IG1=1.0, IG2=1.5, IG3=2.0
        total_weighted += ig_score.compliance_pct * weight
        total_weight += weight
    
    overall = total_weighted / total_weight if total_weight > 0 else 0.0
```

---

## 4. Visual Severity Thresholds

### 4.1 Compliance Grade

| Percentage | Grade |
|-----------|-------|
| ≥ 95% | A |
| ≥ 85% | B |
| ≥ 75% | C |
| ≥ 60% | D |
| < 60% | F |

### 4.2 Risk Level

| Percentage | Risk Level |
|-----------|-----------|
| ≥ 90% | LOW |
| ≥ 75% | MEDIUM |
| ≥ 50% | HIGH |
| < 50% | CRITICAL |

### 4.3 Status Color

| Percentage | Color | Hex |
|-----------|-------|-----|
| ≥ 90% | Green | #27ae60 |
| ≥ 75% | Orange | #f39c12 |
| ≥ 50% | Dark Orange | #e67e22 |
| < 50% | Red | #e74c3c |

### 4.4 Status Class (CSS)

| Percentage | Class |
|-----------|-------|
| ≥ 95% | excellent |
| ≥ 80% | good |
| ≥ 60% | fair |
| ≥ 40% | poor |
| < 40% | critical |

### 4.5 Severity Badge (per control, based on non-compliant finding count)

| Non-Compliant Findings | Badge |
|------------------------|-------|
| > 10 | high |
| > 3 | medium |
| ≤ 3 | low |

---

## 5. Remediation Priority Determination

Priority is determined by combining control weight and affected resource count:

```python
control_weight = control_weights.get(control_id, 1.0)
affected_resources = count(non_compliant_findings_for_rule)

if control_weight >= 1.4 or affected_resources >= 10:
    priority = "HIGH"
elif control_weight >= 1.2 or affected_resources >= 5:
    priority = "MEDIUM"
else:
    priority = "LOW"
```

| Condition | Priority |
|-----------|----------|
| Weight ≥ 1.4 OR ≥ 10 affected resources | HIGH |
| Weight ≥ 1.2 OR ≥ 5 affected resources | MEDIUM |
| Otherwise | LOW |

### 5.1 Effort Estimation

```python
if affected_resources <= 5:    base = "Low"
elif affected_resources <= 20: base = "Medium"
else:                          base = "High"

# Complex rules bump effort up one level
complex_rules = ['iam-password-policy', 'vpc-sg-open-only-to-authorized-ports', 
                 'multi-region-cloudtrail-enabled']
```

---

## 6. Coverage Metrics (Cumulative)

CIS Controls v8.1 uses cumulative Implementation Groups:
- IG1: 56 total safeguards
- IG2: 74 total safeguards (includes all IG1)
- IG3: 153 total safeguards (includes all IG1 + IG2)

Current implementation coverage:
- IG1: 24/56 safeguards = 42.9%
- IG2: 27/74 safeguards = 36.5% (cumulative: IG1 + IG2 controls)
- IG3: 30/153 safeguards = 19.6% (cumulative: IG1 + IG2 + IG3 controls)

---

## 7. Complete Rules Catalog

### 7.1 IG1 — Essential Cyber Hygiene (122 unique rules, 24 controls)

| Control | Title | Weight | Rules | Rule Names |
|---------|-------|--------|-------|------------|
| 1.1 | Establish and Maintain Detailed Enterprise Asset Inventory | 1.0 | 12 | eip-attached, ec2-stopped-instance, vpc-network-acl-unused-check, ec2-instance-managed-by-systems-manager, ec2-security-group-attached-to-eni, ssm-inventory-enabled, config-enabled-all-regions, ami-inventory-tracking, lambda-runtime-inventory, iam-user-inventory-check, asset-tagging-compliance, unauthorized-asset-detection |
| 1.5 | Use a Passive Asset Discovery Tool | 1.0 | 1 | root-account-hardware-mfa-enabled |
| 2.2 | Ensure Authorized Software is Currently Supported | 1.0 | 5 | elastic-beanstalk-managed-updates-enabled, ecs-fargate-latest-platform-version, ec2-os-version-supported, rds-engine-version-supported, lambda-runtime-supported |
| 2.2.1 | Ensure Authorized Software is Currently Supported | 1.0 | 1 | opensearch-in-vpc-only |
| 3.3 | Configure Data Access Control Lists | **1.5** | 39 | s3-bucket-ssl-requests-only, s3-bucket-server-side-encryption-enabled, s3-bucket-logging-enabled, iam-root-access-key-check, iam-user-unused-credentials-check, iam-customer-policy-blocked-kms-actions, iam-inline-policy-blocked-kms-actions, ebs-snapshot-public-restorable-check, rds-snapshots-public-prohibited, rds-instance-public-access-check, redshift-cluster-public-access-check, s3-bucket-level-public-access-prohibited, iam-user-mfa-enabled, s3-bucket-public-read-prohibited, ec2-instance-no-public-ip, autoscaling-launch-config-public-ip-disabled, efs-access-point-enforce-root-directory, ec2-managedinstance-association-compliance-status-check, emr-kerberos-enabled, lambda-inside-vpc, ecs-task-definition-user-for-host-mode-check, iam-group-has-users-check, iam-policy-no-statements-with-full-access, iam-user-no-policies-check, ssm-document-not-public, iam-policy-no-statements-with-admin-access, iam-no-inline-policy-check, iam-user-group-membership-check, dms-replication-not-public, elasticsearch-in-vpc-only, ec2-instances-in-vpc, emr-master-no-public-ip, lambda-function-public-access-prohibited, sagemaker-notebook-no-direct-internet-access, subnet-auto-assign-public-ip-disabled, s3-account-level-public-access-blocks-periodic, s3-bucket-public-write-prohibited, ec2-imdsv2-check, ec2-instance-profile-attached |
| 3.4 | Enforce Data Retention | 1.0 | 3 | s3-bucket-versioning-enabled, s3-version-lifecycle-policy-check, cw-loggroup-retention-period-check |
| 3.10 | Encrypt Sensitive Data in Transit | **1.4** | 8 | alb-http-to-https-redirection-check, elb-tls-https-listeners-only, rds-ssl-connection-required, api-gateway-ssl-enabled, redshift-require-tls-ssl, sns-encrypted-kms, sqs-queue-encrypted, cloudtrail-s3-dataevents-enabled |
| 3.11 | Encrypt Sensitive Data at Rest | **1.4** | 6 | cloudwatch-log-group-encrypted, ebs-encryption-by-default, rds-storage-encrypted, efs-encrypted-check, dynamodb-table-encrypted-kms, s3-default-encryption-kms |
| 3.12 | Segment Data Processing and Storage Based on Sensitivity | 1.0 | 2 | data-classification-tagging, s3-bucket-classification-tags |
| 4.1 | Establish and Maintain a Secure Configuration Process | **1.2** | 8 | account-part-of-organizations, ec2-volume-inuse-check, redshift-cluster-maintenancesettings-check, secretsmanager-rotation-enabled-check, ecs-task-definition-nonroot-user, access-keys-rotated, config-conformance-pack-deployed, securityhub-standards-enabled |
| 5.2 | Use Unique Passwords | **1.3** | 1 | iam-password-policy |
| 5.3 | Disable Dormant Accounts | 1.0 | 3 | sso-enabled-check, identity-center-configured, iam-user-last-access-check |
| 6.2 | Establish and Maintain a Secure Network Architecture | 1.0 | 4 | guardduty-enabled-centralized, inspector-enabled, macie-enabled, iam-access-analyzer-enabled |
| 6.5 | Require MFA for Administrative Access | 1.0 | 3 | iam-admin-mfa-required, cognito-mfa-enabled, vpn-mfa-enabled |
| 7.1 | Establish and Maintain a Vulnerability Management Process | **1.1** | 3 | ssm-patch-manager-enabled, ssm-patch-baseline-configured, ec2-patch-compliance-status |
| 7.5 | Perform Automated Vulnerability Scans | 1.0 | 1 | inspector-assessment-enabled |
| 8.2 | Collect Audit Logs | 1.0 | 5 | cloudtrail-enabled, vpc-flow-logs-enabled, elb-logging-enabled, cloudfront-accesslogs-enabled, wafv2-logging-enabled |
| 8.8 | Collect Command-Line Audit Logs | 1.0 | 1 | securityhub-enabled |
| 11.2 | Perform Automated Backups | 1.0 | 14 | ebs-optimized-instance, dynamodb-in-backup-plan, ebs-in-backup-plan, efs-in-backup-plan, db-instance-backup-enabled, redshift-backup-enabled, dynamodb-pitr-enabled, elasticache-redis-cluster-automatic-backup-check, s3-bucket-replication-enabled, backup-plan-min-frequency-and-min-retention-check, backup-vault-access-policy-check, backup-selection-resource-coverage-check, rds-backup-retention-check, route53-query-logging-enabled |
| 11.3 | Protect Recovery Data | 1.0 | 2 | backup-vault-encryption-enabled, backup-vault-lock-enabled |
| 11.4 | Establish and Maintain an Isolated Instance of Recovery Data | 1.0 | 1 | backup-cross-region-copy-enabled |
| 12.2 | Establish and Maintain a Secure Network Architecture | 1.0 | 2 | vpc-default-security-group-closed, restricted-ssh |
| 12.4 | Establish and Maintain Architecture Diagram(s) | 1.0 | 1 | ssm-session-manager-enabled |
| 13.6 | Deny Communications with Known Malicious IP Addresses | 1.0 | 2 | network-firewall-deployed, route53-resolver-firewall-enabled |

### 7.2 IG2 — Enhanced Security / Regulatory Compliance (75 unique rules, 12 controls)

| Control | Title | Weight | Rules | Rule Names |
|---------|-------|--------|-------|------------|
| 3.3 | Configure Data Access Control Lists | **1.5** | 5 | redshift-enhanced-vpc-routing-enabled, restricted-common-ports, codebuild-project-environment-privileged-check, codebuild-project-envvar-awscred-check, codebuild-project-source-repo-url-check |
| 3.10 | Encrypt Sensitive Data in Transit | **1.4** | 9 | api-gw-ssl-enabled, alb-http-to-https-redirection-check, elb-tls-https-listeners-only, s3-bucket-ssl-requests-only, redshift-require-tls-ssl, elb-acm-certificate-required, elbv2-acm-certificate-required, opensearch-https-required, opensearch-node-to-node-encryption-check |
| 3.11 | Encrypt Sensitive Data at Rest | **1.4** | 20 | secretsmanager-using-cmk, sns-encrypted-kms, sqs-queue-encrypted-kms, kinesis-stream-encrypted, elasticsearch-encrypted-at-rest, encrypted-volumes, rds-storage-encrypted, s3-default-encryption-kms, dynamodb-table-encrypted-kms, backup-recovery-point-encrypted, efs-encrypted-check, cloudwatch-log-group-encrypted, cloud-trail-encryption-enabled, ec2-ebs-encryption-by-default, rds-snapshot-encrypted, opensearch-encrypted-at-rest, redshift-cluster-kms-enabled, sagemaker-endpoint-configuration-kms-key-configured, sagemaker-notebook-instance-kms-key-configured, codebuild-project-artifact-encryption |
| 4.1 | Establish and Maintain a Secure Configuration Process | **1.2** | 6 | acm-certificate-expiration-check, iam-max-session-duration-check, security-group-default-rules-check, vpc-dns-resolution-enabled, rds-default-admin-check, ec2-instance-profile-least-privilege |
| 5.1 | Establish and Maintain an Inventory of Service Accounts | 1.0 | 1 | iam-service-account-inventory-check |
| 5.2 | Centralize Account Management | **1.3** | 3 | iam-admin-policy-attached-to-role-check, sso-enabled-check, iam-user-no-inline-policies |
| 5.5 | Use Unique Passwords | 1.0 | 3 | mfa-enabled-for-iam-console-access, root-account-mfa-enabled, iam-user-unused-credentials-check |
| 6.1 | Establish an Access Granting Process | 1.0 | 5 | iam-access-analyzer-enabled, iam-permission-boundaries-check, organizations-scp-enabled-check, cognito-user-pool-mfa-enabled, vpn-connection-mfa-enabled |
| 8.2 | Collect Audit Logs | 1.0 | 13 | elasticsearch-logs-to-cloudwatch, elb-logging-enabled, rds-logging-enabled, wafv2-logging-enabled, codebuild-project-logging-enabled, redshift-cluster-configuration-check, route53-query-logging-enabled, alb-access-logs-enabled, cloudfront-access-logs-enabled, cloudwatch-log-retention-check, cloudtrail-insights-enabled, config-recording-all-resources, waf-logging-enabled |
| 11.3 | Establish and Maintain Data Recovery Process — Advanced | 1.0 | 3 | backup-vault-lock-check, backup-report-plan-exists-check, backup-restore-testing-plan-exists-check |
| 11.4 | Establish and Maintain an Isolated Instance of Recovery Data | 1.0 | 2 | elb-deletion-protection-enabled, rds-instance-deletion-protection-enabled |
| 12.2 | Establish and Maintain a Secure Network Architecture | 1.0 | 6 | elb-cross-zone-load-balancing-enabled, elbv2-multiple-az, rds-cluster-multi-az-enabled, rds-multi-az-support, vpc-vpn-2-tunnels-up, dynamodb-autoscaling-enabled |

### 7.3 IG3 — Advanced Security / High-Risk Environments (13 unique rules, 4 controls)

| Control | Title | Weight | Rules | Rule Names |
|---------|-------|--------|-------|------------|
| 3.14 | Log Sensitive Data Access | **1.2** | 4 | api-gw-execution-logging-enabled, cloudtrail-s3-dataevents-enabled, multi-region-cloudtrail-enabled, cloud-trail-cloud-watch-logs-enabled |
| 7.1 | Establish and Maintain a Vulnerability Management Process | **1.1** | 3 | ecr-private-image-scanning-enabled, guardduty-enabled-centralized, ec2-managedinstance-patch-compliance-status-check |
| 12.8 | Establish and Maintain Dedicated Computing Resources for All Administrative Work | **1.3** | 3 | api-gw-associated-with-waf, vpc-sg-open-only-to-authorized-ports, no-unrestricted-route-to-igw |
| 13.1 | Centralize Security Event Alerting | **1.2** | 3 | restricted-incoming-traffic, incoming-ssh-disabled, vpc-flow-logs-enabled |

---

## 8. Security Domain Summary

Grouping controls by security domain shows where the assessment focuses:

| Domain | Controls | Total Rules | Key Focus |
|--------|----------|-------------|-----------|
| Data Protection (3.x) | 3.3, 3.4, 3.10, 3.11, 3.12, 3.14 | ~90 | Access control, encryption, data classification, audit logging |
| Identity & Access (5.x, 6.x) | 5.1, 5.2, 5.3, 5.5, 6.1, 6.2, 6.5 | ~28 | IAM, MFA, SSO, password policy, access analyzer |
| Secure Configuration (4.1) | 4.1 | ~14 | Config management, patching, rotation, hardening |
| Asset Management (1.x, 2.x) | 1.1, 1.5, 2.2, 2.2.1 | ~19 | Inventory, software currency, discovery |
| Vulnerability Management (7.x) | 7.1, 7.5 | ~7 | Patching, scanning, GuardDuty, Inspector |
| Audit & Logging (8.x) | 8.2, 8.8 | ~19 | CloudTrail, VPC Flow Logs, ELB/CloudFront/WAF logs |
| Backup & Recovery (11.x) | 11.2, 11.3, 11.4 | ~22 | Backup plans, vault security, cross-region copy |
| Network Security (12.x, 13.x) | 12.2, 12.4, 12.8, 13.1, 13.6 | ~17 | Security groups, WAF, network firewall, flow logs |

---

## 9. AWS Resource Types Covered

The assessment evaluates these AWS resource types:

| Resource Type | Example Rules |
|--------------|---------------|
| AWS::EC2::Instance | ec2-instance-managed-by-systems-manager, ec2-imdsv2-check, ec2-instance-no-public-ip |
| AWS::S3::Bucket | s3-bucket-ssl-requests-only, s3-default-encryption-kms, s3-bucket-public-read-prohibited |
| AWS::IAM::User | iam-user-mfa-enabled, iam-user-unused-credentials-check, access-keys-rotated |
| AWS::IAM::Policy | iam-policy-no-statements-with-admin-access, iam-customer-policy-blocked-kms-actions |
| AWS::IAM::Role | iam-max-session-duration-check, iam-permission-boundaries-check |
| AWS::RDS::DBInstance | rds-storage-encrypted, rds-instance-public-access-check, rds-ssl-connection-required |
| AWS::DynamoDB::Table | dynamodb-table-encrypted-kms, dynamodb-in-backup-plan, dynamodb-autoscaling-enabled |
| AWS::Lambda::Function | lambda-inside-vpc, lambda-function-public-access-prohibited, lambda-runtime-supported |
| AWS::EFS::FileSystem | efs-encrypted-check, efs-in-backup-plan |
| AWS::ElasticLoadBalancingV2::LoadBalancer | alb-http-to-https-redirection-check, elb-logging-enabled |
| AWS::CloudTrail::Trail | cloudtrail-enabled, cloud-trail-encryption-enabled, cloudtrail-insights-enabled |
| AWS::Backup::BackupVault | backup-vault-encryption-enabled, backup-vault-lock-enabled |
| AWS::Backup::BackupPlan | backup-plan-min-frequency-and-min-retention-check, backup-cross-region-copy-enabled |
| AWS::EC2::SecurityGroup | vpc-default-security-group-closed, restricted-ssh, restricted-common-ports |
| AWS::EC2::VPC | vpc-flow-logs-enabled, vpc-dns-resolution-enabled |
| AWS::OpenSearch::Domain | opensearch-encrypted-at-rest, opensearch-https-required |
| AWS::Redshift::Cluster | redshift-require-tls-ssl, redshift-cluster-kms-enabled |
| AWS::WAFv2::WebACL | wafv2-logging-enabled, waf-logging-enabled |
| AWS::Cognito::UserPool | cognito-mfa-enabled, cognito-user-pool-mfa-enabled |
| AWS::SageMaker::NotebookInstance | sagemaker-notebook-no-direct-internet-access, sagemaker-notebook-instance-kms-key-configured |
| AWS::::Account | cloudtrail-enabled, guardduty-enabled-centralized, iam-password-policy, config-enabled-all-regions |

---

## 10. YAML Config Structure

Each IG config file follows this structure:

```yaml
implementation_group: IG1          # IG1, IG2, or IG3
total_rules: 125                   # Declared rule count
description: "Essential cyber hygiene - foundational safeguards"
controls:
  '1.1':                           # CIS Control ID (string key)
    title: "Establish and Maintain Detailed Enterprise Asset Inventory"
    weight: 1.0                    # Control weight in YAML (scoring engine may override)
    config_rules:
      - name: eip-attached         # AWS Config rule name
        resource_types:
          - AWS::EC2::EIP          # AWS resource type(s) evaluated
        parameters: {}             # Rule parameters (usually empty)
        description: "..."         # Human-readable description
        remediation_guidance: "..."  # How to fix non-compliance
```

Key points for reproduction:
- Control IDs are strings (quoted in YAML to handle `3.10` vs `3.1`)
- Weight is declared in YAML but the scoring engine has its own override map
- A control can appear in multiple IGs (e.g., 3.3 is in IG1 and IG2)
- Rules within a control can have duplicate names (deduplication needed)
- `resource_types` can be a list (rule evaluates multiple resource types)
- `AWS::::Account` is a special resource type for account-level checks

---

## 11. Adapting for Another Project

### Replace domain-specific concepts:

| This Project | Your Project |
|-------------|-------------|
| CIS Control ID (1.1, 3.3, ...) | Your check/rule group ID |
| Implementation Group (IG1/IG2/IG3) | Your severity tier / category |
| AWS Config Rule | Your individual check/rule |
| Resource Type | Your target entity type |
| Control Weight | Your rule group importance multiplier |
| IG Weight | Your category importance multiplier |

### Keep the same patterns:
1. YAML configs define the rule catalog with weights
2. Scoring engine applies weighted averages at two levels
3. Visual layer maps percentages to grades/colors/badges
4. Remediation priority combines weight + affected count
5. Coverage metrics track what % of the framework is implemented

