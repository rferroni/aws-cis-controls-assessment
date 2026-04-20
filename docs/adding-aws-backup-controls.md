# Adding AWS Backup Service Controls

## Overview

This guide explains how to add comprehensive AWS Backup service controls to the assessment tool. The tool currently has **resource-specific backup controls** (e.g., `dynamodb-in-backup-plan`, `ebs-in-backup-plan`) that check if individual resources are protected. We'll add **AWS Backup service-level controls** that assess the backup infrastructure itself.

## Current State Analysis

### Existing Backup Controls

The tool currently has **9 backup-related controls** across different services:

**IG1 Controls (Control 11.2 - Perform Automated Backups):**
1. `dynamodb-in-backup-plan` - Checks if DynamoDB tables are in backup plans
2. `ebs-in-backup-plan` - Checks if EBS volumes are in backup plans
3. `efs-in-backup-plan` - Checks if EFS file systems are in backup plans
4. `db-instance-backup-enabled` - Checks if RDS instances have backups enabled
5. `redshift-backup-enabled` - Checks if Redshift clusters have automated snapshots
6. `dynamodb-pitr-enabled` - Checks if DynamoDB has point-in-time recovery
7. `elasticache-redis-cluster-automatic-backup-check` - Checks ElastiCache Redis backups
8. `s3-bucket-replication-enabled` - Checks if S3 buckets have replication

**IG2 Controls (Control 3.11 - Encrypt Sensitive Data at Rest):**
9. `backup-recovery-point-encrypted` - Checks if AWS Backup recovery points are encrypted

### Architecture Pattern

Current controls follow this pattern:
- **Resource-centric**: Check individual resources (DynamoDB tables, EBS volumes, etc.)
- **Service-specific**: Each service has its own backup mechanism
- **Distributed**: Backup logic spread across multiple control files

## Proposed AWS Backup Service Controls

### New Resource Types to Add

AWS Backup provides centralized backup management. We should add controls for:

1. **AWS::Backup::BackupPlan** - Backup plan configuration and policies
2. **AWS::Backup::BackupSelection** - Resource selection for backup plans
3. **AWS::Backup::BackupVault** - Backup storage vaults and access policies
4. **AWS::Backup::RecoveryPoint** - Individual backup recovery points (already exists)
5. **AWS::Backup::ReportPlan** - Backup compliance reporting
6. **AWS::Backup::RestoreTestingPlan** - Automated restore testing

### Recommended Approach: Hybrid Model

**Keep existing resource-specific controls** AND **add AWS Backup service controls**

#### Why Hybrid?

1. **Complementary Coverage**:
   - Resource controls: "Is this DynamoDB table backed up?"
   - Service controls: "Is the backup infrastructure properly configured?"

2. **Different Use Cases**:
   - Resource controls: Operational compliance (are resources protected?)
   - Service controls: Infrastructure compliance (is backup system secure?)

3. **Flexibility**:
   - Some organizations use AWS Backup centrally
   - Others use service-native backup features
   - Hybrid approach covers both scenarios

## Implementation Strategy

### Phase 1: Add Core AWS Backup Service Controls

Create a new control file: `control_aws_backup_service.py`

**Recommended Controls:**

1. **backup-plan-min-frequency-and-min-retention-check**
   - Resource: `AWS::Backup::BackupPlan`
   - Validates backup frequency and retention policies
   - Ensures backups happen regularly and are retained appropriately

2. **backup-vault-access-policy-check**
   - Resource: `AWS::Backup::BackupVault`
   - Checks vault access policies for security
   - Ensures vaults aren't publicly accessible

3. **backup-vault-lock-check**
   - Resource: `AWS::Backup::BackupVault`
   - Verifies vault lock is enabled (prevents deletion)
   - Critical for ransomware protection

4. **backup-selection-resource-coverage-check**
   - Resource: `AWS::Backup::BackupSelection`
   - Validates that backup selections cover critical resources
   - Ensures no resources are accidentally excluded

5. **backup-report-plan-exists-check**
   - Resource: `AWS::Backup::ReportPlan`
   - Checks if backup reporting is configured
   - Ensures backup compliance monitoring

6. **backup-restore-testing-plan-exists-check**
   - Resource: `AWS::Backup::RestoreTestingPlan`
   - Verifies restore testing is configured
   - Ensures backups are actually recoverable

### Phase 2: Enhance Existing Controls

Improve existing resource-specific controls to actually check AWS Backup:

**Current Issue**: Many controls have placeholder implementations:
```python
# For simplicity, assume compliant - full implementation would check backup plans
compliance_status = ComplianceStatus.COMPLIANT
```

**Enhancement**: Actually query AWS Backup API to verify protection:
```python
# Check if resource is actually protected by AWS Backup
backup_client = aws_factory.get_client('backup', region)
protected = backup_client.describe_protected_resource(
    ResourceArn=resource_arn
)
```

### Phase 3: Add to Configuration

Update YAML configuration files to include new controls.

## Detailed Implementation Guide

### Step 1: Create New Control File

Create `aws_cis_assessment/controls/ig1/control_aws_backup_service.py`:

```python
"""AWS Backup Service Controls - Centralized backup infrastructure assessment."""

from typing import Dict, List, Any
import logging
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class BackupPlanMinFrequencyAndMinRetentionCheckAssessment(BaseConfigRuleAssessment):
    """Assessment for backup-plan-min-frequency-and-min-retention-check Config rule."""
    
    def __init__(self):
        super().__init__(
            rule_name="backup-plan-min-frequency-and-min-retention-check",
            control_id="11.2",
            resource_types=["AWS::Backup::BackupPlan"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all AWS Backup plans in the region."""
        if resource_type != "AWS::Backup::BackupPlan":
            return []
        
        try:
            backup_client = aws_factory.get_client('backup', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: backup_client.list_backup_plans()
            )
            
            plans = []
            for plan in response.get('BackupPlansList', []):
                # Get detailed plan information
                plan_id = plan.get('BackupPlanId')
                plan_details = aws_factory.aws_api_call_with_retry(
                    lambda: backup_client.get_backup_plan(BackupPlanId=plan_id)
                )
                
                plans.append({
                    'BackupPlanId': plan_id,
                    'BackupPlanName': plan.get('BackupPlanName'),
                    'BackupPlan': plan_details.get('BackupPlan'),
                    'VersionId': plan.get('VersionId')
                })
            
            return plans
            
        except ClientError as e:
            logger.error(f"Error retrieving backup plans in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if backup plan has appropriate frequency and retention."""
        plan_id = resource.get('BackupPlanId', 'unknown')
        plan_name = resource.get('BackupPlanName', 'unknown')
        backup_plan = resource.get('BackupPlan', {})
        
        # Check backup rules
        rules = backup_plan.get('Rules', [])
        
        if not rules:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = f"Backup plan {plan_name} has no backup rules defined"
        else:
            # Validate each rule has appropriate frequency and retention
            # Minimum: Daily backups, 7 days retention
            compliant_rules = 0
            issues = []
            
            for rule in rules:
                rule_name = rule.get('RuleName', 'unnamed')
                schedule = rule.get('ScheduleExpression', '')
                retention_days = rule.get('Lifecycle', {}).get('DeleteAfterDays', 0)
                
                # Check frequency (should be at least daily)
                if 'cron' in schedule.lower() or 'rate' in schedule.lower():
                    # Basic validation - full implementation would parse schedule
                    has_valid_frequency = True
                else:
                    has_valid_frequency = False
                    issues.append(f"Rule '{rule_name}' has invalid schedule")
                
                # Check retention (should be at least 7 days)
                if retention_days >= 7:
                    has_valid_retention = True
                else:
                    has_valid_retention = False
                    issues.append(f"Rule '{rule_name}' has insufficient retention ({retention_days} days)")
                
                if has_valid_frequency and has_valid_retention:
                    compliant_rules += 1
            
            if compliant_rules == len(rules):
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = f"Backup plan {plan_name} has {len(rules)} compliant rule(s)"
            else:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = f"Backup plan {plan_name} has issues: {'; '.join(issues)}"
        
        return ComplianceResult(
            resource_id=plan_id,
            resource_type="AWS::Backup::BackupPlan",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )


class BackupVaultAccessPolicyCheckAssessment(BaseConfigRuleAssessment):
    """Assessment for backup-vault-access-policy-check Config rule."""
    
    def __init__(self):
        super().__init__(
            rule_name="backup-vault-access-policy-check",
            control_id="11.2",
            resource_types=["AWS::Backup::BackupVault"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all AWS Backup vaults in the region."""
        if resource_type != "AWS::Backup::BackupVault":
            return []
        
        try:
            backup_client = aws_factory.get_client('backup', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: backup_client.list_backup_vaults()
            )
            
            vaults = []
            for vault in response.get('BackupVaultList', []):
                vault_name = vault.get('BackupVaultName')
                
                # Get vault access policy
                try:
                    policy_response = aws_factory.aws_api_call_with_retry(
                        lambda: backup_client.get_backup_vault_access_policy(
                            BackupVaultName=vault_name
                        )
                    )
                    vault['AccessPolicy'] = policy_response.get('Policy')
                except ClientError as e:
                    if e.response.get('Error', {}).get('Code') == 'ResourceNotFoundException':
                        vault['AccessPolicy'] = None
                    else:
                        raise
                
                vaults.append(vault)
            
            return vaults
            
        except ClientError as e:
            logger.error(f"Error retrieving backup vaults in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if backup vault has secure access policy."""
        vault_name = resource.get('BackupVaultName', 'unknown')
        access_policy = resource.get('AccessPolicy')
        
        if not access_policy:
            # No policy means default deny - this is secure
            compliance_status = ComplianceStatus.COMPLIANT
            evaluation_reason = f"Backup vault {vault_name} has no access policy (default deny)"
        else:
            # Check for overly permissive policies
            import json
            try:
                policy_doc = json.loads(access_policy)
                statements = policy_doc.get('Statement', [])
                
                # Check for public access
                has_public_access = False
                for statement in statements:
                    principal = statement.get('Principal', {})
                    if principal == '*' or principal.get('AWS') == '*':
                        has_public_access = True
                        break
                
                if has_public_access:
                    compliance_status = ComplianceStatus.NON_COMPLIANT
                    evaluation_reason = f"Backup vault {vault_name} has overly permissive access policy (allows public access)"
                else:
                    compliance_status = ComplianceStatus.COMPLIANT
                    evaluation_reason = f"Backup vault {vault_name} has appropriate access policy"
                    
            except json.JSONDecodeError:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Backup vault {vault_name} has invalid access policy JSON"
        
        return ComplianceResult(
            resource_id=vault_name,
            resource_type="AWS::Backup::BackupVault",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
```

### Step 2: Register New Controls

Update `aws_cis_assessment/core/assessment_engine.py`:

```python
# Add import
from aws_cis_assessment.controls.ig1.control_aws_backup_service import (
    BackupPlanMinFrequencyAndMinRetentionCheckAssessment,
    BackupVaultAccessPolicyCheckAssessment,
    # ... other new assessments
)

# Add to assessments dictionary
'backup-plan-min-frequency-and-min-retention-check': BackupPlanMinFrequencyAndMinRetentionCheckAssessment(),
'backup-vault-access-policy-check': BackupVaultAccessPolicyCheckAssessment(),
```

### Step 3: Update YAML Configuration

Add to `aws_cis_assessment/config/rules/cis_controls_ig1.yaml`:

```yaml
- name: backup-plan-min-frequency-and-min-retention-check
  resource_types:
    - AWS::Backup::BackupPlan
  parameters: {}
  description: Validates AWS Backup plans have appropriate backup frequency and retention policies
  remediation_guidance: |
    Ensure backup plans have:
    - Backup frequency of at least daily
    - Retention period of at least 7 days
    - Appropriate lifecycle policies

- name: backup-vault-access-policy-check
  resource_types:
    - AWS::Backup::BackupVault
  parameters: {}
  description: Checks AWS Backup vault access policies for security
  remediation_guidance: |
    Ensure backup vaults:
    - Do not allow public access
    - Have restrictive access policies
    - Follow principle of least privilege
```

### Step 4: Update IAM Permissions

The `backup` service is already included in the IAM policy, but verify these actions are covered:

```json
{
  "Effect": "Allow",
  "Action": [
    "backup:ListBackupPlans",
    "backup:GetBackupPlan",
    "backup:ListBackupVaults",
    "backup:GetBackupVaultAccessPolicy",
    "backup:ListBackupSelections",
    "backup:GetBackupSelection",
    "backup:ListRecoveryPointsByBackupVault",
    "backup:DescribeRecoveryPoint",
    "backup:ListReportPlans",
    "backup:DescribeReportPlan",
    "backup:ListRestoreTestingPlans",
    "backup:GetRestoreTestingPlan",
    "backup:DescribeProtectedResource"
  ],
  "Resource": "*"
}
```

## Control Mapping Strategy

### Recommended CIS Controls Mapping

Map new AWS Backup controls to appropriate CIS Controls:

**Control 11.2 - Perform Automated Backups:**
- `backup-plan-min-frequency-and-min-retention-check` (IG1)
- `backup-selection-resource-coverage-check` (IG1)
- `backup-restore-testing-plan-exists-check` (IG2)

**Control 11.3 - Protect Recovery Data:**
- `backup-vault-access-policy-check` (IG1)
- `backup-vault-lock-check` (IG2)
- `backup-recovery-point-encrypted` (IG2) - already exists

**Control 11.5 - Test Data Recovery:**
- `backup-restore-testing-plan-exists-check` (IG2)

**Control 3.11 - Encrypt Sensitive Data at Rest:**
- `backup-recovery-point-encrypted` (IG2) - already exists

## Testing Strategy

### Unit Tests

Create `tests/test_aws_backup_service_controls.py`:

```python
import pytest
from unittest.mock import Mock, patch
from aws_cis_assessment.controls.ig1.control_aws_backup_service import (
    BackupPlanMinFrequencyAndMinRetentionCheckAssessment
)

def test_backup_plan_with_valid_rules():
    """Test backup plan with valid frequency and retention."""
    assessment = BackupPlanMinFrequencyAndMinRetentionCheckAssessment()
    
    resource = {
        'BackupPlanId': 'plan-123',
        'BackupPlanName': 'daily-backup',
        'BackupPlan': {
            'Rules': [{
                'RuleName': 'daily-rule',
                'ScheduleExpression': 'cron(0 5 * * ? *)',
                'Lifecycle': {'DeleteAfterDays': 30}
            }]
        }
    }
    
    # Test evaluation logic
    # ...
```

### Integration Tests

Test with real AWS Backup resources in a test account.

## Migration Path

### For Existing Users

1. **No Breaking Changes**: Existing controls continue to work
2. **Gradual Adoption**: New controls are additive
3. **Backward Compatible**: Reports include both old and new controls

### Deprecation Strategy (Optional)

If you want to eventually consolidate:

1. **Phase 1** (Current): Keep both resource-specific and service controls
2. **Phase 2** (Future): Mark resource-specific controls as "legacy"
3. **Phase 3** (Later): Optionally deprecate duplicates

**Recommendation**: Keep both indefinitely - they serve different purposes.

## Benefits of This Approach

### 1. Comprehensive Coverage
- **Resource-level**: "Is this specific DynamoDB table backed up?"
- **Service-level**: "Is the backup infrastructure properly configured?"

### 2. Flexibility
- Organizations using AWS Backup centrally get service-level insights
- Organizations using service-native backups get resource-level insights
- Both approaches are validated

### 3. Security Depth
- Validates not just that backups exist, but that backup infrastructure is secure
- Checks vault access policies, encryption, restore testing

### 4. Operational Excellence
- Ensures backup plans have appropriate frequency and retention
- Validates restore testing is configured
- Checks backup reporting for compliance monitoring

## Example: Complete Control Flow

```
User runs assessment
    ↓
Resource-Specific Controls Execute:
    - dynamodb-in-backup-plan: "Is table X in a backup plan?"
    - ebs-in-backup-plan: "Is volume Y in a backup plan?"
    ↓
Service-Level Controls Execute:
    - backup-plan-min-frequency-and-min-retention-check: "Do backup plans have good policies?"
    - backup-vault-access-policy-check: "Are backup vaults secure?"
    - backup-restore-testing-plan-exists-check: "Can we actually restore?"
    ↓
Report Generated:
    - Shows both resource protection status AND backup infrastructure health
    - Provides comprehensive backup compliance view
```

## Next Steps

1. **Start with Core Controls**: Implement 2-3 most critical controls first
2. **Test Thoroughly**: Validate with real AWS Backup resources
3. **Document Well**: Update user guide with new controls
4. **Gather Feedback**: See which controls users find most valuable
5. **Iterate**: Add more controls based on user needs

## Questions to Consider

1. **Which controls are most critical for your use case?**
   - Backup plan validation?
   - Vault security?
   - Restore testing?

2. **What's your priority?**
   - Quick wins (add 1-2 controls)?
   - Comprehensive coverage (add all 6 controls)?

3. **Do you want to enhance existing controls?**
   - Fix placeholder implementations?
   - Add actual AWS Backup API checks?

## Conclusion

The hybrid approach (keeping resource-specific controls + adding service-level controls) provides:
- **Best coverage**: Both resource and infrastructure validation
- **Flexibility**: Works for different backup strategies
- **No breaking changes**: Existing functionality preserved
- **Enhanced security**: Deeper backup infrastructure assessment

This approach aligns with the tool's existing architecture and provides maximum value to users.

---

**Ready to implement?** Start with `BackupPlanMinFrequencyAndMinRetentionCheckAssessment` and `BackupVaultAccessPolicyCheckAssessment` as they provide immediate security value.
