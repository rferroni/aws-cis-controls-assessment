"""AWS Backup Service Controls - Centralized backup infrastructure assessment.

This module implements AWS Backup service-level controls that assess the backup
infrastructure itself, complementing the existing resource-specific backup controls.

Controls:
- backup-plan-min-frequency-and-min-retention-check: Validates backup plan policies
- backup-vault-access-policy-check: Checks backup vault security
"""

from typing import Dict, List, Any
import logging
import json
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class BackupPlanMinFrequencyAndMinRetentionCheckAssessment(BaseConfigRuleAssessment):
    """Assessment for backup-plan-min-frequency-and-min-retention-check Config rule.
    
    Validates that AWS Backup plans have appropriate backup frequency and retention
    policies to ensure data protection and recovery capabilities.
    
    Compliance Criteria:
    - Backup plans must have at least one rule defined
    - Each rule should have a valid schedule expression
    - Retention period should be at least 7 days (configurable)
    - Lifecycle policies should be properly configured
    """
    
    def __init__(self, min_retention_days: int = 7):
        """Initialize backup plan assessment.
        
        Args:
            min_retention_days: Minimum retention period in days (default: 7)
        """
        super().__init__(
            rule_name="backup-plan-min-frequency-and-min-retention-check",
            control_id="11.2",
            resource_types=["AWS::Backup::BackupPlan"]
        )
        self.min_retention_days = min_retention_days
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all AWS Backup plans in the region.
        
        Args:
            aws_factory: AWS client factory for API calls
            resource_type: Type of resource to retrieve
            region: AWS region
            
        Returns:
            List of backup plans with detailed configuration
        """
        if resource_type != "AWS::Backup::BackupPlan":
            return []
        
        try:
            backup_client = aws_factory.get_client('backup', region)
            
            # List all backup plans
            response = aws_factory.aws_api_call_with_retry(
                lambda: backup_client.list_backup_plans()
            )
            
            plans = []
            for plan in response.get('BackupPlansList', []):
                plan_id = plan.get('BackupPlanId')
                plan_name = plan.get('BackupPlanName')
                
                try:
                    # Get detailed plan information including rules
                    plan_details = aws_factory.aws_api_call_with_retry(
                        lambda: backup_client.get_backup_plan(BackupPlanId=plan_id)
                    )
                    
                    plans.append({
                        'BackupPlanId': plan_id,
                        'BackupPlanName': plan_name,
                        'BackupPlan': plan_details.get('BackupPlan'),
                        'BackupPlanArn': plan_details.get('BackupPlanArn'),
                        'VersionId': plan.get('VersionId'),
                        'CreationDate': plan.get('CreationDate')
                    })
                    
                except ClientError as e:
                    logger.warning(f"Could not get details for backup plan {plan_name}: {e}")
                    # Include plan with minimal info
                    plans.append({
                        'BackupPlanId': plan_id,
                        'BackupPlanName': plan_name,
                        'BackupPlan': None,
                        'Error': str(e)
                    })
            
            logger.info(f"Retrieved {len(plans)} backup plan(s) in region {region}")
            return plans
            
        except ClientError as e:
            if e.response.get('Error', {}).get('Code') in ['AccessDenied', 'UnauthorizedOperation']:
                logger.warning(f"Insufficient permissions to list backup plans in region {region}")
                return []
            logger.error(f"Error retrieving backup plans in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if backup plan has appropriate frequency and retention.
        
        Args:
            resource: Backup plan resource to evaluate
            aws_factory: AWS client factory
            region: AWS region
            
        Returns:
            ComplianceResult with evaluation details
        """
        plan_id = resource.get('BackupPlanId', 'unknown')
        plan_name = resource.get('BackupPlanName', 'unknown')
        backup_plan = resource.get('BackupPlan')
        
        # Check if plan details were retrieved
        if backup_plan is None:
            error_msg = resource.get('Error', 'Unknown error')
            return ComplianceResult(
                resource_id=plan_id,
                resource_type="AWS::Backup::BackupPlan",
                compliance_status=ComplianceStatus.ERROR,
                evaluation_reason=f"Could not retrieve backup plan details: {error_msg}",
                config_rule_name=self.rule_name,
                region=region
            )
        
        # Check backup rules
        rules = backup_plan.get('Rules', [])
        
        if not rules:
            return ComplianceResult(
                resource_id=plan_id,
                resource_type="AWS::Backup::BackupPlan",
                compliance_status=ComplianceStatus.NON_COMPLIANT,
                evaluation_reason=f"Backup plan '{plan_name}' has no backup rules defined",
                config_rule_name=self.rule_name,
                region=region
            )
        
        # Validate each rule
        compliant_rules = 0
        issues = []
        
        for rule in rules:
            rule_name = rule.get('RuleName', 'unnamed')
            schedule = rule.get('ScheduleExpression', '')
            lifecycle = rule.get('Lifecycle', {})
            
            # Check schedule expression
            if not schedule:
                issues.append(f"Rule '{rule_name}' has no schedule expression")
                continue
            
            # Validate schedule format (cron or rate expression)
            has_valid_schedule = self._validate_schedule_expression(schedule)
            if not has_valid_schedule:
                issues.append(f"Rule '{rule_name}' has invalid schedule expression: {schedule}")
            
            # Check retention period
            delete_after_days = lifecycle.get('DeleteAfterDays')
            move_to_cold_storage_after_days = lifecycle.get('MoveToColdStorageAfterDays')
            
            if delete_after_days is None:
                issues.append(f"Rule '{rule_name}' has no retention period defined")
            elif delete_after_days < self.min_retention_days:
                issues.append(
                    f"Rule '{rule_name}' has insufficient retention "
                    f"({delete_after_days} days, minimum: {self.min_retention_days} days)"
                )
            else:
                # Check cold storage configuration if present
                if move_to_cold_storage_after_days is not None:
                    if move_to_cold_storage_after_days >= delete_after_days:
                        issues.append(
                            f"Rule '{rule_name}' has invalid lifecycle: "
                            f"cold storage transition ({move_to_cold_storage_after_days} days) "
                            f"must be before deletion ({delete_after_days} days)"
                        )
                    else:
                        # Rule is compliant
                        if has_valid_schedule:
                            compliant_rules += 1
                else:
                    # No cold storage, just check schedule and retention
                    if has_valid_schedule:
                        compliant_rules += 1
        
        # Determine overall compliance
        if compliant_rules == len(rules) and not issues:
            compliance_status = ComplianceStatus.COMPLIANT
            evaluation_reason = (
                f"Backup plan '{plan_name}' has {len(rules)} compliant rule(s) "
                f"with valid schedules and retention >= {self.min_retention_days} days"
            )
        elif compliant_rules > 0:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = (
                f"Backup plan '{plan_name}' has {compliant_rules}/{len(rules)} compliant rules. "
                f"Issues: {'; '.join(issues)}"
            )
        else:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = (
                f"Backup plan '{plan_name}' has no compliant rules. "
                f"Issues: {'; '.join(issues)}"
            )
        
        return ComplianceResult(
            resource_id=plan_id,
            resource_type="AWS::Backup::BackupPlan",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _validate_schedule_expression(self, schedule: str) -> bool:
        """Validate AWS Backup schedule expression format.
        
        Args:
            schedule: Schedule expression (cron or rate)
            
        Returns:
            True if valid, False otherwise
        """
        if not schedule:
            return False
        
        schedule_lower = schedule.lower().strip()
        
        # Check for cron expression
        if schedule_lower.startswith('cron(') and schedule_lower.endswith(')'):
            return True
        
        # Check for rate expression
        if schedule_lower.startswith('rate(') and schedule_lower.endswith(')'):
            return True
        
        return False


class BackupVaultAccessPolicyCheckAssessment(BaseConfigRuleAssessment):
    """Assessment for backup-vault-access-policy-check Config rule.
    
    Validates that AWS Backup vaults have secure access policies that follow
    the principle of least privilege and do not allow public access.
    
    Compliance Criteria:
    - Vaults should not allow public access (Principal: "*")
    - Access policies should be restrictive
    - Cross-account access should be explicitly authorized
    - Vault lock should be considered for critical vaults
    """
    
    def __init__(self):
        """Initialize backup vault access policy assessment."""
        super().__init__(
            rule_name="backup-vault-access-policy-check",
            control_id="11.2",
            resource_types=["AWS::Backup::BackupVault"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all AWS Backup vaults in the region.
        
        Args:
            aws_factory: AWS client factory for API calls
            resource_type: Type of resource to retrieve
            region: AWS region
            
        Returns:
            List of backup vaults with access policies
        """
        if resource_type != "AWS::Backup::BackupVault":
            return []
        
        try:
            backup_client = aws_factory.get_client('backup', region)
            
            # List all backup vaults
            response = aws_factory.aws_api_call_with_retry(
                lambda: backup_client.list_backup_vaults()
            )
            
            vaults = []
            for vault in response.get('BackupVaultList', []):
                vault_name = vault.get('BackupVaultName')
                
                # Get vault access policy
                access_policy = None
                policy_error = None
                
                try:
                    policy_response = aws_factory.aws_api_call_with_retry(
                        lambda: backup_client.get_backup_vault_access_policy(
                            BackupVaultName=vault_name
                        )
                    )
                    access_policy = policy_response.get('Policy')
                except ClientError as e:
                    error_code = e.response.get('Error', {}).get('Code')
                    if error_code == 'ResourceNotFoundException':
                        # No policy is set - this is actually secure (default deny)
                        access_policy = None
                    elif error_code in ['AccessDenied', 'UnauthorizedOperation']:
                        policy_error = "Insufficient permissions to get vault policy"
                    else:
                        policy_error = str(e)
                
                # Get vault lock status (if available)
                vault_lock_status = None
                try:
                    lock_response = aws_factory.aws_api_call_with_retry(
                        lambda: backup_client.describe_backup_vault(
                            BackupVaultName=vault_name
                        )
                    )
                    vault_lock_status = lock_response.get('Locked', False)
                except ClientError:
                    # Lock status not available or not supported
                    pass
                
                vaults.append({
                    'BackupVaultName': vault_name,
                    'BackupVaultArn': vault.get('BackupVaultArn'),
                    'AccessPolicy': access_policy,
                    'PolicyError': policy_error,
                    'Locked': vault_lock_status,
                    'CreationDate': vault.get('CreationDate'),
                    'NumberOfRecoveryPoints': vault.get('NumberOfRecoveryPoints', 0)
                })
            
            logger.info(f"Retrieved {len(vaults)} backup vault(s) in region {region}")
            return vaults
            
        except ClientError as e:
            if e.response.get('Error', {}).get('Code') in ['AccessDenied', 'UnauthorizedOperation']:
                logger.warning(f"Insufficient permissions to list backup vaults in region {region}")
                return []
            logger.error(f"Error retrieving backup vaults in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if backup vault has secure access policy.
        
        Args:
            resource: Backup vault resource to evaluate
            aws_factory: AWS client factory
            region: AWS region
            
        Returns:
            ComplianceResult with evaluation details
        """
        vault_name = resource.get('BackupVaultName', 'unknown')
        access_policy = resource.get('AccessPolicy')
        policy_error = resource.get('PolicyError')
        is_locked = resource.get('Locked', False)
        
        # Check if there was an error retrieving the policy
        if policy_error:
            return ComplianceResult(
                resource_id=vault_name,
                resource_type="AWS::Backup::BackupVault",
                compliance_status=ComplianceStatus.ERROR,
                evaluation_reason=f"Could not retrieve access policy for vault '{vault_name}': {policy_error}",
                config_rule_name=self.rule_name,
                region=region
            )
        
        # No policy means default deny - this is secure
        if not access_policy:
            evaluation_reason = f"Backup vault '{vault_name}' has no access policy (default deny - secure)"
            if is_locked:
                evaluation_reason += " and is locked for additional protection"
            
            return ComplianceResult(
                resource_id=vault_name,
                resource_type="AWS::Backup::BackupVault",
                compliance_status=ComplianceStatus.COMPLIANT,
                evaluation_reason=evaluation_reason,
                config_rule_name=self.rule_name,
                region=region
            )
        
        # Parse and validate the access policy
        try:
            policy_doc = json.loads(access_policy)
            statements = policy_doc.get('Statement', [])
            
            if not statements:
                return ComplianceResult(
                    resource_id=vault_name,
                    resource_type="AWS::Backup::BackupVault",
                    compliance_status=ComplianceStatus.COMPLIANT,
                    evaluation_reason=f"Backup vault '{vault_name}' has empty access policy (no permissions granted)",
                    config_rule_name=self.rule_name,
                    region=region
                )
            
            # Check for security issues
            issues = []
            warnings = []
            
            for idx, statement in enumerate(statements):
                statement_id = statement.get('Sid', f'Statement-{idx}')
                effect = statement.get('Effect', 'Allow')
                principal = statement.get('Principal', {})
                actions = statement.get('Action', [])
                
                # Convert single action to list
                if isinstance(actions, str):
                    actions = [actions]
                
                # Check for public access
                if self._is_public_principal(principal):
                    issues.append(
                        f"Statement '{statement_id}' allows public access (Principal: *)"
                    )
                
                # Check for overly broad permissions
                if effect == 'Allow':
                    if '*' in actions or 'backup:*' in actions:
                        warnings.append(
                            f"Statement '{statement_id}' grants broad permissions (Action: *)"
                        )
                    
                    # Check for dangerous actions
                    dangerous_actions = [
                        'backup:DeleteBackupVault',
                        'backup:DeleteRecoveryPoint',
                        'backup:PutBackupVaultAccessPolicy'
                    ]
                    
                    for action in actions:
                        if action in dangerous_actions:
                            warnings.append(
                                f"Statement '{statement_id}' allows potentially dangerous action: {action}"
                            )
            
            # Determine compliance status
            if issues:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = (
                    f"Backup vault '{vault_name}' has insecure access policy. "
                    f"Issues: {'; '.join(issues)}"
                )
                if warnings:
                    evaluation_reason += f". Warnings: {'; '.join(warnings)}"
            elif warnings:
                # Warnings but no critical issues - still compliant but note the warnings
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = (
                    f"Backup vault '{vault_name}' has access policy with warnings: {'; '.join(warnings)}"
                )
            else:
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = f"Backup vault '{vault_name}' has appropriate access policy"
                if is_locked:
                    evaluation_reason += " and is locked for additional protection"
            
            return ComplianceResult(
                resource_id=vault_name,
                resource_type="AWS::Backup::BackupVault",
                compliance_status=compliance_status,
                evaluation_reason=evaluation_reason,
                config_rule_name=self.rule_name,
                region=region
            )
            
        except json.JSONDecodeError as e:
            return ComplianceResult(
                resource_id=vault_name,
                resource_type="AWS::Backup::BackupVault",
                compliance_status=ComplianceStatus.ERROR,
                evaluation_reason=f"Backup vault '{vault_name}' has invalid access policy JSON: {str(e)}",
                config_rule_name=self.rule_name,
                region=region
            )
        except Exception as e:
            return ComplianceResult(
                resource_id=vault_name,
                resource_type="AWS::Backup::BackupVault",
                compliance_status=ComplianceStatus.ERROR,
                evaluation_reason=f"Error evaluating access policy for vault '{vault_name}': {str(e)}",
                config_rule_name=self.rule_name,
                region=region
            )
    
    def _is_public_principal(self, principal: Any) -> bool:
        """Check if principal allows public access.
        
        Args:
            principal: Principal from IAM policy statement
            
        Returns:
            True if principal allows public access, False otherwise
        """
        # Check for wildcard principal
        if principal == '*':
            return True
        
        # Check for AWS principal with wildcard
        if isinstance(principal, dict):
            aws_principal = principal.get('AWS')
            if aws_principal == '*':
                return True
            if isinstance(aws_principal, list) and '*' in aws_principal:
                return True
        
        return False



class BackupVaultLockCheckAssessment(BaseConfigRuleAssessment):
    """Assessment for backup-vault-lock-check Config rule (IG2).
    
    Validates that AWS Backup vaults have Vault Lock enabled to prevent
    deletion of recovery points, providing ransomware protection.
    
    Compliance Criteria:
    - Critical backup vaults should have Vault Lock enabled
    - Vault Lock provides immutable backups (WORM - Write Once Read Many)
    - Protects against accidental or malicious deletion
    - Compliance mode prevents even root user from deleting backups
    """
    
    def __init__(self):
        """Initialize backup vault lock assessment."""
        super().__init__(
            rule_name="backup-vault-lock-check",
            control_id="11.3",
            resource_types=["AWS::Backup::BackupVault"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all AWS Backup vaults with lock status.
        
        Args:
            aws_factory: AWS client factory for API calls
            resource_type: Type of resource to retrieve
            region: AWS region
            
        Returns:
            List of backup vaults with lock configuration
        """
        if resource_type != "AWS::Backup::BackupVault":
            return []
        
        try:
            backup_client = aws_factory.get_client('backup', region)
            
            # List all backup vaults
            response = aws_factory.aws_api_call_with_retry(
                lambda: backup_client.list_backup_vaults()
            )
            
            vaults = []
            for vault in response.get('BackupVaultList', []):
                vault_name = vault.get('BackupVaultName')
                
                # Get detailed vault information including lock status
                try:
                    vault_details = aws_factory.aws_api_call_with_retry(
                        lambda: backup_client.describe_backup_vault(
                            BackupVaultName=vault_name
                        )
                    )
                    
                    vaults.append({
                        'BackupVaultName': vault_name,
                        'BackupVaultArn': vault.get('BackupVaultArn'),
                        'Locked': vault_details.get('Locked', False),
                        'MinRetentionDays': vault_details.get('MinRetentionDays'),
                        'MaxRetentionDays': vault_details.get('MaxRetentionDays'),
                        'LockDate': vault_details.get('LockDate'),
                        'CreationDate': vault.get('CreationDate'),
                        'NumberOfRecoveryPoints': vault.get('NumberOfRecoveryPoints', 0)
                    })
                    
                except ClientError as e:
                    error_code = e.response.get('Error', {}).get('Code')
                    if error_code in ['AccessDenied', 'UnauthorizedOperation']:
                        logger.warning(f"Insufficient permissions to describe vault {vault_name}")
                        vaults.append({
                            'BackupVaultName': vault_name,
                            'BackupVaultArn': vault.get('BackupVaultArn'),
                            'Error': 'Insufficient permissions'
                        })
                    else:
                        logger.warning(f"Could not get details for vault {vault_name}: {e}")
                        vaults.append({
                            'BackupVaultName': vault_name,
                            'BackupVaultArn': vault.get('BackupVaultArn'),
                            'Error': str(e)
                        })
            
            logger.info(f"Retrieved {len(vaults)} backup vault(s) in region {region}")
            return vaults
            
        except ClientError as e:
            if e.response.get('Error', {}).get('Code') in ['AccessDenied', 'UnauthorizedOperation']:
                logger.warning(f"Insufficient permissions to list backup vaults in region {region}")
                return []
            logger.error(f"Error retrieving backup vaults in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if backup vault has Vault Lock enabled.
        
        Args:
            resource: Backup vault resource to evaluate
            aws_factory: AWS client factory
            region: AWS region
            
        Returns:
            ComplianceResult with evaluation details
        """
        vault_name = resource.get('BackupVaultName', 'unknown')
        is_locked = resource.get('Locked', False)
        min_retention = resource.get('MinRetentionDays')
        max_retention = resource.get('MaxRetentionDays')
        lock_date = resource.get('LockDate')
        error = resource.get('Error')
        
        # Check for errors
        if error:
            return ComplianceResult(
                resource_id=vault_name,
                resource_type="AWS::Backup::BackupVault",
                compliance_status=ComplianceStatus.ERROR,
                evaluation_reason=f"Could not evaluate vault lock for '{vault_name}': {error}",
                config_rule_name=self.rule_name,
                region=region
            )
        
        # Evaluate lock status
        if is_locked:
            lock_details = []
            if min_retention:
                lock_details.append(f"min retention: {min_retention} days")
            if max_retention:
                lock_details.append(f"max retention: {max_retention} days")
            if lock_date:
                lock_details.append(f"locked since: {lock_date}")
            
            details_str = ", ".join(lock_details) if lock_details else "lock enabled"
            
            return ComplianceResult(
                resource_id=vault_name,
                resource_type="AWS::Backup::BackupVault",
                compliance_status=ComplianceStatus.COMPLIANT,
                evaluation_reason=f"Backup vault '{vault_name}' has Vault Lock enabled ({details_str})",
                config_rule_name=self.rule_name,
                region=region
            )
        else:
            return ComplianceResult(
                resource_id=vault_name,
                resource_type="AWS::Backup::BackupVault",
                compliance_status=ComplianceStatus.NON_COMPLIANT,
                evaluation_reason=f"Backup vault '{vault_name}' does not have Vault Lock enabled (ransomware protection not configured)",
                config_rule_name=self.rule_name,
                region=region
            )


class BackupSelectionResourceCoverageCheckAssessment(BaseConfigRuleAssessment):
    """Assessment for backup-selection-resource-coverage-check Config rule (IG1).
    
    Validates that AWS Backup plans have backup selections that cover critical
    resources, ensuring comprehensive backup coverage.
    
    Compliance Criteria:
    - Backup plans should have at least one backup selection
    - Backup selections should target specific resources or use tags
    - Critical resource types should be included in backup coverage
    - Selections should not be empty
    """
    
    def __init__(self):
        """Initialize backup selection coverage assessment."""
        super().__init__(
            rule_name="backup-selection-resource-coverage-check",
            control_id="11.2",
            resource_types=["AWS::Backup::BackupPlan"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all AWS Backup plans with their selections.
        
        Args:
            aws_factory: AWS client factory for API calls
            resource_type: Type of resource to retrieve
            region: AWS region
            
        Returns:
            List of backup plans with selection details
        """
        if resource_type != "AWS::Backup::BackupPlan":
            return []
        
        try:
            backup_client = aws_factory.get_client('backup', region)
            
            # List all backup plans
            response = aws_factory.aws_api_call_with_retry(
                lambda: backup_client.list_backup_plans()
            )
            
            plans = []
            for plan in response.get('BackupPlansList', []):
                plan_id = plan.get('BackupPlanId')
                plan_name = plan.get('BackupPlanName')
                
                # Get backup selections for this plan
                selections = []
                try:
                    selections_response = aws_factory.aws_api_call_with_retry(
                        lambda: backup_client.list_backup_selections(
                            BackupPlanId=plan_id
                        )
                    )
                    
                    for selection in selections_response.get('BackupSelectionsList', []):
                        selection_id = selection.get('SelectionId')
                        
                        # Get detailed selection information
                        try:
                            selection_details = aws_factory.aws_api_call_with_retry(
                                lambda: backup_client.get_backup_selection(
                                    BackupPlanId=plan_id,
                                    SelectionId=selection_id
                                )
                            )
                            
                            selections.append({
                                'SelectionId': selection_id,
                                'SelectionName': selection.get('SelectionName'),
                                'BackupSelection': selection_details.get('BackupSelection'),
                                'CreationDate': selection_details.get('CreationDate')
                            })
                            
                        except ClientError as e:
                            logger.warning(f"Could not get selection details for {selection_id}: {e}")
                            selections.append({
                                'SelectionId': selection_id,
                                'SelectionName': selection.get('SelectionName'),
                                'Error': str(e)
                            })
                    
                except ClientError as e:
                    logger.warning(f"Could not list selections for plan {plan_name}: {e}")
                
                plans.append({
                    'BackupPlanId': plan_id,
                    'BackupPlanName': plan_name,
                    'BackupSelections': selections,
                    'CreationDate': plan.get('CreationDate')
                })
            
            logger.info(f"Retrieved {len(plans)} backup plan(s) with selections in region {region}")
            return plans
            
        except ClientError as e:
            if e.response.get('Error', {}).get('Code') in ['AccessDenied', 'UnauthorizedOperation']:
                logger.warning(f"Insufficient permissions to list backup plans in region {region}")
                return []
            logger.error(f"Error retrieving backup plans in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if backup plan has adequate resource coverage.
        
        Args:
            resource: Backup plan resource to evaluate
            aws_factory: AWS client factory
            region: AWS region
            
        Returns:
            ComplianceResult with evaluation details
        """
        plan_id = resource.get('BackupPlanId', 'unknown')
        plan_name = resource.get('BackupPlanName', 'unknown')
        selections = resource.get('BackupSelections', [])
        
        # Check if plan has any selections
        if not selections:
            return ComplianceResult(
                resource_id=plan_id,
                resource_type="AWS::Backup::BackupPlan",
                compliance_status=ComplianceStatus.NON_COMPLIANT,
                evaluation_reason=f"Backup plan '{plan_name}' has no backup selections (no resources will be backed up)",
                config_rule_name=self.rule_name,
                region=region
            )
        
        # Analyze selections
        valid_selections = 0
        issues = []
        resource_coverage = []
        
        for selection in selections:
            selection_name = selection.get('SelectionName', 'unnamed')
            backup_selection = selection.get('BackupSelection')
            error = selection.get('Error')
            
            if error:
                issues.append(f"Selection '{selection_name}' could not be evaluated: {error}")
                continue
            
            if not backup_selection:
                issues.append(f"Selection '{selection_name}' has no configuration")
                continue
            
            # Check selection criteria
            resources = backup_selection.get('Resources', [])
            list_of_tags = backup_selection.get('ListOfTags', [])
            conditions = backup_selection.get('Conditions')
            
            # Validate selection has targeting criteria
            has_resources = len(resources) > 0
            has_tags = len(list_of_tags) > 0
            has_conditions = conditions is not None
            
            if not (has_resources or has_tags or has_conditions):
                issues.append(f"Selection '{selection_name}' has no targeting criteria (resources, tags, or conditions)")
                continue
            
            # Selection is valid
            valid_selections += 1
            
            # Track what's being backed up
            if has_resources:
                resource_coverage.append(f"{len(resources)} specific resource(s)")
            if has_tags:
                resource_coverage.append(f"{len(list_of_tags)} tag-based rule(s)")
            if has_conditions:
                resource_coverage.append("conditional selection")
        
        # Determine compliance
        if valid_selections == 0:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = (
                f"Backup plan '{plan_name}' has {len(selections)} selection(s) but none are valid. "
                f"Issues: {'; '.join(issues)}"
            )
        elif valid_selections < len(selections):
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = (
                f"Backup plan '{plan_name}' has {valid_selections}/{len(selections)} valid selections. "
                f"Coverage: {', '.join(resource_coverage)}. Issues: {'; '.join(issues)}"
            )
        else:
            compliance_status = ComplianceStatus.COMPLIANT
            evaluation_reason = (
                f"Backup plan '{plan_name}' has {valid_selections} valid selection(s) "
                f"covering: {', '.join(resource_coverage)}"
            )
        
        return ComplianceResult(
            resource_id=plan_id,
            resource_type="AWS::Backup::BackupPlan",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )


class BackupReportPlanExistsCheckAssessment(BaseConfigRuleAssessment):
    """Assessment for backup-report-plan-exists-check Config rule (IG2).
    
    Validates that AWS Backup has report plans configured to monitor backup
    compliance and provide audit trails.
    
    Compliance Criteria:
    - At least one backup report plan should exist
    - Report plans should be actively generating reports
    - Reports should cover backup job status and compliance
    - Report delivery should be configured
    """
    
    def __init__(self):
        """Initialize backup report plan assessment."""
        super().__init__(
            rule_name="backup-report-plan-exists-check",
            control_id="11.3",
            resource_types=["AWS::Backup::ReportPlan"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all AWS Backup report plans.
        
        Args:
            aws_factory: AWS client factory for API calls
            resource_type: Type of resource to retrieve
            region: AWS region
            
        Returns:
            List of backup report plans
        """
        if resource_type != "AWS::Backup::ReportPlan":
            return []
        
        try:
            backup_client = aws_factory.get_client('backup', region)
            
            # List all report plans
            response = aws_factory.aws_api_call_with_retry(
                lambda: backup_client.list_report_plans()
            )
            
            report_plans = []
            for plan in response.get('ReportPlans', []):
                report_plan_name = plan.get('ReportPlanName')
                
                # Get detailed report plan information
                try:
                    plan_details = aws_factory.aws_api_call_with_retry(
                        lambda: backup_client.describe_report_plan(
                            ReportPlanName=report_plan_name
                        )
                    )
                    
                    report_plan = plan_details.get('ReportPlan', {})
                    report_plans.append({
                        'ReportPlanName': report_plan_name,
                        'ReportPlanArn': report_plan.get('ReportPlanArn'),
                        'ReportPlanDescription': report_plan.get('ReportPlanDescription'),
                        'ReportSetting': report_plan.get('ReportSetting'),
                        'ReportDeliveryChannel': report_plan.get('ReportDeliveryChannel'),
                        'CreationTime': report_plan.get('CreationTime'),
                        'LastAttemptedExecutionTime': report_plan.get('LastAttemptedExecutionTime'),
                        'LastSuccessfulExecutionTime': report_plan.get('LastSuccessfulExecutionTime')
                    })
                    
                except ClientError as e:
                    logger.warning(f"Could not get details for report plan {report_plan_name}: {e}")
                    report_plans.append({
                        'ReportPlanName': report_plan_name,
                        'Error': str(e)
                    })
            
            logger.info(f"Retrieved {len(report_plans)} backup report plan(s) in region {region}")
            
            # Return a single "account-level" resource if report plans exist
            # This allows us to check if ANY report plans exist
            if report_plans:
                return [{
                    'AccountId': aws_factory.account_id,
                    'Region': region,
                    'ReportPlans': report_plans,
                    'TotalReportPlans': len(report_plans)
                }]
            else:
                # Return empty resource to indicate no report plans
                return [{
                    'AccountId': aws_factory.account_id,
                    'Region': region,
                    'ReportPlans': [],
                    'TotalReportPlans': 0
                }]
            
        except ClientError as e:
            if e.response.get('Error', {}).get('Code') in ['AccessDenied', 'UnauthorizedOperation']:
                logger.warning(f"Insufficient permissions to list report plans in region {region}")
                return []
            logger.error(f"Error retrieving report plans in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if backup report plans exist and are configured.
        
        Args:
            resource: Account-level resource with report plans
            aws_factory: AWS client factory
            region: AWS region
            
        Returns:
            ComplianceResult with evaluation details
        """
        account_id = resource.get('AccountId', 'unknown')
        report_plans = resource.get('ReportPlans', [])
        total_plans = resource.get('TotalReportPlans', 0)
        
        resource_id = f"backup-reporting-{region}"
        
        # Check if any report plans exist
        if total_plans == 0:
            return ComplianceResult(
                resource_id=resource_id,
                resource_type="AWS::Backup::ReportPlan",
                compliance_status=ComplianceStatus.NON_COMPLIANT,
                evaluation_reason=f"No backup report plans configured in region {region} (backup compliance monitoring not enabled)",
                config_rule_name=self.rule_name,
                region=region
            )
        
        # Analyze report plans
        active_plans = 0
        configured_plans = 0
        issues = []
        
        for plan in report_plans:
            plan_name = plan.get('ReportPlanName', 'unnamed')
            error = plan.get('Error')
            
            if error:
                issues.append(f"Report plan '{plan_name}' could not be evaluated: {error}")
                continue
            
            # Check if report delivery is configured
            delivery_channel = plan.get('ReportDeliveryChannel')
            if not delivery_channel:
                issues.append(f"Report plan '{plan_name}' has no delivery channel configured")
                continue
            
            # Check if S3 bucket is configured
            s3_bucket = delivery_channel.get('S3BucketName')
            if not s3_bucket:
                issues.append(f"Report plan '{plan_name}' has no S3 bucket configured for delivery")
                continue
            
            configured_plans += 1
            
            # Check if plan has been executed
            last_successful = plan.get('LastSuccessfulExecutionTime')
            if last_successful:
                active_plans += 1
        
        # Determine compliance
        if configured_plans == 0:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = (
                f"Region {region} has {total_plans} report plan(s) but none are properly configured. "
                f"Issues: {'; '.join(issues)}"
            )
        elif configured_plans < total_plans:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = (
                f"Region {region} has {configured_plans}/{total_plans} properly configured report plans "
                f"({active_plans} active). Issues: {'; '.join(issues)}"
            )
        else:
            compliance_status = ComplianceStatus.COMPLIANT
            evaluation_reason = (
                f"Region {region} has {configured_plans} properly configured report plan(s) "
                f"({active_plans} actively generating reports)"
            )
        
        return ComplianceResult(
            resource_id=resource_id,
            resource_type="AWS::Backup::ReportPlan",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )


class BackupRestoreTestingPlanExistsCheckAssessment(BaseConfigRuleAssessment):
    """Assessment for backup-restore-testing-plan-exists-check Config rule (IG2).
    
    Validates that AWS Backup has restore testing plans configured to ensure
    backups are actually recoverable and meet RTO/RPO requirements.
    
    Compliance Criteria:
    - At least one restore testing plan should exist
    - Testing plans should be actively running
    - Critical backup vaults should be included in testing
    - Testing frequency should be appropriate
    """
    
    def __init__(self):
        """Initialize backup restore testing plan assessment."""
        super().__init__(
            rule_name="backup-restore-testing-plan-exists-check",
            control_id="11.3",
            resource_types=["AWS::Backup::RestoreTestingPlan"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all AWS Backup restore testing plans.
        
        Args:
            aws_factory: AWS client factory for API calls
            resource_type: Type of resource to retrieve
            region: AWS region
            
        Returns:
            List of restore testing plans
        """
        if resource_type != "AWS::Backup::RestoreTestingPlan":
            return []
        
        try:
            backup_client = aws_factory.get_client('backup', region)
            
            # List all restore testing plans
            try:
                response = aws_factory.aws_api_call_with_retry(
                    lambda: backup_client.list_restore_testing_plans()
                )
            except AttributeError:
                # API might not be available in all regions or SDK versions
                logger.warning(f"Restore testing API not available in region {region}")
                return [{
                    'AccountId': aws_factory.account_id,
                    'Region': region,
                    'RestoreTestingPlans': [],
                    'TotalPlans': 0,
                    'ApiNotAvailable': True
                }]
            
            testing_plans = []
            for plan in response.get('RestoreTestingPlans', []):
                plan_name = plan.get('RestoreTestingPlanName')
                
                # Get detailed testing plan information
                try:
                    plan_details = aws_factory.aws_api_call_with_retry(
                        lambda: backup_client.get_restore_testing_plan(
                            RestoreTestingPlanName=plan_name
                        )
                    )
                    
                    testing_plan = plan_details.get('RestoreTestingPlan', {})
                    testing_plans.append({
                        'RestoreTestingPlanName': plan_name,
                        'RestoreTestingPlanArn': testing_plan.get('RestoreTestingPlanArn'),
                        'ScheduleExpression': testing_plan.get('ScheduleExpression'),
                        'StartWindowHours': testing_plan.get('StartWindowHours'),
                        'CreationTime': testing_plan.get('CreationTime'),
                        'LastExecutionTime': testing_plan.get('LastExecutionTime'),
                        'LastUpdateTime': testing_plan.get('LastUpdateTime')
                    })
                    
                except ClientError as e:
                    logger.warning(f"Could not get details for restore testing plan {plan_name}: {e}")
                    testing_plans.append({
                        'RestoreTestingPlanName': plan_name,
                        'Error': str(e)
                    })
            
            logger.info(f"Retrieved {len(testing_plans)} restore testing plan(s) in region {region}")
            
            # Return account-level resource
            if testing_plans:
                return [{
                    'AccountId': aws_factory.account_id,
                    'Region': region,
                    'RestoreTestingPlans': testing_plans,
                    'TotalPlans': len(testing_plans),
                    'ApiNotAvailable': False
                }]
            else:
                return [{
                    'AccountId': aws_factory.account_id,
                    'Region': region,
                    'RestoreTestingPlans': [],
                    'TotalPlans': 0,
                    'ApiNotAvailable': False
                }]
            
        except ClientError as e:
            if e.response.get('Error', {}).get('Code') in ['AccessDenied', 'UnauthorizedOperation']:
                logger.warning(f"Insufficient permissions to list restore testing plans in region {region}")
                return []
            logger.error(f"Error retrieving restore testing plans in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if restore testing plans exist and are active.
        
        Args:
            resource: Account-level resource with testing plans
            aws_factory: AWS client factory
            region: AWS region
            
        Returns:
            ComplianceResult with evaluation details
        """
        account_id = resource.get('AccountId', 'unknown')
        testing_plans = resource.get('RestoreTestingPlans', [])
        total_plans = resource.get('TotalPlans', 0)
        api_not_available = resource.get('ApiNotAvailable', False)
        
        resource_id = f"backup-restore-testing-{region}"
        
        # Check if API is available
        if api_not_available:
            return ComplianceResult(
                resource_id=resource_id,
                resource_type="AWS::Backup::RestoreTestingPlan",
                compliance_status=ComplianceStatus.NOT_APPLICABLE,
                evaluation_reason=f"Restore testing API not available in region {region}",
                config_rule_name=self.rule_name,
                region=region
            )
        
        # Check if any testing plans exist
        if total_plans == 0:
            return ComplianceResult(
                resource_id=resource_id,
                resource_type="AWS::Backup::RestoreTestingPlan",
                compliance_status=ComplianceStatus.NON_COMPLIANT,
                evaluation_reason=f"No restore testing plans configured in region {region} (backup recoverability not validated)",
                config_rule_name=self.rule_name,
                region=region
            )
        
        # Analyze testing plans
        active_plans = 0
        scheduled_plans = 0
        issues = []
        
        for plan in testing_plans:
            plan_name = plan.get('RestoreTestingPlanName', 'unnamed')
            error = plan.get('Error')
            
            if error:
                issues.append(f"Testing plan '{plan_name}' could not be evaluated: {error}")
                continue
            
            # Check if plan has a schedule
            schedule = plan.get('ScheduleExpression')
            if not schedule:
                issues.append(f"Testing plan '{plan_name}' has no schedule configured")
                continue
            
            scheduled_plans += 1
            
            # Check if plan has been executed
            last_execution = plan.get('LastExecutionTime')
            if last_execution:
                active_plans += 1
        
        # Determine compliance
        if scheduled_plans == 0:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = (
                f"Region {region} has {total_plans} restore testing plan(s) but none are properly scheduled. "
                f"Issues: {'; '.join(issues)}"
            )
        elif scheduled_plans < total_plans:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = (
                f"Region {region} has {scheduled_plans}/{total_plans} properly scheduled testing plans "
                f"({active_plans} have executed). Issues: {'; '.join(issues)}"
            )
        else:
            compliance_status = ComplianceStatus.COMPLIANT
            evaluation_reason = (
                f"Region {region} has {scheduled_plans} properly configured restore testing plan(s) "
                f"({active_plans} have executed tests)"
            )
        
        return ComplianceResult(
            resource_id=resource_id,
            resource_type="AWS::Backup::RestoreTestingPlan",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
