"""
CIS Control 11.3, 11.4 - Backup Security
Ensures proper backup security and protection measures.
"""

import logging
from typing import List, Dict, Any
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class BackupVaultEncryptionEnabledAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 11.3 - Protect Recovery Data
    AWS Config Rule: backup-vault-encryption-enabled
    
    Ensures AWS Backup vaults are encrypted with KMS.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="backup-vault-encryption-enabled",
            control_id="11.3",
            resource_types=["AWS::Backup::BackupVault"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get backup vaults and check encryption."""
        if resource_type != "AWS::Backup::BackupVault":
            return []
        
        try:
            backup_client = aws_factory.get_client('backup', region)
            
            response = backup_client.list_backup_vaults()
            vaults = []
            
            for vault in response.get('BackupVaultList', []):
                vault_name = vault.get('BackupVaultName')
                encryption_key_arn = vault.get('EncryptionKeyArn')
                
                # Check if encrypted with KMS
                is_encrypted = bool(encryption_key_arn)
                
                vaults.append({
                    'VaultName': vault_name,
                    'VaultArn': vault.get('BackupVaultArn'),
                    'EncryptionKeyArn': encryption_key_arn,
                    'IsEncrypted': is_encrypted
                })
            
            return vaults
            
        except ClientError as e:
            logger.error(f"Error retrieving backup vaults in {region}: {e}")
            return []
    
    def _evaluate_resource_compliance(
        self, 
        resource: Dict[str, Any], 
        aws_factory: AWSClientFactory, 
        region: str
    ) -> ComplianceResult:
        """Evaluate if backup vault is encrypted."""
        vault_name = resource.get('VaultName', 'unknown')
        is_encrypted = resource.get('IsEncrypted', False)
        encryption_key = resource.get('EncryptionKeyArn', '')
        
        if is_encrypted:
            evaluation_reason = f"Backup vault '{vault_name}' is encrypted with KMS key: {encryption_key}"
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            evaluation_reason = f"Backup vault '{vault_name}' is not encrypted with KMS"
            compliance_status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceResult(
            resource_id=resource.get('VaultArn', vault_name),
            resource_type="AWS::Backup::BackupVault",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get remediation steps for backup vault encryption."""
        return [
            "1. Create encrypted backup vault:",
            "   aws backup create-backup-vault \\",
            "     --backup-vault-name encrypted-vault \\",
            "     --encryption-key-arn <kms-key-arn>",
            "",
            "2. Migrate backups to encrypted vault:",
            "   - Create new encrypted vault",
            "   - Update backup plans to use new vault",
            "   - Copy existing backups to new vault",
            "   - Delete old unencrypted vault",
            "",
            "3. Console method:",
            "   - Navigate to AWS Backup",
            "   - Click 'Backup vaults'",
            "   - Click 'Create backup vault'",
            "   - Enter vault name",
            "   - Select KMS key for encryption",
            "   - Click 'Create backup vault'",
            "",
            "Priority: HIGH - Protects backup data",
            "Effort: Low - Simple vault creation",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/aws-backup/latest/devguide/vaults.html"
        ]


class BackupCrossRegionCopyEnabledAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 11.4 - Establish and Maintain an Isolated Instance of Recovery Data
    AWS Config Rule: backup-cross-region-copy-enabled
    
    Ensures backup plans include cross-region copy for disaster recovery.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="backup-cross-region-copy-enabled",
            control_id="11.4",
            resource_types=["AWS::Backup::BackupPlan"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get backup plans and check for cross-region copy."""
        if resource_type != "AWS::Backup::BackupPlan":
            return []
        
        try:
            backup_client = aws_factory.get_client('backup', region)
            
            response = backup_client.list_backup_plans()
            plans = []
            
            for plan_summary in response.get('BackupPlansList', []):
                plan_id = plan_summary.get('BackupPlanId')
                plan_name = plan_summary.get('BackupPlanName')
                
                try:
                    # Get plan details
                    plan_response = backup_client.get_backup_plan(BackupPlanId=plan_id)
                    plan = plan_response.get('BackupPlan', {})
                    
                    # Check if any rule has cross-region copy
                    has_cross_region = False
                    for rule in plan.get('Rules', []):
                        copy_actions = rule.get('CopyActions', [])
                        if copy_actions:
                            has_cross_region = True
                            break
                    
                    plans.append({
                        'PlanId': plan_id,
                        'PlanName': plan_name,
                        'PlanArn': plan_summary.get('BackupPlanArn'),
                        'HasCrossRegionCopy': has_cross_region
                    })
                
                except ClientError:
                    continue
            
            return plans
            
        except ClientError as e:
            logger.error(f"Error retrieving backup plans in {region}: {e}")
            return []
    
    def _evaluate_resource_compliance(
        self, 
        resource: Dict[str, Any], 
        aws_factory: AWSClientFactory, 
        region: str
    ) -> ComplianceResult:
        """Evaluate if backup plan has cross-region copy."""
        plan_name = resource.get('PlanName', 'unknown')
        has_cross_region = resource.get('HasCrossRegionCopy', False)
        
        if has_cross_region:
            evaluation_reason = f"Backup plan '{plan_name}' includes cross-region copy"
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            evaluation_reason = f"Backup plan '{plan_name}' does not include cross-region copy"
            compliance_status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceResult(
            resource_id=resource.get('PlanArn', plan_name),
            resource_type="AWS::Backup::BackupPlan",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get remediation steps for cross-region backup copy."""
        return [
            "1. Update backup plan to include cross-region copy:",
            "   aws backup update-backup-plan \\",
            "     --backup-plan-id <plan-id> \\",
            "     --backup-plan '{",
            '       "Rules": [{',
            '         "RuleName": "daily-backup",',
            '         "TargetBackupVaultName": "primary-vault",',
            '         "ScheduleExpression": "cron(0 5 * * ? *)",',
            '         "CopyActions": [{',
            '           "DestinationBackupVaultArn": "arn:aws:backup:us-west-2:...:backup-vault:dr-vault",',
            '           "Lifecycle": {"DeleteAfterDays": 90}',
            "         }]",
            "       }]",
            "     }'",
            "",
            "2. Console method:",
            "   - Navigate to AWS Backup",
            "   - Select backup plan",
            "   - Click 'Edit'",
            "   - In backup rule, expand 'Copy to destination'",
            "   - Select destination region",
            "   - Select destination vault",
            "   - Configure lifecycle",
            "   - Click 'Save plan'",
            "",
            "3. Best practices:",
            "   - Copy to geographically distant region",
            "   - Use separate AWS account for DR",
            "   - Encrypt copies with different KMS key",
            "   - Test restore from DR region regularly",
            "",
            "Priority: HIGH - Critical for disaster recovery",
            "Effort: Medium - Requires DR planning",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/aws-backup/latest/devguide/cross-region-backup.html"
        ]


class BackupVaultLockEnabledAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 11.3 - Protect Recovery Data
    AWS Config Rule: backup-vault-lock-enabled
    
    Ensures backup vaults have vault lock enabled to prevent deletion.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="backup-vault-lock-enabled",
            control_id="11.3",
            resource_types=["AWS::Backup::BackupVault"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get backup vaults and check for vault lock."""
        if resource_type != "AWS::Backup::BackupVault":
            return []
        
        try:
            backup_client = aws_factory.get_client('backup', region)
            
            response = backup_client.list_backup_vaults()
            vaults = []
            
            for vault in response.get('BackupVaultList', []):
                vault_name = vault.get('BackupVaultName')
                
                # Check for vault lock configuration
                try:
                    lock_response = backup_client.describe_backup_vault(BackupVaultName=vault_name)
                    min_retention_days = lock_response.get('MinRetentionDays')
                    max_retention_days = lock_response.get('MaxRetentionDays')
                    locked = lock_response.get('Locked', False)
                    
                    has_lock = bool(locked or min_retention_days or max_retention_days)
                except ClientError:
                    has_lock = False
                
                vaults.append({
                    'VaultName': vault_name,
                    'VaultArn': vault.get('BackupVaultArn'),
                    'HasLock': has_lock
                })
            
            return vaults
            
        except ClientError as e:
            logger.error(f"Error retrieving backup vaults in {region}: {e}")
            return []
    
    def _evaluate_resource_compliance(
        self, 
        resource: Dict[str, Any], 
        aws_factory: AWSClientFactory, 
        region: str
    ) -> ComplianceResult:
        """Evaluate if backup vault has lock enabled."""
        vault_name = resource.get('VaultName', 'unknown')
        has_lock = resource.get('HasLock', False)
        
        if has_lock:
            evaluation_reason = f"Backup vault '{vault_name}' has vault lock enabled"
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            evaluation_reason = f"Backup vault '{vault_name}' does not have vault lock enabled"
            compliance_status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceResult(
            resource_id=resource.get('VaultArn', vault_name),
            resource_type="AWS::Backup::BackupVault",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get remediation steps for backup vault lock."""
        return [
            "1. Enable vault lock on backup vault:",
            "   aws backup put-backup-vault-lock-configuration \\",
            "     --backup-vault-name <vault-name> \\",
            "     --min-retention-days 7 \\",
            "     --max-retention-days 365",
            "",
            "2. Console method:",
            "   - Navigate to AWS Backup",
            "   - Select backup vault",
            "   - Click 'Vault lock configuration'",
            "   - Enable vault lock",
            "   - Set minimum retention days",
            "   - Set maximum retention days (optional)",
            "   - Click 'Save'",
            "",
            "3. Important notes:",
            "   - Vault lock is IRREVERSIBLE once enabled",
            "   - Test with non-production vault first",
            "   - Prevents deletion of backups within retention period",
            "   - Protects against ransomware and insider threats",
            "",
            "Priority: HIGH - Protects against backup deletion",
            "Effort: Low - Simple configuration (but irreversible!)",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/aws-backup/latest/devguide/vault-lock.html"
        ]


class Route53QueryLoggingEnabledAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 8.2 - Collect Audit Logs
    AWS Config Rule: route53-query-logging-enabled
    
    Ensures Route 53 hosted zones have query logging enabled.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="route53-query-logging-enabled",
            control_id="8.2",
            resource_types=["AWS::Route53::HostedZone"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get Route 53 hosted zones and check for query logging."""
        if resource_type != "AWS::Route53::HostedZone":
            return []
        
        # Route 53 is global, only process in us-east-1
        if region != 'us-east-1':
            return []
        
        try:
            route53_client = aws_factory.get_client('route53', region)
            
            response = route53_client.list_hosted_zones()
            zones = []
            
            for zone in response.get('HostedZones', []):
                zone_id = zone.get('Id').split('/')[-1]  # Extract ID from full path
                zone_name = zone.get('Name')
                
                # Check for query logging configuration
                try:
                    logging_response = route53_client.list_query_logging_configs(
                        HostedZoneId=zone_id
                    )
                    has_logging = len(logging_response.get('QueryLoggingConfigs', [])) > 0
                except ClientError:
                    has_logging = False
                
                zones.append({
                    'ZoneId': zone_id,
                    'ZoneName': zone_name,
                    'HasQueryLogging': has_logging,
                    'IsPrivate': zone.get('Config', {}).get('PrivateZone', False)
                })
            
            return zones
            
        except ClientError as e:
            logger.error(f"Error retrieving Route 53 hosted zones: {e}")
            return []
    
    def _evaluate_resource_compliance(
        self, 
        resource: Dict[str, Any], 
        aws_factory: AWSClientFactory, 
        region: str
    ) -> ComplianceResult:
        """Evaluate if hosted zone has query logging enabled."""
        zone_id = resource.get('ZoneId', 'unknown')
        zone_name = resource.get('ZoneName', 'unknown')
        has_logging = resource.get('HasQueryLogging', False)
        is_private = resource.get('IsPrivate', False)
        
        if has_logging:
            evaluation_reason = f"Route 53 hosted zone '{zone_name}' has query logging enabled"
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            evaluation_reason = f"Route 53 hosted zone '{zone_name}' does not have query logging enabled"
            compliance_status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceResult(
            resource_id=zone_id,
            resource_type="AWS::Route53::HostedZone",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get remediation steps for Route 53 query logging."""
        return [
            "1. Create CloudWatch log group for query logs:",
            "   aws logs create-log-group \\",
            "     --log-group-name /aws/route53/queries",
            "",
            "2. Create query logging configuration:",
            "   aws route53 create-query-logging-config \\",
            "     --hosted-zone-id <zone-id> \\",
            "     --cloudwatch-logs-log-group-arn <log-group-arn>",
            "",
            "3. Console method:",
            "   - Navigate to Route 53",
            "   - Select hosted zone",
            "   - Click 'Configure query logging'",
            "   - Select or create CloudWatch log group",
            "   - Click 'Create'",
            "",
            "4. Best practices:",
            "   - Enable for all public hosted zones",
            "   - Consider for private zones with sensitive data",
            "   - Set appropriate log retention period",
            "   - Monitor logs for suspicious queries",
            "",
            "Priority: MEDIUM - DNS query monitoring",
            "Effort: Low - Simple configuration",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/query-logs.html"
        ]


class RDSBackupRetentionCheckAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 11.2 - Perform Automated Backups
    AWS Config Rule: rds-backup-retention-check
    
    Ensures RDS instances have adequate backup retention periods.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="rds-backup-retention-check",
            control_id="11.2",
            resource_types=["AWS::RDS::DBInstance"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get RDS instances and check backup retention."""
        if resource_type != "AWS::RDS::DBInstance":
            return []
        
        try:
            rds_client = aws_factory.get_client('rds', region)
            
            response = rds_client.describe_db_instances()
            instances = []
            
            for db in response.get('DBInstances', []):
                retention_period = db.get('BackupRetentionPeriod', 0)
                
                # Minimum recommended retention is 7 days
                meets_minimum = retention_period >= 7
                
                instances.append({
                    'DBInstanceIdentifier': db.get('DBInstanceIdentifier'),
                    'BackupRetentionPeriod': retention_period,
                    'MeetsMinimum': meets_minimum
                })
            
            return instances
            
        except ClientError as e:
            logger.error(f"Error retrieving RDS instances in {region}: {e}")
            return []
    
    def _evaluate_resource_compliance(
        self, 
        resource: Dict[str, Any], 
        aws_factory: AWSClientFactory, 
        region: str
    ) -> ComplianceResult:
        """Evaluate if RDS instance has adequate backup retention."""
        db_id = resource.get('DBInstanceIdentifier', 'unknown')
        retention_period = resource.get('BackupRetentionPeriod', 0)
        meets_minimum = resource.get('MeetsMinimum', False)
        
        if meets_minimum:
            evaluation_reason = f"RDS instance '{db_id}' has {retention_period} days backup retention (meets 7-day minimum)"
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            evaluation_reason = f"RDS instance '{db_id}' has {retention_period} days backup retention (below 7-day minimum)"
            compliance_status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceResult(
            resource_id=db_id,
            resource_type="AWS::RDS::DBInstance",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get remediation steps for RDS backup retention."""
        return [
            "1. Update RDS backup retention period:",
            "   aws rds modify-db-instance \\",
            "     --db-instance-identifier <db-id> \\",
            "     --backup-retention-period 7 \\",
            "     --apply-immediately",
            "",
            "2. Set retention for new instances:",
            "   aws rds create-db-instance \\",
            "     --db-instance-identifier <db-id> \\",
            "     --backup-retention-period 30 \\",
            "     ...",
            "",
            "3. Console method:",
            "   - Navigate to RDS",
            "   - Select database instance",
            "   - Click 'Modify'",
            "   - Under 'Backup', set retention period",
            "   - Click 'Continue'",
            "   - Select 'Apply immediately'",
            "   - Click 'Modify DB instance'",
            "",
            "4. Recommended retention periods:",
            "   - Development: 7 days minimum",
            "   - Production: 30 days recommended",
            "   - Compliance: 90+ days as required",
            "",
            "Priority: HIGH - Essential for data recovery",
            "Effort: Low - Simple configuration change",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_WorkingWithAutomatedBackups.html"
        ]
