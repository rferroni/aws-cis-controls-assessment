"""
CIS Control 3.11 - RDS Storage Encryption
Ensures RDS database instances have storage encryption enabled for data at rest protection.
"""

import logging
from typing import List, Dict, Any
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class RDSStorageEncryptedAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 3.11 - Encrypt Sensitive Data at Rest
    AWS Config Rule: rds-storage-encrypted
    
    Ensures RDS database instances have storage encryption enabled.
    Encrypted storage protects data at rest, including automated backups,
    read replicas, and snapshots.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="rds-storage-encrypted",
            control_id="3.11",
            resource_types=["AWS::RDS::DBInstance"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all RDS database instances in the region."""
        if resource_type != "AWS::RDS::DBInstance":
            return []
        
        try:
            rds_client = aws_factory.get_client('rds', region)
            
            db_instances = []
            paginator = rds_client.get_paginator('describe_db_instances')
            
            for page in paginator.paginate():
                for db_instance in page.get('DBInstances', []):
                    db_instance_id = db_instance.get('DBInstanceIdentifier', '')
                    storage_encrypted = db_instance.get('StorageEncrypted', False)
                    kms_key_id = db_instance.get('KmsKeyId', '')
                    engine = db_instance.get('Engine', '')
                    engine_version = db_instance.get('EngineVersion', '')
                    db_instance_status = db_instance.get('DBInstanceStatus', '')
                    
                    db_instances.append({
                        'DBInstanceIdentifier': db_instance_id,
                        'StorageEncrypted': storage_encrypted,
                        'KmsKeyId': kms_key_id,
                        'Engine': engine,
                        'EngineVersion': engine_version,
                        'DBInstanceStatus': db_instance_status,
                        'DBInstanceArn': db_instance.get('DBInstanceArn', ''),
                        'MultiAZ': db_instance.get('MultiAZ', False)
                    })
            
            logger.debug(f"Found {len(db_instances)} RDS instances in {region}")
            return db_instances
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'AccessDenied':
                logger.warning(f"Access denied to list RDS instances in {region}")
            else:
                logger.error(f"Error retrieving RDS instances from {region}: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error retrieving RDS instances from {region}: {e}")
            return []
    
    def _evaluate_resource_compliance(
        self, 
        resource: Dict[str, Any], 
        aws_factory: AWSClientFactory, 
        region: str
    ) -> ComplianceResult:
        """Evaluate if RDS instance has storage encryption enabled."""
        db_instance_id = resource.get('DBInstanceIdentifier', 'unknown')
        storage_encrypted = resource.get('StorageEncrypted', False)
        kms_key_id = resource.get('KmsKeyId', '')
        engine = resource.get('Engine', '')
        db_status = resource.get('DBInstanceStatus', '')
        
        # Check if storage is encrypted
        is_compliant = storage_encrypted
        
        if is_compliant:
            if kms_key_id:
                evaluation_reason = (
                    f"RDS instance '{db_instance_id}' ({engine}) has storage encryption enabled "
                    f"with KMS key: {kms_key_id}"
                )
            else:
                evaluation_reason = (
                    f"RDS instance '{db_instance_id}' ({engine}) has storage encryption enabled "
                    f"with AWS managed key"
                )
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            evaluation_reason = (
                f"RDS instance '{db_instance_id}' ({engine}) does not have storage encryption enabled. "
                f"Status: {db_status}"
            )
            compliance_status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceResult(
            resource_id=db_instance_id,
            resource_type="AWS::RDS::DBInstance",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get remediation steps for enabling RDS storage encryption."""
        return [
            "1. IMPORTANT: You CANNOT enable encryption on an existing unencrypted RDS instance.",
            "   You must create a new encrypted instance from a snapshot.",
            "",
            "2. Create an encrypted snapshot from the unencrypted instance:",
            "   # Create a snapshot of the unencrypted instance",
            "   aws rds create-db-snapshot \\",
            "     --db-instance-identifier <unencrypted-instance-id> \\",
            "     --db-snapshot-identifier <snapshot-name> \\",
            "     --region <region>",
            "",
            "   # Wait for snapshot to complete",
            "   aws rds wait db-snapshot-completed \\",
            "     --db-snapshot-identifier <snapshot-name> \\",
            "     --region <region>",
            "",
            "   # Copy snapshot with encryption enabled",
            "   aws rds copy-db-snapshot \\",
            "     --source-db-snapshot-identifier <snapshot-name> \\",
            "     --target-db-snapshot-identifier <encrypted-snapshot-name> \\",
            "     --kms-key-id <kms-key-id> \\",
            "     --region <region>",
            "",
            "3. Restore a new encrypted instance from the encrypted snapshot:",
            "   aws rds restore-db-instance-from-db-snapshot \\",
            "     --db-instance-identifier <new-encrypted-instance-id> \\",
            "     --db-snapshot-identifier <encrypted-snapshot-name> \\",
            "     --db-instance-class <instance-class> \\",
            "     --region <region>",
            "",
            "4. Update application connection strings to point to the new instance:",
            "   # Get the new endpoint",
            "   aws rds describe-db-instances \\",
            "     --db-instance-identifier <new-encrypted-instance-id> \\",
            "     --query 'DBInstances[0].Endpoint.Address' \\",
            "     --output text \\",
            "     --region <region>",
            "",
            "5. Test the new encrypted instance thoroughly:",
            "   - Verify application connectivity",
            "   - Verify data integrity",
            "   - Verify performance is acceptable",
            "   - Test backup and restore procedures",
            "",
            "6. After successful testing, delete the old unencrypted instance:",
            "   # Create a final backup before deletion (optional)",
            "   aws rds create-db-snapshot \\",
            "     --db-instance-identifier <unencrypted-instance-id> \\",
            "     --db-snapshot-identifier <final-backup-snapshot> \\",
            "     --region <region>",
            "",
            "   # Delete the unencrypted instance",
            "   aws rds delete-db-instance \\",
            "     --db-instance-identifier <unencrypted-instance-id> \\",
            "     --skip-final-snapshot \\",  # or --final-db-snapshot-identifier <name>",
            "     --region <region>",
            "",
            "7. For NEW instances, always enable encryption at creation:",
            "   aws rds create-db-instance \\",
            "     --db-instance-identifier <instance-id> \\",
            "     --db-instance-class <instance-class> \\",
            "     --engine <engine> \\",
            "     --master-username <username> \\",
            "     --master-user-password <password> \\",
            "     --allocated-storage <size-in-gb> \\",
            "     --storage-encrypted \\",
            "     --kms-key-id <kms-key-id> \\",  # Optional, uses default if omitted",
            "     --region <region>",
            "",
            "8. Best practices:",
            "   - Use customer-managed KMS keys for better control",
            "   - Enable automatic key rotation for KMS keys",
            "   - Grant appropriate IAM permissions for KMS key usage",
            "   - Ensure read replicas are also encrypted (automatic if source is encrypted)",
            "   - Document the KMS key used for each database",
            "   - Test disaster recovery procedures with encrypted instances",
            "",
            "9. Console method:",
            "   - Navigate to RDS service",
            "   - Select the unencrypted instance",
            "   - Actions > Take snapshot",
            "   - After snapshot completes, select it",
            "   - Actions > Copy snapshot",
            "   - Check 'Enable encryption' and select KMS key",
            "   - After copy completes, select encrypted snapshot",
            "   - Actions > Restore snapshot",
            "   - Configure new instance settings",
            "   - Launch the encrypted instance",
            "",
            "10. Important notes:",
            "    - Encryption cannot be removed once enabled",
            "    - Encrypted instances can only be restored to encrypted instances",
            "    - Read replicas inherit encryption from source instance",
            "    - Snapshots inherit encryption from source instance",
            "    - Cross-region snapshot copies can change encryption settings",
            "    - Performance impact is negligible",
            "    - No additional cost for encryption (KMS key costs apply)",
            "",
            "Priority: HIGH - Database encryption is critical for compliance and data protection",
            "Effort: High - Requires creating new instance and migrating data",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html"
        ]
