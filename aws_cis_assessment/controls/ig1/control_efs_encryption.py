"""
CIS Control 3.11 - EFS Encryption
Ensures EFS file systems have encryption enabled for data at rest protection.
"""

import logging
from typing import List, Dict, Any
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class EFSEncryptedCheckAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 3.11 - Encrypt Sensitive Data at Rest
    AWS Config Rule: efs-encrypted-check
    
    Ensures EFS file systems have encryption at rest enabled.
    Encrypted file systems protect data stored in EFS, including all files,
    directories, and metadata.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="efs-encrypted-check",
            control_id="3.11",
            resource_types=["AWS::EFS::FileSystem"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all EFS file systems in the region."""
        if resource_type != "AWS::EFS::FileSystem":
            return []
        
        try:
            efs_client = aws_factory.get_client('efs', region)
            
            file_systems = []
            paginator = efs_client.get_paginator('describe_file_systems')
            
            for page in paginator.paginate():
                for fs in page.get('FileSystems', []):
                    file_system_id = fs.get('FileSystemId', '')
                    encrypted = fs.get('Encrypted', False)
                    kms_key_id = fs.get('KmsKeyId', '')
                    name = fs.get('Name', '')
                    lifecycle_state = fs.get('LifeCycleState', '')
                    
                    # Get tags to find Name tag
                    tags = fs.get('Tags', [])
                    name_tag = next((tag['Value'] for tag in tags if tag['Key'] == 'Name'), '')
                    
                    file_systems.append({
                        'FileSystemId': file_system_id,
                        'Encrypted': encrypted,
                        'KmsKeyId': kms_key_id,
                        'Name': name_tag or name,
                        'LifeCycleState': lifecycle_state,
                        'FileSystemArn': fs.get('FileSystemArn', ''),
                        'SizeInBytes': fs.get('SizeInBytes', {}).get('Value', 0),
                        'NumberOfMountTargets': fs.get('NumberOfMountTargets', 0)
                    })
            
            logger.debug(f"Found {len(file_systems)} EFS file systems in {region}")
            return file_systems
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'AccessDeniedException':
                logger.warning(f"Access denied to list EFS file systems in {region}")
            else:
                logger.error(f"Error retrieving EFS file systems from {region}: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error retrieving EFS file systems from {region}: {e}")
            return []
    
    def _evaluate_resource_compliance(
        self, 
        resource: Dict[str, Any], 
        aws_factory: AWSClientFactory, 
        region: str
    ) -> ComplianceResult:
        """Evaluate if EFS file system has encryption enabled."""
        file_system_id = resource.get('FileSystemId', 'unknown')
        encrypted = resource.get('Encrypted', False)
        kms_key_id = resource.get('KmsKeyId', '')
        name = resource.get('Name', '')
        lifecycle_state = resource.get('LifeCycleState', '')
        
        # Check if file system is encrypted
        is_compliant = encrypted
        
        if is_compliant:
            if kms_key_id:
                evaluation_reason = (
                    f"EFS file system '{file_system_id}' "
                    f"{f'({name}) ' if name else ''}"
                    f"has encryption enabled with KMS key: {kms_key_id}"
                )
            else:
                evaluation_reason = (
                    f"EFS file system '{file_system_id}' "
                    f"{f'({name}) ' if name else ''}"
                    f"has encryption enabled with AWS managed key"
                )
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            evaluation_reason = (
                f"EFS file system '{file_system_id}' "
                f"{f'({name}) ' if name else ''}"
                f"does not have encryption enabled. "
                f"State: {lifecycle_state}"
            )
            compliance_status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceResult(
            resource_id=file_system_id,
            resource_type="AWS::EFS::FileSystem",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get remediation steps for enabling EFS encryption."""
        return [
            "1. IMPORTANT: You CANNOT enable encryption on an existing unencrypted EFS file system.",
            "   You must create a new encrypted file system and migrate data.",
            "",
            "2. Create a new encrypted EFS file system:",
            "   aws efs create-file-system \\",
            "     --encrypted \\",
            "     --kms-key-id <kms-key-id> \\",  # Optional, uses default aws/elasticfilesystem if omitted",
            "     --performance-mode <generalPurpose|maxIO> \\",
            "     --throughput-mode <bursting|provisioned> \\",
            "     --tags Key=Name,Value=<name> \\",
            "     --region <region>",
            "",
            "3. Create mount targets in the same subnets as the old file system:",
            "   # Get the new file system ID from the previous command",
            "   NEW_FS_ID=<new-file-system-id>",
            "",
            "   # Create mount target for each subnet",
            "   aws efs create-mount-target \\",
            "     --file-system-id $NEW_FS_ID \\",
            "     --subnet-id <subnet-id> \\",
            "     --security-groups <security-group-id> \\",
            "     --region <region>",
            "",
            "4. Wait for the new file system to become available:",
            "   aws efs describe-file-systems \\",
            "     --file-system-id $NEW_FS_ID \\",
            "     --query 'FileSystems[0].LifeCycleState' \\",
            "     --output text \\",
            "     --region <region>",
            "",
            "5. Migrate data from old file system to new encrypted file system:",
            "   # Option A: Using rsync from an EC2 instance with both file systems mounted",
            "   # Mount old file system",
            "   sudo mount -t nfs4 -o nfsvers=4.1 <old-fs-id>.efs.<region>.amazonaws.com:/ /mnt/old-efs",
            "",
            "   # Mount new file system",
            "   sudo mount -t nfs4 -o nfsvers=4.1 <new-fs-id>.efs.<region>.amazonaws.com:/ /mnt/new-efs",
            "",
            "   # Copy data preserving permissions and timestamps",
            "   sudo rsync -avh --progress /mnt/old-efs/ /mnt/new-efs/",
            "",
            "   # Option B: Using AWS DataSync for large datasets",
            "   # Create DataSync task to migrate data",
            "   # See: https://docs.aws.amazon.com/datasync/latest/userguide/create-efs-location.html",
            "",
            "6. Verify data integrity after migration:",
            "   # Compare file counts",
            "   find /mnt/old-efs -type f | wc -l",
            "   find /mnt/new-efs -type f | wc -l",
            "",
            "   # Compare total size",
            "   du -sh /mnt/old-efs",
            "   du -sh /mnt/new-efs",
            "",
            "7. Update application mount points to use the new file system:",
            "   # Update /etc/fstab or application configuration",
            "   # Old: <old-fs-id>.efs.<region>.amazonaws.com:/",
            "   # New: <new-fs-id>.efs.<region>.amazonaws.com:/",
            "",
            "8. Test applications thoroughly with the new encrypted file system:",
            "   - Verify read/write operations",
            "   - Verify application functionality",
            "   - Verify performance is acceptable",
            "   - Test backup and restore procedures",
            "",
            "9. After successful testing, delete the old unencrypted file system:",
            "   # First, delete all mount targets",
            "   aws efs describe-mount-targets \\",
            "     --file-system-id <old-fs-id> \\",
            "     --region <region> \\",
            "     --query 'MountTargets[].MountTargetId' \\",
            "     --output text | xargs -n1 aws efs delete-mount-target --mount-target-id",
            "",
            "   # Wait for mount targets to be deleted",
            "   # Then delete the file system",
            "   aws efs delete-file-system \\",
            "     --file-system-id <old-fs-id> \\",
            "     --region <region>",
            "",
            "10. For NEW file systems, always enable encryption at creation:",
            "    # Console method:",
            "    - Navigate to EFS service",
            "    - Click 'Create file system'",
            "    - Click 'Customize'",
            "    - Under 'Encryption', check 'Enable encryption of data at rest'",
            "    - Select KMS key (or use default aws/elasticfilesystem)",
            "    - Complete the configuration",
            "",
            "11. Best practices:",
            "    - Use customer-managed KMS keys for better control",
            "    - Enable automatic key rotation for KMS keys",
            "    - Grant appropriate IAM permissions for KMS key usage",
            "    - Enable encryption in transit (TLS) in addition to at-rest encryption",
            "    - Document the KMS key used for each file system",
            "    - Use EFS Access Points for application-specific access control",
            "    - Enable EFS Backup for encrypted file systems",
            "",
            "12. Important notes:",
            "    - Encryption cannot be removed once enabled",
            "    - Encrypted file systems can only be restored to encrypted file systems",
            "    - Backups inherit encryption from source file system",
            "    - Performance impact is negligible",
            "    - No additional cost for encryption (KMS key costs apply)",
            "    - Encryption in transit (TLS) is separate and should also be enabled",
            "",
            "Priority: HIGH - File system encryption is critical for compliance and data protection",
            "Effort: High - Requires creating new file system and migrating data",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/efs/latest/ug/encryption.html"
        ]
