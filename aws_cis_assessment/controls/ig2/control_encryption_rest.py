"""Control 3.11: Encrypt Sensitive Data at Rest assessments."""

from typing import Dict, List, Any
import logging
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class CloudTrailEncryptionEnabledAssessment(BaseConfigRuleAssessment):
    """Assessment for cloud-trail-encryption-enabled Config rule."""
    
    def __init__(self):
        """Initialize CloudTrail encryption assessment."""
        super().__init__(
            rule_name="cloud-trail-encryption-enabled",
            control_id="3.11",
            resource_types=["AWS::CloudTrail::Trail"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all CloudTrail trails."""
        if resource_type != "AWS::CloudTrail::Trail":
            return []
        
        try:
            cloudtrail_client = aws_factory.get_client('cloudtrail', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: cloudtrail_client.describe_trails()
            )
            
            trails = []
            for trail in response.get('trailList', []):
                trails.append({
                    'TrailARN': trail.get('TrailARN'),
                    'Name': trail.get('Name'),
                    'S3BucketName': trail.get('S3BucketName'),
                    'KMSKeyId': trail.get('KMSKeyId'),
                    'IsMultiRegionTrail': trail.get('IsMultiRegionTrail', False),
                    'HomeRegion': trail.get('HomeRegion')
                })
            
            logger.debug(f"Found {len(trails)} CloudTrail trails")
            return trails
            
        except ClientError as e:
            logger.error(f"Error retrieving CloudTrail trails: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving CloudTrail trails: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if CloudTrail trail has encryption enabled."""
        trail_arn = resource.get('TrailARN', 'unknown')
        trail_name = resource.get('Name', 'unknown')
        kms_key_id = resource.get('KMSKeyId')
        
        if kms_key_id:
            compliance_status = ComplianceStatus.COMPLIANT
            evaluation_reason = f"CloudTrail {trail_name} has encryption enabled with KMS key: {kms_key_id}"
        else:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = f"CloudTrail {trail_name} does not have encryption enabled"
        
        return ComplianceResult(
            resource_id=trail_arn,
            resource_type="AWS::CloudTrail::Trail",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for CloudTrail encryption."""
        return [
            "Identify CloudTrail trails without encryption enabled",
            "For each unencrypted trail:",
            "  1. Create or identify a KMS key for CloudTrail encryption",
            "  2. Update the trail configuration to use the KMS key",
            "  3. Ensure CloudTrail service has permissions to use the key",
            "  4. Test that logs are being encrypted properly",
            "  5. Monitor for any delivery failures",
            "Use AWS CLI: aws cloudtrail put-trail --name <trail> --kms-key-id <key-id>",
            "Ensure KMS key policy allows CloudTrail service access",
            "Consider using separate KMS keys for different environments",
            "Monitor KMS key usage and costs"
        ]


class EFSEncryptedCheckAssessment(BaseConfigRuleAssessment):
    """Assessment for efs-encrypted-check Config rule."""
    
    def __init__(self):
        """Initialize EFS encryption assessment."""
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
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: efs_client.describe_file_systems()
            )
            
            file_systems = []
            for fs in response.get('FileSystems', []):
                file_systems.append({
                    'FileSystemId': fs.get('FileSystemId'),
                    'FileSystemArn': fs.get('FileSystemArn'),
                    'CreationTime': fs.get('CreationTime'),
                    'LifeCycleState': fs.get('LifeCycleState'),
                    'Encrypted': fs.get('Encrypted', False),
                    'KmsKeyId': fs.get('KmsKeyId'),
                    'Name': fs.get('Name', fs.get('FileSystemId'))
                })
            
            logger.debug(f"Found {len(file_systems)} EFS file systems in region {region}")
            return file_systems
            
        except ClientError as e:
            logger.error(f"Error retrieving EFS file systems in region {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving EFS file systems in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if EFS file system has encryption enabled."""
        fs_id = resource.get('FileSystemId', 'unknown')
        fs_arn = resource.get('FileSystemArn', 'unknown')
        encrypted = resource.get('Encrypted', False)
        kms_key_id = resource.get('KmsKeyId')
        
        if encrypted:
            compliance_status = ComplianceStatus.COMPLIANT
            evaluation_reason = f"EFS file system {fs_id} has encryption enabled"
            if kms_key_id:
                evaluation_reason += f" with KMS key: {kms_key_id}"
        else:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = f"EFS file system {fs_id} does not have encryption enabled"
        
        return ComplianceResult(
            resource_id=fs_arn or fs_id,
            resource_type="AWS::EFS::FileSystem",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for EFS encryption."""
        return [
            "Identify EFS file systems without encryption enabled",
            "For each unencrypted file system:",
            "  1. Create a new encrypted EFS file system",
            "  2. Copy data from the unencrypted file system to the encrypted one",
            "  3. Update applications to use the new encrypted file system",
            "  4. Test functionality with the encrypted file system",
            "  5. Delete the old unencrypted file system",
            "Note: Encryption cannot be enabled on existing EFS file systems",
            "Use AWS CLI: aws efs create-file-system --encrypted --kms-key-id <key-id>",
            "Use AWS DataSync or rsync to migrate data between file systems",
            "Plan for downtime during the migration process"
        ]


class EC2EBSEncryptionByDefaultAssessment(BaseConfigRuleAssessment):
    """Assessment for ec2-ebs-encryption-by-default Config rule."""
    
    def __init__(self):
        """Initialize EC2 EBS encryption by default assessment."""
        super().__init__(
            rule_name="ec2-ebs-encryption-by-default",
            control_id="3.11",
            resource_types=["AWS::::Account"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get account information for EBS encryption by default check."""
        if resource_type != "AWS::::Account":
            return []
        
        try:
            # Get account ID
            account_info = aws_factory.get_account_info()
            account_id = account_info.get('account_id', 'unknown')
            
            return [{
                'AccountId': account_id,
                'Region': region,
                'Type': 'Account'
            }]
            
        except Exception as e:
            logger.error(f"Error getting account information: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if EBS encryption by default is enabled."""
        account_id = resource.get('AccountId', 'unknown')
        
        try:
            ec2_client = aws_factory.get_client('ec2', region)
            
            # Check if EBS encryption by default is enabled
            response = aws_factory.aws_api_call_with_retry(
                lambda: ec2_client.get_ebs_encryption_by_default()
            )
            
            encryption_by_default = response.get('EbsEncryptionByDefault', False)
            
            if encryption_by_default:
                # Get the default KMS key
                try:
                    key_response = aws_factory.aws_api_call_with_retry(
                        lambda: ec2_client.get_ebs_default_kms_key_id()
                    )
                    default_key = key_response.get('KmsKeyId', 'AWS managed key')
                    
                    compliance_status = ComplianceStatus.COMPLIANT
                    evaluation_reason = f"Account {account_id} has EBS encryption by default enabled in region {region} with key: {default_key}"
                except ClientError:
                    compliance_status = ComplianceStatus.COMPLIANT
                    evaluation_reason = f"Account {account_id} has EBS encryption by default enabled in region {region}"
            else:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = f"Account {account_id} does not have EBS encryption by default enabled in region {region}"
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code in ['AccessDenied', 'UnauthorizedOperation']:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Insufficient permissions to check EBS encryption by default for account {account_id} in region {region}"
            else:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Error checking EBS encryption by default for account {account_id} in region {region}: {str(e)}"
        except Exception as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Unexpected error checking EBS encryption by default for account {account_id} in region {region}: {str(e)}"
        
        return ComplianceResult(
            resource_id=f"{account_id}-{region}",
            resource_type="AWS::::Account",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for EBS encryption by default."""
        return [
            "Enable EBS encryption by default in each AWS region",
            "For each region where it's not enabled:",
            "  1. Enable EBS encryption by default",
            "  2. Optionally set a customer-managed KMS key as default",
            "  3. Verify that new volumes are encrypted by default",
            "  4. Update any automation/scripts that create volumes",
            "Use AWS CLI: aws ec2 enable-ebs-encryption-by-default --region <region>",
            "Use AWS CLI: aws ec2 modify-ebs-default-kms-key-id --kms-key-id <key-id> --region <region>",
            "Note: This only affects new volumes; existing volumes remain unchanged",
            "Consider encrypting existing unencrypted volumes as needed"
        ]


class RDSSnapshotEncryptedAssessment(BaseConfigRuleAssessment):
    """Assessment for rds-snapshot-encrypted Config rule."""
    
    def __init__(self):
        """Initialize RDS snapshot encryption assessment."""
        super().__init__(
            rule_name="rds-snapshot-encrypted",
            control_id="3.11",
            resource_types=["AWS::RDS::DBSnapshot", "AWS::RDS::DBClusterSnapshot"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all RDS snapshots in the region."""
        resources = []
        
        try:
            rds_client = aws_factory.get_client('rds', region)
            
            if resource_type == "AWS::RDS::DBSnapshot":
                # Get DB snapshots
                response = aws_factory.aws_api_call_with_retry(
                    lambda: rds_client.describe_db_snapshots(SnapshotType='manual')
                )
                
                for snapshot in response.get('DBSnapshots', []):
                    resources.append({
                        'SnapshotId': snapshot.get('DBSnapshotIdentifier'),
                        'SnapshotArn': snapshot.get('DBSnapshotArn'),
                        'Type': 'DBSnapshot',
                        'Encrypted': snapshot.get('Encrypted', False),
                        'KmsKeyId': snapshot.get('KmsKeyId'),
                        'Status': snapshot.get('Status')
                    })
            
            elif resource_type == "AWS::RDS::DBClusterSnapshot":
                # Get DB cluster snapshots
                response = aws_factory.aws_api_call_with_retry(
                    lambda: rds_client.describe_db_cluster_snapshots(SnapshotType='manual')
                )
                
                for snapshot in response.get('DBClusterSnapshots', []):
                    resources.append({
                        'SnapshotId': snapshot.get('DBClusterSnapshotIdentifier'),
                        'SnapshotArn': snapshot.get('DBClusterSnapshotArn'),
                        'Type': 'DBClusterSnapshot',
                        'Encrypted': snapshot.get('StorageEncrypted', False),
                        'KmsKeyId': snapshot.get('KmsKeyId'),
                        'Status': snapshot.get('Status')
                    })
            
            logger.debug(f"Found {len(resources)} RDS {resource_type.split('::')[-1]}s in region {region}")
            return resources
            
        except ClientError as e:
            logger.error(f"Error retrieving RDS {resource_type} in region {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving RDS {resource_type} in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if RDS snapshot is encrypted."""
        snapshot_id = resource.get('SnapshotId', 'unknown')
        snapshot_arn = resource.get('SnapshotArn', 'unknown')
        snapshot_type = resource.get('Type', 'unknown')
        encrypted = resource.get('Encrypted', False)
        kms_key_id = resource.get('KmsKeyId')
        
        if encrypted:
            compliance_status = ComplianceStatus.COMPLIANT
            evaluation_reason = f"RDS {snapshot_type} {snapshot_id} is encrypted"
            if kms_key_id:
                evaluation_reason += f" with KMS key: {kms_key_id}"
        else:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = f"RDS {snapshot_type} {snapshot_id} is not encrypted"
        
        return ComplianceResult(
            resource_id=snapshot_arn or snapshot_id,
            resource_type=f"AWS::RDS::{snapshot_type}",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for RDS snapshot encryption."""
        return [
            "Identify unencrypted RDS snapshots",
            "For each unencrypted snapshot:",
            "  1. Create an encrypted copy of the snapshot",
            "  2. Verify the encrypted copy is complete and functional",
            "  3. Update any references to use the encrypted snapshot",
            "  4. Delete the unencrypted snapshot",
            "Use AWS CLI: aws rds copy-db-snapshot --source-db-snapshot-identifier <source> --target-db-snapshot-identifier <target> --kms-key-id <key-id>",
            "Use AWS CLI: aws rds copy-db-cluster-snapshot --source-db-cluster-snapshot-identifier <source> --target-db-cluster-snapshot-identifier <target> --kms-key-id <key-id>",
            "Ensure source databases have encryption enabled to prevent future unencrypted snapshots",
            "Implement policies to automatically encrypt snapshots"
        ]