"""Control 3.11: Encrypt Sensitive Data at Rest assessments."""

from typing import Dict, List, Any
import logging
import json
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class EncryptedVolumesAssessment(BaseConfigRuleAssessment):
    """Assessment for encrypted-volumes Config rule - ensures EBS volumes are encrypted."""
    
    def __init__(self):
        """Initialize encrypted volumes assessment."""
        super().__init__(
            rule_name="encrypted-volumes",
            control_id="3.11",
            resource_types=["AWS::EC2::Volume"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all EBS volumes in the region."""
        if resource_type != "AWS::EC2::Volume":
            return []
        
        try:
            ec2_client = aws_factory.get_client('ec2', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: ec2_client.describe_volumes()
            )
            
            volumes = []
            for volume in response.get('Volumes', []):
                volumes.append({
                    'VolumeId': volume.get('VolumeId'),
                    'VolumeType': volume.get('VolumeType'),
                    'Size': volume.get('Size'),
                    'State': volume.get('State'),
                    'Encrypted': volume.get('Encrypted', False),
                    'KmsKeyId': volume.get('KmsKeyId'),
                    'Attachments': volume.get('Attachments', []),
                    'Tags': volume.get('Tags', [])
                })
            
            logger.debug(f"Found {len(volumes)} EBS volumes in region {region}")
            return volumes
            
        except ClientError as e:
            logger.error(f"Error retrieving EBS volumes in region {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving EBS volumes in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if EBS volume is encrypted."""
        volume_id = resource.get('VolumeId', 'unknown')
        volume_type = resource.get('VolumeType', 'unknown')
        volume_state = resource.get('State', 'unknown')
        is_encrypted = resource.get('Encrypted', False)
        kms_key_id = resource.get('KmsKeyId')
        
        # Skip volumes that are being deleted
        if volume_state in ['deleting', 'deleted']:
            return ComplianceResult(
                resource_id=volume_id,
                resource_type="AWS::EC2::Volume",
                compliance_status=ComplianceStatus.NOT_APPLICABLE,
                evaluation_reason=f"EBS volume {volume_id} is in state '{volume_state}'",
                config_rule_name=self.rule_name,
                region=region
            )
        
        # Evaluate encryption status
        if is_encrypted:
            compliance_status = ComplianceStatus.COMPLIANT
            if kms_key_id:
                evaluation_reason = f"EBS volume {volume_id} ({volume_type}) is encrypted with KMS key {kms_key_id}"
            else:
                evaluation_reason = f"EBS volume {volume_id} ({volume_type}) is encrypted with default key"
        else:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = f"EBS volume {volume_id} ({volume_type}) is not encrypted"
        
        return ComplianceResult(
            resource_id=volume_id,
            resource_type="AWS::EC2::Volume",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for EBS volume encryption."""
        return [
            "Identify unencrypted EBS volumes",
            "For each unencrypted volume:",
            "  1. Create a snapshot of the unencrypted volume",
            "  2. Create an encrypted copy of the snapshot",
            "  3. Create a new encrypted volume from the encrypted snapshot",
            "  4. Stop the instance and detach the unencrypted volume",
            "  5. Attach the new encrypted volume to the instance",
            "  6. Start the instance and verify functionality",
            "Use AWS CLI: aws ec2 create-snapshot --volume-id <volume-id> --description 'Snapshot for encryption'",
            "Copy with encryption: aws ec2 copy-snapshot --source-region <region> --source-snapshot-id <snapshot-id> --encrypted --kms-key-id <key-id>",
            "Create encrypted volume: aws ec2 create-volume --snapshot-id <encrypted-snapshot-id> --availability-zone <az>",
            "Enable EBS encryption by default: aws ec2 enable-ebs-encryption-by-default",
            "Set default KMS key: aws ec2 modify-ebs-default-kms-key-id --kms-key-id <key-id>"
        ]


class RDSStorageEncryptedAssessment(BaseConfigRuleAssessment):
    """Assessment for rds-storage-encrypted Config rule - ensures RDS instances have storage encryption."""
    
    def __init__(self):
        """Initialize RDS storage encrypted assessment."""
        super().__init__(
            rule_name="rds-storage-encrypted",
            control_id="3.11",
            resource_types=["AWS::RDS::DBInstance"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all RDS instances in the region."""
        if resource_type != "AWS::RDS::DBInstance":
            return []
        
        try:
            rds_client = aws_factory.get_client('rds', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: rds_client.describe_db_instances()
            )
            
            instances = []
            for instance in response.get('DBInstances', []):
                instances.append({
                    'DBInstanceIdentifier': instance.get('DBInstanceIdentifier'),
                    'DBInstanceClass': instance.get('DBInstanceClass'),
                    'Engine': instance.get('Engine'),
                    'EngineVersion': instance.get('EngineVersion'),
                    'DBInstanceStatus': instance.get('DBInstanceStatus'),
                    'StorageEncrypted': instance.get('StorageEncrypted', False),
                    'KmsKeyId': instance.get('KmsKeyId'),
                    'AllocatedStorage': instance.get('AllocatedStorage'),
                    'StorageType': instance.get('StorageType'),
                    'TagList': instance.get('TagList', [])
                })
            
            logger.debug(f"Found {len(instances)} RDS instances in region {region}")
            return instances
            
        except ClientError as e:
            logger.error(f"Error retrieving RDS instances in region {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving RDS instances in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if RDS instance has storage encryption enabled."""
        db_identifier = resource.get('DBInstanceIdentifier', 'unknown')
        db_class = resource.get('DBInstanceClass', 'unknown')
        engine = resource.get('Engine', 'unknown')
        db_status = resource.get('DBInstanceStatus', 'unknown')
        storage_encrypted = resource.get('StorageEncrypted', False)
        kms_key_id = resource.get('KmsKeyId')
        
        # Skip instances that are not available
        if db_status not in ['available', 'backing-up', 'maintenance']:
            return ComplianceResult(
                resource_id=db_identifier,
                resource_type="AWS::RDS::DBInstance",
                compliance_status=ComplianceStatus.NOT_APPLICABLE,
                evaluation_reason=f"RDS instance {db_identifier} is in status '{db_status}'",
                config_rule_name=self.rule_name,
                region=region
            )
        
        # Evaluate encryption status
        if storage_encrypted:
            compliance_status = ComplianceStatus.COMPLIANT
            if kms_key_id:
                evaluation_reason = f"RDS instance {db_identifier} ({engine}) has storage encryption enabled with KMS key {kms_key_id}"
            else:
                evaluation_reason = f"RDS instance {db_identifier} ({engine}) has storage encryption enabled with default key"
        else:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = f"RDS instance {db_identifier} ({engine}) does not have storage encryption enabled"
        
        return ComplianceResult(
            resource_id=db_identifier,
            resource_type="AWS::RDS::DBInstance",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for RDS storage encryption."""
        return [
            "Identify RDS instances without storage encryption",
            "For each unencrypted RDS instance:",
            "  1. Create a snapshot of the unencrypted instance",
            "  2. Create an encrypted copy of the snapshot",
            "  3. Restore a new RDS instance from the encrypted snapshot",
            "  4. Update applications to use the new encrypted instance",
            "  5. Delete the old unencrypted instance after verification",
            "Use AWS CLI: aws rds create-db-snapshot --db-instance-identifier <instance-id> --db-snapshot-identifier <snapshot-id>",
            "Copy with encryption: aws rds copy-db-snapshot --source-db-snapshot-identifier <snapshot-id> --target-db-snapshot-identifier <encrypted-snapshot-id> --kms-key-id <key-id>",
            "Restore encrypted: aws rds restore-db-instance-from-db-snapshot --db-instance-identifier <new-instance-id> --db-snapshot-identifier <encrypted-snapshot-id>",
            "For new instances, enable encryption during creation: --storage-encrypted --kms-key-id <key-id>",
            "Update RDS parameter groups to enforce encryption where applicable"
        ]


class S3DefaultEncryptionKMSAssessment(BaseConfigRuleAssessment):
    """Assessment for s3-default-encryption-kms Config rule - ensures S3 buckets have default KMS encryption."""
    
    def __init__(self):
        """Initialize S3 default encryption KMS assessment."""
        super().__init__(
            rule_name="s3-default-encryption-kms",
            control_id="3.11",
            resource_types=["AWS::S3::Bucket"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all S3 buckets (S3 is global but we'll check from this region)."""
        if resource_type != "AWS::S3::Bucket":
            return []
        
        try:
            s3_client = aws_factory.get_client('s3', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: s3_client.list_buckets()
            )
            
            buckets = []
            for bucket in response.get('Buckets', []):
                bucket_name = bucket.get('Name')
                
                # Get bucket location to determine if we should evaluate it from this region
                try:
                    location_response = aws_factory.aws_api_call_with_retry(
                        lambda: s3_client.get_bucket_location(Bucket=bucket_name)
                    )
                    bucket_region = location_response.get('LocationConstraint')
                    
                    # Handle special case where us-east-1 returns None
                    if bucket_region is None:
                        bucket_region = 'us-east-1'
                    
                    # Only include buckets in this region or if we're in us-east-1 (global)
                    if bucket_region == region or region == 'us-east-1':
                        buckets.append({
                            'Name': bucket_name,
                            'CreationDate': bucket.get('CreationDate'),
                            'Region': bucket_region
                        })
                        
                except ClientError as e:
                    # If we can't get bucket location, skip this bucket
                    logger.warning(f"Could not get location for bucket {bucket_name}: {e}")
                    continue
            
            logger.debug(f"Found {len(buckets)} S3 buckets accessible from region {region}")
            return buckets
            
        except ClientError as e:
            logger.error(f"Error retrieving S3 buckets from region {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving S3 buckets from region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if S3 bucket has default KMS encryption enabled."""
        bucket_name = resource.get('Name', 'unknown')
        bucket_region = resource.get('Region', region)
        
        try:
            # Use the bucket's region for API calls
            s3_client = aws_factory.get_client('s3', bucket_region)
            
            # Get bucket encryption configuration
            try:
                encryption_response = aws_factory.aws_api_call_with_retry(
                    lambda: s3_client.get_bucket_encryption(Bucket=bucket_name)
                )
                
                server_side_encryption_config = encryption_response.get('ServerSideEncryptionConfiguration', {})
                rules = server_side_encryption_config.get('Rules', [])
                
                has_kms_encryption = False
                encryption_details = []
                
                for rule in rules:
                    apply_server_side_encryption = rule.get('ApplyServerSideEncryptionByDefault', {})
                    sse_algorithm = apply_server_side_encryption.get('SSEAlgorithm', '')
                    kms_master_key_id = apply_server_side_encryption.get('KMSMasterKeyID', '')
                    
                    encryption_details.append(f"{sse_algorithm}")
                    
                    if sse_algorithm == 'aws:kms':
                        has_kms_encryption = True
                
                if has_kms_encryption:
                    compliance_status = ComplianceStatus.COMPLIANT
                    evaluation_reason = f"S3 bucket {bucket_name} has default KMS encryption enabled ({', '.join(encryption_details)})"
                else:
                    compliance_status = ComplianceStatus.NON_COMPLIANT
                    if encryption_details:
                        evaluation_reason = f"S3 bucket {bucket_name} has encryption but not KMS ({', '.join(encryption_details)})"
                    else:
                        evaluation_reason = f"S3 bucket {bucket_name} has encryption configured but no KMS encryption found"
                
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', '')
                if error_code == 'ServerSideEncryptionConfigurationNotFoundError':
                    compliance_status = ComplianceStatus.NON_COMPLIANT
                    evaluation_reason = f"S3 bucket {bucket_name} has no default encryption configured"
                elif error_code in ['AccessDenied', 'UnauthorizedOperation']:
                    compliance_status = ComplianceStatus.ERROR
                    evaluation_reason = f"Insufficient permissions to check encryption for bucket {bucket_name}"
                else:
                    compliance_status = ComplianceStatus.ERROR
                    evaluation_reason = f"Error checking encryption for bucket {bucket_name}: {str(e)}"
            
        except Exception as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Unexpected error checking encryption for bucket {bucket_name}: {str(e)}"
        
        return ComplianceResult(
            resource_id=bucket_name,
            resource_type="AWS::S3::Bucket",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=bucket_region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for S3 default KMS encryption."""
        return [
            "Identify S3 buckets without default KMS encryption",
            "For each non-compliant bucket:",
            "  1. Create or identify a KMS key for S3 encryption",
            "  2. Configure default encryption with KMS for the bucket",
            "  3. Verify that new objects are encrypted with KMS",
            "Use AWS CLI: aws s3api put-bucket-encryption --bucket <bucket-name> --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"aws:kms\",\"KMSMasterKeyID\":\"<key-id>\"}}]}'",
            "Create KMS key if needed: aws kms create-key --description 'S3 bucket encryption key'",
            "Set bucket key for cost optimization: --server-side-encryption-configuration '{\"Rules\":[{\"ApplyServerSideEncryptionByDefault\":{\"SSEAlgorithm\":\"aws:kms\",\"KMSMasterKeyID\":\"<key-id>\"},\"BucketKeyEnabled\":true}]}'",
            "Update bucket policies to deny unencrypted uploads",
            "Test encryption by uploading objects and verifying encryption status"
        ]


class DynamoDBTableEncryptedKMSAssessment(BaseConfigRuleAssessment):
    """Assessment for dynamodb-table-encrypted-kms Config rule - ensures DynamoDB tables are encrypted with KMS."""
    
    def __init__(self):
        """Initialize DynamoDB table encrypted KMS assessment."""
        super().__init__(
            rule_name="dynamodb-table-encrypted-kms",
            control_id="3.11",
            resource_types=["AWS::DynamoDB::Table"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all DynamoDB tables in the region."""
        if resource_type != "AWS::DynamoDB::Table":
            return []
        
        try:
            dynamodb_client = aws_factory.get_client('dynamodb', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: dynamodb_client.list_tables()
            )
            
            table_names = response.get('TableNames', [])
            tables = []
            
            for table_name in table_names:
                try:
                    # Get detailed table information
                    table_response = aws_factory.aws_api_call_with_retry(
                        lambda: dynamodb_client.describe_table(TableName=table_name)
                    )
                    
                    table_info = table_response.get('Table', {})
                    tables.append({
                        'TableName': table_info.get('TableName'),
                        'TableStatus': table_info.get('TableStatus'),
                        'CreationDateTime': table_info.get('CreationDateTime'),
                        'SSEDescription': table_info.get('SSEDescription', {}),
                        'BillingModeSummary': table_info.get('BillingModeSummary', {}),
                        'TableSizeBytes': table_info.get('TableSizeBytes', 0)
                    })
                    
                except ClientError as e:
                    logger.warning(f"Could not describe table {table_name}: {e}")
                    continue
            
            logger.debug(f"Found {len(tables)} DynamoDB tables in region {region}")
            return tables
            
        except ClientError as e:
            logger.error(f"Error retrieving DynamoDB tables in region {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving DynamoDB tables in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if DynamoDB table is encrypted with KMS."""
        table_name = resource.get('TableName', 'unknown')
        table_status = resource.get('TableStatus', 'unknown')
        sse_description = resource.get('SSEDescription', {})
        
        # Skip tables that are not active
        if table_status not in ['ACTIVE']:
            return ComplianceResult(
                resource_id=table_name,
                resource_type="AWS::DynamoDB::Table",
                compliance_status=ComplianceStatus.NOT_APPLICABLE,
                evaluation_reason=f"DynamoDB table {table_name} is in status '{table_status}'",
                config_rule_name=self.rule_name,
                region=region
            )
        
        # Check encryption status
        sse_status = sse_description.get('Status', 'DISABLED')
        sse_type = sse_description.get('SSEType', '')
        kms_master_key_arn = sse_description.get('KMSMasterKeyArn', '')
        
        if sse_status == 'ENABLED':
            if sse_type == 'KMS':
                compliance_status = ComplianceStatus.COMPLIANT
                if kms_master_key_arn:
                    evaluation_reason = f"DynamoDB table {table_name} is encrypted with KMS key {kms_master_key_arn}"
                else:
                    evaluation_reason = f"DynamoDB table {table_name} is encrypted with KMS (default key)"
            else:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = f"DynamoDB table {table_name} is encrypted but not with KMS (type: {sse_type})"
        else:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = f"DynamoDB table {table_name} does not have encryption enabled"
        
        return ComplianceResult(
            resource_id=table_name,
            resource_type="AWS::DynamoDB::Table",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for DynamoDB KMS encryption."""
        return [
            "Identify DynamoDB tables without KMS encryption",
            "For each non-compliant table:",
            "  1. Create or identify a KMS key for DynamoDB encryption",
            "  2. Enable encryption at rest with KMS for the table",
            "  3. Verify encryption status after enabling",
            "Note: Encryption can only be enabled during table creation for existing tables",
            "For existing unencrypted tables:",
            "  1. Create a backup of the table data",
            "  2. Create a new table with KMS encryption enabled",
            "  3. Migrate data from old table to new encrypted table",
            "  4. Update applications to use the new table",
            "  5. Delete the old unencrypted table after verification",
            "Use AWS CLI for new tables: aws dynamodb create-table --table-name <table-name> --sse-specification Enabled=true,SSEType=KMS,KMSMasterKeyId=<key-id>",
            "Create KMS key if needed: aws kms create-key --description 'DynamoDB table encryption key'",
            "For point-in-time recovery, ensure backups are also encrypted"
        ]


class BackupRecoveryPointEncryptedAssessment(BaseConfigRuleAssessment):
    """Assessment for backup-recovery-point-encrypted Config rule - ensures AWS Backup recovery points are encrypted."""
    
    def __init__(self):
        """Initialize backup recovery point encrypted assessment."""
        super().__init__(
            rule_name="backup-recovery-point-encrypted",
            control_id="3.11",
            resource_types=["AWS::Backup::RecoveryPoint"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all AWS Backup recovery points in the region."""
        if resource_type != "AWS::Backup::RecoveryPoint":
            return []
        
        try:
            backup_client = aws_factory.get_client('backup', region)
            
            # First get all backup vaults
            vaults_response = aws_factory.aws_api_call_with_retry(
                lambda: backup_client.list_backup_vaults()
            )
            
            recovery_points = []
            
            for vault in vaults_response.get('BackupVaultList', []):
                vault_name = vault.get('BackupVaultName')
                
                try:
                    # Get recovery points for each vault
                    points_response = aws_factory.aws_api_call_with_retry(
                        lambda: backup_client.list_recovery_points_by_backup_vault(
                            BackupVaultName=vault_name
                        )
                    )
                    
                    for point in points_response.get('RecoveryPoints', []):
                        recovery_points.append({
                            'RecoveryPointArn': point.get('RecoveryPointArn'),
                            'BackupVaultName': vault_name,
                            'ResourceArn': point.get('ResourceArn'),
                            'ResourceType': point.get('ResourceType'),
                            'CreationDate': point.get('CreationDate'),
                            'Status': point.get('Status'),
                            'IsEncrypted': point.get('IsEncrypted', False),
                            'EncryptionKeyArn': point.get('EncryptionKeyArn'),
                            'BackupSizeInBytes': point.get('BackupSizeInBytes', 0)
                        })
                        
                except ClientError as e:
                    logger.warning(f"Could not get recovery points for vault {vault_name}: {e}")
                    continue
            
            logger.debug(f"Found {len(recovery_points)} backup recovery points in region {region}")
            return recovery_points
            
        except ClientError as e:
            logger.error(f"Error retrieving backup recovery points in region {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving backup recovery points in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if backup recovery point is encrypted."""
        recovery_point_arn = resource.get('RecoveryPointArn', 'unknown')
        vault_name = resource.get('BackupVaultName', 'unknown')
        resource_type = resource.get('ResourceType', 'unknown')
        status = resource.get('Status', 'unknown')
        is_encrypted = resource.get('IsEncrypted', False)
        encryption_key_arn = resource.get('EncryptionKeyArn')
        
        # Skip recovery points that are not completed
        if status not in ['COMPLETED']:
            return ComplianceResult(
                resource_id=recovery_point_arn,
                resource_type="AWS::Backup::RecoveryPoint",
                compliance_status=ComplianceStatus.NOT_APPLICABLE,
                evaluation_reason=f"Recovery point in vault {vault_name} is in status '{status}'",
                config_rule_name=self.rule_name,
                region=region
            )
        
        # Evaluate encryption status
        if is_encrypted:
            compliance_status = ComplianceStatus.COMPLIANT
            if encryption_key_arn:
                evaluation_reason = f"Recovery point for {resource_type} in vault {vault_name} is encrypted with key {encryption_key_arn}"
            else:
                evaluation_reason = f"Recovery point for {resource_type} in vault {vault_name} is encrypted"
        else:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = f"Recovery point for {resource_type} in vault {vault_name} is not encrypted"
        
        return ComplianceResult(
            resource_id=recovery_point_arn,
            resource_type="AWS::Backup::RecoveryPoint",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for backup recovery point encryption."""
        return [
            "Identify backup recovery points that are not encrypted",
            "For each non-compliant recovery point:",
            "  1. Review the backup vault encryption settings",
            "  2. Ensure backup vaults are configured with KMS encryption",
            "  3. Create new backups with encryption enabled",
            "  4. Consider deleting unencrypted recovery points after creating encrypted replacements",
            "Configure backup vault encryption: aws backup put-backup-vault-encryption --backup-vault-name <vault-name> --encryption-key-arn <kms-key-arn>",
            "Create KMS key for backups: aws kms create-key --description 'AWS Backup encryption key'",
            "Update backup plans to use encrypted vaults",
            "For existing unencrypted recovery points, create new encrypted backups and delete old ones",
            "Ensure backup policies require encryption for all new backups"
        ]


class EFSEncryptedCheckAssessment(BaseConfigRuleAssessment):
    """Assessment for efs-encrypted-check Config rule - ensures EFS file systems are encrypted."""
    
    def __init__(self):
        """Initialize EFS encrypted check assessment."""
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
                    'CreationToken': fs.get('CreationToken'),
                    'LifeCycleState': fs.get('LifeCycleState'),
                    'Encrypted': fs.get('Encrypted', False),
                    'KmsKeyId': fs.get('KmsKeyId'),
                    'PerformanceMode': fs.get('PerformanceMode'),
                    'ThroughputMode': fs.get('ThroughputMode'),
                    'Tags': fs.get('Tags', [])
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
        """Evaluate if EFS file system is encrypted."""
        fs_id = resource.get('FileSystemId', 'unknown')
        lifecycle_state = resource.get('LifeCycleState', 'unknown')
        is_encrypted = resource.get('Encrypted', False)
        kms_key_id = resource.get('KmsKeyId')
        
        # Skip file systems that are not available
        if lifecycle_state not in ['available']:
            return ComplianceResult(
                resource_id=fs_id,
                resource_type="AWS::EFS::FileSystem",
                compliance_status=ComplianceStatus.NOT_APPLICABLE,
                evaluation_reason=f"EFS file system {fs_id} is in state '{lifecycle_state}'",
                config_rule_name=self.rule_name,
                region=region
            )
        
        # Evaluate encryption status
        if is_encrypted:
            compliance_status = ComplianceStatus.COMPLIANT
            if kms_key_id:
                evaluation_reason = f"EFS file system {fs_id} is encrypted with KMS key {kms_key_id}"
            else:
                evaluation_reason = f"EFS file system {fs_id} is encrypted with default key"
        else:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = f"EFS file system {fs_id} is not encrypted"
        
        return ComplianceResult(
            resource_id=fs_id,
            resource_type="AWS::EFS::FileSystem",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for EFS encryption."""
        return [
            "Identify EFS file systems that are not encrypted",
            "For each unencrypted file system:",
            "  1. Create a backup of the file system data",
            "  2. Create a new encrypted EFS file system",
            "  3. Copy data from the unencrypted file system to the encrypted one",
            "  4. Update mount targets and applications to use the new encrypted file system",
            "  5. Delete the old unencrypted file system after verification",
            "Note: Encryption can only be enabled during file system creation",
            "Use AWS CLI: aws efs create-file-system --creation-token <token> --encrypted --kms-key-id <key-id>",
            "Create KMS key if needed: aws kms create-key --description 'EFS encryption key'",
            "Use AWS DataSync to copy data between file systems",
            "Update EC2 instances and applications to mount the new encrypted file system",
            "For new file systems, always enable encryption during creation"
        ]


class SecretsManagerUsingKMSKeyAssessment(BaseConfigRuleAssessment):
    """Assessment for secretsmanager-using-cmk Config rule - ensures Secrets Manager secrets use KMS keys."""
    
    def __init__(self):
        """Initialize Secrets Manager KMS key assessment."""
        super().__init__(
            rule_name="secretsmanager-using-cmk",
            control_id="3.11",
            resource_types=["AWS::SecretsManager::Secret"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all Secrets Manager secrets in the region."""
        if resource_type != "AWS::SecretsManager::Secret":
            return []
        
        try:
            secretsmanager_client = aws_factory.get_client('secretsmanager', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: secretsmanager_client.list_secrets()
            )
            
            secrets = []
            for secret in response.get('SecretList', []):
                secrets.append({
                    'ARN': secret.get('ARN'),
                    'Name': secret.get('Name'),
                    'Description': secret.get('Description', ''),
                    'KmsKeyId': secret.get('KmsKeyId'),
                    'CreatedDate': secret.get('CreatedDate'),
                    'LastChangedDate': secret.get('LastChangedDate'),
                    'Tags': secret.get('Tags', [])
                })
            
            logger.debug(f"Found {len(secrets)} Secrets Manager secrets in region {region}")
            return secrets
            
        except ClientError as e:
            logger.error(f"Error retrieving Secrets Manager secrets in region {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving Secrets Manager secrets in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if Secrets Manager secret uses KMS key."""
        secret_arn = resource.get('ARN', 'unknown')
        secret_name = resource.get('Name', 'unknown')
        kms_key_id = resource.get('KmsKeyId')
        
        # Check if secret uses KMS key
        if kms_key_id:
            # Check if it's using a customer-managed key (not the default AWS managed key)
            if kms_key_id.startswith('alias/aws/secretsmanager'):
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = f"Secret {secret_name} uses AWS managed key instead of customer managed key"
            else:
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = f"Secret {secret_name} uses customer managed KMS key {kms_key_id}"
        else:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = f"Secret {secret_name} does not specify a KMS key (using default encryption)"
        
        return ComplianceResult(
            resource_id=secret_arn,
            resource_type="AWS::SecretsManager::Secret",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for Secrets Manager KMS encryption."""
        return [
            "Identify Secrets Manager secrets not using customer managed KMS keys",
            "For each non-compliant secret:",
            "  1. Create or identify a customer managed KMS key",
            "  2. Update the secret to use the customer managed KMS key",
            "  3. Verify the secret is encrypted with the new key",
            "Create KMS key: aws kms create-key --description 'Secrets Manager encryption key'",
            "Update secret: aws secretsmanager update-secret --secret-id <secret-name> --kms-key-id <key-id>",
            "For new secrets, specify KMS key during creation: --kms-key-id <key-id>",
            "Ensure proper IAM permissions for the KMS key",
            "Consider key rotation policies for enhanced security"
        ]


class SNSTopicEncryptedKMSAssessment(BaseConfigRuleAssessment):
    """Assessment for sns-encrypted-kms Config rule - ensures SNS topics are encrypted with KMS."""
    
    def __init__(self):
        """Initialize SNS topic encrypted KMS assessment."""
        super().__init__(
            rule_name="sns-encrypted-kms",
            control_id="3.11",
            resource_types=["AWS::SNS::Topic"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all SNS topics in the region."""
        if resource_type != "AWS::SNS::Topic":
            return []
        
        try:
            sns_client = aws_factory.get_client('sns', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: sns_client.list_topics()
            )
            
            topics = []
            for topic in response.get('Topics', []):
                topic_arn = topic.get('TopicArn')
                
                try:
                    # Get topic attributes to check encryption
                    attrs_response = aws_factory.aws_api_call_with_retry(
                        lambda: sns_client.get_topic_attributes(TopicArn=topic_arn)
                    )
                    
                    attributes = attrs_response.get('Attributes', {})
                    topics.append({
                        'TopicArn': topic_arn,
                        'DisplayName': attributes.get('DisplayName', ''),
                        'KmsMasterKeyId': attributes.get('KmsMasterKeyId'),
                        'Policy': attributes.get('Policy', ''),
                        'SubscriptionsConfirmed': attributes.get('SubscriptionsConfirmed', '0'),
                        'SubscriptionsPending': attributes.get('SubscriptionsPending', '0')
                    })
                    
                except ClientError as e:
                    logger.warning(f"Could not get attributes for topic {topic_arn}: {e}")
                    continue
            
            logger.debug(f"Found {len(topics)} SNS topics in region {region}")
            return topics
            
        except ClientError as e:
            logger.error(f"Error retrieving SNS topics in region {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving SNS topics in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if SNS topic is encrypted with KMS."""
        topic_arn = resource.get('TopicArn', 'unknown')
        display_name = resource.get('DisplayName', '')
        kms_master_key_id = resource.get('KmsMasterKeyId')
        
        topic_name = topic_arn.split(':')[-1] if ':' in topic_arn else topic_arn
        
        # Check if topic uses KMS encryption
        if kms_master_key_id:
            compliance_status = ComplianceStatus.COMPLIANT
            evaluation_reason = f"SNS topic {topic_name} is encrypted with KMS key {kms_master_key_id}"
        else:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = f"SNS topic {topic_name} is not encrypted with KMS"
        
        return ComplianceResult(
            resource_id=topic_arn,
            resource_type="AWS::SNS::Topic",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for SNS KMS encryption."""
        return [
            "Identify SNS topics without KMS encryption",
            "For each non-compliant topic:",
            "  1. Create or identify a KMS key for SNS encryption",
            "  2. Set the KmsMasterKeyId attribute for the topic",
            "  3. Verify encryption is enabled",
            "Create KMS key: aws kms create-key --description 'SNS topic encryption key'",
            "Enable encryption: aws sns set-topic-attributes --topic-arn <topic-arn> --attribute-name KmsMasterKeyId --attribute-value <key-id>",
            "For new topics, specify KMS key during creation: --attributes KmsMasterKeyId=<key-id>",
            "Update IAM policies to allow SNS to use the KMS key",
            "Test message publishing and subscription after enabling encryption"
        ]


class SQSQueueEncryptedKMSAssessment(BaseConfigRuleAssessment):
    """Assessment for sqs-queue-encrypted-kms Config rule - ensures SQS queues are encrypted with KMS."""
    
    def __init__(self):
        """Initialize SQS queue encrypted KMS assessment."""
        super().__init__(
            rule_name="sqs-queue-encrypted-kms",
            control_id="3.11",
            resource_types=["AWS::SQS::Queue"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all SQS queues in the region."""
        if resource_type != "AWS::SQS::Queue":
            return []
        
        try:
            sqs_client = aws_factory.get_client('sqs', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: sqs_client.list_queues()
            )
            
            queue_urls = response.get('QueueUrls', [])
            queues = []
            
            for queue_url in queue_urls:
                try:
                    # Get queue attributes to check encryption
                    attrs_response = aws_factory.aws_api_call_with_retry(
                        lambda: sqs_client.get_queue_attributes(
                            QueueUrl=queue_url,
                            AttributeNames=['All']
                        )
                    )
                    
                    attributes = attrs_response.get('Attributes', {})
                    queue_name = queue_url.split('/')[-1]
                    
                    queues.append({
                        'QueueUrl': queue_url,
                        'QueueName': queue_name,
                        'KmsMasterKeyId': attributes.get('KmsMasterKeyId'),
                        'KmsDataKeyReusePeriodSeconds': attributes.get('KmsDataKeyReusePeriodSeconds'),
                        'ApproximateNumberOfMessages': attributes.get('ApproximateNumberOfMessages', '0'),
                        'CreatedTimestamp': attributes.get('CreatedTimestamp')
                    })
                    
                except ClientError as e:
                    logger.warning(f"Could not get attributes for queue {queue_url}: {e}")
                    continue
            
            logger.debug(f"Found {len(queues)} SQS queues in region {region}")
            return queues
            
        except ClientError as e:
            logger.error(f"Error retrieving SQS queues in region {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving SQS queues in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if SQS queue is encrypted with KMS."""
        queue_url = resource.get('QueueUrl', 'unknown')
        queue_name = resource.get('QueueName', 'unknown')
        kms_master_key_id = resource.get('KmsMasterKeyId')
        
        # Check if queue uses KMS encryption
        if kms_master_key_id:
            compliance_status = ComplianceStatus.COMPLIANT
            evaluation_reason = f"SQS queue {queue_name} is encrypted with KMS key {kms_master_key_id}"
        else:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = f"SQS queue {queue_name} is not encrypted with KMS"
        
        return ComplianceResult(
            resource_id=queue_url,
            resource_type="AWS::SQS::Queue",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for SQS KMS encryption."""
        return [
            "Identify SQS queues without KMS encryption",
            "For each non-compliant queue:",
            "  1. Create or identify a KMS key for SQS encryption",
            "  2. Set the KmsMasterKeyId attribute for the queue",
            "  3. Optionally configure KmsDataKeyReusePeriodSeconds",
            "Create KMS key: aws kms create-key --description 'SQS queue encryption key'",
            "Enable encryption: aws sqs set-queue-attributes --queue-url <queue-url> --attributes KmsMasterKeyId=<key-id>",
            "For new queues, specify KMS key during creation: --attributes KmsMasterKeyId=<key-id>",
            "Update IAM policies to allow SQS to use the KMS key",
            "Test message sending and receiving after enabling encryption"
        ]


class CloudWatchLogsEncryptedAssessment(BaseConfigRuleAssessment):
    """Assessment for cloudwatch-log-group-encrypted Config rule - ensures CloudWatch log groups are encrypted."""
    
    def __init__(self):
        """Initialize CloudWatch logs encrypted assessment."""
        super().__init__(
            rule_name="cloudwatch-log-group-encrypted",
            control_id="3.11",
            resource_types=["AWS::Logs::LogGroup"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all CloudWatch log groups in the region."""
        if resource_type != "AWS::Logs::LogGroup":
            return []
        
        try:
            logs_client = aws_factory.get_client('logs', region)
            
            log_groups = []
            next_token = None
            
            while True:
                if next_token:
                    response = aws_factory.aws_api_call_with_retry(
                        lambda: logs_client.describe_log_groups(nextToken=next_token)
                    )
                else:
                    response = aws_factory.aws_api_call_with_retry(
                        lambda: logs_client.describe_log_groups()
                    )
                
                for log_group in response.get('logGroups', []):
                    log_groups.append({
                        'logGroupName': log_group.get('logGroupName'),
                        'logGroupArn': log_group.get('arn'),
                        'creationTime': log_group.get('creationTime'),
                        'retentionInDays': log_group.get('retentionInDays'),
                        'kmsKeyId': log_group.get('kmsKeyId'),
                        'storedBytes': log_group.get('storedBytes', 0)
                    })
                
                next_token = response.get('nextToken')
                if not next_token:
                    break
            
            logger.debug(f"Found {len(log_groups)} CloudWatch log groups in region {region}")
            return log_groups
            
        except ClientError as e:
            logger.error(f"Error retrieving CloudWatch log groups in region {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving CloudWatch log groups in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if CloudWatch log group is encrypted."""
        log_group_name = resource.get('logGroupName', 'unknown')
        log_group_arn = resource.get('logGroupArn', 'unknown')
        kms_key_id = resource.get('kmsKeyId')
        
        # Check if log group uses KMS encryption
        if kms_key_id:
            compliance_status = ComplianceStatus.COMPLIANT
            evaluation_reason = f"CloudWatch log group {log_group_name} is encrypted with KMS key {kms_key_id}"
        else:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = f"CloudWatch log group {log_group_name} is not encrypted with KMS"
        
        return ComplianceResult(
            resource_id=log_group_arn or log_group_name,
            resource_type="AWS::Logs::LogGroup",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for CloudWatch logs KMS encryption."""
        return [
            "Identify CloudWatch log groups without KMS encryption",
            "For each non-compliant log group:",
            "  1. Create or identify a KMS key for CloudWatch logs encryption",
            "  2. Associate the KMS key with the log group",
            "  3. Verify encryption is enabled",
            "Create KMS key: aws kms create-key --description 'CloudWatch logs encryption key'",
            "Associate key: aws logs associate-kms-key --log-group-name <log-group-name> --kms-key-id <key-id>",
            "For new log groups, specify KMS key during creation: --kms-key-id <key-id>",
            "Update IAM policies to allow CloudWatch Logs to use the KMS key",
            "Test log ingestion after enabling encryption"
        ]


class KinesisStreamEncryptedAssessment(BaseConfigRuleAssessment):
    """Assessment for kinesis-stream-encrypted Config rule - ensures Kinesis streams are encrypted."""
    
    def __init__(self):
        """Initialize Kinesis stream encrypted assessment."""
        super().__init__(
            rule_name="kinesis-stream-encrypted",
            control_id="3.11",
            resource_types=["AWS::Kinesis::Stream"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all Kinesis streams in the region."""
        if resource_type != "AWS::Kinesis::Stream":
            return []
        
        try:
            kinesis_client = aws_factory.get_client('kinesis', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: kinesis_client.list_streams()
            )
            
            stream_names = response.get('StreamNames', [])
            streams = []
            
            for stream_name in stream_names:
                try:
                    # Get stream details
                    stream_response = aws_factory.aws_api_call_with_retry(
                        lambda: kinesis_client.describe_stream(StreamName=stream_name)
                    )
                    
                    stream_description = stream_response.get('StreamDescription', {})
                    streams.append({
                        'StreamName': stream_description.get('StreamName'),
                        'StreamARN': stream_description.get('StreamARN'),
                        'StreamStatus': stream_description.get('StreamStatus'),
                        'StreamCreationTimestamp': stream_description.get('StreamCreationTimestamp'),
                        'EncryptionType': stream_description.get('EncryptionType'),
                        'KeyId': stream_description.get('KeyId'),
                        'ShardCount': len(stream_description.get('Shards', []))
                    })
                    
                except ClientError as e:
                    logger.warning(f"Could not describe stream {stream_name}: {e}")
                    continue
            
            logger.debug(f"Found {len(streams)} Kinesis streams in region {region}")
            return streams
            
        except ClientError as e:
            logger.error(f"Error retrieving Kinesis streams in region {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving Kinesis streams in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if Kinesis stream is encrypted."""
        stream_name = resource.get('StreamName', 'unknown')
        stream_arn = resource.get('StreamARN', 'unknown')
        stream_status = resource.get('StreamStatus', 'unknown')
        encryption_type = resource.get('EncryptionType')
        key_id = resource.get('KeyId')
        
        # Skip streams that are not active
        if stream_status not in ['ACTIVE']:
            return ComplianceResult(
                resource_id=stream_arn or stream_name,
                resource_type="AWS::Kinesis::Stream",
                compliance_status=ComplianceStatus.NOT_APPLICABLE,
                evaluation_reason=f"Kinesis stream {stream_name} is in status '{stream_status}'",
                config_rule_name=self.rule_name,
                region=region
            )
        
        # Check encryption status
        if encryption_type == 'KMS':
            compliance_status = ComplianceStatus.COMPLIANT
            if key_id:
                evaluation_reason = f"Kinesis stream {stream_name} is encrypted with KMS key {key_id}"
            else:
                evaluation_reason = f"Kinesis stream {stream_name} is encrypted with KMS"
        elif encryption_type == 'NONE' or not encryption_type:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = f"Kinesis stream {stream_name} is not encrypted"
        else:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = f"Kinesis stream {stream_name} uses unsupported encryption type: {encryption_type}"
        
        return ComplianceResult(
            resource_id=stream_arn or stream_name,
            resource_type="AWS::Kinesis::Stream",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for Kinesis stream encryption."""
        return [
            "Identify Kinesis streams without encryption",
            "For each non-compliant stream:",
            "  1. Create or identify a KMS key for Kinesis encryption",
            "  2. Enable server-side encryption for the stream",
            "  3. Verify encryption is active",
            "Create KMS key: aws kms create-key --description 'Kinesis stream encryption key'",
            "Enable encryption: aws kinesis enable-stream-encryption --stream-name <stream-name> --encryption-type KMS --key-id <key-id>",
            "For new streams, specify encryption during creation: --encryption-type KMS --key-id <key-id>",
            "Update IAM policies to allow Kinesis to use the KMS key",
            "Test data ingestion and consumption after enabling encryption"
        ]


class ElasticSearchDomainEncryptedAssessment(BaseConfigRuleAssessment):
    """Assessment for elasticsearch-encrypted-at-rest Config rule - ensures Elasticsearch domains are encrypted at rest."""
    
    def __init__(self):
        """Initialize Elasticsearch domain encrypted assessment."""
        super().__init__(
            rule_name="elasticsearch-encrypted-at-rest",
            control_id="3.11",
            resource_types=["AWS::Elasticsearch::Domain"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all Elasticsearch domains in the region."""
        if resource_type != "AWS::Elasticsearch::Domain":
            return []
        
        try:
            es_client = aws_factory.get_client('es', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: es_client.list_domain_names()
            )
            
            domain_names = [domain['DomainName'] for domain in response.get('DomainNames', [])]
            domains = []
            
            for domain_name in domain_names:
                try:
                    # Get domain details
                    domain_response = aws_factory.aws_api_call_with_retry(
                        lambda: es_client.describe_elasticsearch_domain(DomainName=domain_name)
                    )
                    
                    domain_status = domain_response.get('DomainStatus', {})
                    encryption_at_rest = domain_status.get('EncryptionAtRestOptions', {})
                    
                    domains.append({
                        'DomainName': domain_status.get('DomainName'),
                        'DomainId': domain_status.get('DomainId'),
                        'ARN': domain_status.get('ARN'),
                        'Created': domain_status.get('Created'),
                        'Processing': domain_status.get('Processing'),
                        'EncryptionAtRestEnabled': encryption_at_rest.get('Enabled', False),
                        'KmsKeyId': encryption_at_rest.get('KmsKeyId'),
                        'ElasticsearchVersion': domain_status.get('ElasticsearchVersion')
                    })
                    
                except ClientError as e:
                    logger.warning(f"Could not describe Elasticsearch domain {domain_name}: {e}")
                    continue
            
            logger.debug(f"Found {len(domains)} Elasticsearch domains in region {region}")
            return domains
            
        except ClientError as e:
            logger.error(f"Error retrieving Elasticsearch domains in region {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving Elasticsearch domains in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if Elasticsearch domain has encryption at rest enabled."""
        domain_name = resource.get('DomainName', 'unknown')
        domain_arn = resource.get('ARN', 'unknown')
        is_processing = resource.get('Processing', False)
        encryption_enabled = resource.get('EncryptionAtRestEnabled', False)
        kms_key_id = resource.get('KmsKeyId')
        
        # Skip domains that are being processed
        if is_processing:
            return ComplianceResult(
                resource_id=domain_arn or domain_name,
                resource_type="AWS::Elasticsearch::Domain",
                compliance_status=ComplianceStatus.NOT_APPLICABLE,
                evaluation_reason=f"Elasticsearch domain {domain_name} is currently being processed",
                config_rule_name=self.rule_name,
                region=region
            )
        
        # Check encryption status
        if encryption_enabled:
            compliance_status = ComplianceStatus.COMPLIANT
            if kms_key_id:
                evaluation_reason = f"Elasticsearch domain {domain_name} has encryption at rest enabled with KMS key {kms_key_id}"
            else:
                evaluation_reason = f"Elasticsearch domain {domain_name} has encryption at rest enabled"
        else:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = f"Elasticsearch domain {domain_name} does not have encryption at rest enabled"
        
        return ComplianceResult(
            resource_id=domain_arn or domain_name,
            resource_type="AWS::Elasticsearch::Domain",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for Elasticsearch encryption at rest."""
        return [
            "Identify Elasticsearch domains without encryption at rest",
            "For each non-compliant domain:",
            "  1. Create a snapshot of the domain data",
            "  2. Create a new domain with encryption at rest enabled",
            "  3. Restore data from snapshot to the new encrypted domain",
            "  4. Update applications to use the new encrypted domain",
            "  5. Delete the old unencrypted domain after verification",
            "Note: Encryption at rest can only be enabled during domain creation",
            "Create KMS key: aws kms create-key --description 'Elasticsearch encryption key'",
            "Create encrypted domain: aws es create-elasticsearch-domain --domain-name <domain-name> --encryption-at-rest-options Enabled=true,KmsKeyId=<key-id>",
            "Use domain migration tools or manual reindexing to move data",
            "For new domains, always enable encryption at rest during creation"
        ]