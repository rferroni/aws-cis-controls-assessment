"""Control 4.1: Establish and Maintain a Secure Configuration Process assessments."""

from typing import Dict, List, Any
import logging
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class AccountPartOfOrganizationsAssessment(BaseConfigRuleAssessment):
    """Assessment for account-part-of-organizations Config rule."""
    
    def __init__(self):
        """Initialize account part of organizations assessment."""
        super().__init__(
            rule_name="account-part-of-organizations",
            control_id="4.1",
            resource_types=["AWS::::Account"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get account information."""
        if resource_type != "AWS::::Account":
            return []
        
        try:
            # Get account information (use allow_global_region for account-level resources)
            sts_client = aws_factory.get_client('sts', region, allow_global_region=True)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: sts_client.get_caller_identity()
            )
            
            account_id = response.get('Account')
            
            return [{
                'AccountId': account_id,
                'Arn': response.get('Arn'),
                'UserId': response.get('UserId')
            }]
            
        except ClientError as e:
            logger.error(f"Error retrieving account information: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving account information: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if account is part of AWS Organizations."""
        account_id = resource.get('AccountId', 'unknown')
        
        try:
            # Check if account is part of an organization (use allow_global_region for account-level resources)
            organizations_client = aws_factory.get_client('organizations', region, allow_global_region=True)
            
            # Try to describe the organization
            response = aws_factory.aws_api_call_with_retry(
                lambda: organizations_client.describe_organization()
            )
            
            organization = response.get('Organization', {})
            org_id = organization.get('Id')
            master_account_id = organization.get('MasterAccountId')
            
            if org_id:
                compliance_status = ComplianceStatus.COMPLIANT
                if account_id == master_account_id:
                    evaluation_reason = f"Account {account_id} is the master account of organization {org_id}"
                else:
                    evaluation_reason = f"Account {account_id} is a member of organization {org_id}"
            else:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = f"Account {account_id} is not part of any AWS Organization"
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'AWSOrganizationsNotInUseException':
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = f"Account {account_id} is not part of any AWS Organization"
            elif error_code in ['AccessDenied', 'UnauthorizedOperation']:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Insufficient permissions to check organization status for account {account_id}"
            else:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Error checking organization status for account {account_id}: {str(e)}"
        except Exception as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Unexpected error checking organization status for account {account_id}: {str(e)}"
        
        return ComplianceResult(
            resource_id=account_id,
            resource_type="AWS::::Account",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for accounts not in organizations."""
        return [
            "Create an AWS Organization or join an existing one:",
            "  1. Sign in to the AWS Organizations console with master account credentials",
            "  2. Choose 'Create organization' to create a new organization",
            "  3. Or accept an invitation to join an existing organization",
            "Benefits of AWS Organizations:",
            "  - Centralized billing and cost management",
            "  - Service Control Policies (SCPs) for governance",
            "  - Consolidated CloudTrail logging",
            "  - Cross-account resource sharing",
            "Use AWS CLI: aws organizations create-organization --feature-set ALL",
            "Or join: aws organizations accept-handshake --handshake-id <handshake-id>",
            "Configure Service Control Policies for additional security governance"
        ]


class EC2VolumeInUseAssessment(BaseConfigRuleAssessment):
    """Assessment for ec2-volume-inuse-check Config rule."""
    
    def __init__(self):
        """Initialize EC2 volume in use assessment."""
        super().__init__(
            rule_name="ec2-volume-inuse-check",
            control_id="4.1",
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
                    'State': volume.get('State'),
                    'Size': volume.get('Size'),
                    'VolumeType': volume.get('VolumeType'),
                    'Attachments': volume.get('Attachments', []),
                    'CreateTime': volume.get('CreateTime'),
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
        """Evaluate if EBS volume is attached to an instance."""
        volume_id = resource.get('VolumeId', 'unknown')
        state = resource.get('State', 'unknown')
        attachments = resource.get('Attachments', [])
        
        # Check if volume is attached
        if attachments:
            # Volume is attached
            attachment = attachments[0]  # EBS volumes can only be attached to one instance
            instance_id = attachment.get('InstanceId', 'unknown')
            attachment_state = attachment.get('State', 'unknown')
            
            if attachment_state == 'attached':
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = f"Volume {volume_id} is attached to instance {instance_id}"
            else:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = f"Volume {volume_id} attachment is in state '{attachment_state}'"
        else:
            # Volume is not attached
            if state == 'available':
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = f"Volume {volume_id} is available but not attached to any instance"
            elif state == 'creating':
                compliance_status = ComplianceStatus.NOT_APPLICABLE
                evaluation_reason = f"Volume {volume_id} is still being created"
            elif state == 'deleting':
                compliance_status = ComplianceStatus.NOT_APPLICABLE
                evaluation_reason = f"Volume {volume_id} is being deleted"
            else:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = f"Volume {volume_id} is in state '{state}' and not attached"
        
        return ComplianceResult(
            resource_id=volume_id,
            resource_type="AWS::EC2::Volume",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for unattached volumes."""
        return [
            "Identify EBS volumes that are not attached to any EC2 instances",
            "For each unattached volume, determine if it's still needed:",
            "  - If needed: Attach the volume to an appropriate EC2 instance",
            "  - If not needed: Create a snapshot for backup, then delete the volume",
            "To attach a volume:",
            "  1. Ensure the volume and instance are in the same Availability Zone",
            "  2. Use AWS CLI: aws ec2 attach-volume --volume-id <vol-id> --instance-id <instance-id> --device /dev/sdf",
            "  3. Mount the volume inside the instance if needed",
            "To delete unused volumes:",
            "  1. Create snapshot: aws ec2 create-snapshot --volume-id <vol-id> --description 'Backup before deletion'",
            "  2. Delete volume: aws ec2 delete-volume --volume-id <vol-id>",
            "Set up monitoring to alert on unattached volumes to prevent unnecessary costs"
        ]


class RedshiftClusterMaintenanceSettingsAssessment(BaseConfigRuleAssessment):
    """Assessment for redshift-cluster-maintenancesettings-check Config rule."""
    
    def __init__(self):
        """Initialize Redshift cluster maintenance settings assessment."""
        super().__init__(
            rule_name="redshift-cluster-maintenancesettings-check",
            control_id="4.1",
            resource_types=["AWS::Redshift::Cluster"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all Redshift clusters in the region."""
        if resource_type != "AWS::Redshift::Cluster":
            return []
        
        try:
            redshift_client = aws_factory.get_client('redshift', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: redshift_client.describe_clusters()
            )
            
            clusters = []
            for cluster in response.get('Clusters', []):
                clusters.append({
                    'ClusterIdentifier': cluster.get('ClusterIdentifier'),
                    'ClusterStatus': cluster.get('ClusterStatus'),
                    'AutomatedSnapshotRetentionPeriod': cluster.get('AutomatedSnapshotRetentionPeriod'),
                    'PreferredMaintenanceWindow': cluster.get('PreferredMaintenanceWindow'),
                    'AllowVersionUpgrade': cluster.get('AllowVersionUpgrade'),
                    'ClusterVersion': cluster.get('ClusterVersion'),
                    'Tags': cluster.get('Tags', [])
                })
            
            logger.debug(f"Found {len(clusters)} Redshift clusters in region {region}")
            return clusters
            
        except ClientError as e:
            logger.error(f"Error retrieving Redshift clusters in region {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving Redshift clusters in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if Redshift cluster has proper maintenance settings."""
        cluster_id = resource.get('ClusterIdentifier', 'unknown')
        status = resource.get('ClusterStatus', 'unknown')
        
        # Only evaluate available clusters
        if status != 'available':
            return ComplianceResult(
                resource_id=cluster_id,
                resource_type="AWS::Redshift::Cluster",
                compliance_status=ComplianceStatus.NOT_APPLICABLE,
                evaluation_reason=f"Cluster {cluster_id} is in state '{status}', not available",
                config_rule_name=self.rule_name,
                region=region
            )
        
        # Check maintenance settings
        automated_snapshot_retention = resource.get('AutomatedSnapshotRetentionPeriod', 0)
        maintenance_window = resource.get('PreferredMaintenanceWindow')
        allow_version_upgrade = resource.get('AllowVersionUpgrade', False)
        
        compliance_issues = []
        
        # Check automated snapshot retention (should be > 0)
        if automated_snapshot_retention <= 0:
            compliance_issues.append("Automated snapshot retention is disabled")
        
        # Check if maintenance window is configured
        if not maintenance_window:
            compliance_issues.append("No preferred maintenance window configured")
        
        # Check if version upgrades are allowed
        if not allow_version_upgrade:
            compliance_issues.append("Automatic version upgrades are disabled")
        
        if compliance_issues:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = f"Cluster {cluster_id} has maintenance issues: {'; '.join(compliance_issues)}"
        else:
            compliance_status = ComplianceStatus.COMPLIANT
            evaluation_reason = f"Cluster {cluster_id} has proper maintenance settings configured"
        
        return ComplianceResult(
            resource_id=cluster_id,
            resource_type="AWS::Redshift::Cluster",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for Redshift maintenance settings."""
        return [
            "Configure proper maintenance settings for Redshift clusters:",
            "1. Enable automated snapshots:",
            "   - Set retention period to at least 1 day (recommended: 7-35 days)",
            "   - Use AWS CLI: aws redshift modify-cluster --cluster-identifier <cluster-id> --automated-snapshot-retention-period 7",
            "2. Configure preferred maintenance window:",
            "   - Choose a low-traffic time window",
            "   - Use AWS CLI: aws redshift modify-cluster --cluster-identifier <cluster-id> --preferred-maintenance-window 'sun:05:00-sun:06:00'",
            "3. Enable automatic version upgrades:",
            "   - Use AWS CLI: aws redshift modify-cluster --cluster-identifier <cluster-id> --allow-version-upgrade",
            "4. Monitor cluster maintenance events and plan for major version upgrades",
            "5. Test maintenance procedures in non-production environments first"
        ]


class SecretsManagerRotationEnabledAssessment(BaseConfigRuleAssessment):
    """Assessment for secretsmanager-rotation-enabled-check Config rule."""
    
    def __init__(self):
        """Initialize Secrets Manager rotation enabled assessment."""
        super().__init__(
            rule_name="secretsmanager-rotation-enabled-check",
            control_id="4.1",
            resource_types=["AWS::SecretsManager::Secret"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all Secrets Manager secrets in the region."""
        if resource_type != "AWS::SecretsManager::Secret":
            return []
        
        try:
            secretsmanager_client = aws_factory.get_client('secretsmanager', region)
            
            # List all secrets
            response = aws_factory.aws_api_call_with_retry(
                lambda: secretsmanager_client.list_secrets()
            )
            
            secrets = []
            for secret in response.get('SecretList', []):
                # Get detailed information about each secret
                secret_arn = secret.get('ARN')
                try:
                    detail_response = aws_factory.aws_api_call_with_retry(
                        lambda: secretsmanager_client.describe_secret(SecretId=secret_arn)
                    )
                    
                    secrets.append({
                        'ARN': detail_response.get('ARN'),
                        'Name': detail_response.get('Name'),
                        'Description': detail_response.get('Description'),
                        'RotationEnabled': detail_response.get('RotationEnabled', False),
                        'RotationLambdaARN': detail_response.get('RotationLambdaARN'),
                        'RotationRules': detail_response.get('RotationRules', {}),
                        'LastRotatedDate': detail_response.get('LastRotatedDate'),
                        'Tags': detail_response.get('Tags', [])
                    })
                    
                except ClientError as e:
                    logger.warning(f"Could not describe secret {secret_arn}: {e}")
                    # Add basic info even if we can't get details
                    secrets.append({
                        'ARN': secret.get('ARN'),
                        'Name': secret.get('Name'),
                        'RotationEnabled': False,
                        'Error': str(e)
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
        """Evaluate if Secrets Manager secret has rotation enabled."""
        secret_arn = resource.get('ARN', 'unknown')
        secret_name = resource.get('Name', 'unknown')
        rotation_enabled = resource.get('RotationEnabled', False)
        
        # Check if there was an error getting secret details
        if 'Error' in resource:
            return ComplianceResult(
                resource_id=secret_arn,
                resource_type="AWS::SecretsManager::Secret",
                compliance_status=ComplianceStatus.ERROR,
                evaluation_reason=f"Could not evaluate secret {secret_name}: {resource['Error']}",
                config_rule_name=self.rule_name,
                region=region
            )
        
        if rotation_enabled:
            rotation_lambda = resource.get('RotationLambdaARN')
            rotation_rules = resource.get('RotationRules', {})
            rotation_interval = rotation_rules.get('AutomaticallyAfterDays', 'unknown')
            
            compliance_status = ComplianceStatus.COMPLIANT
            evaluation_reason = f"Secret {secret_name} has rotation enabled"
            if rotation_lambda:
                evaluation_reason += f" with Lambda function {rotation_lambda}"
            if rotation_interval != 'unknown':
                evaluation_reason += f" (interval: {rotation_interval} days)"
        else:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = f"Secret {secret_name} does not have rotation enabled"
        
        return ComplianceResult(
            resource_id=secret_arn,
            resource_type="AWS::SecretsManager::Secret",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for secrets without rotation."""
        return [
            "Enable automatic rotation for Secrets Manager secrets:",
            "1. For RDS/Aurora database credentials:",
            "   - Use AWS CLI: aws secretsmanager rotate-secret --secret-id <secret-arn> --rotation-rules AutomaticallyAfterDays=30",
            "   - AWS will automatically create the rotation Lambda function",
            "2. For other secrets, create a custom rotation Lambda function:",
            "   - Create Lambda function with appropriate permissions",
            "   - Configure rotation: aws secretsmanager update-secret --secret-id <secret-arn> --rotation-lambda-arn <lambda-arn>",
            "3. Set appropriate rotation interval (recommended: 30-90 days)",
            "4. Test rotation functionality in non-production environment first",
            "5. Monitor rotation events and failures through CloudWatch",
            "6. Ensure applications can handle secret rotation gracefully",
            "7. Consider using AWS SDK features for automatic secret retrieval"
        ]