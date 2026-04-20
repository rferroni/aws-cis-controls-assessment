"""Access Keys Rotation and Management assessments."""

from typing import Dict, List, Any
import logging
from datetime import datetime, timezone, timedelta
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class AccessKeysRotatedAssessment(BaseConfigRuleAssessment):
    """Assessment for access-keys-rotated Config rule."""
    
    def __init__(self, max_access_key_age: int = 90):
        """Initialize access keys rotation assessment."""
        super().__init__(
            rule_name="access-keys-rotated",
            control_id="4.1",
            resource_types=["AWS::IAM::User"],
            parameters={"maxAccessKeyAge": max_access_key_age}
        )
        self.max_access_key_age = max_access_key_age
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all IAM users with access keys."""
        if resource_type != "AWS::IAM::User":
            return []
        
        try:
            iam_client = aws_factory.get_client('iam', region)
            
            # Get all users
            users_response = aws_factory.aws_api_call_with_retry(
                lambda: iam_client.list_users()
            )
            
            users_with_keys = []
            for user in users_response.get('Users', []):
                user_name = user.get('UserName')
                
                # Get access keys for each user
                try:
                    keys_response = aws_factory.aws_api_call_with_retry(
                        lambda: iam_client.list_access_keys(UserName=user_name)
                    )
                    
                    access_keys = keys_response.get('AccessKeyMetadata', [])
                    if access_keys:
                        users_with_keys.append({
                            'UserName': user_name,
                            'UserId': user.get('UserId'),
                            'CreateDate': user.get('CreateDate'),
                            'AccessKeys': access_keys
                        })
                        
                except ClientError as e:
                    logger.debug(f"Cannot access keys for user {user_name}: {e}")
                    continue
            
            logger.debug(f"Found {len(users_with_keys)} IAM users with access keys")
            return users_with_keys
            
        except ClientError as e:
            logger.error(f"Error retrieving IAM users: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving IAM users: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if IAM user's access keys are rotated within the specified timeframe."""
        user_name = resource.get('UserName', 'unknown')
        access_keys = resource.get('AccessKeys', [])
        
        now = datetime.now(timezone.utc)
        old_keys = []
        compliant_keys = []
        
        for key in access_keys:
            if key.get('Status') == 'Active':
                create_date = key.get('CreateDate')
                if isinstance(create_date, datetime):
                    if create_date.tzinfo is None:
                        create_date = create_date.replace(tzinfo=timezone.utc)
                    
                    age_days = (now - create_date).days
                    
                    if age_days > self.max_access_key_age:
                        old_keys.append({
                            'AccessKeyId': key.get('AccessKeyId'),
                            'Age': age_days
                        })
                    else:
                        compliant_keys.append({
                            'AccessKeyId': key.get('AccessKeyId'),
                            'Age': age_days
                        })
        
        if old_keys:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            key_details = [f"{key['AccessKeyId']} ({key['Age']} days old)" for key in old_keys]
            evaluation_reason = f"User {user_name} has {len(old_keys)} access key(s) older than {self.max_access_key_age} days: {', '.join(key_details)}"
        elif compliant_keys:
            compliance_status = ComplianceStatus.COMPLIANT
            evaluation_reason = f"User {user_name} has {len(compliant_keys)} access key(s) within rotation period"
        else:
            compliance_status = ComplianceStatus.NOT_APPLICABLE
            evaluation_reason = f"User {user_name} has no active access keys"
        
        return ComplianceResult(
            resource_id=user_name,
            resource_type="AWS::IAM::User",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for access key rotation."""
        return [
            f"Identify IAM users with access keys older than {self.max_access_key_age} days",
            "For each user with old access keys:",
            "  1. Create a new access key for the user",
            "  2. Update applications/services to use the new access key",
            "  3. Test that applications work with the new key",
            "  4. Deactivate the old access key",
            "  5. Monitor for any issues, then delete the old key",
            "Use AWS CLI: aws iam create-access-key --user-name <username>",
            "Use AWS CLI: aws iam delete-access-key --user-name <username> --access-key-id <old-key-id>",
            "Set up automated access key rotation using AWS Secrets Manager or custom solutions",
            "Implement monitoring and alerting for access key age"
        ]


class EC2IMDSv2CheckAssessment(BaseConfigRuleAssessment):
    """Assessment for ec2-imdsv2-check Config rule."""
    
    def __init__(self):
        """Initialize EC2 IMDSv2 assessment."""
        super().__init__(
            rule_name="ec2-imdsv2-check",
            control_id="3.3",
            resource_types=["AWS::EC2::Instance"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all EC2 instances in the region."""
        if resource_type != "AWS::EC2::Instance":
            return []
        
        try:
            ec2_client = aws_factory.get_client('ec2', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: ec2_client.describe_instances()
            )
            
            instances = []
            for reservation in response.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    if instance.get('State', {}).get('Name') in ['running', 'stopped']:
                        instances.append({
                            'InstanceId': instance.get('InstanceId'),
                            'State': instance.get('State', {}),
                            'MetadataOptions': instance.get('MetadataOptions', {}),
                            'InstanceType': instance.get('InstanceType'),
                            'Tags': instance.get('Tags', [])
                        })
            
            logger.debug(f"Found {len(instances)} EC2 instances in region {region}")
            return instances
            
        except ClientError as e:
            logger.error(f"Error retrieving EC2 instances in region {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving EC2 instances in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if EC2 instance requires IMDSv2."""
        instance_id = resource.get('InstanceId', 'unknown')
        metadata_options = resource.get('MetadataOptions', {})
        
        # Check if IMDSv2 is required
        http_tokens = metadata_options.get('HttpTokens', 'optional')
        http_endpoint = metadata_options.get('HttpEndpoint', 'enabled')
        
        if http_endpoint == 'disabled':
            compliance_status = ComplianceStatus.COMPLIANT
            evaluation_reason = f"Instance {instance_id} has metadata service disabled"
        elif http_tokens == 'required':
            compliance_status = ComplianceStatus.COMPLIANT
            evaluation_reason = f"Instance {instance_id} requires IMDSv2 (HttpTokens: required)"
        else:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = f"Instance {instance_id} allows IMDSv1 (HttpTokens: {http_tokens})"
        
        return ComplianceResult(
            resource_id=instance_id,
            resource_type="AWS::EC2::Instance",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for IMDSv2 enforcement."""
        return [
            "Identify EC2 instances that allow IMDSv1 access",
            "For each instance, enforce IMDSv2:",
            "  1. Test applications to ensure IMDSv2 compatibility",
            "  2. Stop the instance (if required for modification)",
            "  3. Modify instance metadata options to require IMDSv2",
            "  4. Start the instance and verify functionality",
            "Use AWS CLI: aws ec2 modify-instance-metadata-options --instance-id <id> --http-tokens required",
            "Update launch templates and Auto Scaling groups to enforce IMDSv2 by default",
            "Monitor applications for any IMDSv1 dependencies",
            "Consider setting HttpPutResponseHopLimit to 1 for additional security"
        ]


class EC2InstanceProfileAttachedAssessment(BaseConfigRuleAssessment):
    """Assessment for ec2-instance-profile-attached Config rule."""
    
    def __init__(self):
        """Initialize EC2 instance profile assessment."""
        super().__init__(
            rule_name="ec2-instance-profile-attached",
            control_id="3.3",
            resource_types=["AWS::EC2::Instance"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all EC2 instances in the region."""
        if resource_type != "AWS::EC2::Instance":
            return []
        
        try:
            ec2_client = aws_factory.get_client('ec2', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: ec2_client.describe_instances()
            )
            
            instances = []
            for reservation in response.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    if instance.get('State', {}).get('Name') in ['running', 'stopped']:
                        instances.append({
                            'InstanceId': instance.get('InstanceId'),
                            'State': instance.get('State', {}),
                            'IamInstanceProfile': instance.get('IamInstanceProfile'),
                            'InstanceType': instance.get('InstanceType'),
                            'Tags': instance.get('Tags', [])
                        })
            
            logger.debug(f"Found {len(instances)} EC2 instances in region {region}")
            return instances
            
        except ClientError as e:
            logger.error(f"Error retrieving EC2 instances in region {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving EC2 instances in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if EC2 instance has an IAM instance profile attached."""
        instance_id = resource.get('InstanceId', 'unknown')
        iam_instance_profile = resource.get('IamInstanceProfile')
        
        if iam_instance_profile:
            profile_arn = iam_instance_profile.get('Arn', 'unknown')
            compliance_status = ComplianceStatus.COMPLIANT
            evaluation_reason = f"Instance {instance_id} has IAM instance profile attached: {profile_arn}"
        else:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = f"Instance {instance_id} does not have an IAM instance profile attached"
        
        return ComplianceResult(
            resource_id=instance_id,
            resource_type="AWS::EC2::Instance",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for instance profile attachment."""
        return [
            "Identify EC2 instances without IAM instance profiles",
            "For each instance, attach an appropriate IAM instance profile:",
            "  1. Create an IAM role with necessary permissions",
            "  2. Create an instance profile and add the role to it",
            "  3. Stop the instance (if required)",
            "  4. Associate the instance profile with the instance",
            "  5. Start the instance and verify functionality",
            "Use AWS CLI: aws ec2 associate-iam-instance-profile --instance-id <id> --iam-instance-profile Name=<profile>",
            "Follow principle of least privilege when creating IAM roles",
            "Update launch templates to include instance profiles by default",
            "Monitor and audit instance profile usage regularly"
        ]