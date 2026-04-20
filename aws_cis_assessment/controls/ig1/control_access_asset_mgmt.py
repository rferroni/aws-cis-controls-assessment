"""
CIS Control 5.3, 4.1 - Access and Asset Management
Ensures proper access tracking and asset authorization.
"""

import logging
from typing import List, Dict, Any
from datetime import datetime, timedelta
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class IAMUserLastAccessCheckAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 5.3 - Disable Dormant Accounts
    AWS Config Rule: iam-user-last-access-check
    
    Ensures IAM users have been accessed recently (within 90 days).
    """
    
    def __init__(self):
        super().__init__(
            rule_name="iam-user-last-access-check",
            control_id="5.3",
            resource_types=["AWS::IAM::User"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get IAM users with last access information."""
        if resource_type != "AWS::IAM::User":
            return []
        
        # IAM is global, only process in us-east-1
        if region != 'us-east-1':
            return []
        
        try:
            iam_client = aws_factory.get_client('iam', region)
            users = []
            
            paginator = iam_client.get_paginator('list_users')
            for page in paginator.paginate():
                for user in page.get('Users', []):
                    user_name = user.get('UserName')
                    
                    try:
                        # Get user details with last access info
                        user_detail = iam_client.get_user(UserName=user_name)
                        user_info = user_detail.get('User', {})
                        
                        password_last_used = user_info.get('PasswordLastUsed')
                        
                        # Get access key last used
                        access_keys = iam_client.list_access_keys(UserName=user_name)
                        last_key_used = None
                        
                        for key in access_keys.get('AccessKeyMetadata', []):
                            key_id = key.get('AccessKeyId')
                            try:
                                key_last_used = iam_client.get_access_key_last_used(AccessKeyId=key_id)
                                key_used_date = key_last_used.get('AccessKeyLastUsed', {}).get('LastUsedDate')
                                if key_used_date:
                                    if not last_key_used or key_used_date > last_key_used:
                                        last_key_used = key_used_date
                            except ClientError:
                                pass
                        
                        # Determine most recent access
                        last_access = None
                        if password_last_used and last_key_used:
                            last_access = max(password_last_used, last_key_used)
                        elif password_last_used:
                            last_access = password_last_used
                        elif last_key_used:
                            last_access = last_key_used
                        
                        # Check if accessed within 90 days
                        days_since_access = None
                        is_dormant = False
                        
                        if last_access:
                            days_since_access = (datetime.now(last_access.tzinfo) - last_access).days
                            is_dormant = days_since_access > 90
                        else:
                            # Never accessed
                            is_dormant = True
                            days_since_access = -1
                        
                        users.append({
                            'UserName': user_name,
                            'Arn': user.get('Arn'),
                            'LastAccess': last_access,
                            'DaysSinceAccess': days_since_access,
                            'IsDormant': is_dormant
                        })
                    
                    except ClientError as e:
                        logger.warning(f"Error getting details for user {user_name}: {e}")
                        continue
            
            return users
            
        except ClientError as e:
            logger.error(f"Error retrieving IAM users: {e}")
            return []
    
    def _evaluate_resource_compliance(
        self, 
        resource: Dict[str, Any], 
        aws_factory: AWSClientFactory, 
        region: str
    ) -> ComplianceResult:
        """Evaluate if IAM user has been accessed recently."""
        user_name = resource.get('UserName', 'unknown')
        is_dormant = resource.get('IsDormant', False)
        days_since_access = resource.get('DaysSinceAccess', -1)
        
        if not is_dormant:
            if days_since_access >= 0:
                evaluation_reason = f"IAM user '{user_name}' accessed {days_since_access} days ago"
            else:
                evaluation_reason = f"IAM user '{user_name}' has recent access"
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            if days_since_access == -1:
                evaluation_reason = f"IAM user '{user_name}' has never been accessed"
            else:
                evaluation_reason = f"IAM user '{user_name}' not accessed in {days_since_access} days (>90 days)"
            compliance_status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceResult(
            resource_id=resource.get('Arn', user_name),
            resource_type="AWS::IAM::User",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get remediation steps for dormant user accounts."""
        return [
            "1. List users with last access time:",
            "   aws iam get-credential-report",
            "   aws iam generate-credential-report",
            "",
            "2. Disable dormant user:",
            "   aws iam delete-login-profile --user-name <user-name>",
            "   aws iam update-access-key --user-name <user-name> --access-key-id <key-id> --status Inactive",
            "",
            "3. Delete dormant user (after verification):",
            "   aws iam delete-user --user-name <user-name>",
            "",
            "Priority: MEDIUM - Reduces attack surface",
            "Effort: Low - Simple deactivation",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_finding-unused.html"
        ]


class SSMSessionManagerEnabledAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 12.4 - Establish and Maintain Architecture Diagram(s)
    AWS Config Rule: ssm-session-manager-enabled
    
    Ensures Systems Manager Session Manager is available for secure instance access.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="ssm-session-manager-enabled",
            control_id="12.4",
            resource_types=["AWS::EC2::Instance"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get EC2 instances and check Session Manager availability."""
        if resource_type != "AWS::EC2::Instance":
            return []
        
        try:
            ssm_client = aws_factory.get_client('ssm', region)
            
            # Get managed instances
            response = ssm_client.describe_instance_information()
            managed_instances = {
                inst.get('InstanceId'): inst 
                for inst in response.get('InstanceInformationList', [])
            }
            
            # Get all EC2 instances
            ec2_client = aws_factory.get_client('ec2', region)
            ec2_response = ec2_client.describe_instances()
            
            instances = []
            for reservation in ec2_response.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instance_id = instance.get('InstanceId')
                    state = instance.get('State', {}).get('Name')
                    
                    # Only check running instances
                    if state == 'running':
                        is_managed = instance_id in managed_instances
                        
                        instances.append({
                            'InstanceId': instance_id,
                            'State': state,
                            'IsManaged': is_managed
                        })
            
            return instances
            
        except ClientError as e:
            logger.error(f"Error checking Session Manager in {region}: {e}")
            return []
    
    def _evaluate_resource_compliance(
        self, 
        resource: Dict[str, Any], 
        aws_factory: AWSClientFactory, 
        region: str
    ) -> ComplianceResult:
        """Evaluate if instance has Session Manager enabled."""
        instance_id = resource.get('InstanceId', 'unknown')
        is_managed = resource.get('IsManaged', False)
        
        if is_managed:
            evaluation_reason = f"Instance {instance_id} is managed by Systems Manager"
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            evaluation_reason = f"Instance {instance_id} is not managed by Systems Manager"
            compliance_status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceResult(
            resource_id=instance_id,
            resource_type="AWS::EC2::Instance",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get remediation steps for enabling Session Manager."""
        return [
            "1. Attach IAM role to EC2 instance:",
            "   aws ec2 associate-iam-instance-profile \\",
            "     --instance-id <instance-id> \\",
            "     --iam-instance-profile Name=SSMInstanceProfile",
            "",
            "2. Ensure SSM agent is installed and running",
            "3. Verify instance appears in Systems Manager:",
            "   aws ssm describe-instance-information",
            "",
            "Priority: MEDIUM - Improves secure access",
            "Effort: Low - Attach IAM role",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/systems-manager/latest/userguide/session-manager.html"
        ]


class UnauthorizedAssetDetectionAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 1.1 - Establish and Maintain Detailed Enterprise Asset Inventory
    AWS Config Rule: unauthorized-asset-detection
    
    Detects resources without proper authorization tags.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="unauthorized-asset-detection",
            control_id="1.1",
            resource_types=["AWS::EC2::Instance"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get EC2 instances and check for authorization tags."""
        if resource_type != "AWS::EC2::Instance":
            return []
        
        try:
            ec2_client = aws_factory.get_client('ec2', region)
            
            response = ec2_client.describe_instances()
            instances = []
            
            for reservation in response.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                    
                    # Check for authorization tags
                    has_authorization = bool(
                        tags.get('Authorized') == 'true' or 
                        tags.get('Approved') == 'true' or
                        tags.get('Owner')
                    )
                    
                    instances.append({
                        'InstanceId': instance.get('InstanceId'),
                        'Tags': tags,
                        'HasAuthorization': has_authorization
                    })
            
            return instances
            
        except ClientError as e:
            logger.error(f"Error retrieving EC2 instances in {region}: {e}")
            return []
    
    def _evaluate_resource_compliance(
        self, 
        resource: Dict[str, Any], 
        aws_factory: AWSClientFactory, 
        region: str
    ) -> ComplianceResult:
        """Evaluate if instance has authorization tags."""
        instance_id = resource.get('InstanceId', 'unknown')
        has_authorization = resource.get('HasAuthorization', False)
        
        if has_authorization:
            evaluation_reason = f"Instance {instance_id} has authorization tags"
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            evaluation_reason = f"Instance {instance_id} missing authorization tags (Authorized, Approved, or Owner)"
            compliance_status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceResult(
            resource_id=instance_id,
            resource_type="AWS::EC2::Instance",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get remediation steps for unauthorized asset detection."""
        return [
            "1. Tag authorized resources:",
            "   aws ec2 create-tags \\",
            "     --resources <instance-id> \\",
            "     --tags Key=Authorized,Value=true Key=Owner,Value=team-name",
            "",
            "2. Investigate unauthorized resources",
            "3. Terminate or tag unauthorized instances",
            "",
            "Priority: HIGH - Security risk from unauthorized assets",
            "Effort: Low - Tagging or termination",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_Tags.html"
        ]
