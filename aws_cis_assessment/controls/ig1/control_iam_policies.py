"""IAM Policy Management assessments."""

from typing import Dict, List, Any
import logging
import json
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class IAMPolicyNoStatementsWithAdminAccessAssessment(BaseConfigRuleAssessment):
    """Assessment for iam-policy-no-statements-with-admin-access Config rule."""
    
    def __init__(self):
        """Initialize IAM policy admin access assessment."""
        super().__init__(
            rule_name="iam-policy-no-statements-with-admin-access",
            control_id="3.3",
            resource_types=["AWS::IAM::Policy"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all customer-managed IAM policies."""
        if resource_type != "AWS::IAM::Policy":
            return []
        
        try:
            iam_client = aws_factory.get_client('iam', region)
            
            # Get customer-managed policies only
            response = aws_factory.aws_api_call_with_retry(
                lambda: iam_client.list_policies(Scope='Local')
            )
            
            policies = []
            for policy in response.get('Policies', []):
                policies.append({
                    'PolicyName': policy.get('PolicyName'),
                    'PolicyId': policy.get('PolicyId'),
                    'Arn': policy.get('Arn'),
                    'DefaultVersionId': policy.get('DefaultVersionId'),
                    'CreateDate': policy.get('CreateDate')
                })
            
            logger.debug(f"Found {len(policies)} customer-managed IAM policies")
            return policies
            
        except ClientError as e:
            logger.error(f"Error retrieving IAM policies: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving IAM policies: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if IAM policy contains admin access statements."""
        policy_arn = resource.get('Arn', 'unknown')
        policy_name = resource.get('PolicyName', 'unknown')
        version_id = resource.get('DefaultVersionId', 'v1')
        
        try:
            iam_client = aws_factory.get_client('iam', region)
            
            # Get policy document
            policy_response = aws_factory.aws_api_call_with_retry(
                lambda: iam_client.get_policy_version(
                    PolicyArn=policy_arn,
                    VersionId=version_id
                )
            )
            
            policy_document = policy_response.get('PolicyVersion', {}).get('Document', {})
            
            # Check for admin access patterns
            admin_statements = []
            statements = policy_document.get('Statement', [])
            
            if not isinstance(statements, list):
                statements = [statements]
            
            for i, statement in enumerate(statements):
                if statement.get('Effect') == 'Allow':
                    actions = statement.get('Action', [])
                    resources = statement.get('Resource', [])
                    
                    if not isinstance(actions, list):
                        actions = [actions]
                    if not isinstance(resources, list):
                        resources = [resources]
                    
                    # Check for admin access pattern: Action: "*" and Resource: "*"
                    if '*' in actions and '*' in resources:
                        admin_statements.append(f"Statement {i+1}")
            
            if admin_statements:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = f"Policy {policy_name} contains admin access statements: {', '.join(admin_statements)}"
            else:
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = f"Policy {policy_name} does not contain admin access statements"
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code in ['AccessDenied', 'NoSuchEntity']:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Cannot access policy {policy_name}: {error_code}"
            else:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Error checking policy {policy_name}: {str(e)}"
        except Exception as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Unexpected error checking policy {policy_name}: {str(e)}"
        
        return ComplianceResult(
            resource_id=policy_arn,
            resource_type="AWS::IAM::Policy",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for admin access policies."""
        return [
            "Identify IAM policies with admin access statements (Action: '*', Resource: '*')",
            "For each policy with admin access:",
            "  1. Review the policy's purpose and usage",
            "  2. Identify specific permissions actually needed",
            "  3. Create a new policy version with least privilege permissions",
            "  4. Test the new policy with affected users/roles",
            "  5. Set the new version as default",
            "  6. Monitor for any access issues",
            "Use AWS CLI: aws iam create-policy-version --policy-arn <arn> --policy-document file://policy.json",
            "Consider using AWS managed policies for common use cases",
            "Implement regular policy reviews and access audits"
        ]


class IAMNoInlinePolicyCheckAssessment(BaseConfigRuleAssessment):
    """Assessment for iam-no-inline-policy-check Config rule."""
    
    def __init__(self):
        """Initialize IAM inline policy assessment."""
        super().__init__(
            rule_name="iam-no-inline-policy-check",
            control_id="3.3",
            resource_types=["AWS::IAM::User", "AWS::IAM::Role", "AWS::IAM::Group"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all IAM users, roles, and groups."""
        resources = []
        
        try:
            iam_client = aws_factory.get_client('iam', region)
            
            if resource_type == "AWS::IAM::User":
                response = aws_factory.aws_api_call_with_retry(
                    lambda: iam_client.list_users()
                )
                for user in response.get('Users', []):
                    resources.append({
                        'Type': 'User',
                        'Name': user.get('UserName'),
                        'Arn': user.get('Arn'),
                        'CreateDate': user.get('CreateDate')
                    })
            
            elif resource_type == "AWS::IAM::Role":
                response = aws_factory.aws_api_call_with_retry(
                    lambda: iam_client.list_roles()
                )
                for role in response.get('Roles', []):
                    resources.append({
                        'Type': 'Role',
                        'Name': role.get('RoleName'),
                        'Arn': role.get('Arn'),
                        'CreateDate': role.get('CreateDate')
                    })
            
            elif resource_type == "AWS::IAM::Group":
                response = aws_factory.aws_api_call_with_retry(
                    lambda: iam_client.list_groups()
                )
                for group in response.get('Groups', []):
                    resources.append({
                        'Type': 'Group',
                        'Name': group.get('GroupName'),
                        'Arn': group.get('Arn'),
                        'CreateDate': group.get('CreateDate')
                    })
            
            logger.debug(f"Found {len(resources)} IAM {resource_type.split('::')[-1].lower()}s")
            return resources
            
        except ClientError as e:
            logger.error(f"Error retrieving IAM {resource_type}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving IAM {resource_type}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if IAM entity has inline policies."""
        entity_type = resource.get('Type', 'unknown')
        entity_name = resource.get('Name', 'unknown')
        entity_arn = resource.get('Arn', 'unknown')
        
        try:
            iam_client = aws_factory.get_client('iam', region)
            
            inline_policies = []
            
            if entity_type == 'User':
                response = aws_factory.aws_api_call_with_retry(
                    lambda: iam_client.list_user_policies(UserName=entity_name)
                )
                inline_policies = response.get('PolicyNames', [])
                
            elif entity_type == 'Role':
                response = aws_factory.aws_api_call_with_retry(
                    lambda: iam_client.list_role_policies(RoleName=entity_name)
                )
                inline_policies = response.get('PolicyNames', [])
                
            elif entity_type == 'Group':
                response = aws_factory.aws_api_call_with_retry(
                    lambda: iam_client.list_group_policies(GroupName=entity_name)
                )
                inline_policies = response.get('PolicyNames', [])
            
            if inline_policies:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = f"{entity_type} {entity_name} has {len(inline_policies)} inline policy(ies): {', '.join(inline_policies)}"
            else:
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = f"{entity_type} {entity_name} has no inline policies"
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code in ['AccessDenied', 'NoSuchEntity']:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Cannot access {entity_type.lower()} {entity_name}: {error_code}"
            else:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Error checking {entity_type.lower()} {entity_name}: {str(e)}"
        except Exception as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Unexpected error checking {entity_type.lower()} {entity_name}: {str(e)}"
        
        return ComplianceResult(
            resource_id=entity_arn,
            resource_type=f"AWS::IAM::{entity_type}",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for inline policies."""
        return [
            "Identify IAM users, roles, and groups with inline policies",
            "For each entity with inline policies:",
            "  1. Review the inline policy permissions",
            "  2. Create equivalent managed policies",
            "  3. Attach the managed policies to the entity",
            "  4. Test that permissions work correctly",
            "  5. Remove the inline policies",
            "Use AWS CLI: aws iam create-policy --policy-name <name> --policy-document file://policy.json",
            "Use AWS CLI: aws iam attach-user-policy --user-name <user> --policy-arn <arn>",
            "Use AWS CLI: aws iam delete-user-policy --user-name <user> --policy-name <policy>",
            "Prefer AWS managed policies when available",
            "Implement governance to prevent future inline policy creation"
        ]


class IAMUserGroupMembershipCheckAssessment(BaseConfigRuleAssessment):
    """Assessment for iam-user-group-membership-check Config rule."""
    
    def __init__(self):
        """Initialize IAM user group membership assessment."""
        super().__init__(
            rule_name="iam-user-group-membership-check",
            control_id="3.3",
            resource_types=["AWS::IAM::User"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all IAM users."""
        if resource_type != "AWS::IAM::User":
            return []
        
        try:
            iam_client = aws_factory.get_client('iam', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: iam_client.list_users()
            )
            
            users = []
            for user in response.get('Users', []):
                users.append({
                    'UserName': user.get('UserName'),
                    'UserId': user.get('UserId'),
                    'Arn': user.get('Arn'),
                    'CreateDate': user.get('CreateDate')
                })
            
            logger.debug(f"Found {len(users)} IAM users")
            return users
            
        except ClientError as e:
            logger.error(f"Error retrieving IAM users: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving IAM users: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if IAM user is member of at least one group."""
        user_name = resource.get('UserName', 'unknown')
        user_arn = resource.get('Arn', 'unknown')
        
        try:
            iam_client = aws_factory.get_client('iam', region)
            
            # Get groups for user using list_groups_for_user (correct boto3 method)
            response = iam_client.list_groups_for_user(UserName=user_name)
            
            groups = response.get('Groups', [])
            
            if groups:
                group_names = [group.get('GroupName') for group in groups]
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = f"User {user_name} is member of {len(groups)} group(s): {', '.join(group_names)}"
            else:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = f"User {user_name} is not a member of any groups"
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code in ['AccessDenied', 'NoSuchEntity']:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Cannot access user {user_name}: {error_code}"
            else:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Error checking user {user_name}: {str(e)}"
        except Exception as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Unexpected error checking user {user_name}: {str(e)}"
        
        return ComplianceResult(
            resource_id=user_arn,
            resource_type="AWS::IAM::User",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for user group membership."""
        return [
            "Identify IAM users who are not members of any groups",
            "For each user without group membership:",
            "  1. Determine appropriate groups based on user's role/responsibilities",
            "  2. Create groups if they don't exist",
            "  3. Add the user to appropriate groups",
            "  4. Remove any direct policy attachments from the user",
            "  5. Verify the user has necessary permissions through group membership",
            "Use AWS CLI: aws iam add-user-to-group --user-name <user> --group-name <group>",
            "Use AWS CLI: aws iam detach-user-policy --user-name <user> --policy-arn <arn>",
            "Follow principle of least privilege when assigning group memberships",
            "Implement regular reviews of user group memberships"
        ]