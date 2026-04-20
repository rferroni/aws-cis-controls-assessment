"""
CIS Control 2.4-2.7, 2.15 - Access Control and MFA Controls
Ensures proper access control mechanisms and multi-factor authentication.
"""

import logging
from typing import List, Dict, Any
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class SSOEnabledCheckAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 2.4 - Centralize Account Management
    AWS Config Rule: sso-enabled-check
    
    Ensures AWS Single Sign-On (SSO) / Identity Center is enabled
    for centralized identity management.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="sso-enabled-check",
            control_id="2.4",
            resource_types=["AWS::::Account"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get SSO/Identity Center configuration for the account."""
        if resource_type != "AWS::::Account":
            return []
        
        # SSO is a global service, only check in us-east-1
        if region != 'us-east-1':
            return []
        
        try:
            sso_admin_client = aws_factory.get_client('sso-admin', region)
            
            # List SSO instances
            response = sso_admin_client.list_instances()
            instances = response.get('Instances', [])
            
            has_sso = len(instances) > 0
            
            instance_info = []
            for instance in instances:
                instance_arn = instance.get('InstanceArn', '')
                identity_store_id = instance.get('IdentityStoreId', '')
                
                instance_info.append({
                    'InstanceArn': instance_arn,
                    'IdentityStoreId': identity_store_id
                })
            
            return [{
                'AccountId': aws_factory.get_account_info().get('account_id', 'unknown'),
                'Region': region,
                'HasSSO': has_sso,
                'InstanceCount': len(instances),
                'Instances': instance_info
            }]
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'AccessDeniedException':
                logger.warning(f"Access denied to check SSO in {region}")
            else:
                logger.error(f"Error checking SSO in {region}: {e}")
            return []
    
    def _evaluate_resource_compliance(
        self, 
        resource: Dict[str, Any], 
        aws_factory: AWSClientFactory, 
        region: str
    ) -> ComplianceResult:
        """Evaluate if SSO/Identity Center is enabled."""
        account_id = resource.get('AccountId', 'unknown')
        has_sso = resource.get('HasSSO', False)
        instance_count = resource.get('InstanceCount', 0)
        
        is_compliant = has_sso
        
        if is_compliant:
            evaluation_reason = (
                f"AWS SSO (Identity Center) is enabled with {instance_count} instance(s). "
                f"Centralized identity management is configured."
            )
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            evaluation_reason = (
                "AWS SSO (Identity Center) is not enabled. "
                "Consider enabling SSO for centralized identity management and single sign-on."
            )
            compliance_status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceResult(
            resource_id=account_id,
            resource_type="AWS::::Account",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get remediation steps for enabling SSO."""
        return [
            "1. Enable AWS SSO (Identity Center) via Console:",
            "   - Navigate to AWS IAM Identity Center (successor to AWS SSO)",
            "   - Click 'Enable'",
            "   - Choose identity source:",
            "     * Identity Center directory (default)",
            "     * Active Directory",
            "     * External identity provider (SAML 2.0)",
            "   - Complete the setup wizard",
            "",
            "2. Note: AWS SSO cannot be enabled via CLI directly",
            "   You must use the AWS Console or AWS Organizations",
            "",
            "3. Configure identity source:",
            "   - For Identity Center directory:",
            "     * Add users and groups directly",
            "     * Manage within Identity Center",
            "   ",
            "   - For Active Directory:",
            "     * Connect AWS Managed Microsoft AD",
            "     * Or connect self-managed AD via AD Connector",
            "   ",
            "   - For external IdP:",
            "     * Configure SAML 2.0 integration",
            "     * Upload IdP metadata",
            "",
            "4. Create permission sets:",
            "   - Navigate to 'Permission sets'",
            "   - Click 'Create permission set'",
            "   - Choose predefined or custom policies",
            "   - Define session duration",
            "   - Add tags (optional)",
            "",
            "5. Assign users/groups to AWS accounts:",
            "   - Navigate to 'AWS accounts'",
            "   - Select account(s)",
            "   - Click 'Assign users or groups'",
            "   - Select users/groups",
            "   - Select permission sets",
            "   - Click 'Submit'",
            "",
            "6. Configure MFA (recommended):",
            "   - Navigate to 'Settings'",
            "   - Under 'Authentication', configure MFA",
            "   - Options:",
            "     * Authenticator apps",
            "     * Security keys and built-in authenticators",
            "   - Set MFA requirement level",
            "",
            "7. Set up user portal:",
            "   - Users access: https://<your-subdomain>.awsapps.com/start",
            "   - Customize portal URL (optional)",
            "   - Configure portal settings",
            "",
            "8. Best practices:",
            "   - Enable MFA for all users",
            "   - Use permission sets instead of inline policies",
            "   - Implement least privilege access",
            "   - Use groups for permission assignment",
            "   - Enable CloudTrail logging for SSO events",
            "   - Regularly review access assignments",
            "   - Set appropriate session durations",
            "",
            "9. Integrate with external identity providers:",
            "   # For SAML 2.0 IdPs (Okta, Azure AD, etc.)",
            "   - Download AWS SSO SAML metadata",
            "   - Configure in your IdP",
            "   - Upload IdP SAML metadata to AWS SSO",
            "   - Test SSO login",
            "",
            "10. Verify SSO configuration:",
            "    aws sso-admin list-instances --region us-east-1",
            "",
            "Priority: HIGH - Centralized identity management improves security",
            "Effort: Medium - Requires initial setup and user migration",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/singlesignon/latest/userguide/what-is.html"
        ]



class IdentityCenterConfiguredAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 2.5 - Centralize Account Management  
    AWS Config Rule: identity-center-configured
    
    Ensures Identity Center is properly configured with users and permission sets.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="identity-center-configured",
            control_id="2.5",
            resource_types=["AWS::::Account"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get Identity Center configuration details."""
        if resource_type != "AWS::::Account":
            return []
        
        if region != 'us-east-1':
            return []
        
        try:
            sso_admin_client = aws_factory.get_client('sso-admin', region)
            
            # Get SSO instances
            instances_response = sso_admin_client.list_instances()
            instances = instances_response.get('Instances', [])
            
            if not instances:
                return [{
                    'AccountId': aws_factory.get_account_info().get('account_id', 'unknown'),
                    'Region': region,
                    'HasInstances': False,
                    'PermissionSetCount': 0,
                    'IsConfigured': False
                }]
            
            instance_arn = instances[0].get('InstanceArn', '')
            
            # Count permission sets
            permission_sets = []
            paginator = sso_admin_client.get_paginator('list_permission_sets')
            for page in paginator.paginate(InstanceArn=instance_arn):
                permission_sets.extend(page.get('PermissionSets', []))
            
            is_configured = len(permission_sets) > 0
            
            return [{
                'AccountId': aws_factory.get_account_info().get('account_id', 'unknown'),
                'Region': region,
                'HasInstances': True,
                'InstanceArn': instance_arn,
                'PermissionSetCount': len(permission_sets),
                'IsConfigured': is_configured
            }]
            
        except ClientError as e:
            logger.warning(f"Error checking Identity Center configuration: {e}")
            return []
    
    def _evaluate_resource_compliance(
        self, 
        resource: Dict[str, Any], 
        aws_factory: AWSClientFactory, 
        region: str
    ) -> ComplianceResult:
        """Evaluate if Identity Center is properly configured."""
        account_id = resource.get('AccountId', 'unknown')
        is_configured = resource.get('IsConfigured', False)
        permission_set_count = resource.get('PermissionSetCount', 0)
        has_instances = resource.get('HasInstances', False)
        
        if is_configured:
            evaluation_reason = (
                f"Identity Center is properly configured with {permission_set_count} permission set(s)."
            )
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            if not has_instances:
                evaluation_reason = "Identity Center is not enabled."
            else:
                evaluation_reason = "Identity Center is enabled but has no permission sets configured."
            compliance_status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceResult(
            resource_id=account_id,
            resource_type="AWS::::Account",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get remediation steps for configuring Identity Center."""
        return [
            "1. Create permission sets in Identity Center:",
            "   - Navigate to IAM Identity Center",
            "   - Click 'Permission sets'",
            "   - Click 'Create permission set'",
            "   - Choose type: Predefined or Custom",
            "   - Configure policies and session duration",
            "",
            "2. Add users to Identity Center:",
            "   - Navigate to 'Users'",
            "   - Click 'Add user'",
            "   - Enter user details",
            "   - Send invitation email",
            "",
            "3. Create groups and assign users:",
            "   - Navigate to 'Groups'",
            "   - Click 'Create group'",
            "   - Add users to group",
            "",
            "4. Assign access to AWS accounts:",
            "   - Navigate to 'AWS accounts'",
            "   - Select account(s)",
            "   - Click 'Assign users or groups'",
            "   - Select users/groups and permission sets",
            "",
            "Priority: HIGH - Proper configuration is essential for SSO",
            "Effort: Medium - Requires permission set and user setup",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/singlesignon/latest/userguide/permissionsets.html"
        ]
