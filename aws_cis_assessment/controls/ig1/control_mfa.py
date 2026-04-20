"""
CIS Control 2.6, 2.7, 2.15 - Multi-Factor Authentication Controls
Ensures MFA is enabled for administrative access and critical services.
"""

import logging
from typing import List, Dict, Any
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class IAMAdminMFARequiredAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 2.6 - Establish an Access Granting Process
    AWS Config Rule: iam-admin-mfa-required
    
    Ensures IAM users with administrative privileges have MFA enabled.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="iam-admin-mfa-required",
            control_id="2.6",
            resource_types=["AWS::IAM::User"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all IAM users and check for admin privileges and MFA."""
        if resource_type != "AWS::IAM::User":
            return []
        
        # IAM is global, only check in us-east-1
        if region != 'us-east-1':
            return []
        
        try:
            iam_client = aws_factory.get_client('iam', region)
            
            users = []
            paginator = iam_client.get_paginator('list_users')
            
            for page in paginator.paginate():
                for user in page.get('Users', []):
                    user_name = user.get('UserName', '')
                    
                    # Check if user has MFA
                    try:
                        mfa_devices = iam_client.list_mfa_devices(UserName=user_name)
                        has_mfa = len(mfa_devices.get('MFADevices', [])) > 0
                    except ClientError:
                        has_mfa = False
                    
                    # Check if user has admin policies
                    is_admin = self._is_admin_user(iam_client, user_name)
                    
                    if is_admin:  # Only include admin users
                        users.append({
                            'UserName': user_name,
                            'UserArn': user.get('Arn', ''),
                            'HasMFA': has_mfa,
                            'IsAdmin': is_admin
                        })
            
            logger.debug(f"Found {len(users)} admin IAM users")
            return users
            
        except ClientError as e:
            logger.error(f"Error retrieving IAM users: {e}")
            return []
    
    def _is_admin_user(self, iam_client, user_name: str) -> bool:
        """Check if user has administrative privileges."""
        try:
            # Check attached policies
            attached_policies = iam_client.list_attached_user_policies(UserName=user_name)
            for policy in attached_policies.get('AttachedPolicies', []):
                policy_arn = policy.get('PolicyArn', '')
                if 'AdministratorAccess' in policy_arn or 'PowerUserAccess' in policy_arn:
                    return True
            
            # Check inline policies
            inline_policies = iam_client.list_user_policies(UserName=user_name)
            for policy_name in inline_policies.get('PolicyNames', []):
                policy_doc = iam_client.get_user_policy(UserName=user_name, PolicyName=policy_name)
                policy_document = policy_doc.get('PolicyDocument', {})
                if self._has_admin_permissions(policy_document):
                    return True
            
            # Check group memberships
            groups = iam_client.list_groups_for_user(UserName=user_name)
            for group in groups.get('Groups', []):
                group_name = group.get('GroupName', '')
                if 'admin' in group_name.lower():
                    return True
            
            return False
        except ClientError:
            return False
    
    def _has_admin_permissions(self, policy_document: Dict) -> bool:
        """Check if policy document grants admin permissions."""
        statements = policy_document.get('Statement', [])
        for statement in statements:
            if statement.get('Effect') == 'Allow':
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                if '*' in actions or 'iam:*' in actions:
                    return True
        return False
    
    def _evaluate_resource_compliance(
        self, 
        resource: Dict[str, Any], 
        aws_factory: AWSClientFactory, 
        region: str
    ) -> ComplianceResult:
        """Evaluate if admin user has MFA enabled."""
        user_name = resource.get('UserName', 'unknown')
        has_mfa = resource.get('HasMFA', False)
        
        if has_mfa:
            evaluation_reason = f"IAM admin user '{user_name}' has MFA enabled."
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            evaluation_reason = (
                f"IAM admin user '{user_name}' does not have MFA enabled. "
                f"MFA is required for all administrative users."
            )
            compliance_status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceResult(
            resource_id=user_name,
            resource_type="AWS::IAM::User",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get remediation steps for enabling MFA for admin users."""
        return [
            "1. Enable MFA for IAM user via Console:",
            "   - Sign in to AWS Console",
            "   - Navigate to IAM > Users",
            "   - Select the user",
            "   - Click 'Security credentials' tab",
            "   - Under 'Multi-factor authentication (MFA)', click 'Assign MFA device'",
            "   - Choose MFA device type:",
            "     * Authenticator app (recommended)",
            "     * Security key (FIDO)",
            "     * Hardware TOTP token",
            "   - Follow the setup wizard",
            "",
            "2. Enable MFA via AWS CLI:",
            "   # For virtual MFA device",
            "   aws iam create-virtual-mfa-device \\",
            "     --virtual-mfa-device-name <user-name>-mfa \\",
            "     --outfile QRCode.png \\",
            "     --bootstrap-method QRCodePNG",
            "",
            "   # Scan QR code with authenticator app, then enable",
            "   aws iam enable-mfa-device \\",
            "     --user-name <user-name> \\",
            "     --serial-number arn:aws:iam::<account-id>:mfa/<user-name>-mfa \\",
            "     --authentication-code-1 <code1> \\",
            "     --authentication-code-2 <code2>",
            "",
            "3. Enforce MFA with IAM policy:",
            "   {",
            '     "Version": "2012-10-17",',
            '     "Statement": [{',
            '       "Sid": "DenyAllExceptListedIfNoMFA",',
            '       "Effect": "Deny",',
            '       "NotAction": [',
            '         "iam:CreateVirtualMFADevice",',
            '         "iam:EnableMFADevice",',
            '         "iam:GetUser",',
            '         "iam:ListMFADevices",',
            '         "iam:ListVirtualMFADevices",',
            '         "iam:ResyncMFADevice",',
            '         "sts:GetSessionToken"',
            "       ],",
            '       "Resource": "*",',
            '       "Condition": {',
            '         "BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}',
            "       }",
            "     }]",
            "   }",
            "",
            "4. Best practices:",
            "   - Require MFA for all admin users",
            "   - Use authenticator apps (Google Authenticator, Authy, etc.)",
            "   - Consider hardware security keys for highest security",
            "   - Store backup codes securely",
            "   - Regularly audit MFA compliance",
            "   - Disable console access for users without MFA",
            "",
            "Priority: CRITICAL - Admin access without MFA is a major security risk",
            "Effort: Low - Can be enabled in minutes per user",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_mfa.html"
        ]


class CognitoMFAEnabledAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 2.7 - Establish an Access Granting Process
    AWS Config Rule: cognito-mfa-enabled
    
    Ensures Cognito user pools have MFA enabled for user authentication.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="cognito-mfa-enabled",
            control_id="2.7",
            resource_types=["AWS::Cognito::UserPool"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all Cognito user pools and their MFA configuration."""
        if resource_type != "AWS::Cognito::UserPool":
            return []
        
        try:
            cognito_client = aws_factory.get_client('cognito-idp', region)
            
            user_pools = []
            paginator = cognito_client.get_paginator('list_user_pools')
            
            for page in paginator.paginate(MaxResults=60):
                for pool in page.get('UserPools', []):
                    pool_id = pool.get('Id', '')
                    pool_name = pool.get('Name', '')
                    
                    try:
                        # Get detailed pool configuration
                        pool_details = cognito_client.describe_user_pool(UserPoolId=pool_id)
                        user_pool = pool_details.get('UserPool', {})
                        
                        mfa_config = user_pool.get('MfaConfiguration', 'OFF')
                        
                        user_pools.append({
                            'UserPoolId': pool_id,
                            'UserPoolName': pool_name,
                            'MfaConfiguration': mfa_config,
                            'MfaEnabled': mfa_config in ['ON', 'OPTIONAL']
                        })
                    except ClientError as e:
                        logger.warning(f"Error describing user pool {pool_id}: {e}")
                        continue
            
            logger.debug(f"Found {len(user_pools)} Cognito user pools in {region}")
            return user_pools
            
        except ClientError as e:
            logger.error(f"Error retrieving Cognito user pools from {region}: {e}")
            return []
    
    def _evaluate_resource_compliance(
        self, 
        resource: Dict[str, Any], 
        aws_factory: AWSClientFactory, 
        region: str
    ) -> ComplianceResult:
        """Evaluate if Cognito user pool has MFA enabled."""
        pool_id = resource.get('UserPoolId', 'unknown')
        pool_name = resource.get('UserPoolName', '')
        mfa_config = resource.get('MfaConfiguration', 'OFF')
        mfa_enabled = resource.get('MfaEnabled', False)
        
        if mfa_enabled:
            evaluation_reason = (
                f"Cognito user pool '{pool_name}' has MFA configured as '{mfa_config}'."
            )
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            evaluation_reason = (
                f"Cognito user pool '{pool_name}' does not have MFA enabled. "
                f"Current configuration: {mfa_config}"
            )
            compliance_status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceResult(
            resource_id=pool_id,
            resource_type="AWS::Cognito::UserPool",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get remediation steps for enabling Cognito MFA."""
        return [
            "1. Enable MFA for Cognito user pool via Console:",
            "   - Navigate to Amazon Cognito",
            "   - Select 'User pools'",
            "   - Select the user pool",
            "   - Click 'Sign-in experience' tab",
            "   - Under 'Multi-factor authentication', click 'Edit'",
            "   - Select MFA enforcement:",
            "     * Required - MFA required for all users",
            "     * Optional - Users can choose to enable MFA",
            "   - Select MFA methods:",
            "     * SMS text message",
            "     * Authenticator apps (TOTP)",
            "   - Click 'Save changes'",
            "",
            "2. Enable MFA via AWS CLI:",
            "   aws cognito-idp set-user-pool-mfa-config \\",
            "     --user-pool-id <pool-id> \\",
            "     --mfa-configuration ON \\",
            "     --software-token-mfa-configuration Enabled=true \\",
            "     --region <region>",
            "",
            "3. Enable SMS MFA:",
            "   aws cognito-idp set-user-pool-mfa-config \\",
            "     --user-pool-id <pool-id> \\",
            "     --mfa-configuration ON \\",
            "     --sms-mfa-configuration SmsConfiguration={SnsCallerArn=<sns-role-arn>} \\",
            "     --region <region>",
            "",
            "4. Best practices:",
            "   - Use 'Required' for production applications",
            "   - Prefer authenticator apps over SMS",
            "   - Configure both SMS and TOTP for flexibility",
            "   - Set up SNS for SMS delivery",
            "   - Monitor MFA usage with CloudWatch",
            "",
            "Priority: HIGH - MFA protects user accounts from compromise",
            "Effort: Low - Can be enabled quickly",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-mfa.html"
        ]


class VPNMFAEnabledAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 2.15 - Secure Remote Access
    AWS Config Rule: vpn-mfa-enabled
    
    Ensures Client VPN endpoints require MFA for authentication.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="vpn-mfa-enabled",
            control_id="2.15",
            resource_types=["AWS::EC2::ClientVpnEndpoint"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all Client VPN endpoints and their MFA configuration."""
        if resource_type != "AWS::EC2::ClientVpnEndpoint":
            return []
        
        try:
            ec2_client = aws_factory.get_client('ec2', region)
            
            vpn_endpoints = []
            paginator = ec2_client.get_paginator('describe_client_vpn_endpoints')
            
            for page in paginator.paginate():
                for endpoint in page.get('ClientVpnEndpoints', []):
                    endpoint_id = endpoint.get('ClientVpnEndpointId', '')
                    
                    # Check authentication options
                    auth_options = endpoint.get('AuthenticationOptions', [])
                    has_mfa = False
                    auth_types = []
                    
                    for auth in auth_options:
                        auth_type = auth.get('Type', '')
                        auth_types.append(auth_type)
                        
                        # Check if MFA is enabled for this auth method
                        if auth_type == 'federated-authentication':
                            # SAML-based auth can enforce MFA at IdP level
                            has_mfa = True
                        elif auth_type == 'directory-service-authentication':
                            # AD can enforce MFA
                            has_mfa = True
                    
                    vpn_endpoints.append({
                        'ClientVpnEndpointId': endpoint_id,
                        'Description': endpoint.get('Description', ''),
                        'Status': endpoint.get('Status', {}).get('Code', ''),
                        'AuthenticationOptions': auth_types,
                        'HasMFA': has_mfa
                    })
            
            logger.debug(f"Found {len(vpn_endpoints)} Client VPN endpoints in {region}")
            return vpn_endpoints
            
        except ClientError as e:
            logger.error(f"Error retrieving Client VPN endpoints from {region}: {e}")
            return []
    
    def _evaluate_resource_compliance(
        self, 
        resource: Dict[str, Any], 
        aws_factory: AWSClientFactory, 
        region: str
    ) -> ComplianceResult:
        """Evaluate if VPN endpoint has MFA enabled."""
        endpoint_id = resource.get('ClientVpnEndpointId', 'unknown')
        has_mfa = resource.get('HasMFA', False)
        auth_options = resource.get('AuthenticationOptions', [])
        
        if has_mfa:
            evaluation_reason = (
                f"Client VPN endpoint '{endpoint_id}' uses authentication methods that support MFA: "
                f"{', '.join(auth_options)}"
            )
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            evaluation_reason = (
                f"Client VPN endpoint '{endpoint_id}' does not have MFA-capable authentication configured. "
                f"Current auth: {', '.join(auth_options) if auth_options else 'None'}"
            )
            compliance_status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceResult(
            resource_id=endpoint_id,
            resource_type="AWS::EC2::ClientVpnEndpoint",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get remediation steps for enabling VPN MFA."""
        return [
            "1. Configure MFA for Client VPN using SAML-based authentication:",
            "   - Set up SAML 2.0 identity provider (Okta, Azure AD, etc.)",
            "   - Configure MFA in your IdP",
            "   - Create Client VPN endpoint with federated authentication:",
            "   ",
            "   aws ec2 create-client-vpn-endpoint \\",
            "     --client-cidr-block 10.0.0.0/16 \\",
            "     --server-certificate-arn <cert-arn> \\",
            "     --authentication-options Type=federated-authentication,SAMLProviderArn=<saml-provider-arn> \\",
            "     --connection-log-options Enabled=true,CloudwatchLogGroup=<log-group> \\",
            "     --region <region>",
            "",
            "2. Configure MFA using AWS Directory Service:",
            "   - Set up AWS Managed Microsoft AD or AD Connector",
            "   - Enable MFA in Active Directory",
            "   - Create Client VPN with directory authentication:",
            "   ",
            "   aws ec2 create-client-vpn-endpoint \\",
            "     --client-cidr-block 10.0.0.0/16 \\",
            "     --server-certificate-arn <cert-arn> \\",
            "     --authentication-options Type=directory-service-authentication,ActiveDirectory={DirectoryId=<directory-id>} \\",
            "     --region <region>",
            "",
            "3. Modify existing VPN endpoint (requires recreation):",
            "   Note: You cannot modify authentication options on existing endpoints",
            "   You must create a new endpoint with MFA-enabled authentication",
            "",
            "4. Best practices:",
            "   - Use SAML-based authentication with enterprise IdP",
            "   - Enforce MFA at the IdP level",
            "   - Enable connection logging",
            "   - Use certificate-based authentication in addition to MFA",
            "   - Implement least privilege access",
            "   - Monitor VPN connections with CloudWatch",
            "",
            "Priority: CRITICAL - VPN access without MFA is a major security risk",
            "Effort: High - Requires IdP setup and VPN endpoint recreation",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/vpn/latest/clientvpn-admin/client-authentication.html"
        ]
