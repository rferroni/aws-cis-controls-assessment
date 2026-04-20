"""Control 5.2: Use Unique Passwords assessments."""

from typing import Dict, List, Any, Optional
import json
import logging
from datetime import datetime, timedelta
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class MFAEnabledForIAMConsoleAccessAssessment(BaseConfigRuleAssessment):
    """Assessment for mfa-enabled-for-iam-console-access Config rule - ensures MFA for console access."""
    
    def __init__(self):
        """Initialize MFA enabled for IAM console access assessment."""
        super().__init__(
            rule_name="mfa-enabled-for-iam-console-access",
            control_id="5.2",
            resource_types=["AWS::IAM::User"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all IAM users with console access."""
        if resource_type != "AWS::IAM::User":
            return []
        
        try:
            iam_client = aws_factory.get_client('iam', region)
            
            users_with_console = []
            paginator = iam_client.get_paginator('list_users')
            
            for page in paginator.paginate():
                for user in page.get('Users', []):
                    user_name = user.get('UserName')
                    
                    # Check if user has console access (login profile)
                    try:
                        aws_factory.aws_api_call_with_retry(
                            lambda: iam_client.get_login_profile(UserName=user_name)
                        )
                        # User has console access
                        users_with_console.append({
                            'UserName': user_name,
                            'UserId': user.get('UserId'),
                            'Arn': user.get('Arn'),
                            'CreateDate': user.get('CreateDate'),
                            'PasswordLastUsed': user.get('PasswordLastUsed'),
                            'Tags': user.get('Tags', [])
                        })
                    except ClientError as e:
                        if e.response.get('Error', {}).get('Code') != 'NoSuchEntity':
                            logger.warning(f"Error checking login profile for user {user_name}: {e}")
            
            logger.debug(f"Found {len(users_with_console)} IAM users with console access")
            return users_with_console
            
        except ClientError as e:
            logger.error(f"Error retrieving IAM users: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving IAM users: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if IAM user with console access has MFA enabled."""
        user_name = resource.get('UserName', 'unknown')
        
        try:
            iam_client = aws_factory.get_client('iam', region)
            
            # Check MFA devices
            response = aws_factory.aws_api_call_with_retry(
                lambda: iam_client.list_mfa_devices(UserName=user_name)
            )
            
            mfa_devices = response.get('MFADevices', [])
            
            if mfa_devices:
                compliance_status = ComplianceStatus.COMPLIANT
                device_count = len(mfa_devices)
                device_types = [device.get('SerialNumber', '').split('/')[-1] for device in mfa_devices]
                evaluation_reason = f"User {user_name} has {device_count} MFA device(s) configured: {', '.join(device_types)}"
            else:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = f"User {user_name} has console access but no MFA devices configured"
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code in ['AccessDenied', 'UnauthorizedOperation']:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Insufficient permissions to check MFA for user {user_name}"
            else:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Error checking MFA for user {user_name}: {str(e)}"
        except Exception as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Unexpected error checking MFA for user {user_name}: {str(e)}"
        
        return ComplianceResult(
            resource_id=user_name,
            resource_type="AWS::IAM::User",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for IAM console MFA."""
        return [
            "Enable MFA for all IAM users with console access:",
            "1. Identify users with console access but no MFA:",
            "   aws iam list-users --query 'Users[?PasswordLastUsed!=null].UserName'",
            "2. For each user, enable MFA using one of these methods:",
            "   - Virtual MFA device (recommended): Google Authenticator, Authy, Microsoft Authenticator",
            "   - Hardware MFA device: YubiKey, Gemalto token",
            "   - SMS MFA (not recommended for high security environments)",
            "3. Enable virtual MFA device:",
            "   aws iam create-virtual-mfa-device --virtual-mfa-device-name <device-name> --path /",
            "   aws iam enable-mfa-device --user-name <username> --serial-number <device-arn> --authentication-code1 <code1> --authentication-code2 <code2>",
            "4. Use AWS Console: IAM > Users > [User] > Security credentials > Multi-factor authentication",
            "5. Consider enforcing MFA through IAM policies that deny access without MFA",
            "6. Provide MFA setup instructions and training to users",
            "7. Regularly audit MFA compliance using this assessment"
        ]


class RootAccountMFAEnabledAssessment(BaseConfigRuleAssessment):
    """Assessment for root-account-mfa-enabled Config rule - ensures root account has MFA."""
    
    def __init__(self):
        """Initialize root account MFA assessment."""
        super().__init__(
            rule_name="root-account-mfa-enabled",
            control_id="5.2",
            resource_types=["AWS::::Account"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get account-level resource for root MFA check."""
        if resource_type != "AWS::::Account":
            return []
        
        try:
            account_info = aws_factory.get_account_info()
            return [{
                'AccountId': account_info.get('account_id', 'unknown'),
                'ResourceType': 'AWS::::Account'
            }]
        except Exception as e:
            logger.error(f"Error getting account info: {e}")
            return [{
                'AccountId': 'unknown',
                'ResourceType': 'AWS::::Account'
            }]
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if root account has MFA enabled."""
        account_id = resource.get('AccountId', 'unknown')
        
        try:
            iam_client = aws_factory.get_client('iam', region)
            
            # Get account summary which includes MFA info
            response = aws_factory.aws_api_call_with_retry(
                lambda: iam_client.get_account_summary()
            )
            
            summary = response.get('SummaryMap', {})
            
            # Check for root MFA devices
            root_mfa_enabled = summary.get('AccountMFAEnabled', 0)
            
            if root_mfa_enabled > 0:
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = f"Root account has MFA enabled ({root_mfa_enabled} device(s))"
            else:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = "Root account does not have MFA enabled - this is a critical security risk"
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code in ['AccessDenied', 'UnauthorizedOperation']:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = "Insufficient permissions to check root account MFA status"
            else:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Error checking root account MFA: {str(e)}"
        except Exception as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Unexpected error checking root account MFA: {str(e)}"
        
        return ComplianceResult(
            resource_id=account_id,
            resource_type="AWS::::Account",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for root account MFA."""
        return [
            "Enable MFA for the root account immediately:",
            "1. Log in to AWS Console as root user",
            "2. Go to 'My Security Credentials' in the account menu",
            "3. In the 'Multi-factor authentication (MFA)' section, click 'Activate MFA'",
            "4. Choose MFA device type:",
            "   - Virtual MFA device (recommended): Use authenticator app",
            "   - Hardware MFA device: Use physical token",
            "5. Follow the setup wizard to configure the MFA device",
            "6. Test the MFA device by logging out and back in",
            "7. Store backup codes in a secure location",
            "Additional security measures:",
            "   - Use a strong, unique password for the root account",
            "   - Store root credentials in a secure password manager",
            "   - Limit root account usage to emergency situations only",
            "   - Consider using multiple MFA devices for redundancy",
            "   - Regularly test root account access procedures"
        ]


class IAMUserUnusedCredentialsAssessment(BaseConfigRuleAssessment):
    """Assessment for iam-user-unused-credentials-check Config rule - identifies unused credentials."""
    
    def __init__(self, parameters: Optional[Dict[str, Any]] = None):
        """Initialize IAM user unused credentials assessment."""
        default_params = {
            'maxCredentialUsageAge': 90  # Days
        }
        
        if parameters:
            default_params.update(parameters)
        
        super().__init__(
            rule_name="iam-user-unused-credentials-check",
            control_id="5.2",
            resource_types=["AWS::IAM::User"],
            parameters=default_params
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all IAM users."""
        if resource_type != "AWS::IAM::User":
            return []
        
        try:
            iam_client = aws_factory.get_client('iam', region)
            
            users = []
            paginator = iam_client.get_paginator('list_users')
            
            for page in paginator.paginate():
                for user in page.get('Users', []):
                    users.append({
                        'UserName': user.get('UserName'),
                        'UserId': user.get('UserId'),
                        'Arn': user.get('Arn'),
                        'CreateDate': user.get('CreateDate'),
                        'PasswordLastUsed': user.get('PasswordLastUsed'),
                        'Tags': user.get('Tags', [])
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
        """Evaluate if IAM user has unused credentials."""
        user_name = resource.get('UserName', 'unknown')
        max_age_days = self.parameters.get('maxCredentialUsageAge', 90)
        cutoff_date = datetime.now() - timedelta(days=max_age_days)
        
        try:
            iam_client = aws_factory.get_client('iam', region)
            
            unused_credentials = []
            
            # Check console password usage
            has_console_access = False
            password_last_used = None
            try:
                login_profile = aws_factory.aws_api_call_with_retry(
                    lambda: iam_client.get_login_profile(UserName=user_name)
                )
                has_console_access = True
                password_last_used = resource.get('PasswordLastUsed')
                
                if password_last_used is None:
                    unused_credentials.append("Console password never used")
                elif password_last_used < cutoff_date:
                    days_unused = (datetime.now() - password_last_used.replace(tzinfo=None)).days
                    unused_credentials.append(f"Console password unused for {days_unused} days")
                    
            except ClientError as e:
                if e.response.get('Error', {}).get('Code') != 'NoSuchEntity':
                    raise
            
            # Check access keys
            access_keys_response = aws_factory.aws_api_call_with_retry(
                lambda: iam_client.list_access_keys(UserName=user_name)
            )
            
            for access_key in access_keys_response.get('AccessKeyMetadata', []):
                access_key_id = access_key.get('AccessKeyId')
                
                # Get access key last used info
                try:
                    last_used_response = aws_factory.aws_api_call_with_retry(
                        lambda: iam_client.get_access_key_last_used(AccessKeyId=access_key_id)
                    )
                    
                    last_used_info = last_used_response.get('AccessKeyLastUsed', {})
                    last_used_date = last_used_info.get('LastUsedDate')
                    
                    if last_used_date is None:
                        unused_credentials.append(f"Access key {access_key_id} never used")
                    elif last_used_date < cutoff_date:
                        days_unused = (datetime.now() - last_used_date.replace(tzinfo=None)).days
                        unused_credentials.append(f"Access key {access_key_id} unused for {days_unused} days")
                        
                except ClientError as e:
                    logger.warning(f"Error checking access key usage for {access_key_id}: {e}")
            
            if unused_credentials:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = f"User {user_name} has unused credentials: {'; '.join(unused_credentials)}"
            else:
                if has_console_access or access_keys_response.get('AccessKeyMetadata'):
                    compliance_status = ComplianceStatus.COMPLIANT
                    evaluation_reason = f"User {user_name} has no unused credentials (all credentials used within {max_age_days} days)"
                else:
                    compliance_status = ComplianceStatus.NOT_APPLICABLE
                    evaluation_reason = f"User {user_name} has no credentials to evaluate"
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code in ['AccessDenied', 'UnauthorizedOperation']:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Insufficient permissions to check credentials for user {user_name}"
            else:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Error checking credentials for user {user_name}: {str(e)}"
        except Exception as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Unexpected error checking credentials for user {user_name}: {str(e)}"
        
        return ComplianceResult(
            resource_id=user_name,
            resource_type="AWS::IAM::User",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for unused credentials."""
        max_age_days = self.parameters.get('maxCredentialUsageAge', 90)
        return [
            f"Remove or rotate unused IAM credentials (unused for >{max_age_days} days):",
            "1. Identify users with unused credentials:",
            "   aws iam generate-credential-report",
            "   aws iam get-credential-report",
            "2. For unused console passwords:",
            "   - Contact the user to verify if console access is still needed",
            "   - If not needed: aws iam delete-login-profile --user-name <username>",
            "   - If needed: Force password reset on next login",
            "3. For unused access keys:",
            "   - Verify with the user/application owner if keys are still needed",
            "   - If not needed: aws iam delete-access-key --user-name <username> --access-key-id <key-id>",
            "   - If needed: Rotate the access keys",
            "4. For users with no activity:",
            "   - Consider deactivating or removing the user account",
            "   - Document the business justification for keeping inactive accounts",
            "5. Implement automated credential rotation policies",
            "6. Set up CloudWatch alarms for credential usage monitoring",
            f"7. Regularly review credential usage (recommend monthly for >{max_age_days} day threshold)",
            "8. Use AWS IAM Access Analyzer to identify unused access"
        ]