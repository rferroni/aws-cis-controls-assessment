"""Control 3.3: Configure Data Access Control Lists assessments."""

from typing import Dict, List, Any, Optional
import json
import logging
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class IAMPasswordPolicyAssessment(BaseConfigRuleAssessment):
    """Assessment for iam-password-policy Config rule - ensures strong password policy."""
    
    def __init__(self, parameters: Optional[Dict[str, Any]] = None):
        """Initialize IAM password policy assessment."""
        default_params = {
            'MinimumPasswordLength': 14,
            'RequireSymbols': True,
            'RequireNumbers': True,
            'RequireUppercaseCharacters': True,
            'RequireLowercaseCharacters': True,
            'MaxPasswordAge': 90,
            'PasswordReusePrevention': 24,
            'AllowUsersToChangePassword': True,
            'HardExpiry': False
        }
        
        if parameters:
            # Validate parameter types and ranges
            validated_params = self._validate_parameters(parameters)
            default_params.update(validated_params)
        
        super().__init__(
            rule_name="iam-password-policy",
            control_id="5.2",  # Updated to reflect Control 5.2 for password management
            resource_types=["AWS::::Account"],
            parameters=default_params
        )
    
    def _validate_parameters(self, parameters: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and sanitize input parameters."""
        validated = {}
        
        # Validate MinimumPasswordLength
        if 'MinimumPasswordLength' in parameters:
            min_length = parameters['MinimumPasswordLength']
            if isinstance(min_length, int) and 6 <= min_length <= 128:
                validated['MinimumPasswordLength'] = min_length
            else:
                logger.warning(f"Invalid MinimumPasswordLength: {min_length}. Must be integer between 6-128. Using default: 14")
        
        # Validate MaxPasswordAge
        if 'MaxPasswordAge' in parameters:
            max_age = parameters['MaxPasswordAge']
            if isinstance(max_age, int) and 1 <= max_age <= 1095:
                validated['MaxPasswordAge'] = max_age
            else:
                logger.warning(f"Invalid MaxPasswordAge: {max_age}. Must be integer between 1-1095 days. Using default: 90")
        
        # Validate PasswordReusePrevention
        if 'PasswordReusePrevention' in parameters:
            reuse_prevention = parameters['PasswordReusePrevention']
            if isinstance(reuse_prevention, int) and 1 <= reuse_prevention <= 24:
                validated['PasswordReusePrevention'] = reuse_prevention
            else:
                logger.warning(f"Invalid PasswordReusePrevention: {reuse_prevention}. Must be integer between 1-24. Using default: 24")
        
        # Validate boolean parameters
        boolean_params = [
            'RequireSymbols', 'RequireNumbers', 'RequireUppercaseCharacters', 
            'RequireLowercaseCharacters', 'AllowUsersToChangePassword', 'HardExpiry'
        ]
        
        for param in boolean_params:
            if param in parameters:
                value = parameters[param]
                if isinstance(value, bool):
                    validated[param] = value
                elif isinstance(value, str) and value.lower() in ['true', '1', 'yes', 'on', 'false', '0', 'no', 'off']:
                    validated[param] = value.lower() in ['true', '1', 'yes', 'on']
                else:
                    logger.warning(f"Invalid {param}: {value}. Must be boolean. Using default.")
                    # Don't add to validated, will use default
        
        return validated
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get account-level resource for password policy check."""
        if resource_type != "AWS::::Account":
            return []
        
        # Account-level resource - return single item representing the account
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
        """Evaluate IAM password policy compliance."""
        account_id = resource.get('AccountId', 'unknown')
        
        try:
            iam_client = aws_factory.get_client('iam', region)
            
            # Get password policy
            response = aws_factory.aws_api_call_with_retry(
                lambda: iam_client.get_account_password_policy()
            )
            
            policy = response.get('PasswordPolicy', {})
            
            # Check each requirement
            violations = []
            
            # Minimum password length
            min_length = policy.get('MinimumPasswordLength', 0)
            required_min_length = self.parameters.get('MinimumPasswordLength', 14)
            if min_length < required_min_length:
                violations.append(f"Minimum password length is {min_length}, required: {required_min_length}")
            
            # Character requirements
            if self.parameters.get('RequireSymbols', True) and not policy.get('RequireSymbols', False):
                violations.append("Password policy does not require symbols")
            
            if self.parameters.get('RequireNumbers', True) and not policy.get('RequireNumbers', False):
                violations.append("Password policy does not require numbers")
            
            if self.parameters.get('RequireUppercaseCharacters', True) and not policy.get('RequireUppercaseCharacters', False):
                violations.append("Password policy does not require uppercase characters")
            
            if self.parameters.get('RequireLowercaseCharacters', True) and not policy.get('RequireLowercaseCharacters', False):
                violations.append("Password policy does not require lowercase characters")
            
            # Password age
            max_age = policy.get('MaxPasswordAge')
            required_max_age = self.parameters.get('MaxPasswordAge', 90)
            if max_age is None or max_age > required_max_age:
                violations.append(f"Maximum password age is {max_age or 'unlimited'}, required: {required_max_age} days")
            
            # Password reuse prevention
            reuse_prevention = policy.get('PasswordReusePrevention', 0)
            required_reuse_prevention = self.parameters.get('PasswordReusePrevention', 24)
            if reuse_prevention < required_reuse_prevention:
                violations.append(f"Password reuse prevention is {reuse_prevention}, required: {required_reuse_prevention}")
            
            # Allow users to change password
            allow_change = policy.get('AllowUsersToChangePassword', False)
            required_allow_change = self.parameters.get('AllowUsersToChangePassword', True)
            if required_allow_change and not allow_change:
                violations.append("Password policy does not allow users to change their own passwords")
            elif not required_allow_change and allow_change:
                violations.append("Password policy allows users to change passwords when it should not")
            
            # Hard expiry
            hard_expiry = policy.get('HardExpiry', False)
            required_hard_expiry = self.parameters.get('HardExpiry', False)
            if required_hard_expiry and not hard_expiry:
                violations.append("Password policy does not enforce hard expiry")
            elif not required_hard_expiry and hard_expiry:
                violations.append("Password policy enforces hard expiry when it should not")
            
            if violations:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = f"IAM password policy violations: {'; '.join(violations)}"
            else:
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = "IAM password policy meets all security requirements"
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'NoSuchEntity':
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = "No IAM password policy is configured"
            elif error_code in ['AccessDenied', 'UnauthorizedOperation']:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = "Insufficient permissions to check IAM password policy"
            else:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Error checking IAM password policy: {str(e)}"
        except Exception as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Unexpected error checking IAM password policy: {str(e)}"
        
        return ComplianceResult(
            resource_id=account_id,
            resource_type="AWS::::Account",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for IAM password policy."""
        return [
            "Update the IAM password policy to meet security requirements:",
            f"  - Set minimum password length to {self.parameters.get('MinimumPasswordLength', 14)} characters",
            "  - Require symbols, numbers, uppercase and lowercase characters",
            f"  - Set maximum password age to {self.parameters.get('MaxPasswordAge', 90)} days",
            f"  - Set password reuse prevention to {self.parameters.get('PasswordReusePrevention', 24)} passwords",
            f"  - {'Allow' if self.parameters.get('AllowUsersToChangePassword', True) else 'Disallow'} users to change their own passwords",
            f"  - {'Enable' if self.parameters.get('HardExpiry', False) else 'Disable'} hard expiry for passwords",
            "Use AWS CLI command:",
            f"  aws iam update-account-password-policy \\",
            f"    --minimum-password-length {self.parameters.get('MinimumPasswordLength', 14)} \\",
            f"    {'--require-symbols' if self.parameters.get('RequireSymbols', True) else '--no-require-symbols'} \\",
            f"    {'--require-numbers' if self.parameters.get('RequireNumbers', True) else '--no-require-numbers'} \\",
            f"    {'--require-uppercase-characters' if self.parameters.get('RequireUppercaseCharacters', True) else '--no-require-uppercase-characters'} \\",
            f"    {'--require-lowercase-characters' if self.parameters.get('RequireLowercaseCharacters', True) else '--no-require-lowercase-characters'} \\",
            f"    --max-password-age {self.parameters.get('MaxPasswordAge', 90)} \\",
            f"    --password-reuse-prevention {self.parameters.get('PasswordReusePrevention', 24)} \\",
            f"    {'--allow-users-to-change-password' if self.parameters.get('AllowUsersToChangePassword', True) else '--no-allow-users-to-change-password'}" +
            (f" \\\n    {'--hard-expiry' if self.parameters.get('HardExpiry', False) else '--no-hard-expiry'}" if 'HardExpiry' in self.parameters else ""),
            "Or use AWS Console: IAM > Account settings > Password policy",
            "Additional recommendations:",
            "  - Communicate password policy changes to all users in advance",
            "  - Provide password manager recommendations to users",
            "  - Consider implementing password complexity training",
            "  - Monitor password policy compliance regularly"
        ]


class IAMUserMFAEnabledAssessment(BaseConfigRuleAssessment):
    """Assessment for iam-user-mfa-enabled Config rule - ensures IAM users have MFA."""
    
    def __init__(self):
        """Initialize IAM user MFA assessment."""
        super().__init__(
            rule_name="iam-user-mfa-enabled",
            control_id="3.3",
            resource_types=["AWS::IAM::User"]
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
        """Evaluate if IAM user has MFA enabled."""
        user_name = resource.get('UserName', 'unknown')
        
        try:
            iam_client = aws_factory.get_client('iam', region)
            
            # Check if user has console access (login profile)
            has_console_access = False
            try:
                aws_factory.aws_api_call_with_retry(
                    lambda: iam_client.get_login_profile(UserName=user_name)
                )
                has_console_access = True
            except ClientError as e:
                if e.response.get('Error', {}).get('Code') != 'NoSuchEntity':
                    raise
            
            # If no console access, user doesn't need MFA
            if not has_console_access:
                return ComplianceResult(
                    resource_id=user_name,
                    resource_type="AWS::IAM::User",
                    compliance_status=ComplianceStatus.NOT_APPLICABLE,
                    evaluation_reason=f"User {user_name} does not have console access",
                    config_rule_name=self.rule_name,
                    region=region
                )
            
            # Check MFA devices
            response = aws_factory.aws_api_call_with_retry(
                lambda: iam_client.list_mfa_devices(UserName=user_name)
            )
            
            mfa_devices = response.get('MFADevices', [])
            
            if mfa_devices:
                compliance_status = ComplianceStatus.COMPLIANT
                device_count = len(mfa_devices)
                evaluation_reason = f"User {user_name} has {device_count} MFA device(s) configured"
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
        """Get specific remediation steps for IAM user MFA."""
        return [
            "Enable MFA for all IAM users with console access:",
            "1. Identify users without MFA who have console access",
            "2. For each user, enable MFA using one of these methods:",
            "   - Virtual MFA device (Google Authenticator, Authy, etc.)",
            "   - Hardware MFA device (YubiKey, etc.)",
            "   - SMS MFA (not recommended for high security)",
            "Use AWS CLI: aws iam enable-mfa-device --user-name <username> --serial-number <device-arn> --authentication-code1 <code1> --authentication-code2 <code2>",
            "Or use AWS Console: IAM > Users > [User] > Security credentials > Multi-factor authentication",
            "Consider enforcing MFA through IAM policies",
            "Provide MFA setup instructions to users"
        ]


class IAMRootAccessKeyAssessment(BaseConfigRuleAssessment):
    """Assessment for iam-root-access-key-check Config rule - ensures root has no access keys."""
    
    def __init__(self):
        """Initialize IAM root access key assessment."""
        super().__init__(
            rule_name="iam-root-access-key-check",
            control_id="3.3",
            resource_types=["AWS::::Account"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get account-level resource for root access key check."""
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
        """Evaluate if root user has access keys."""
        account_id = resource.get('AccountId', 'unknown')
        
        try:
            iam_client = aws_factory.get_client('iam', region)
            
            # Get account summary which includes root access key info
            response = aws_factory.aws_api_call_with_retry(
                lambda: iam_client.get_account_summary()
            )
            
            summary = response.get('SummaryMap', {})
            
            # Check for root access keys
            root_access_keys_present = summary.get('AccountAccessKeysPresent', 0)
            
            if root_access_keys_present > 0:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = f"Root user has {root_access_keys_present} access key(s) - this is a security risk"
            else:
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = "Root user has no access keys configured"
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code in ['AccessDenied', 'UnauthorizedOperation']:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = "Insufficient permissions to check root access keys"
            else:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Error checking root access keys: {str(e)}"
        except Exception as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Unexpected error checking root access keys: {str(e)}"
        
        return ComplianceResult(
            resource_id=account_id,
            resource_type="AWS::::Account",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for root access keys."""
        return [
            "Remove root user access keys immediately:",
            "1. Log in to AWS Console as root user",
            "2. Go to 'My Security Credentials' in the account menu",
            "3. In the 'Access keys' section, delete any existing access keys",
            "4. Create IAM users with appropriate permissions instead",
            "5. Use IAM roles for applications and services",
            "Alternative using AWS CLI (if you have the keys):",
            "  aws iam delete-access-key --access-key-id <access-key-id>",
            "Best practices:",
            "  - Never use root credentials for daily operations",
            "  - Enable MFA on the root account",
            "  - Use IAM users and roles for all programmatic access"
        ]


class S3BucketPublicReadProhibitedAssessment(BaseConfigRuleAssessment):
    """Assessment for s3-bucket-public-read-prohibited Config rule."""
    
    def __init__(self):
        """Initialize S3 bucket public read assessment."""
        super().__init__(
            rule_name="s3-bucket-public-read-prohibited",
            control_id="3.3",
            resource_types=["AWS::S3::Bucket"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all S3 buckets."""
        if resource_type != "AWS::S3::Bucket":
            return []
        
        try:
            s3_client = aws_factory.get_client('s3', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: s3_client.list_buckets()
            )
            
            buckets = []
            for bucket in response.get('Buckets', []):
                buckets.append({
                    'Name': bucket.get('Name'),
                    'CreationDate': bucket.get('CreationDate')
                })
            
            logger.debug(f"Found {len(buckets)} S3 buckets")
            return buckets
            
        except ClientError as e:
            logger.error(f"Error retrieving S3 buckets: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving S3 buckets: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if S3 bucket allows public read access."""
        bucket_name = resource.get('Name', 'unknown')
        
        try:
            s3_client = aws_factory.get_client('s3', region)
            
            public_access_issues = []
            
            # Check bucket ACL
            try:
                acl_response = aws_factory.aws_api_call_with_retry(
                    lambda: s3_client.get_bucket_acl(Bucket=bucket_name)
                )
                
                for grant in acl_response.get('Grants', []):
                    grantee = grant.get('Grantee', {})
                    permission = grant.get('Permission', '')
                    
                    # Check for public read permissions
                    if grantee.get('Type') == 'Group':
                        uri = grantee.get('URI', '')
                        if 'AllUsers' in uri and permission in ['READ', 'FULL_CONTROL']:
                            public_access_issues.append(f"Bucket ACL grants {permission} to AllUsers")
                        elif 'AuthenticatedUsers' in uri and permission in ['READ', 'FULL_CONTROL']:
                            public_access_issues.append(f"Bucket ACL grants {permission} to AuthenticatedUsers")
                            
            except ClientError as e:
                if e.response.get('Error', {}).get('Code') not in ['AccessDenied', 'NoSuchBucket']:
                    raise
            
            # Check bucket policy
            try:
                policy_response = aws_factory.aws_api_call_with_retry(
                    lambda: s3_client.get_bucket_policy(Bucket=bucket_name)
                )
                
                policy_doc = json.loads(policy_response.get('Policy', '{}'))
                
                for statement in policy_doc.get('Statement', []):
                    effect = statement.get('Effect', '')
                    principal = statement.get('Principal', {})
                    action = statement.get('Action', [])
                    
                    if effect == 'Allow':
                        # Check for public principals
                        if principal == '*' or (isinstance(principal, dict) and principal.get('AWS') == '*'):
                            # Check for read actions
                            actions = action if isinstance(action, list) else [action]
                            for act in actions:
                                if any(read_action in act for read_action in ['s3:GetObject', 's3:ListBucket', 's3:*']):
                                    public_access_issues.append(f"Bucket policy allows public {act}")
                                    
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', '')
                if error_code not in ['NoSuchBucketPolicy', 'AccessDenied', 'NoSuchBucket']:
                    raise
            
            # Check public access block settings
            try:
                pab_response = aws_factory.aws_api_call_with_retry(
                    lambda: s3_client.get_public_access_block(Bucket=bucket_name)
                )
                
                pab_config = pab_response.get('PublicAccessBlockConfiguration', {})
                
                if not pab_config.get('BlockPublicAcls', False):
                    public_access_issues.append("Public Access Block does not block public ACLs")
                if not pab_config.get('IgnorePublicAcls', False):
                    public_access_issues.append("Public Access Block does not ignore public ACLs")
                if not pab_config.get('BlockPublicPolicy', False):
                    public_access_issues.append("Public Access Block does not block public policies")
                if not pab_config.get('RestrictPublicBuckets', False):
                    public_access_issues.append("Public Access Block does not restrict public buckets")
                    
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', '')
                if error_code == 'NoSuchPublicAccessBlockConfiguration':
                    public_access_issues.append("No Public Access Block configuration found")
                elif error_code not in ['AccessDenied', 'NoSuchBucket']:
                    raise
            
            if public_access_issues:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = f"Bucket {bucket_name} has public read access issues: {'; '.join(public_access_issues)}"
            else:
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = f"Bucket {bucket_name} does not allow public read access"
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'NoSuchBucket':
                compliance_status = ComplianceStatus.NOT_APPLICABLE
                evaluation_reason = f"Bucket {bucket_name} does not exist"
            elif error_code in ['AccessDenied', 'UnauthorizedOperation']:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Insufficient permissions to check bucket {bucket_name}"
            else:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Error checking bucket {bucket_name}: {str(e)}"
        except Exception as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Unexpected error checking bucket {bucket_name}: {str(e)}"
        
        return ComplianceResult(
            resource_id=bucket_name,
            resource_type="AWS::S3::Bucket",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for S3 public read access."""
        return [
            "Remove public read access from S3 buckets:",
            "1. Enable S3 Public Access Block at bucket level:",
            "   aws s3api put-public-access-block --bucket <bucket-name> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true",
            "2. Review and remove public permissions from bucket ACLs:",
            "   aws s3api get-bucket-acl --bucket <bucket-name>",
            "   aws s3api put-bucket-acl --bucket <bucket-name> --acl private",
            "3. Review and update bucket policies to remove public access:",
            "   aws s3api get-bucket-policy --bucket <bucket-name>",
            "   aws s3api delete-bucket-policy --bucket <bucket-name>  # if policy grants public access",
            "4. Use CloudFront or signed URLs for legitimate public content access",
            "5. Regularly audit bucket permissions using AWS Config or Trusted Advisor"
        ]


class EC2InstanceNoPublicIPAssessment(BaseConfigRuleAssessment):
    """Assessment for ec2-instance-no-public-ip Config rule."""
    
    def __init__(self):
        """Initialize EC2 instance no public IP assessment."""
        super().__init__(
            rule_name="ec2-instance-no-public-ip",
            control_id="3.3",
            resource_types=["AWS::EC2::Instance"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all EC2 instances."""
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
                    instances.append({
                        'InstanceId': instance.get('InstanceId'),
                        'State': instance.get('State', {}),
                        'PublicIpAddress': instance.get('PublicIpAddress'),
                        'PrivateIpAddress': instance.get('PrivateIpAddress'),
                        'SubnetId': instance.get('SubnetId'),
                        'VpcId': instance.get('VpcId'),
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
        """Evaluate if EC2 instance has a public IP address."""
        instance_id = resource.get('InstanceId', 'unknown')
        state = resource.get('State', {})
        state_name = state.get('Name', 'unknown')
        public_ip = resource.get('PublicIpAddress')
        
        # Only evaluate running instances
        if state_name not in ['running', 'stopped']:
            return ComplianceResult(
                resource_id=instance_id,
                resource_type="AWS::EC2::Instance",
                compliance_status=ComplianceStatus.NOT_APPLICABLE,
                evaluation_reason=f"Instance {instance_id} is in state '{state_name}'",
                config_rule_name=self.rule_name,
                region=region
            )
        
        if public_ip:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = f"Instance {instance_id} has public IP address {public_ip}"
        else:
            compliance_status = ComplianceStatus.COMPLIANT
            evaluation_reason = f"Instance {instance_id} does not have a public IP address"
        
        return ComplianceResult(
            resource_id=instance_id,
            resource_type="AWS::EC2::Instance",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for EC2 instances with public IPs."""
        return [
            "Remove public IP addresses from EC2 instances:",
            "1. For existing instances with public IPs:",
            "   - Stop the instance if it has a dynamic public IP",
            "   - Disassociate Elastic IP if attached: aws ec2 disassociate-address --association-id <assoc-id>",
            "   - Start the instance without public IP assignment",
            "2. For new instances, launch in private subnets:",
            "   - Use subnets that don't auto-assign public IPs",
            "   - Set 'Auto-assign Public IP' to 'Disable'",
            "3. Set up internet access through NAT Gateway or NAT Instance:",
            "   - Create NAT Gateway in public subnet",
            "   - Route private subnet traffic through NAT Gateway",
            "4. Use Application Load Balancer or CloudFront for web applications",
            "5. Use VPN or Direct Connect for administrative access",
            "6. Consider using AWS Systems Manager Session Manager for secure shell access"
        ]