"""Controls 4, 5, 6: Access & Configuration Controls - Phase 2 assessments.

This module implements 18 critical assessment classes for CIS Controls 4 (Secure
Configuration), 5 (Account Management), and 6 (Access Control Management). These
assessments evaluate AWS resources for comprehensive access control, identity
management, and secure configuration compliance:

Control 4 - Secure Configuration (5 rules):
1. IAMMaxSessionDurationCheckAssessment - Validates IAM role session duration <= 12 hours
2. SecurityGroupDefaultRulesCheckAssessment - Ensures default security groups have no rules
3. VPCDnsResolutionEnabledAssessment - Validates VPC DNS configuration
4. RDSDefaultAdminCheckAssessment - Ensures RDS instances don't use default admin usernames
5. EC2InstanceProfileLeastPrivilegeAssessment - Validates EC2 instance profile least privilege

Control 5 - Account Management (4 rules):
1. IAMServiceAccountInventoryCheckAssessment - Validates service account documentation tags
2. IAMAdminPolicyAttachedToRoleCheckAssessment - Ensures admin policies attached to roles, not users
3. SSOEnabledCheckAssessment - Validates AWS IAM Identity Center (SSO) is configured
4. IAMUserNoInlinePoliciesAssessment - Ensures IAM users don't have inline policies

Control 6 - Access Control Management (9 rules):
1. IAMAccessAnalyzerEnabledAssessment - Ensures IAM Access Analyzer enabled in all regions
2. IAMPermissionBoundariesCheckAssessment - Validates permission boundaries for elevated privileges
3. OrganizationsSCPEnabledCheckAssessment - Ensures Service Control Policies are enabled
4. CognitoUserPoolMFAEnabledAssessment - Validates Cognito user pools have MFA enabled
5. VPNConnectionMFAEnabledAssessment - Ensures Client VPN endpoints require MFA

These rules address critical gaps in access control and configuration management
identified in the CIS Controls Gap Analysis and increase the total rule count
from 149 to 167.
"""

from typing import Dict, List, Any
import logging
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


# ============================================================================
# Control 4: Secure Configuration Assessments
# ============================================================================

class IAMMaxSessionDurationCheckAssessment(BaseConfigRuleAssessment):
    """Assessment for iam-max-session-duration-check AWS Config rule.
    
    Validates that IAM role session duration does not exceed 12 hours (43200 seconds)
    to limit the window of opportunity for credential compromise.
    
    This is a global service assessment that only runs in us-east-1.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="iam-max-session-duration-check",
            control_id="4.1",
            resource_types=["AWS::IAM::Role"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get IAM roles.
        
        IAM is a global service, so we only query in us-east-1.
        
        Args:
            aws_factory: AWS client factory for API access
            resource_type: AWS resource type (should be AWS::IAM::Role)
            region: AWS region (should be us-east-1 for IAM)
            
        Returns:
            List of IAM role dictionaries with RoleName, RoleId, Arn, MaxSessionDuration
        """
        if resource_type != "AWS::IAM::Role":
            return []
        
        # IAM is a global service - only evaluate in us-east-1
        if region != 'us-east-1':
            logger.debug(f"Skipping IAM evaluation in {region} - global service evaluated in us-east-1 only")
            return []
        
        try:
            iam_client = aws_factory.get_client('iam', region)
            
            # List all IAM roles with pagination support
            roles = []
            marker = None
            
            while True:
                if marker:
                    response = aws_factory.aws_api_call_with_retry(
                        lambda: iam_client.list_roles(Marker=marker)
                    )
                else:
                    response = aws_factory.aws_api_call_with_retry(
                        lambda: iam_client.list_roles()
                    )
                
                roles.extend(response.get('Roles', []))
                
                # Check if there are more results
                if response.get('IsTruncated', False):
                    marker = response.get('Marker')
                else:
                    break
            
            logger.debug(f"Found {len(roles)} IAM roles")
            return roles
            
        except ClientError as e:
            logger.error(f"Error retrieving IAM roles: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if IAM role session duration is within acceptable limits.
        
        Args:
            resource: IAM role resource dictionary
            aws_factory: AWS client factory for additional API calls
            region: AWS region
            
        Returns:
            ComplianceResult indicating whether session duration is compliant
        """
        role_name = resource.get('RoleName', 'unknown')
        role_arn = resource.get('Arn', 'unknown')
        max_session_duration = resource.get('MaxSessionDuration', 3600)  # Default is 1 hour
        
        # Maximum allowed session duration: 12 hours = 43200 seconds
        max_allowed_duration = 43200
        
        try:
            if max_session_duration <= max_allowed_duration:
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = (
                    f"IAM role {role_name} has session duration of {max_session_duration} seconds "
                    f"({max_session_duration // 3600} hours), which is within the 12-hour limit"
                )
            else:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                hours = max_session_duration // 3600
                evaluation_reason = (
                    f"IAM role {role_name} has session duration of {max_session_duration} seconds "
                    f"({hours} hours), which exceeds the 12-hour limit. "
                    f"Update IAM role to limit session duration to 12 hours or less:\n"
                    f"1. Go to IAM console > Roles\n"
                    f"2. Select the role '{role_name}'\n"
                    f"3. Edit Maximum session duration\n"
                    f"4. Set to 12 hours (43200 seconds) or less\n"
                    f"5. Save changes\n\n"
                    f"AWS CLI example:\n"
                    f"aws iam update-role --role-name {role_name} --max-session-duration 43200"
                )
                
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            
            if error_code == 'AccessDenied':
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = (
                    f"Insufficient permissions to evaluate IAM role {role_name}. "
                    f"Required permissions: iam:ListRoles, iam:GetRole"
                )
            elif error_code == 'NoSuchEntity':
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"IAM role {role_name} not found (may have been deleted)"
            else:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Error evaluating IAM role {role_name}: {str(e)}"
        
        except Exception as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Unexpected error evaluating IAM role {role_name}: {str(e)}"
        
        return ComplianceResult(
            resource_id=role_arn,
            resource_type="AWS::IAM::Role",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
class SecurityGroupDefaultRulesCheckAssessment(BaseConfigRuleAssessment):
    """Assessment for security-group-default-rules-check AWS Config rule.
    
    Ensures default security groups have no inbound or outbound rules as a security
    best practice. Default security groups should not be used for actual workloads.
    
    This is a regional service assessment that runs in all active regions.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="security-group-default-rules-check",
            control_id="4.2",
            resource_types=["AWS::EC2::SecurityGroup"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get default security groups.
        
        Security groups are regional resources, so we query in each active region.
        We filter for security groups with GroupName='default'.
        
        Args:
            aws_factory: AWS client factory for API access
            resource_type: AWS resource type (should be AWS::EC2::SecurityGroup)
            region: AWS region
            
        Returns:
            List of default security group dictionaries with GroupId, GroupName, VpcId, IpPermissions, IpPermissionsEgress
        """
        if resource_type != "AWS::EC2::SecurityGroup":
            return []
        
        try:
            ec2_client = aws_factory.get_client('ec2', region)
            
            # List all default security groups with pagination support
            security_groups = []
            next_token = None
            
            while True:
                # Filter for default security groups only
                filters = [{'Name': 'group-name', 'Values': ['default']}]
                
                if next_token:
                    response = aws_factory.aws_api_call_with_retry(
                        lambda: ec2_client.describe_security_groups(
                            Filters=filters,
                            NextToken=next_token
                        )
                    )
                else:
                    response = aws_factory.aws_api_call_with_retry(
                        lambda: ec2_client.describe_security_groups(Filters=filters)
                    )
                
                security_groups.extend(response.get('SecurityGroups', []))
                
                # Check if there are more results
                next_token = response.get('NextToken')
                if not next_token:
                    break
            
            logger.debug(f"Found {len(security_groups)} default security groups in {region}")
            return security_groups
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            
            if error_code in ['UnauthorizedOperation', 'AccessDenied']:
                logger.warning(f"Insufficient permissions to list security groups in {region}: {e}")
                return []
            else:
                logger.error(f"Error retrieving security groups in {region}: {e}")
                raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if default security group has no rules.
        
        Args:
            resource: Security group resource dictionary
            aws_factory: AWS client factory for additional API calls
            region: AWS region
            
        Returns:
            ComplianceResult indicating whether the default security group is compliant
        """
        group_id = resource.get('GroupId', 'unknown')
        group_name = resource.get('GroupName', 'unknown')
        vpc_id = resource.get('VpcId', 'unknown')
        
        try:
            # Get inbound and outbound rules
            inbound_rules = resource.get('IpPermissions', [])
            outbound_rules = resource.get('IpPermissionsEgress', [])
            
            # Check if both rule lists are empty
            if not inbound_rules and not outbound_rules:
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = (
                    f"Default security group {group_id} in VPC {vpc_id} has no inbound or outbound rules"
                )
            else:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                
                # Build detailed message about which rules exist
                rule_details = []
                if inbound_rules:
                    rule_details.append(f"{len(inbound_rules)} inbound rule(s)")
                if outbound_rules:
                    rule_details.append(f"{len(outbound_rules)} outbound rule(s)")
                
                evaluation_reason = (
                    f"Default security group {group_id} in VPC {vpc_id} has {' and '.join(rule_details)}. "
                    f"Default security groups should have no rules as a security best practice.\n\n"
                    f"Remove all rules from default security group:\n"
                    f"1. Go to EC2 console > Security Groups\n"
                    f"2. Select the default security group (ID: {group_id})\n"
                    f"3. Remove all inbound rules\n"
                    f"4. Remove all outbound rules (except the default allow-all egress if needed)\n"
                    f"5. Create custom security groups for actual use\n\n"
                    f"AWS CLI example to revoke inbound rules:\n"
                    f"aws ec2 describe-security-groups --group-ids {group_id} --region {region} --query 'SecurityGroups[0].IpPermissions' > permissions.json\n"
                    f"aws ec2 revoke-security-group-ingress --group-id {group_id} --region {region} --ip-permissions file://permissions.json\n\n"
                    f"AWS CLI example to revoke outbound rules:\n"
                    f"aws ec2 describe-security-groups --group-ids {group_id} --region {region} --query 'SecurityGroups[0].IpPermissionsEgress' > egress.json\n"
                    f"aws ec2 revoke-security-group-egress --group-id {group_id} --region {region} --ip-permissions file://egress.json\n\n"
                    f"Note: Default security groups cannot be deleted, only restricted."
                )
        
        except Exception as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Unexpected error evaluating security group {group_id}: {str(e)}"
        
        return ComplianceResult(
            resource_id=group_id,
            resource_type="AWS::EC2::SecurityGroup",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )


class VPCDnsResolutionEnabledAssessment(BaseConfigRuleAssessment):
    """Assessment for vpc-dns-resolution-enabled AWS Config rule.
    
    Validates that VPCs have both enableDnsHostnames and enableDnsSupport enabled
    to ensure proper DNS resolution for resources within the VPC.
    
    This is a regional service assessment that runs in all active regions.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="vpc-dns-resolution-enabled",
            control_id="4.3",
            resource_types=["AWS::EC2::VPC"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get VPCs.
        
        VPCs are regional resources, so we query in each active region.
        
        Args:
            aws_factory: AWS client factory for API access
            resource_type: AWS resource type (should be AWS::EC2::VPC)
            region: AWS region
            
        Returns:
            List of VPC dictionaries with VpcId, CidrBlock, State, IsDefault
        """
        if resource_type != "AWS::EC2::VPC":
            return []
        
        try:
            ec2_client = aws_factory.get_client('ec2', region)
            
            # List all VPCs with pagination support
            vpcs = []
            next_token = None
            
            while True:
                if next_token:
                    response = aws_factory.aws_api_call_with_retry(
                        lambda: ec2_client.describe_vpcs(NextToken=next_token)
                    )
                else:
                    response = aws_factory.aws_api_call_with_retry(
                        lambda: ec2_client.describe_vpcs()
                    )
                
                vpcs.extend(response.get('Vpcs', []))
                
                # Check if there are more results
                next_token = response.get('NextToken')
                if not next_token:
                    break
            
            logger.debug(f"Found {len(vpcs)} VPCs in {region}")
            return vpcs
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            
            if error_code in ['UnauthorizedOperation', 'AccessDenied']:
                logger.warning(f"Insufficient permissions to list VPCs in {region}: {e}")
                return []
            else:
                logger.error(f"Error retrieving VPCs in {region}: {e}")
                raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if VPC has DNS resolution and hostnames enabled.
        
        Args:
            resource: VPC resource dictionary
            aws_factory: AWS client factory for additional API calls
            region: AWS region
            
        Returns:
            ComplianceResult indicating whether the VPC DNS configuration is compliant
        """
        vpc_id = resource.get('VpcId', 'unknown')
        
        try:
            ec2_client = aws_factory.get_client('ec2', region)
            
            # Check enableDnsSupport attribute
            dns_support_response = aws_factory.aws_api_call_with_retry(
                lambda: ec2_client.describe_vpc_attribute(
                    VpcId=vpc_id,
                    Attribute='enableDnsSupport'
                )
            )
            enable_dns_support = dns_support_response.get('EnableDnsSupport', {}).get('Value', False)
            
            # Check enableDnsHostnames attribute
            dns_hostnames_response = aws_factory.aws_api_call_with_retry(
                lambda: ec2_client.describe_vpc_attribute(
                    VpcId=vpc_id,
                    Attribute='enableDnsHostnames'
                )
            )
            enable_dns_hostnames = dns_hostnames_response.get('EnableDnsHostnames', {}).get('Value', False)
            
            # Both must be enabled for compliance
            if enable_dns_support and enable_dns_hostnames:
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = (
                    f"VPC {vpc_id} has both DNS support and DNS hostnames enabled"
                )
            else:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                
                # Build detailed message about which settings are disabled
                disabled_settings = []
                if not enable_dns_support:
                    disabled_settings.append("DNS support (enableDnsSupport)")
                if not enable_dns_hostnames:
                    disabled_settings.append("DNS hostnames (enableDnsHostnames)")
                
                evaluation_reason = (
                    f"VPC {vpc_id} has the following DNS settings disabled: {', '.join(disabled_settings)}. "
                    f"Both settings must be enabled for proper DNS resolution.\n\n"
                    f"Enable DNS resolution for VPC:\n"
                    f"1. Go to VPC console\n"
                    f"2. Select the VPC (ID: {vpc_id})\n"
                )
                
                if not enable_dns_support:
                    evaluation_reason += (
                        f"3. Actions > Edit DNS resolution\n"
                        f"4. Enable DNS resolution (enableDnsSupport)\n"
                    )
                
                if not enable_dns_hostnames:
                    evaluation_reason += (
                        f"5. Actions > Edit DNS hostnames\n"
                        f"6. Enable DNS hostnames (enableDnsHostnames)\n"
                    )
                
                evaluation_reason += f"\nAWS CLI examples:\n"
                if not enable_dns_support:
                    evaluation_reason += f"aws ec2 modify-vpc-attribute --vpc-id {vpc_id} --enable-dns-support --region {region}\n"
                if not enable_dns_hostnames:
                    evaluation_reason += f"aws ec2 modify-vpc-attribute --vpc-id {vpc_id} --enable-dns-hostnames --region {region}\n"
        
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            
            if error_code == 'InvalidVpcID.NotFound':
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"VPC {vpc_id} not found (may have been deleted)"
            elif error_code in ['UnauthorizedOperation', 'AccessDenied']:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = (
                    f"Insufficient permissions to evaluate VPC {vpc_id}. "
                    f"Required permissions: ec2:DescribeVpcs, ec2:DescribeVpcAttribute"
                )
            else:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Error evaluating VPC {vpc_id}: {str(e)}"
        
        except Exception as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Unexpected error evaluating VPC {vpc_id}: {str(e)}"
        
        return ComplianceResult(
            resource_id=vpc_id,
            resource_type="AWS::EC2::VPC",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )


class RDSDefaultAdminCheckAssessment(BaseConfigRuleAssessment):
    """Assessment for rds-default-admin-check AWS Config rule.
    
    Ensures RDS instances don't use default admin usernames which are commonly
    targeted in brute force attacks. Default usernames include: postgres, admin,
    root, mysql, administrator, sa.
    
    This is a regional service assessment that runs in all active regions.
    """
    
    # Default usernames to check (case-insensitive)
    DEFAULT_USERNAMES = {'postgres', 'admin', 'root', 'mysql', 'administrator', 'sa'}
    
    def __init__(self):
        super().__init__(
            rule_name="rds-default-admin-check",
            control_id="4.4",
            resource_types=["AWS::RDS::DBInstance"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get RDS instances.
        
        RDS instances are regional resources, so we query in each active region.
        
        Args:
            aws_factory: AWS client factory for API access
            resource_type: AWS resource type (should be AWS::RDS::DBInstance)
            region: AWS region
            
        Returns:
            List of RDS instance dictionaries with DBInstanceIdentifier, DBInstanceArn, MasterUsername, Engine
        """
        if resource_type != "AWS::RDS::DBInstance":
            return []
        
        try:
            rds_client = aws_factory.get_client('rds', region)
            
            # List all RDS instances with pagination support
            db_instances = []
            marker = None
            
            while True:
                if marker:
                    response = aws_factory.aws_api_call_with_retry(
                        lambda: rds_client.describe_db_instances(Marker=marker)
                    )
                else:
                    response = aws_factory.aws_api_call_with_retry(
                        lambda: rds_client.describe_db_instances()
                    )
                
                db_instances.extend(response.get('DBInstances', []))
                
                # Check if there are more results
                marker = response.get('Marker')
                if not marker:
                    break
            
            logger.debug(f"Found {len(db_instances)} RDS instances in {region}")
            return db_instances
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            
            if error_code in ['AccessDenied']:
                logger.warning(f"Insufficient permissions to list RDS instances in {region}: {e}")
                return []
            else:
                logger.error(f"Error retrieving RDS instances in {region}: {e}")
                raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if RDS instance uses a default admin username.
        
        Args:
            resource: RDS instance resource dictionary
            aws_factory: AWS client factory for additional API calls
            region: AWS region
            
        Returns:
            ComplianceResult indicating whether the RDS instance username is compliant
        """
        db_instance_id = resource.get('DBInstanceIdentifier', 'unknown')
        db_instance_arn = resource.get('DBInstanceArn', 'unknown')
        master_username = resource.get('MasterUsername', '')
        engine = resource.get('Engine', 'unknown')
        
        try:
            # Check if master username is in the default list (case-insensitive)
            if master_username.lower() in self.DEFAULT_USERNAMES:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = (
                    f"RDS instance {db_instance_id} (engine: {engine}) uses default master username '{master_username}'. "
                    f"Default usernames are commonly targeted in brute force attacks and should be avoided.\n\n"
                    f"RDS master username cannot be changed after creation. Remediation requires:\n"
                    f"1. Create a snapshot of the existing RDS instance:\n"
                    f"   aws rds create-db-snapshot --db-instance-identifier {db_instance_id} --db-snapshot-identifier {db_instance_id}-snapshot --region {region}\n\n"
                    f"2. Restore snapshot to a new instance with a custom master username:\n"
                    f"   aws rds restore-db-instance-from-db-snapshot \\\n"
                    f"     --db-instance-identifier {db_instance_id}-new \\\n"
                    f"     --db-snapshot-identifier {db_instance_id}-snapshot \\\n"
                    f"     --region {region}\n"
                    f"   Note: You cannot change the master username during restore. You must create a new user with admin privileges.\n\n"
                    f"3. After restore, connect to the database and create a new admin user with a custom username\n"
                    f"4. Update application connection strings to use the new instance endpoint and new admin user\n"
                    f"5. Test the new instance thoroughly\n"
                    f"6. Delete the old instance after verification:\n"
                    f"   aws rds delete-db-instance --db-instance-identifier {db_instance_id} --skip-final-snapshot --region {region}\n\n"
                    f"Note: This is a disruptive change requiring downtime. Plan accordingly and test in a non-production environment first.\n\n"
                    f"Best practice: When creating new RDS instances, always use custom master usernames that are not easily guessable."
                )
            else:
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = (
                    f"RDS instance {db_instance_id} (engine: {engine}) uses custom master username '{master_username}' "
                    f"which is not a default value"
                )
        
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            
            if error_code == 'DBInstanceNotFound':
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"RDS instance {db_instance_id} not found (may have been deleted)"
            elif error_code in ['AccessDenied']:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = (
                    f"Insufficient permissions to evaluate RDS instance {db_instance_id}. "
                    f"Required permissions: rds:DescribeDBInstances"
                )
            else:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Error evaluating RDS instance {db_instance_id}: {str(e)}"
        
        except Exception as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Unexpected error evaluating RDS instance {db_instance_id}: {str(e)}"
        
        return ComplianceResult(
            resource_id=db_instance_arn,
            resource_type="AWS::RDS::DBInstance",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )


class EC2InstanceProfileLeastPrivilegeAssessment(BaseConfigRuleAssessment):
    """Assessment for ec2-instance-profile-least-privilege AWS Config rule.
    
    Validates that EC2 instance profiles follow the principle of least privilege
    by checking for overly permissive policies such as AdministratorAccess,
    PowerUserAccess, or policies with Action:"*" and Resource:"*".
    
    This is a regional service assessment (EC2) that queries global IAM service.
    """
    
    # Overly permissive managed policy ARNs
    OVERLY_PERMISSIVE_POLICIES = {
        'arn:aws:iam::aws:policy/AdministratorAccess',
        'arn:aws:iam::aws:policy/PowerUserAccess'
    }
    
    def __init__(self):
        super().__init__(
            rule_name="ec2-instance-profile-least-privilege",
            control_id="4.5",
            resource_types=["AWS::EC2::Instance"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get EC2 instances with instance profiles.
        
        EC2 instances are regional resources, so we query in each active region.
        We only return instances that have an instance profile attached.
        
        Args:
            aws_factory: AWS client factory for API access
            resource_type: AWS resource type (should be AWS::EC2::Instance)
            region: AWS region
            
        Returns:
            List of EC2 instance dictionaries with InstanceId, IamInstanceProfile, State
        """
        if resource_type != "AWS::EC2::Instance":
            return []
        
        try:
            ec2_client = aws_factory.get_client('ec2', region)
            
            # List all EC2 instances with pagination support
            instances = []
            next_token = None
            
            while True:
                if next_token:
                    response = aws_factory.aws_api_call_with_retry(
                        lambda: ec2_client.describe_instances(NextToken=next_token)
                    )
                else:
                    response = aws_factory.aws_api_call_with_retry(
                        lambda: ec2_client.describe_instances()
                    )
                
                # Extract instances from reservations
                for reservation in response.get('Reservations', []):
                    for instance in reservation.get('Instances', []):
                        # Only include instances with instance profiles
                        if 'IamInstanceProfile' in instance:
                            instances.append(instance)
                
                # Check if there are more results
                next_token = response.get('NextToken')
                if not next_token:
                    break
            
            logger.debug(f"Found {len(instances)} EC2 instances with instance profiles in {region}")
            return instances
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            
            if error_code in ['UnauthorizedOperation', 'AccessDenied']:
                logger.warning(f"Insufficient permissions to list EC2 instances in {region}: {e}")
                return []
            else:
                logger.error(f"Error retrieving EC2 instances in {region}: {e}")
                raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if EC2 instance profile follows least privilege.
        
        Args:
            resource: EC2 instance resource dictionary
            aws_factory: AWS client factory for additional API calls
            region: AWS region
            
        Returns:
            ComplianceResult indicating whether the instance profile is compliant
        """
        instance_id = resource.get('InstanceId', 'unknown')
        instance_profile_info = resource.get('IamInstanceProfile', {})
        instance_profile_arn = instance_profile_info.get('Arn', 'unknown')
        
        try:
            # Extract instance profile name from ARN
            # ARN format: arn:aws:iam::123456789012:instance-profile/profile-name
            instance_profile_name = instance_profile_arn.split('/')[-1] if '/' in instance_profile_arn else 'unknown'
            
            # Get IAM client (global service, use us-east-1)
            iam_client = aws_factory.get_client('iam', 'us-east-1')
            
            # Get instance profile details to find the associated role
            instance_profile_response = aws_factory.aws_api_call_with_retry(
                lambda: iam_client.get_instance_profile(InstanceProfileName=instance_profile_name)
            )
            
            instance_profile = instance_profile_response.get('InstanceProfile', {})
            roles = instance_profile.get('Roles', [])
            
            if not roles:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"EC2 instance {instance_id} has instance profile {instance_profile_name} with no associated roles"
                
                return ComplianceResult(
                    resource_id=instance_id,
                    resource_type="AWS::EC2::Instance",
                    compliance_status=compliance_status,
                    evaluation_reason=evaluation_reason,
                    config_rule_name=self.rule_name,
                    region=region
                )
            
            # Check the first role (instance profiles typically have one role)
            role = roles[0]
            role_name = role.get('RoleName', 'unknown')
            
            # Check for overly permissive policies
            overly_permissive_policies = []
            
            # Check attached managed policies
            attached_policies_response = aws_factory.aws_api_call_with_retry(
                lambda: iam_client.list_attached_role_policies(RoleName=role_name)
            )
            
            for policy in attached_policies_response.get('AttachedPolicies', []):
                policy_arn = policy.get('PolicyArn', '')
                policy_name = policy.get('PolicyName', '')
                
                # Check if it's an overly permissive managed policy
                if policy_arn in self.OVERLY_PERMISSIVE_POLICIES:
                    overly_permissive_policies.append(f"Managed policy: {policy_name} ({policy_arn})")
            
            # Check inline policies
            inline_policies_response = aws_factory.aws_api_call_with_retry(
                lambda: iam_client.list_role_policies(RoleName=role_name)
            )
            
            for policy_name in inline_policies_response.get('PolicyNames', []):
                # Get the policy document
                policy_response = aws_factory.aws_api_call_with_retry(
                    lambda: iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                )
                
                policy_document = policy_response.get('PolicyDocument', {})
                
                # Check if policy has Action:"*" with Resource:"*"
                if self._is_overly_permissive_policy(policy_document):
                    overly_permissive_policies.append(f"Inline policy: {policy_name} (contains Action:'*' with Resource:'*')")
            
            # Determine compliance status
            if overly_permissive_policies:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = (
                    f"EC2 instance {instance_id} has instance profile {instance_profile_name} with role {role_name} "
                    f"that contains overly permissive policies:\n"
                )
                for policy in overly_permissive_policies:
                    evaluation_reason += f"  - {policy}\n"
                
                evaluation_reason += (
                    f"\nApply least privilege to instance profile:\n"
                    f"1. Review the instance profile's IAM role policies\n"
                    f"2. Identify overly broad permissions (wildcards, full access)\n"
                    f"3. Create new policies with specific actions and resources\n"
                    f"4. Replace broad policies with specific policies\n"
                    f"5. Test application functionality\n"
                    f"6. Remove overly permissive policies\n\n"
                    f"AWS CLI examples:\n"
                    f"# Create a specific policy\n"
                    f"aws iam create-policy --policy-name {role_name}-specific-policy --policy-document file://policy.json\n\n"
                    f"# Attach specific policy to role\n"
                    f"aws iam attach-role-policy --role-name {role_name} --policy-arn arn:aws:iam::<account>:policy/{role_name}-specific-policy\n\n"
                    f"# Detach overly permissive policy\n"
                    f"aws iam detach-role-policy --role-name {role_name} --policy-arn <overly-permissive-policy-arn>\n\n"
                    f"Best practices:\n"
                    f"- Grant only the permissions required for the instance's workload\n"
                    f"- Use specific actions instead of wildcards\n"
                    f"- Limit resources to specific ARNs when possible\n"
                    f"- Regularly review and refine permissions"
                )
            else:
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = (
                    f"EC2 instance {instance_id} has instance profile {instance_profile_name} with role {role_name} "
                    f"that follows least privilege principles (no overly permissive policies detected)"
                )
        
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            
            if error_code == 'InvalidInstanceID.NotFound':
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"EC2 instance {instance_id} not found (may have been deleted)"
            elif error_code == 'NoSuchEntity':
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Instance profile or role for EC2 instance {instance_id} not found (may have been deleted)"
            elif error_code in ['AccessDenied', 'UnauthorizedOperation']:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = (
                    f"Insufficient permissions to evaluate EC2 instance {instance_id}. "
                    f"Required permissions: ec2:DescribeInstances, iam:GetInstanceProfile, "
                    f"iam:ListAttachedRolePolicies, iam:ListRolePolicies, iam:GetRolePolicy"
                )
            else:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Error evaluating EC2 instance {instance_id}: {str(e)}"
        
        except Exception as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Unexpected error evaluating EC2 instance {instance_id}: {str(e)}"
        
        return ComplianceResult(
            resource_id=instance_id,
            resource_type="AWS::EC2::Instance",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _is_overly_permissive_policy(self, policy_document: Dict[str, Any]) -> bool:
        """Check if a policy document contains overly permissive permissions.
        
        Args:
            policy_document: IAM policy document
            
        Returns:
            True if policy contains Action:"*" with Resource:"*", False otherwise
        """
        statements = policy_document.get('Statement', [])
        
        for statement in statements:
            # Skip deny statements
            if statement.get('Effect') != 'Allow':
                continue
            
            actions = statement.get('Action', [])
            resources = statement.get('Resource', [])
            
            # Normalize to lists
            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]
            
            # Check if both Action and Resource contain wildcards
            has_wildcard_action = '*' in actions
            has_wildcard_resource = '*' in resources
            
            if has_wildcard_action and has_wildcard_resource:
                return True
        
        return False


# ============================================================================
# Control 5: Account Management Assessments
# ============================================================================

class IAMServiceAccountInventoryCheckAssessment(BaseConfigRuleAssessment):
    """Assessment for iam-service-account-inventory-check AWS Config rule.
    
    Validates that service accounts (IAM users and roles) have required documentation
    tags: Purpose, Owner, and LastReviewed. Service accounts are identified by naming
    convention (contains "service", "app", "application") or ServiceAccount=true tag.
    
    This is a global service assessment that only runs in us-east-1.
    """
    
    # Required tags for service accounts
    REQUIRED_TAGS = {'Purpose', 'Owner', 'LastReviewed'}
    
    # Keywords in names that indicate service accounts
    SERVICE_ACCOUNT_KEYWORDS = {'service', 'app', 'application'}
    
    def __init__(self):
        super().__init__(
            rule_name="iam-service-account-inventory-check",
            control_id="5.1",
            resource_types=["AWS::IAM::User", "AWS::IAM::Role"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get IAM users and roles that are service accounts.
        
        IAM is a global service, so we only query in us-east-1.
        
        Args:
            aws_factory: AWS client factory for API access
            resource_type: AWS resource type (AWS::IAM::User or AWS::IAM::Role)
            region: AWS region (should be us-east-1 for IAM)
            
        Returns:
            List of IAM user/role dictionaries that are identified as service accounts
        """
        if resource_type not in ["AWS::IAM::User", "AWS::IAM::Role"]:
            return []
        
        # IAM is a global service - only evaluate in us-east-1
        if region != 'us-east-1':
            logger.debug(f"Skipping IAM evaluation in {region} - global service evaluated in us-east-1 only")
            return []
        
        try:
            iam_client = aws_factory.get_client('iam', region)
            service_accounts = []
            
            if resource_type == "AWS::IAM::User":
                # List all IAM users with pagination
                marker = None
                while True:
                    if marker:
                        response = aws_factory.aws_api_call_with_retry(
                            lambda: iam_client.list_users(Marker=marker)
                        )
                    else:
                        response = aws_factory.aws_api_call_with_retry(
                            lambda: iam_client.list_users()
                        )
                    
                    users = response.get('Users', [])
                    
                    # Filter for service accounts
                    for user in users:
                        if self._is_service_account(user.get('UserName', ''), user.get('Tags', [])):
                            service_accounts.append(user)
                    
                    if response.get('IsTruncated', False):
                        marker = response.get('Marker')
                    else:
                        break
            
            elif resource_type == "AWS::IAM::Role":
                # List all IAM roles with pagination
                marker = None
                while True:
                    if marker:
                        response = aws_factory.aws_api_call_with_retry(
                            lambda: iam_client.list_roles(Marker=marker)
                        )
                    else:
                        response = aws_factory.aws_api_call_with_retry(
                            lambda: iam_client.list_roles()
                        )
                    
                    roles = response.get('Roles', [])
                    
                    # Filter for service accounts
                    for role in roles:
                        if self._is_service_account(role.get('RoleName', ''), role.get('Tags', [])):
                            service_accounts.append(role)
                    
                    if response.get('IsTruncated', False):
                        marker = response.get('Marker')
                    else:
                        break
            
            logger.debug(f"Found {len(service_accounts)} service accounts of type {resource_type}")
            return service_accounts
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            
            if error_code in ['AccessDenied']:
                logger.warning(f"Insufficient permissions to list {resource_type}: {e}")
                return []
            else:
                logger.error(f"Error retrieving {resource_type}: {e}")
                raise
    
    def _is_service_account(self, name: str, tags: List[Dict[str, str]]) -> bool:
        """Determine if an IAM user or role is a service account.
        
        Service accounts are identified by:
        1. Name contains "service", "app", or "application" (case-insensitive)
        2. Has ServiceAccount=true tag
        
        Args:
            name: IAM user or role name
            tags: List of tags
            
        Returns:
            True if identified as service account, False otherwise
        """
        # Check naming convention
        name_lower = name.lower()
        for keyword in self.SERVICE_ACCOUNT_KEYWORDS:
            if keyword in name_lower:
                return True
        
        # Check for ServiceAccount tag
        for tag in tags:
            if tag.get('Key') == 'ServiceAccount' and tag.get('Value', '').lower() == 'true':
                return True
        
        return False
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if service account has required documentation tags.
        
        Args:
            resource: IAM user or role resource dictionary
            aws_factory: AWS client factory for additional API calls
            region: AWS region
            
        Returns:
            ComplianceResult indicating whether the service account has required tags
        """
        # Determine resource type and extract identifiers
        if 'UserName' in resource:
            resource_type = "AWS::IAM::User"
            resource_name = resource.get('UserName', 'unknown')
            resource_id = resource.get('Arn', 'unknown')
        else:
            resource_type = "AWS::IAM::Role"
            resource_name = resource.get('RoleName', 'unknown')
            resource_id = resource.get('Arn', 'unknown')
        
        try:
            # Get tags from resource
            tags = resource.get('Tags', [])
            
            # Extract tag keys and check for required tags
            tag_dict = {tag.get('Key'): tag.get('Value', '') for tag in tags}
            present_required_tags = set(tag_dict.keys()) & self.REQUIRED_TAGS
            missing_tags = self.REQUIRED_TAGS - present_required_tags
            
            # Check if all required tags are present with non-empty values
            empty_tags = []
            for tag_key in present_required_tags:
                if not tag_dict.get(tag_key, '').strip():
                    empty_tags.append(tag_key)
            
            if not missing_tags and not empty_tags:
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = (
                    f"Service account {resource_name} has all required documentation tags: "
                    f"Purpose='{tag_dict.get('Purpose')}', Owner='{tag_dict.get('Owner')}', "
                    f"LastReviewed='{tag_dict.get('LastReviewed')}'"
                )
            else:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                
                issues = []
                if missing_tags:
                    issues.append(f"Missing tags: {', '.join(sorted(missing_tags))}")
                if empty_tags:
                    issues.append(f"Empty tags: {', '.join(sorted(empty_tags))}")
                
                evaluation_reason = (
                    f"Service account {resource_name} is missing required documentation tags. "
                    f"{' and '.join(issues)}.\n\n"
                    f"Add required documentation tags to service accounts:\n"
                    f"1. Go to IAM console > {'Users' if resource_type == 'AWS::IAM::User' else 'Roles'}\n"
                    f"2. Select the service account '{resource_name}'\n"
                    f"3. Tags tab > Manage tags\n"
                    f"4. Add required tags:\n"
                    f"   - Purpose: Description of what the account is used for\n"
                    f"   - Owner: Team or individual responsible\n"
                    f"   - LastReviewed: Date of last access review (YYYY-MM-DD)\n"
                    f"5. Save changes\n\n"
                    f"AWS CLI example:\n"
                )
                
                if resource_type == "AWS::IAM::User":
                    evaluation_reason += (
                        f"aws iam tag-user --user-name {resource_name} --tags "
                        f"Key=Purpose,Value=\"API access for app\" "
                        f"Key=Owner,Value=\"platform-team\" "
                        f"Key=LastReviewed,Value=\"2024-01-15\"\n\n"
                    )
                else:
                    evaluation_reason += (
                        f"aws iam tag-role --role-name {resource_name} --tags "
                        f"Key=Purpose,Value=\"Lambda execution\" "
                        f"Key=Owner,Value=\"dev-team\" "
                        f"Key=LastReviewed,Value=\"2024-01-15\"\n\n"
                    )
                
                evaluation_reason += (
                    f"Best practices:\n"
                    f"- Review service accounts quarterly\n"
                    f"- Update LastReviewed tag after each review\n"
                    f"- Remove unused service accounts\n"
                    f"- Document service account inventory"
                )
        
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            
            if error_code == 'NoSuchEntity':
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Service account {resource_name} not found (may have been deleted)"
            elif error_code in ['AccessDenied']:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = (
                    f"Insufficient permissions to evaluate service account {resource_name}. "
                    f"Required permissions: iam:ListUsers, iam:ListRoles, iam:ListUserTags, iam:ListRoleTags"
                )
            else:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Error evaluating service account {resource_name}: {str(e)}"
        
        except Exception as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Unexpected error evaluating service account {resource_name}: {str(e)}"
        
        return ComplianceResult(
            resource_id=resource_id,
            resource_type=resource_type,
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )


class IAMAdminPolicyAttachedToRoleCheckAssessment(BaseConfigRuleAssessment):
    """Assessment for iam-admin-policy-attached-to-role-check AWS Config rule.
    
    Ensures administrative policies are attached to roles, not directly to users.
    This promotes best practices of using temporary credentials via role assumption
    rather than long-lived user credentials with administrative access.
    
    This is a global service assessment that only runs in us-east-1.
    """
    
    # Administrative managed policy ARNs
    ADMIN_MANAGED_POLICIES = {
        'arn:aws:iam::aws:policy/AdministratorAccess',
        'arn:aws:iam::aws:policy/PowerUserAccess'
    }
    
    def __init__(self):
        super().__init__(
            rule_name="iam-admin-policy-attached-to-role-check",
            control_id="5.2",
            resource_types=["AWS::IAM::User"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get IAM users.
        
        IAM is a global service, so we only query in us-east-1.
        
        Args:
            aws_factory: AWS client factory for API access
            resource_type: AWS resource type (should be AWS::IAM::User)
            region: AWS region (should be us-east-1 for IAM)
            
        Returns:
            List of IAM user dictionaries
        """
        if resource_type != "AWS::IAM::User":
            return []
        
        # IAM is a global service - only evaluate in us-east-1
        if region != 'us-east-1':
            logger.debug(f"Skipping IAM evaluation in {region} - global service evaluated in us-east-1 only")
            return []
        
        try:
            iam_client = aws_factory.get_client('iam', region)
            
            # List all IAM users with pagination
            users = []
            marker = None
            
            while True:
                if marker:
                    response = aws_factory.aws_api_call_with_retry(
                        lambda: iam_client.list_users(Marker=marker)
                    )
                else:
                    response = aws_factory.aws_api_call_with_retry(
                        lambda: iam_client.list_users()
                    )
                
                users.extend(response.get('Users', []))
                
                if response.get('IsTruncated', False):
                    marker = response.get('Marker')
                else:
                    break
            
            logger.debug(f"Found {len(users)} IAM users")
            return users
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            
            if error_code in ['AccessDenied']:
                logger.warning(f"Insufficient permissions to list IAM users: {e}")
                return []
            else:
                logger.error(f"Error retrieving IAM users: {e}")
                raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if IAM user has administrative policies attached.
        
        Args:
            resource: IAM user resource dictionary
            aws_factory: AWS client factory for additional API calls
            region: AWS region
            
        Returns:
            ComplianceResult indicating whether the user has admin policies
        """
        user_name = resource.get('UserName', 'unknown')
        user_arn = resource.get('Arn', 'unknown')
        
        try:
            iam_client = aws_factory.get_client('iam', 'us-east-1')
            admin_policies = []
            
            # Check attached managed policies
            attached_policies_response = aws_factory.aws_api_call_with_retry(
                lambda: iam_client.list_attached_user_policies(UserName=user_name)
            )
            
            for policy in attached_policies_response.get('AttachedPolicies', []):
                policy_arn = policy.get('PolicyArn', '')
                policy_name = policy.get('PolicyName', '')
                
                if policy_arn in self.ADMIN_MANAGED_POLICIES:
                    admin_policies.append(f"Managed policy: {policy_name} ({policy_arn})")
            
            # Check inline policies
            inline_policies_response = aws_factory.aws_api_call_with_retry(
                lambda: iam_client.list_user_policies(UserName=user_name)
            )
            
            for policy_name in inline_policies_response.get('PolicyNames', []):
                # Get the policy document
                policy_response = aws_factory.aws_api_call_with_retry(
                    lambda: iam_client.get_user_policy(UserName=user_name, PolicyName=policy_name)
                )
                
                policy_document = policy_response.get('PolicyDocument', {})
                
                # Check if policy has Action:"*" with Resource:"*"
                if self._is_admin_policy(policy_document):
                    admin_policies.append(f"Inline policy: {policy_name} (contains Action:'*' with Resource:'*')")
            
            # Determine compliance status
            if admin_policies:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = (
                    f"IAM user {user_name} has administrative policies attached directly:\n"
                )
                for policy in admin_policies:
                    evaluation_reason += f"  - {policy}\n"
                
                evaluation_reason += (
                    f"\nMove administrative access from users to roles:\n"
                    f"1. Create an IAM role for administrative access\n"
                    f"2. Attach administrative policies to the role\n"
                    f"3. Configure trust policy for the role (allow users to assume)\n"
                    f"4. Remove administrative policies from IAM users\n"
                    f"5. Users should assume the role when admin access is needed\n\n"
                    f"AWS CLI example:\n"
                    f"# Create admin role\n"
                    f"aws iam create-role --role-name AdminRole --assume-role-policy-document file://trust-policy.json\n"
                    f"aws iam attach-role-policy --role-name AdminRole --policy-arn arn:aws:iam::aws:policy/AdministratorAccess\n\n"
                    f"# Remove admin policy from user\n"
                    f"aws iam detach-user-policy --user-name {user_name} --policy-arn arn:aws:iam::aws:policy/AdministratorAccess\n\n"
                    f"# User assumes role\n"
                    f"aws sts assume-role --role-arn arn:aws:iam::<account>:role/AdminRole --role-session-name admin-session\n\n"
                    f"Benefits:\n"
                    f"- Temporary credentials with session limits\n"
                    f"- Audit trail of role assumptions\n"
                    f"- Centralized permission management\n"
                    f"- Easier to revoke access"
                )
            else:
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = (
                    f"IAM user {user_name} does not have administrative policies attached directly"
                )
        
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            
            if error_code == 'NoSuchEntity':
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"IAM user {user_name} not found (may have been deleted)"
            elif error_code in ['AccessDenied']:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = (
                    f"Insufficient permissions to evaluate IAM user {user_name}. "
                    f"Required permissions: iam:ListAttachedUserPolicies, iam:ListUserPolicies, iam:GetUserPolicy"
                )
            else:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Error evaluating IAM user {user_name}: {str(e)}"
        
        except Exception as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Unexpected error evaluating IAM user {user_name}: {str(e)}"
        
        return ComplianceResult(
            resource_id=user_arn,
            resource_type="AWS::IAM::User",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _is_admin_policy(self, policy_document: Dict[str, Any]) -> bool:
        """Check if a policy document grants administrative permissions.
        
        Args:
            policy_document: IAM policy document
            
        Returns:
            True if policy contains Action:"*" with Resource:"*", False otherwise
        """
        statements = policy_document.get('Statement', [])
        
        for statement in statements:
            # Skip deny statements
            if statement.get('Effect') != 'Allow':
                continue
            
            actions = statement.get('Action', [])
            resources = statement.get('Resource', [])
            
            # Normalize to lists
            if isinstance(actions, str):
                actions = [actions]
            if isinstance(resources, str):
                resources = [resources]
            
            # Check if both Action and Resource contain wildcards
            has_wildcard_action = '*' in actions
            has_wildcard_resource = '*' in resources
            
            if has_wildcard_action and has_wildcard_resource:
                return True
        
        return False


class SSOEnabledCheckAssessment(BaseConfigRuleAssessment):
    """Assessment for sso-enabled-check AWS Config rule.
    
    Validates that AWS IAM Identity Center (SSO) is configured and enabled.
    SSO provides centralized user management and single sign-on experience,
    reducing IAM user sprawl and improving security.
    
    This is a global service assessment that only runs in us-east-1.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="sso-enabled-check",
            control_id="5.3",
            resource_types=["AWS::::Account"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get account-level resource for SSO check.
        
        SSO is a global service, so we only query in us-east-1.
        Returns a single account-level resource.
        
        Args:
            aws_factory: AWS client factory for API access
            resource_type: AWS resource type (should be AWS::::Account)
            region: AWS region (should be us-east-1 for SSO)
            
        Returns:
            List containing single account-level resource dictionary
        """
        if resource_type != "AWS::::Account":
            return []
        
        # SSO is a global service - only evaluate in us-east-1
        if region != 'us-east-1':
            logger.debug(f"Skipping SSO evaluation in {region} - global service evaluated in us-east-1 only")
            return []
        
        try:
            # Get account ID for resource identification
            sts_client = aws_factory.get_client('sts', region)
            identity_response = aws_factory.aws_api_call_with_retry(
                lambda: sts_client.get_caller_identity()
            )
            account_id = identity_response.get('Account', 'unknown')
            
            # Return single account-level resource
            return [{
                'AccountId': account_id,
                'ResourceType': 'AWS::::Account'
            }]
            
        except ClientError as e:
            logger.error(f"Error getting account identity: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if AWS IAM Identity Center (SSO) is enabled.
        
        Args:
            resource: Account resource dictionary
            aws_factory: AWS client factory for additional API calls
            region: AWS region
            
        Returns:
            ComplianceResult indicating whether SSO is enabled
        """
        account_id = resource.get('AccountId', 'unknown')
        resource_id = f"arn:aws::::account/{account_id}"
        
        try:
            sso_admin_client = aws_factory.get_client('sso-admin', 'us-east-1')
            
            # List SSO instances
            instances_response = aws_factory.aws_api_call_with_retry(
                lambda: sso_admin_client.list_instances()
            )
            
            instances = instances_response.get('Instances', [])
            
            if instances:
                # SSO is enabled - at least one instance exists
                instance_arns = [inst.get('InstanceArn', 'unknown') for inst in instances]
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = (
                    f"AWS IAM Identity Center (SSO) is enabled for account {account_id}. "
                    f"Found {len(instances)} SSO instance(s): {', '.join(instance_arns)}"
                )
            else:
                # No SSO instances found
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = (
                    f"AWS IAM Identity Center (SSO) is not enabled for account {account_id}.\n\n"
                    f"Enable AWS IAM Identity Center (SSO):\n"
                    f"1. Go to IAM Identity Center console\n"
                    f"2. Enable IAM Identity Center\n"
                    f"3. Choose identity source:\n"
                    f"   - Identity Center directory (default)\n"
                    f"   - Active Directory\n"
                    f"   - External identity provider (SAML 2.0)\n"
                    f"4. Configure users and groups\n"
                    f"5. Assign users to AWS accounts and permission sets\n"
                    f"6. Users access AWS via SSO portal\n\n"
                    f"AWS CLI example:\n"
                    f"# SSO must be enabled through console or Organizations API\n"
                    f"# After enabling, configure permission sets:\n"
                    f"aws sso-admin create-permission-set --instance-arn <instance-arn> --name ReadOnlyAccess\n"
                    f"aws sso-admin attach-managed-policy-to-permission-set \\\n"
                    f"  --instance-arn <instance-arn> \\\n"
                    f"  --permission-set-arn <ps-arn> \\\n"
                    f"  --managed-policy-arn arn:aws:iam::aws:policy/ReadOnlyAccess\n\n"
                    f"Benefits:\n"
                    f"- Centralized user management\n"
                    f"- Single sign-on experience\n"
                    f"- Temporary credentials\n"
                    f"- Integration with corporate identity providers\n"
                    f"- Reduced IAM user sprawl"
                )
        
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            
            if error_code in ['ResourceNotFoundException']:
                # ResourceNotFoundException indicates SSO is not configured
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = (
                    f"AWS IAM Identity Center (SSO) is not enabled for account {account_id}. "
                    f"Enable SSO through the IAM Identity Center console to provide centralized "
                    f"user management and single sign-on capabilities."
                )
            elif error_code in ['AccessDenied']:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = (
                    f"Insufficient permissions to check SSO status for account {account_id}. "
                    f"Required permissions: sso:ListInstances"
                )
            else:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Error checking SSO status for account {account_id}: {str(e)}"
        
        except Exception as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Unexpected error checking SSO status for account {account_id}: {str(e)}"
        
        return ComplianceResult(
            resource_id=resource_id,
            resource_type="AWS::::Account",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )


class IAMUserNoInlinePoliciesAssessment(BaseConfigRuleAssessment):
    """Assessment for iam-user-no-inline-policies AWS Config rule.
    
    Ensures IAM users don't have inline policies attached. Inline policies are
    harder to manage, audit, and reuse compared to managed policies. Best practice
    is to use managed policies or group memberships for permission management.
    
    This is a global service assessment that only runs in us-east-1.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="iam-user-no-inline-policies",
            control_id="5.4",
            resource_types=["AWS::IAM::User"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get IAM users.
        
        IAM is a global service, so we only query in us-east-1.
        
        Args:
            aws_factory: AWS client factory for API access
            resource_type: AWS resource type (should be AWS::IAM::User)
            region: AWS region (should be us-east-1 for IAM)
            
        Returns:
            List of IAM user dictionaries
        """
        if resource_type != "AWS::IAM::User":
            return []
        
        # IAM is a global service - only evaluate in us-east-1
        if region != 'us-east-1':
            logger.debug(f"Skipping IAM evaluation in {region} - global service evaluated in us-east-1 only")
            return []
        
        try:
            iam_client = aws_factory.get_client('iam', region)
            
            # List all IAM users with pagination
            users = []
            marker = None
            
            while True:
                if marker:
                    response = aws_factory.aws_api_call_with_retry(
                        lambda: iam_client.list_users(Marker=marker)
                    )
                else:
                    response = aws_factory.aws_api_call_with_retry(
                        lambda: iam_client.list_users()
                    )
                
                users.extend(response.get('Users', []))
                
                if response.get('IsTruncated', False):
                    marker = response.get('Marker')
                else:
                    break
            
            logger.debug(f"Found {len(users)} IAM users")
            return users
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            
            if error_code in ['AccessDenied']:
                logger.warning(f"Insufficient permissions to list IAM users: {e}")
                return []
            else:
                logger.error(f"Error retrieving IAM users: {e}")
                raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if IAM user has inline policies.
        
        Args:
            resource: IAM user resource dictionary
            aws_factory: AWS client factory for additional API calls
            region: AWS region
            
        Returns:
            ComplianceResult indicating whether the user has inline policies
        """
        user_name = resource.get('UserName', 'unknown')
        user_arn = resource.get('Arn', 'unknown')
        
        try:
            iam_client = aws_factory.get_client('iam', 'us-east-1')
            
            # List inline policies for the user
            inline_policies_response = aws_factory.aws_api_call_with_retry(
                lambda: iam_client.list_user_policies(UserName=user_name)
            )
            
            inline_policy_names = inline_policies_response.get('PolicyNames', [])
            
            if not inline_policy_names:
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = (
                    f"IAM user {user_name} has no inline policies attached"
                )
            else:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = (
                    f"IAM user {user_name} has {len(inline_policy_names)} inline policy/policies attached: "
                    f"{', '.join(inline_policy_names)}.\n\n"
                    f"Replace inline policies with managed policies or group memberships:\n"
                    f"1. Review inline policy document\n"
                    f"2. Create equivalent managed policy or identify existing managed policy\n"
                    f"3. Attach managed policy to user or add user to appropriate group\n"
                    f"4. Test that user still has required permissions\n"
                    f"5. Delete inline policy\n\n"
                    f"AWS CLI example:\n"
                    f"# Get inline policy document\n"
                    f"aws iam get-user-policy --user-name {user_name} --policy-name <inline-policy> > policy.json\n\n"
                    f"# Create managed policy from document\n"
                    f"aws iam create-policy --policy-name {user_name}-policy --policy-document file://policy.json\n\n"
                    f"# Attach managed policy to user\n"
                    f"aws iam attach-user-policy --user-name {user_name} --policy-arn <policy-arn>\n\n"
                    f"# Delete inline policy\n"
                    f"aws iam delete-user-policy --user-name {user_name} --policy-name <inline-policy>\n\n"
                    f"Best practices:\n"
                    f"- Use managed policies for reusability\n"
                    f"- Use groups for common permission sets\n"
                    f"- Avoid user-specific permissions when possible\n"
                    f"- Managed policies are easier to audit and update"
                )
        
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            
            if error_code == 'NoSuchEntity':
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"IAM user {user_name} not found (may have been deleted)"
            elif error_code in ['AccessDenied']:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = (
                    f"Insufficient permissions to evaluate IAM user {user_name}. "
                    f"Required permissions: iam:ListUserPolicies"
                )
            else:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Error evaluating IAM user {user_name}: {str(e)}"
        
        except Exception as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Unexpected error evaluating IAM user {user_name}: {str(e)}"
        
        return ComplianceResult(
            resource_id=user_arn,
            resource_type="AWS::IAM::User",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )


# ============================================================================
# Control 6: Access Control Management Assessments
# ============================================================================

class IAMAccessAnalyzerEnabledAssessment(BaseConfigRuleAssessment):
    """Assessment for iam-access-analyzer-enabled AWS Config rule.
    
    Ensures IAM Access Analyzer is enabled in all active regions to identify
    resources shared with external entities and detect unintended access.
    
    This is a regional service assessment that runs in all active regions.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="iam-access-analyzer-enabled",
            control_id="6.1",
            resource_types=["AWS::AccessAnalyzer::Analyzer"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get Access Analyzer analyzers.
        
        Access Analyzer is a regional service, so we query in each active region.
        
        Args:
            aws_factory: AWS client factory for API access
            resource_type: AWS resource type (should be AWS::AccessAnalyzer::Analyzer)
            region: AWS region
            
        Returns:
            List of analyzer dictionaries or a single region-level resource
        """
        if resource_type != "AWS::AccessAnalyzer::Analyzer":
            return []
        
        try:
            analyzer_client = aws_factory.get_client('accessanalyzer', region)
            
            # List all analyzers with pagination support
            analyzers = []
            next_token = None
            
            while True:
                if next_token:
                    response = aws_factory.aws_api_call_with_retry(
                        lambda: analyzer_client.list_analyzers(nextToken=next_token)
                    )
                else:
                    response = aws_factory.aws_api_call_with_retry(
                        lambda: analyzer_client.list_analyzers()
                    )
                
                analyzers.extend(response.get('analyzers', []))
                
                # Check if there are more results
                next_token = response.get('nextToken')
                if not next_token:
                    break
            
            # Return a single region-level resource to check if any active analyzer exists
            # This allows us to evaluate the region as a whole
            return [{'region': region, 'analyzers': analyzers}]
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            
            if error_code in ['AccessDenied']:
                logger.warning(f"Insufficient permissions to list Access Analyzers in {region}: {e}")
                return []
            else:
                logger.error(f"Error retrieving Access Analyzers in {region}: {e}")
                raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if Access Analyzer is enabled in the region.
        
        Args:
            resource: Region-level resource with analyzers list
            aws_factory: AWS client factory for additional API calls
            region: AWS region
            
        Returns:
            ComplianceResult indicating whether Access Analyzer is enabled
        """
        analyzers = resource.get('analyzers', [])
        resource_id = f"access-analyzer-{region}"
        
        try:
            # Check if at least one analyzer with status ACTIVE exists
            active_analyzers = [a for a in analyzers if a.get('status') == 'ACTIVE']
            
            if active_analyzers:
                compliance_status = ComplianceStatus.COMPLIANT
                analyzer_names = [a.get('name', 'unknown') for a in active_analyzers]
                evaluation_reason = (
                    f"IAM Access Analyzer is enabled in region {region} with {len(active_analyzers)} active analyzer(s): "
                    f"{', '.join(analyzer_names)}"
                )
            else:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = (
                    f"IAM Access Analyzer is not enabled in region {region}. "
                    f"Enable Access Analyzer to identify resources shared with external entities.\n\n"
                    f"Enable IAM Access Analyzer:\n"
                    f"1. Go to IAM console > Access Analyzer\n"
                    f"2. Create analyzer for region {region}\n"
                    f"3. Choose analyzer type:\n"
                    f"   - Account analyzer: Analyzes resources in the account\n"
                    f"   - Organization analyzer: Analyzes resources across organization\n"
                    f"4. Review findings regularly\n\n"
                    f"AWS CLI example:\n"
                    f"aws accessanalyzer create-analyzer --analyzer-name account-analyzer --type ACCOUNT --region {region}\n\n"
                    f"Benefits:\n"
                    f"- Identifies resources shared with external entities\n"
                    f"- Detects unintended access\n"
                    f"- Continuous monitoring\n"
                    f"- Compliance validation"
                )
        
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            
            if error_code in ['AccessDenied']:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = (
                    f"Insufficient permissions to evaluate Access Analyzer in {region}. "
                    f"Required permissions: access-analyzer:ListAnalyzers"
                )
            elif error_code == 'ResourceNotFoundException':
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = f"No Access Analyzer found in region {region}"
            else:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Error evaluating Access Analyzer in {region}: {str(e)}"
        
        except Exception as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Unexpected error evaluating Access Analyzer in {region}: {str(e)}"
        
        return ComplianceResult(
            resource_id=resource_id,
            resource_type="AWS::AccessAnalyzer::Analyzer",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )



class IAMPermissionBoundariesCheckAssessment(BaseConfigRuleAssessment):
    """Assessment for iam-permission-boundaries-check AWS Config rule.
    
    Validates that IAM roles with elevated privileges have permission boundaries
    configured to limit the maximum permissions they can grant.
    
    This is a global service assessment that only runs in us-east-1.
    """
    
    # Elevated privilege managed policy ARNs
    ELEVATED_PRIVILEGE_POLICIES = {
        'arn:aws:iam::aws:policy/AdministratorAccess',
        'arn:aws:iam::aws:policy/PowerUserAccess'
    }
    
    def __init__(self):
        super().__init__(
            rule_name="iam-permission-boundaries-check",
            control_id="6.2",
            resource_types=["AWS::IAM::Role"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get IAM roles with elevated privileges.
        
        IAM is a global service, so we only query in us-east-1.
        We filter for roles with elevated privileges.
        
        Args:
            aws_factory: AWS client factory for API access
            resource_type: AWS resource type (should be AWS::IAM::Role)
            region: AWS region (should be us-east-1 for IAM)
            
        Returns:
            List of IAM role dictionaries with elevated privileges
        """
        if resource_type != "AWS::IAM::Role":
            return []
        
        # IAM is a global service - only evaluate in us-east-1
        if region != 'us-east-1':
            logger.debug(f"Skipping IAM evaluation in {region} - global service evaluated in us-east-1 only")
            return []
        
        try:
            iam_client = aws_factory.get_client('iam', region)
            elevated_privilege_roles = []
            
            # List all IAM roles with pagination
            marker = None
            while True:
                if marker:
                    response = aws_factory.aws_api_call_with_retry(
                        lambda: iam_client.list_roles(Marker=marker)
                    )
                else:
                    response = aws_factory.aws_api_call_with_retry(
                        lambda: iam_client.list_roles()
                    )
                
                roles = response.get('Roles', [])
                
                # Check each role for elevated privileges
                for role in roles:
                    role_name = role.get('RoleName', '')
                    if self._has_elevated_privileges(iam_client, role_name, aws_factory):
                        elevated_privilege_roles.append(role)
                
                if response.get('IsTruncated', False):
                    marker = response.get('Marker')
                else:
                    break
            
            logger.debug(f"Found {len(elevated_privilege_roles)} roles with elevated privileges")
            return elevated_privilege_roles
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            
            if error_code in ['AccessDenied']:
                logger.warning(f"Insufficient permissions to list IAM roles: {e}")
                return []
            else:
                logger.error(f"Error retrieving IAM roles: {e}")
                raise
    
    def _has_elevated_privileges(self, iam_client, role_name: str, aws_factory: AWSClientFactory) -> bool:
        """Check if a role has elevated privileges.
        
        Args:
            iam_client: IAM boto3 client
            role_name: IAM role name
            aws_factory: AWS client factory for retry logic
            
        Returns:
            True if role has elevated privileges, False otherwise
        """
        try:
            # Check attached managed policies
            attached_policies_response = aws_factory.aws_api_call_with_retry(
                lambda: iam_client.list_attached_role_policies(RoleName=role_name)
            )
            
            for policy in attached_policies_response.get('AttachedPolicies', []):
                policy_arn = policy.get('PolicyArn', '')
                if policy_arn in self.ELEVATED_PRIVILEGE_POLICIES:
                    return True
            
            # Check inline policies for Action:"*"
            inline_policies_response = aws_factory.aws_api_call_with_retry(
                lambda: iam_client.list_role_policies(RoleName=role_name)
            )
            
            for policy_name in inline_policies_response.get('PolicyNames', []):
                policy_response = aws_factory.aws_api_call_with_retry(
                    lambda: iam_client.get_role_policy(RoleName=role_name, PolicyName=policy_name)
                )
                
                policy_document = policy_response.get('PolicyDocument', {})
                if self._has_wildcard_action(policy_document):
                    return True
            
            return False
            
        except ClientError as e:
            logger.warning(f"Error checking privileges for role {role_name}: {e}")
            return False
    
    def _has_wildcard_action(self, policy_document: Dict[str, Any]) -> bool:
        """Check if policy document contains Action:"*".
        
        Args:
            policy_document: IAM policy document
            
        Returns:
            True if policy contains Action:"*", False otherwise
        """
        statements = policy_document.get('Statement', [])
        
        for statement in statements:
            if statement.get('Effect') != 'Allow':
                continue
            
            actions = statement.get('Action', [])
            if isinstance(actions, str):
                actions = [actions]
            
            if '*' in actions:
                return True
        
        return False
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if role with elevated privileges has permission boundary.
        
        Args:
            resource: IAM role resource dictionary
            aws_factory: AWS client factory for additional API calls
            region: AWS region
            
        Returns:
            ComplianceResult indicating whether the role has permission boundary
        """
        role_name = resource.get('RoleName', 'unknown')
        role_arn = resource.get('Arn', 'unknown')
        permissions_boundary = resource.get('PermissionsBoundary')
        
        try:
            if permissions_boundary and permissions_boundary.get('PermissionsBoundaryArn'):
                compliance_status = ComplianceStatus.COMPLIANT
                boundary_arn = permissions_boundary.get('PermissionsBoundaryArn', '')
                evaluation_reason = (
                    f"IAM role {role_name} with elevated privileges has permission boundary configured: {boundary_arn}"
                )
            else:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = (
                    f"IAM role {role_name} has elevated privileges but no permission boundary configured. "
                    f"Permission boundaries limit the maximum permissions a role can grant.\n\n"
                    f"Configure permission boundaries for delegated administration:\n"
                    f"1. Create a permission boundary policy that defines maximum permissions\n"
                    f"2. Attach permission boundary to roles with elevated privileges\n"
                    f"3. Permission boundary limits what the role can do, even with full access policies\n\n"
                    f"AWS CLI example:\n"
                    f"# Create permission boundary policy\n"
                    f"aws iam create-policy --policy-name DelegatedAdminBoundary --policy-document file://boundary.json\n\n"
                    f"# Attach boundary to role\n"
                    f"aws iam put-role-permissions-boundary --role-name {role_name} --permissions-boundary arn:aws:iam::<account>:policy/DelegatedAdminBoundary\n\n"
                    f"Use cases:\n"
                    f"- Delegated administration\n"
                    f"- Developer self-service\n"
                    f"- Prevent privilege escalation\n"
                    f"- Enforce organizational policies"
                )
        
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            
            if error_code == 'NoSuchEntity':
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"IAM role {role_name} not found (may have been deleted)"
            elif error_code in ['AccessDenied']:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = (
                    f"Insufficient permissions to evaluate IAM role {role_name}. "
                    f"Required permissions: iam:ListRoles, iam:ListAttachedRolePolicies, iam:ListRolePolicies"
                )
            else:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Error evaluating IAM role {role_name}: {str(e)}"
        
        except Exception as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Unexpected error evaluating IAM role {role_name}: {str(e)}"
        
        return ComplianceResult(
            resource_id=role_arn,
            resource_type="AWS::IAM::Role",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )



class OrganizationsSCPEnabledCheckAssessment(BaseConfigRuleAssessment):
    """Assessment for organizations-scp-enabled-check AWS Config rule.
    
    Ensures Service Control Policies (SCPs) are enabled and in use within
    AWS Organizations to enforce organizational policies and guardrails.
    
    This is a global service assessment that only runs in us-east-1.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="organizations-scp-enabled-check",
            control_id="6.3",
            resource_types=["AWS::::Account"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get account-level resource for SCP check.
        
        Organizations is a global service, so we only query in us-east-1.
        Returns a single account-level resource.
        
        Args:
            aws_factory: AWS client factory for API access
            resource_type: AWS resource type (should be AWS::::Account)
            region: AWS region (should be us-east-1 for Organizations)
            
        Returns:
            List with single account-level resource dictionary
        """
        if resource_type != "AWS::::Account":
            return []
        
        # Organizations is a global service - only evaluate in us-east-1
        if region != 'us-east-1':
            logger.debug(f"Skipping Organizations evaluation in {region} - global service evaluated in us-east-1 only")
            return []
        
        # Return a single account-level resource
        return [{'account': 'current', 'region': region}]
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if Service Control Policies are enabled and in use.
        
        Args:
            resource: Account-level resource dictionary
            aws_factory: AWS client factory for additional API calls
            region: AWS region
            
        Returns:
            ComplianceResult indicating whether SCPs are enabled and in use
        """
        resource_id = "aws-account-scp-check"
        
        try:
            org_client = aws_factory.get_client('organizations', region)
            
            # Check if account is part of an organization
            try:
                org_response = aws_factory.aws_api_call_with_retry(
                    lambda: org_client.describe_organization()
                )
                organization = org_response.get('Organization', {})
            except ClientError as e:
                if e.response.get('Error', {}).get('Code') == 'AWSOrganizationsNotInUseException':
                    compliance_status = ComplianceStatus.NON_COMPLIANT
                    evaluation_reason = (
                        f"Account is not part of an AWS Organization. "
                        f"Service Control Policies require AWS Organizations.\n\n"
                        f"Enable AWS Organizations:\n"
                        f"1. Go to AWS Organizations console\n"
                        f"2. Create an organization\n"
                        f"3. Enable all features (includes SCPs)\n"
                        f"4. Create custom SCPs to enforce organizational policies\n\n"
                        f"AWS CLI example:\n"
                        f"aws organizations create-organization --feature-set ALL\n\n"
                        f"Benefits:\n"
                        f"- Centralized account management\n"
                        f"- Policy-based access controls\n"
                        f"- Consolidated billing\n"
                        f"- Service control policies"
                    )
                    
                    return ComplianceResult(
                        resource_id=resource_id,
                        resource_type="AWS::::Account",
                        compliance_status=compliance_status,
                        evaluation_reason=evaluation_reason,
                        config_rule_name=self.rule_name,
                        region=region
                    )
                else:
                    raise
            
            # Check if SCPs are enabled (FeatureSet includes ALL or SERVICE_CONTROL_POLICY)
            feature_set = organization.get('FeatureSet', '')
            
            if feature_set not in ['ALL']:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = (
                    f"AWS Organization exists but Service Control Policies are not enabled. "
                    f"Current feature set: {feature_set}. Enable all features to use SCPs.\n\n"
                    f"Enable all features in Organizations:\n"
                    f"aws organizations enable-all-features\n\n"
                    f"Note: This requires approval from all member accounts if using consolidated billing only."
                )
                
                return ComplianceResult(
                    resource_id=resource_id,
                    resource_type="AWS::::Account",
                    compliance_status=compliance_status,
                    evaluation_reason=evaluation_reason,
                    config_rule_name=self.rule_name,
                    region=region
                )
            
            # List SCPs to verify custom policies exist (beyond default FullAWSAccess)
            policies_response = aws_factory.aws_api_call_with_retry(
                lambda: org_client.list_policies(Filter='SERVICE_CONTROL_POLICY')
            )
            
            policies = policies_response.get('Policies', [])
            
            # Filter out the default FullAWSAccess policy
            custom_policies = [p for p in policies if p.get('Name') != 'FullAWSAccess']
            
            if custom_policies:
                compliance_status = ComplianceStatus.COMPLIANT
                policy_names = [p.get('Name', 'unknown') for p in custom_policies]
                evaluation_reason = (
                    f"Service Control Policies are enabled with {len(custom_policies)} custom policy/policies: "
                    f"{', '.join(policy_names)}"
                )
            else:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = (
                    f"Service Control Policies are enabled but no custom SCPs are in use. "
                    f"Only the default FullAWSAccess policy exists.\n\n"
                    f"Create custom SCPs to enforce organizational policies:\n"
                    f"1. Go to AWS Organizations console > Policies > Service control policies\n"
                    f"2. Create custom SCP\n"
                    f"3. Attach SCP to OUs or accounts\n\n"
                    f"AWS CLI example:\n"
                    f"# Create custom SCP\n"
                    f"aws organizations create-policy --name DenyRootUser --type SERVICE_CONTROL_POLICY --content file://scp.json\n\n"
                    f"# Attach SCP to OU\n"
                    f"aws organizations attach-policy --policy-id <policy-id> --target-id <ou-id>\n\n"
                    f"Common SCP use cases:\n"
                    f"- Deny access to specific regions\n"
                    f"- Deny root user actions\n"
                    f"- Require MFA for sensitive operations\n"
                    f"- Prevent disabling security services\n"
                    f"- Enforce tagging requirements"
                )
        
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            
            if error_code == 'AWSOrganizationsNotInUseException':
                compliance_status = ComplianceStatus.NOT_APPLICABLE
                evaluation_reason = "AWS Organizations is not enabled for this account"
            elif error_code in ['AccessDenied']:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = (
                    f"Insufficient permissions to evaluate Organizations. "
                    f"Required permissions: organizations:DescribeOrganization, organizations:ListPolicies"
                )
            else:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Error evaluating Organizations: {str(e)}"
        
        except Exception as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Unexpected error evaluating Organizations: {str(e)}"
        
        return ComplianceResult(
            resource_id=resource_id,
            resource_type="AWS::::Account",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )



class CognitoUserPoolMFAEnabledAssessment(BaseConfigRuleAssessment):
    """Assessment for cognito-user-pool-mfa-enabled AWS Config rule.
    
    Validates that Cognito user pools have MFA enabled to provide an additional
    layer of security for user authentication.
    
    This is a regional service assessment that runs in all active regions.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="cognito-user-pool-mfa-enabled",
            control_id="6.4",
            resource_types=["AWS::Cognito::UserPool"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get Cognito user pools.
        
        Cognito user pools are regional resources, so we query in each active region.
        
        Args:
            aws_factory: AWS client factory for API access
            resource_type: AWS resource type (should be AWS::Cognito::UserPool)
            region: AWS region
            
        Returns:
            List of Cognito user pool dictionaries
        """
        if resource_type != "AWS::Cognito::UserPool":
            return []
        
        try:
            cognito_client = aws_factory.get_client('cognito-idp', region)
            
            # List all user pools with pagination support
            user_pools = []
            next_token = None
            
            while True:
                if next_token:
                    response = aws_factory.aws_api_call_with_retry(
                        lambda: cognito_client.list_user_pools(MaxResults=60, NextToken=next_token)
                    )
                else:
                    response = aws_factory.aws_api_call_with_retry(
                        lambda: cognito_client.list_user_pools(MaxResults=60)
                    )
                
                user_pools.extend(response.get('UserPools', []))
                
                # Check if there are more results
                next_token = response.get('NextToken')
                if not next_token:
                    break
            
            logger.debug(f"Found {len(user_pools)} Cognito user pools in {region}")
            return user_pools
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            
            if error_code in ['AccessDenied']:
                logger.warning(f"Insufficient permissions to list Cognito user pools in {region}: {e}")
                return []
            else:
                logger.error(f"Error retrieving Cognito user pools in {region}: {e}")
                raise

    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if Cognito user pool has MFA enabled.
        
        Args:
            resource: Cognito user pool resource dictionary
            aws_factory: AWS client factory for additional API calls
            region: AWS region
            
        Returns:
            ComplianceResult indicating whether the user pool has MFA enabled
        """
        user_pool_id = resource.get('Id', 'unknown')
        user_pool_name = resource.get('Name', 'unknown')
        
        try:
            cognito_client = aws_factory.get_client('cognito-idp', region)
            
            # Get detailed user pool configuration including MFA settings
            pool_response = aws_factory.aws_api_call_with_retry(
                lambda: cognito_client.describe_user_pool(UserPoolId=user_pool_id)
            )
            
            user_pool = pool_response.get('UserPool', {})
            mfa_configuration = user_pool.get('MfaConfiguration', 'OFF')
            
            # MFA is compliant if set to 'ON' or 'OPTIONAL'
            if mfa_configuration in ['ON', 'OPTIONAL']:
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = (
                    f"Cognito user pool {user_pool_name} (ID: {user_pool_id}) has MFA configured as '{mfa_configuration}'"
                )
            else:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = (
                    f"Cognito user pool {user_pool_name} (ID: {user_pool_id}) has MFA disabled (configuration: '{mfa_configuration}'). "
                    f"Enable MFA to provide additional security for user authentication.\n\n"
                    f"Enable MFA for Cognito user pools:\n"
                    f"1. Go to Cognito console > User pools\n"
                    f"2. Select the user pool '{user_pool_name}'\n"
                    f"3. Sign-in experience tab > Multi-factor authentication\n"
                    f"4. Configure MFA:\n"
                    f"   - Required: All users must use MFA\n"
                    f"   - Optional: Users can choose to enable MFA\n"
                    f"5. Choose MFA methods:\n"
                    f"   - SMS text message\n"
                    f"   - Time-based one-time password (TOTP)\n"
                    f"   - Both\n"
                    f"6. Save changes\n\n"
                    f"AWS CLI example:\n"
                    f"aws cognito-idp set-user-pool-mfa-config \\\n"
                    f"  --user-pool-id {user_pool_id} \\\n"
                    f"  --mfa-configuration ON \\\n"
                    f"  --software-token-mfa-configuration Enabled=true \\\n"
                    f"  --region {region}\n\n"
                    f"Best practices:\n"
                    f"- Use 'Required' for sensitive applications\n"
                    f"- Support both SMS and TOTP for flexibility\n"
                    f"- Test MFA flow before enforcing"
                )
        
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            
            if error_code == 'ResourceNotFoundException':
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Cognito user pool {user_pool_id} not found (may have been deleted)"
            elif error_code in ['AccessDenied']:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = (
                    f"Insufficient permissions to evaluate Cognito user pool {user_pool_id}. "
                    f"Required permissions: cognito-idp:DescribeUserPool"
                )
            else:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Error evaluating Cognito user pool {user_pool_id}: {str(e)}"
        
        except Exception as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Unexpected error evaluating Cognito user pool {user_pool_id}: {str(e)}"
        
        return ComplianceResult(
            resource_id=user_pool_id,
            resource_type="AWS::Cognito::UserPool",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )



class VPNConnectionMFAEnabledAssessment(BaseConfigRuleAssessment):
    """Assessment for vpn-connection-mfa-enabled AWS Config rule.
    
    Ensures Client VPN endpoints require MFA authentication to provide an additional
    layer of security for VPN access.
    
    This is a regional service assessment that runs in all active regions.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="vpn-connection-mfa-enabled",
            control_id="6.5",
            resource_types=["AWS::EC2::ClientVpnEndpoint"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get Client VPN endpoints.
        
        Client VPN endpoints are regional resources, so we query in each active region.
        
        Args:
            aws_factory: AWS client factory for API access
            resource_type: AWS resource type (should be AWS::EC2::ClientVpnEndpoint)
            region: AWS region
            
        Returns:
            List of Client VPN endpoint dictionaries
        """
        if resource_type != "AWS::EC2::ClientVpnEndpoint":
            return []
        
        try:
            ec2_client = aws_factory.get_client('ec2', region)
            
            # List all Client VPN endpoints with pagination support
            vpn_endpoints = []
            next_token = None
            
            while True:
                if next_token:
                    response = aws_factory.aws_api_call_with_retry(
                        lambda: ec2_client.describe_client_vpn_endpoints(NextToken=next_token)
                    )
                else:
                    response = aws_factory.aws_api_call_with_retry(
                        lambda: ec2_client.describe_client_vpn_endpoints()
                    )
                
                vpn_endpoints.extend(response.get('ClientVpnEndpoints', []))
                
                # Check if there are more results
                next_token = response.get('NextToken')
                if not next_token:
                    break
            
            logger.debug(f"Found {len(vpn_endpoints)} Client VPN endpoints in {region}")
            return vpn_endpoints
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            
            if error_code in ['UnauthorizedOperation', 'AccessDenied']:
                logger.warning(f"Insufficient permissions to list Client VPN endpoints in {region}: {e}")
                return []
            else:
                logger.error(f"Error retrieving Client VPN endpoints in {region}: {e}")
                raise

    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if Client VPN endpoint requires MFA authentication.
        
        Args:
            resource: Client VPN endpoint resource dictionary
            aws_factory: AWS client factory for additional API calls
            region: AWS region
            
        Returns:
            ComplianceResult indicating whether the VPN endpoint requires MFA
        """
        endpoint_id = resource.get('ClientVpnEndpointId', 'unknown')
        status = resource.get('Status', {}).get('Code', 'unknown')
        
        try:
            # Get authentication options
            auth_options = resource.get('AuthenticationOptions', [])
            
            # Check if any authentication option requires MFA
            has_mfa = False
            auth_details = []
            
            for auth_option in auth_options:
                auth_type = auth_option.get('Type', '')
                auth_details.append(auth_type)
                
                # Check for directory-service-authentication (can have MFA through AD)
                if auth_type == 'directory-service-authentication':
                    # Directory service authentication can enforce MFA through Active Directory
                    # We consider this compliant if configured
                    directory_id = auth_option.get('ActiveDirectory', {}).get('DirectoryId')
                    if directory_id:
                        has_mfa = True
                        break
                
                # Check for federated-authentication (can have MFA through SAML IdP)
                elif auth_type == 'federated-authentication':
                    # Federated authentication can enforce MFA through the identity provider
                    # We consider this compliant if configured
                    saml_provider_arn = auth_option.get('FederatedAuthentication', {}).get('SAMLProviderArn')
                    if saml_provider_arn:
                        has_mfa = True
                        break
                
                # certificate-authentication alone doesn't provide MFA
                # (certificate is "something you have", but MFA needs a second factor)
            
            if has_mfa:
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = (
                    f"Client VPN endpoint {endpoint_id} has MFA-capable authentication configured: {', '.join(auth_details)}"
                )
            else:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = (
                    f"Client VPN endpoint {endpoint_id} does not have MFA-capable authentication configured. "
                    f"Current authentication: {', '.join(auth_details) if auth_details else 'None'}. "
                    f"Enable MFA to provide additional security for VPN access.\n\n"
                    f"Enable MFA for Client VPN endpoints:\n\n"
                    f"For Active Directory authentication:\n"
                    f"1. Go to VPC console > Client VPN Endpoints\n"
                    f"2. Select the endpoint (ID: {endpoint_id})\n"
                    f"3. Modify authentication\n"
                    f"4. Enable MFA in Active Directory configuration\n"
                    f"5. Apply changes\n\n"
                    f"For SAML-based authentication:\n"
                    f"1. Configure MFA in your identity provider (IdP)\n"
                    f"2. Update SAML assertion to include MFA claim\n"
                    f"3. Client VPN will enforce MFA through IdP\n\n"
                    f"AWS CLI example (create with AD authentication):\n"
                    f"aws ec2 create-client-vpn-endpoint \\\n"
                    f"  --client-cidr-block 10.0.0.0/16 \\\n"
                    f"  --server-certificate-arn <cert-arn> \\\n"
                    f"  --authentication-options Type=directory-service-authentication,ActiveDirectory={{DirectoryId=<dir-id>}} \\\n"
                    f"  --connection-log-options Enabled=true,CloudwatchLogGroup=<log-group> \\\n"
                    f"  --region {region}\n\n"
                    f"Note: MFA enforcement depends on the authentication method:\n"
                    f"- Active Directory: Configure MFA in AD\n"
                    f"- SAML: Configure MFA in IdP\n"
                    f"- Mutual authentication: Use certificate + additional factor\n\n"
                    f"Best practices:\n"
                    f"- Always require MFA for VPN access\n"
                    f"- Use strong MFA methods (TOTP, hardware tokens)\n"
                    f"- Monitor VPN connection logs\n"
                    f"- Regularly review VPN access"
                )
        
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            
            if error_code == 'InvalidClientVpnEndpointId.NotFound':
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Client VPN endpoint {endpoint_id} not found (may have been deleted)"
            elif error_code in ['UnauthorizedOperation', 'AccessDenied']:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = (
                    f"Insufficient permissions to evaluate Client VPN endpoint {endpoint_id}. "
                    f"Required permissions: ec2:DescribeClientVpnEndpoints"
                )
            else:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Error evaluating Client VPN endpoint {endpoint_id}: {str(e)}"
        
        except Exception as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Unexpected error evaluating Client VPN endpoint {endpoint_id}: {str(e)}"
        
        return ComplianceResult(
            resource_id=endpoint_id,
            resource_type="AWS::EC2::ClientVpnEndpoint",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
