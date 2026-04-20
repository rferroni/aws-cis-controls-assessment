"""
CIS Control 1.1 - Inventory Management
Ensures proper asset inventory tracking across AWS resources.
"""

import logging
from typing import List, Dict, Any
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class SSMInventoryEnabledAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 1.1 - Establish and Maintain Detailed Enterprise Asset Inventory
    AWS Config Rule: ssm-inventory-enabled
    
    Ensures AWS Systems Manager Inventory is enabled for asset tracking.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="ssm-inventory-enabled",
            control_id="1.1",
            resource_types=["AWS::::Account"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Check if SSM Inventory is configured."""
        if resource_type != "AWS::::Account":
            return []
        
        try:
            ssm_client = aws_factory.get_client('ssm', region)
            
            # Check for inventory associations
            response = ssm_client.list_associations(
                AssociationFilterList=[
                    {'key': 'AssociationName', 'value': 'AWS-GatherSoftwareInventory'}
                ]
            )
            
            associations = response.get('Associations', [])
            inventory_enabled = len(associations) > 0
            
            return [{
                'AccountId': region,
                'InventoryEnabled': inventory_enabled,
                'AssociationCount': len(associations)
            }]
            
        except ClientError as e:
            logger.error(f"Error checking SSM Inventory in {region}: {e}")
            return []
    
    def _evaluate_resource_compliance(
        self, 
        resource: Dict[str, Any], 
        aws_factory: AWSClientFactory, 
        region: str
    ) -> ComplianceResult:
        """Evaluate if SSM Inventory is enabled."""
        inventory_enabled = resource.get('InventoryEnabled', False)
        association_count = resource.get('AssociationCount', 0)
        
        if inventory_enabled:
            evaluation_reason = f"SSM Inventory is enabled with {association_count} association(s)"
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            evaluation_reason = "SSM Inventory is not enabled"
            compliance_status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceResult(
            resource_id=f"account-{region}",
            resource_type="AWS::::Account",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get remediation steps for enabling SSM Inventory."""
        return [
            "1. Enable SSM Inventory using AWS CLI:",
            "   aws ssm create-association \\",
            "     --name AWS-GatherSoftwareInventory \\",
            "     --targets Key=InstanceIds,Values=* \\",
            "     --schedule-expression 'rate(30 minutes)'",
            "",
            "2. Console method:",
            "   - Navigate to Systems Manager",
            "   - Click 'Inventory' in left menu",
            "   - Click 'Setup Inventory'",
            "   - Configure targets and schedule",
            "   - Click 'Setup Inventory'",
            "",
            "Priority: MEDIUM - Important for asset tracking",
            "Effort: Low - Quick setup",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-inventory-configuring.html"
        ]


class ConfigEnabledAllRegionsAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 1.1 - Establish and Maintain Detailed Enterprise Asset Inventory
    AWS Config Rule: config-enabled-all-regions
    
    Ensures AWS Config is enabled in all regions for comprehensive resource tracking.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="config-enabled-all-regions",
            control_id="1.1",
            resource_types=["AWS::::Account"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Check AWS Config status across all regions."""
        if resource_type != "AWS::::Account":
            return []
        
        try:
            ec2_client = aws_factory.get_client('ec2', 'us-east-1')
            all_regions = [r['RegionName'] for r in ec2_client.describe_regions()['Regions']]
            
            enabled_regions = []
            disabled_regions = []
            
            for check_region in all_regions:
                try:
                    # Create config client directly using the factory's session since this
                    # control needs to check all regions, not just the configured assessment regions
                    try:
                        config_client = aws_factory.get_client('config', check_region)
                    except ValueError:
                        # Region not in configured assessment regions — use session directly
                        config_client = aws_factory._session.client(
                            'config', region_name=check_region, config=aws_factory._config
                        )
                    recorders = config_client.describe_configuration_recorders()
                    
                    if recorders.get('ConfigurationRecorders'):
                        # Check if recorder is recording
                        status = config_client.describe_configuration_recorder_status()
                        if status.get('ConfigurationRecordersStatus'):
                            if status['ConfigurationRecordersStatus'][0].get('recording'):
                                enabled_regions.append(check_region)
                            else:
                                disabled_regions.append(check_region)
                        else:
                            disabled_regions.append(check_region)
                    else:
                        disabled_regions.append(check_region)
                except ClientError:
                    disabled_regions.append(check_region)
            
            return [{
                'AccountId': 'global',
                'EnabledRegions': enabled_regions,
                'DisabledRegions': disabled_regions,
                'TotalRegions': len(all_regions)
            }]
            
        except ClientError as e:
            logger.error(f"Error checking Config status: {e}")
            return []
    
    def _evaluate_resource_compliance(
        self, 
        resource: Dict[str, Any], 
        aws_factory: AWSClientFactory, 
        region: str
    ) -> ComplianceResult:
        """Evaluate if Config is enabled in all regions."""
        enabled_regions = resource.get('EnabledRegions', [])
        disabled_regions = resource.get('DisabledRegions', [])
        total_regions = resource.get('TotalRegions', 0)
        
        if not disabled_regions:
            evaluation_reason = f"AWS Config is enabled in all {total_regions} regions"
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            evaluation_reason = (
                f"AWS Config is disabled in {len(disabled_regions)} region(s): "
                f"{', '.join(disabled_regions[:5])}"
            )
            compliance_status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceResult(
            resource_id="account-config-status",
            resource_type="AWS::::Account",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get remediation steps for enabling Config in all regions."""
        return [
            "1. Enable AWS Config in a region:",
            "   aws configservice put-configuration-recorder \\",
            "     --configuration-recorder name=default,roleARN=<role-arn> \\",
            "     --recording-group allSupported=true,includeGlobalResourceTypes=true",
            "",
            "   aws configservice put-delivery-channel \\",
            "     --delivery-channel name=default,s3BucketName=<bucket-name>",
            "",
            "   aws configservice start-configuration-recorder \\",
            "     --configuration-recorder-name default",
            "",
            "2. Enable in all regions (script):",
            "   for region in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do",
            "     aws configservice put-configuration-recorder --region $region ...",
            "   done",
            "",
            "Priority: HIGH - Essential for compliance tracking",
            "Effort: Medium - Requires setup in each region",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/config/latest/developerguide/gs-console.html"
        ]


class AMIInventoryTrackingAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 1.1 - Establish and Maintain Detailed Enterprise Asset Inventory
    AWS Config Rule: ami-inventory-tracking
    
    Ensures AMIs are properly tagged for inventory tracking.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="ami-inventory-tracking",
            control_id="1.1",
            resource_types=["AWS::EC2::Image"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all AMIs owned by the account."""
        if resource_type != "AWS::EC2::Image":
            return []
        
        try:
            ec2_client = aws_factory.get_client('ec2', region)
            
            # Get account ID
            sts_client = aws_factory.get_client('sts', region)
            account_id = sts_client.get_caller_identity()['Account']
            
            # List AMIs owned by this account
            response = ec2_client.describe_images(Owners=[account_id])
            images = response.get('Images', [])
            
            amis = []
            for image in images:
                tags = {tag['Key']: tag['Value'] for tag in image.get('Tags', [])}
                
                amis.append({
                    'ImageId': image.get('ImageId'),
                    'Name': image.get('Name', 'unnamed'),
                    'Tags': tags,
                    'HasInventoryTags': bool(tags.get('Environment') or tags.get('Owner') or tags.get('Application'))
                })
            
            return amis
            
        except ClientError as e:
            logger.error(f"Error retrieving AMIs in {region}: {e}")
            return []
    
    def _evaluate_resource_compliance(
        self, 
        resource: Dict[str, Any], 
        aws_factory: AWSClientFactory, 
        region: str
    ) -> ComplianceResult:
        """Evaluate if AMI has proper inventory tags."""
        image_id = resource.get('ImageId', 'unknown')
        name = resource.get('Name', 'unnamed')
        has_inventory_tags = resource.get('HasInventoryTags', False)
        
        if has_inventory_tags:
            evaluation_reason = f"AMI '{name}' has proper inventory tags"
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            evaluation_reason = f"AMI '{name}' is missing inventory tags (Environment, Owner, or Application)"
            compliance_status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceResult(
            resource_id=image_id,
            resource_type="AWS::EC2::Image",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get remediation steps for AMI inventory tagging."""
        return [
            "1. Tag an AMI with inventory information:",
            "   aws ec2 create-tags \\",
            "     --resources <ami-id> \\",
            "     --tags Key=Environment,Value=production \\",
            "            Key=Owner,Value=team-name \\",
            "            Key=Application,Value=app-name",
            "",
            "2. Tag multiple AMIs (script):",
            "   for ami in $(aws ec2 describe-images --owners self --query 'Images[].ImageId' --output text); do",
            "     aws ec2 create-tags --resources $ami --tags Key=Environment,Value=production",
            "   done",
            "",
            "Priority: MEDIUM - Important for asset management",
            "Effort: Low - Simple tagging operation",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIs.html"
        ]


class LambdaRuntimeInventoryAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 1.1 - Establish and Maintain Detailed Enterprise Asset Inventory
    AWS Config Rule: lambda-runtime-inventory
    
    Tracks Lambda function runtimes for inventory purposes.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="lambda-runtime-inventory",
            control_id="1.1",
            resource_types=["AWS::Lambda::Function"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all Lambda functions and their runtimes."""
        if resource_type != "AWS::Lambda::Function":
            return []
        
        try:
            lambda_client = aws_factory.get_client('lambda', region)
            functions = []
            
            paginator = lambda_client.get_paginator('list_functions')
            for page in paginator.paginate():
                for func in page.get('Functions', []):
                    functions.append({
                        'FunctionName': func.get('FunctionName'),
                        'FunctionArn': func.get('FunctionArn'),
                        'Runtime': func.get('Runtime', 'unknown'),
                        'LastModified': func.get('LastModified')
                    })
            
            return functions
            
        except ClientError as e:
            logger.error(f"Error retrieving Lambda functions in {region}: {e}")
            return []
    
    def _evaluate_resource_compliance(
        self, 
        resource: Dict[str, Any], 
        aws_factory: AWSClientFactory, 
        region: str
    ) -> ComplianceResult:
        """Evaluate Lambda function for inventory tracking."""
        function_name = resource.get('FunctionName', 'unknown')
        runtime = resource.get('Runtime', 'unknown')
        
        # This is primarily for inventory - all functions are compliant
        evaluation_reason = f"Lambda function '{function_name}' tracked with runtime: {runtime}"
        compliance_status = ComplianceStatus.COMPLIANT
        
        return ComplianceResult(
            resource_id=resource.get('FunctionArn', function_name),
            resource_type="AWS::Lambda::Function",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get remediation steps for Lambda inventory."""
        return [
            "1. List all Lambda functions and runtimes:",
            "   aws lambda list-functions \\",
            "     --query 'Functions[].{Name:FunctionName,Runtime:Runtime}' \\",
            "     --output table",
            "",
            "2. Export to CSV for inventory:",
            "   aws lambda list-functions \\",
            "     --query 'Functions[].{Name:FunctionName,Runtime:Runtime,Modified:LastModified}' \\",
            "     --output json > lambda-inventory.json",
            "",
            "Priority: LOW - Informational inventory",
            "Effort: None - Automated tracking",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html"
        ]


class IAMUserInventoryCheckAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 1.1 - Establish and Maintain Detailed Enterprise Asset Inventory
    AWS Config Rule: iam-user-inventory-check
    
    Ensures IAM users have proper inventory tags.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="iam-user-inventory-check",
            control_id="1.1",
            resource_types=["AWS::IAM::User"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all IAM users and their tags."""
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
                        # Get user tags
                        tags_response = iam_client.list_user_tags(UserName=user_name)
                        tags = {tag['Key']: tag['Value'] for tag in tags_response.get('Tags', [])}
                        
                        users.append({
                            'UserName': user_name,
                            'Arn': user.get('Arn'),
                            'Tags': tags,
                            'HasInventoryTags': bool(tags.get('Department') or tags.get('Owner') or tags.get('CostCenter'))
                        })
                    except ClientError:
                        users.append({
                            'UserName': user_name,
                            'Arn': user.get('Arn'),
                            'Tags': {},
                            'HasInventoryTags': False
                        })
            
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
        """Evaluate if IAM user has proper inventory tags."""
        user_name = resource.get('UserName', 'unknown')
        has_inventory_tags = resource.get('HasInventoryTags', False)
        
        if has_inventory_tags:
            evaluation_reason = f"IAM user '{user_name}' has proper inventory tags"
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            evaluation_reason = f"IAM user '{user_name}' is missing inventory tags (Department, Owner, or CostCenter)"
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
        """Get remediation steps for IAM user inventory tagging."""
        return [
            "1. Tag an IAM user with inventory information:",
            "   aws iam tag-user \\",
            "     --user-name <user-name> \\",
            "     --tags Key=Department,Value=engineering \\",
            "            Key=Owner,Value=manager-name \\",
            "            Key=CostCenter,Value=12345",
            "",
            "2. Tag multiple users (script):",
            "   for user in $(aws iam list-users --query 'Users[].UserName' --output text); do",
            "     aws iam tag-user --user-name $user --tags Key=Department,Value=engineering",
            "   done",
            "",
            "Priority: MEDIUM - Important for user management",
            "Effort: Low - Simple tagging operation",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_tags.html"
        ]
