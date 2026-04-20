"""
CIS Control 4.1 - Configuration Management
Ensures proper configuration management practices across AWS resources.
"""

import logging
from typing import List, Dict, Any
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class ConfigConformancePackDeployedAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 4.1 - Establish and Maintain a Secure Configuration Process
    AWS Config Rule: config-conformance-pack-deployed
    
    Ensures AWS Config conformance packs are deployed for configuration management.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="config-conformance-pack-deployed",
            control_id="4.1",
            resource_types=["AWS::::Account"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Check if conformance packs are deployed."""
        if resource_type != "AWS::::Account":
            return []
        
        try:
            config_client = aws_factory.get_client('config', region)
            
            response = config_client.describe_conformance_packs()
            packs = response.get('ConformancePackDetails', [])
            
            return [{
                'AccountId': region,
                'ConformancePacksDeployed': len(packs) > 0,
                'PackCount': len(packs),
                'PackNames': [p.get('ConformancePackName') for p in packs]
            }]
            
        except ClientError as e:
            logger.error(f"Error checking conformance packs in {region}: {e}")
            return []
    
    def _evaluate_resource_compliance(
        self, 
        resource: Dict[str, Any], 
        aws_factory: AWSClientFactory, 
        region: str
    ) -> ComplianceResult:
        """Evaluate if conformance packs are deployed."""
        packs_deployed = resource.get('ConformancePacksDeployed', False)
        pack_count = resource.get('PackCount', 0)
        
        if packs_deployed:
            evaluation_reason = f"{pack_count} conformance pack(s) deployed"
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            evaluation_reason = "No conformance packs deployed"
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
        """Get remediation steps for deploying conformance packs."""
        return [
            "1. Deploy a conformance pack:",
            "   aws configservice put-conformance-pack \\",
            "     --conformance-pack-name security-best-practices \\",
            "     --template-s3-uri s3://bucket/conformance-pack.yaml",
            "",
            "2. Deploy AWS managed conformance pack:",
            "   aws configservice put-conformance-pack \\",
            "     --conformance-pack-name operational-best-practices-for-cis",
            "",
            "Priority: HIGH - Essential for configuration compliance",
            "Effort: Medium - Requires pack configuration",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/config/latest/developerguide/conformance-packs.html"
        ]


class SecurityHubStandardsEnabledAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 4.1 - Establish and Maintain a Secure Configuration Process
    AWS Config Rule: securityhub-standards-enabled
    
    Ensures Security Hub standards are enabled for security configuration management.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="securityhub-standards-enabled",
            control_id="4.1",
            resource_types=["AWS::::Account"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Check if Security Hub standards are enabled."""
        if resource_type != "AWS::::Account":
            return []
        
        try:
            securityhub_client = aws_factory.get_client('securityhub', region)
            
            response = securityhub_client.get_enabled_standards()
            standards = response.get('StandardsSubscriptions', [])
            
            enabled_standards = [s for s in standards if s.get('StandardsStatus') == 'READY']
            
            return [{
                'AccountId': region,
                'StandardsEnabled': len(enabled_standards) > 0,
                'StandardCount': len(enabled_standards),
                'Standards': [s.get('StandardsArn') for s in enabled_standards]
            }]
            
        except ClientError as e:
            if e.response.get('Error', {}).get('Code') == 'InvalidAccessException':
                # Security Hub not enabled
                return [{
                    'AccountId': region,
                    'StandardsEnabled': False,
                    'StandardCount': 0,
                    'Standards': []
                }]
            logger.error(f"Error checking Security Hub standards in {region}: {e}")
            return []
    
    def _evaluate_resource_compliance(
        self, 
        resource: Dict[str, Any], 
        aws_factory: AWSClientFactory, 
        region: str
    ) -> ComplianceResult:
        """Evaluate if Security Hub standards are enabled."""
        standards_enabled = resource.get('StandardsEnabled', False)
        standard_count = resource.get('StandardCount', 0)
        
        if standards_enabled:
            evaluation_reason = f"{standard_count} Security Hub standard(s) enabled"
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            evaluation_reason = "No Security Hub standards enabled"
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
        """Get remediation steps for enabling Security Hub standards."""
        return [
            "1. Enable Security Hub:",
            "   aws securityhub enable-security-hub",
            "",
            "2. Enable CIS AWS Foundations Benchmark:",
            "   aws securityhub batch-enable-standards \\",
            "     --standards-subscription-requests StandardsArn=arn:aws:securityhub:::ruleset/cis-aws-foundations-benchmark/v/1.2.0",
            "",
            "3. Enable AWS Foundational Security Best Practices:",
            "   aws securityhub batch-enable-standards \\",
            "     --standards-subscription-requests StandardsArn=arn:aws:securityhub:us-east-1::standards/aws-foundational-security-best-practices/v/1.0.0",
            "",
            "Priority: HIGH - Critical for security posture",
            "Effort: Low - Quick enablement",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/securityhub/latest/userguide/securityhub-standards.html"
        ]


class AssetTaggingComplianceAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 1.1 - Establish and Maintain Detailed Enterprise Asset Inventory
    AWS Config Rule: asset-tagging-compliance
    
    Ensures resources have required tags for asset management.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="asset-tagging-compliance",
            control_id="1.1",
            resource_types=["AWS::EC2::Instance"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get EC2 instances and check for required tags."""
        if resource_type != "AWS::EC2::Instance":
            return []
        
        try:
            ec2_client = aws_factory.get_client('ec2', region)
            
            response = ec2_client.describe_instances()
            instances = []
            
            for reservation in response.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    tags = {tag['Key']: tag['Value'] for tag in instance.get('Tags', [])}
                    
                    required_tags = ['Name', 'Environment', 'Owner']
                    has_required_tags = all(tag in tags for tag in required_tags)
                    
                    instances.append({
                        'InstanceId': instance.get('InstanceId'),
                        'Tags': tags,
                        'HasRequiredTags': has_required_tags,
                        'MissingTags': [tag for tag in required_tags if tag not in tags]
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
        """Evaluate if instance has required tags."""
        instance_id = resource.get('InstanceId', 'unknown')
        has_required_tags = resource.get('HasRequiredTags', False)
        missing_tags = resource.get('MissingTags', [])
        
        if has_required_tags:
            evaluation_reason = f"Instance {instance_id} has all required tags"
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            evaluation_reason = f"Instance {instance_id} missing tags: {', '.join(missing_tags)}"
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
        """Get remediation steps for asset tagging."""
        return [
            "1. Tag an EC2 instance:",
            "   aws ec2 create-tags \\",
            "     --resources <instance-id> \\",
            "     --tags Key=Name,Value=web-server \\",
            "            Key=Environment,Value=production \\",
            "            Key=Owner,Value=team-name",
            "",
            "2. Tag multiple instances:",
            "   for instance in $(aws ec2 describe-instances --query 'Reservations[].Instances[].InstanceId' --output text); do",
            "     aws ec2 create-tags --resources $instance --tags Key=Environment,Value=production",
            "   done",
            "",
            "Priority: MEDIUM - Important for asset management",
            "Effort: Low - Simple tagging",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/Using_Tags.html"
        ]


class InspectorAssessmentEnabledAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 7.5 - Perform Automated Vulnerability Scans
    AWS Config Rule: inspector-assessment-enabled
    
    Ensures Amazon Inspector assessments are actively running.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="inspector-assessment-enabled",
            control_id="7.5",
            resource_types=["AWS::::Account"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Check if Inspector assessments are enabled."""
        if resource_type != "AWS::::Account":
            return []
        
        try:
            inspector_client = aws_factory.get_client('inspector2', region)
            
            # Check Inspector status
            response = inspector_client.batch_get_account_status(accountIds=[])
            accounts = response.get('accounts', [])
            
            if accounts:
                account = accounts[0]
                status = account.get('status', 'DISABLED')
                resource_state = account.get('resourceState', {})
                
                ec2_enabled = resource_state.get('ec2', {}).get('status') == 'ENABLED'
                ecr_enabled = resource_state.get('ecr', {}).get('status') == 'ENABLED'
                lambda_enabled = resource_state.get('lambda', {}).get('status') == 'ENABLED'
                
                return [{
                    'AccountId': region,
                    'InspectorEnabled': status == 'ENABLED',
                    'EC2Enabled': ec2_enabled,
                    'ECREnabled': ecr_enabled,
                    'LambdaEnabled': lambda_enabled
                }]
            
            return [{
                'AccountId': region,
                'InspectorEnabled': False,
                'EC2Enabled': False,
                'ECREnabled': False,
                'LambdaEnabled': False
            }]
            
        except ClientError as e:
            logger.error(f"Error checking Inspector in {region}: {e}")
            return []
    
    def _evaluate_resource_compliance(
        self, 
        resource: Dict[str, Any], 
        aws_factory: AWSClientFactory, 
        region: str
    ) -> ComplianceResult:
        """Evaluate if Inspector assessments are enabled."""
        inspector_enabled = resource.get('InspectorEnabled', False)
        ec2_enabled = resource.get('EC2Enabled', False)
        ecr_enabled = resource.get('ECREnabled', False)
        lambda_enabled = resource.get('LambdaEnabled', False)
        
        if inspector_enabled and (ec2_enabled or ecr_enabled or lambda_enabled):
            enabled_types = []
            if ec2_enabled:
                enabled_types.append('EC2')
            if ecr_enabled:
                enabled_types.append('ECR')
            if lambda_enabled:
                enabled_types.append('Lambda')
            
            evaluation_reason = f"Inspector enabled for: {', '.join(enabled_types)}"
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            evaluation_reason = "Inspector is not enabled or no resource types are being scanned"
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
        """Get remediation steps for enabling Inspector."""
        return [
            "1. Enable Inspector for EC2:",
            "   aws inspector2 enable \\",
            "     --resource-types EC2",
            "",
            "2. Enable Inspector for ECR:",
            "   aws inspector2 enable \\",
            "     --resource-types ECR",
            "",
            "3. Enable Inspector for Lambda:",
            "   aws inspector2 enable \\",
            "     --resource-types LAMBDA",
            "",
            "4. Enable all resource types:",
            "   aws inspector2 enable \\",
            "     --resource-types EC2 ECR LAMBDA",
            "",
            "Priority: HIGH - Critical for vulnerability management",
            "Effort: Low - Quick enablement",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/inspector/latest/user/getting_started_tutorial.html"
        ]
