"""
CIS Control 2.2 - Version Management
Ensures software versions are current and supported.
"""

import logging
from typing import List, Dict, Any
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class EC2OSVersionSupportedAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 2.2 - Ensure Authorized Software is Currently Supported
    AWS Config Rule: ec2-os-version-supported
    
    Ensures EC2 instances run supported operating system versions.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="ec2-os-version-supported",
            control_id="2.2",
            resource_types=["AWS::EC2::Instance"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get EC2 instances with OS information."""
        if resource_type != "AWS::EC2::Instance":
            return []
        
        try:
            ssm_client = aws_factory.get_client('ssm', region)
            
            # Get instance information from SSM
            response = ssm_client.describe_instance_information()
            instances = []
            
            for instance in response.get('InstanceInformationList', []):
                platform_name = instance.get('PlatformName', 'Unknown')
                platform_version = instance.get('PlatformVersion', 'Unknown')
                
                # Simple heuristic for supported versions
                is_supported = self._check_version_support(platform_name, platform_version)
                
                instances.append({
                    'InstanceId': instance.get('InstanceId'),
                    'PlatformName': platform_name,
                    'PlatformVersion': platform_version,
                    'IsSupported': is_supported
                })
            
            return instances
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            # Log parameter validation errors at DEBUG level (expected for some resources)
            if 'Parameter' in error_code or 'parameter' in str(e).lower():
                logger.debug(f"Parameter validation issue retrieving instance information in {region}: {e}")
            else:
                logger.error(f"Error retrieving instance information in {region}: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error retrieving instance information in {region}: {e}")
            return []
    
    def _check_version_support(self, platform_name: str, platform_version: str) -> bool:
        """Check if OS version is supported (simplified logic)."""
        # This is a simplified check - in production, maintain a list of EOL versions
        deprecated_keywords = ['2008', '2012', 'centos 6', 'ubuntu 14', 'ubuntu 16']
        platform_lower = f"{platform_name} {platform_version}".lower()
        
        return not any(keyword in platform_lower for keyword in deprecated_keywords)
    
    def _evaluate_resource_compliance(
        self, 
        resource: Dict[str, Any], 
        aws_factory: AWSClientFactory, 
        region: str
    ) -> ComplianceResult:
        """Evaluate if EC2 instance runs supported OS version."""
        instance_id = resource.get('InstanceId', 'unknown')
        platform_name = resource.get('PlatformName', 'Unknown')
        platform_version = resource.get('PlatformVersion', 'Unknown')
        is_supported = resource.get('IsSupported', True)
        
        if is_supported:
            evaluation_reason = f"Instance {instance_id} runs supported OS: {platform_name} {platform_version}"
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            evaluation_reason = f"Instance {instance_id} runs unsupported OS: {platform_name} {platform_version}"
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
        """Get remediation steps for OS version support."""
        return [
            "1. Identify instances with unsupported OS:",
            "   aws ssm describe-instance-information \\",
            "     --query 'InstanceInformationList[].{ID:InstanceId,OS:PlatformName,Version:PlatformVersion}'",
            "",
            "2. Plan migration to supported OS versions",
            "3. Create new instances with supported OS",
            "4. Migrate workloads to new instances",
            "5. Decommission old instances",
            "",
            "Priority: HIGH - Security risk with unsupported OS",
            "Effort: High - Requires migration planning",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/AMIs.html"
        ]


class RDSEngineVersionSupportedAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 2.2 - Ensure Authorized Software is Currently Supported
    AWS Config Rule: rds-engine-version-supported
    
    Ensures RDS instances run supported database engine versions.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="rds-engine-version-supported",
            control_id="2.2",
            resource_types=["AWS::RDS::DBInstance"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get RDS instances with engine version information."""
        if resource_type != "AWS::RDS::DBInstance":
            return []
        
        try:
            rds_client = aws_factory.get_client('rds', region)
            
            response = rds_client.describe_db_instances()
            instances = []
            
            for db in response.get('DBInstances', []):
                engine = db.get('Engine')
                engine_version = db.get('EngineVersion')
                
                # Check if version is deprecated
                try:
                    versions_response = rds_client.describe_db_engine_versions(
                        Engine=engine,
                        EngineVersion=engine_version
                    )
                    
                    if versions_response.get('DBEngineVersions'):
                        version_info = versions_response['DBEngineVersions'][0]
                        is_deprecated = version_info.get('Status') == 'deprecated'
                    else:
                        is_deprecated = False
                except ClientError:
                    is_deprecated = False
                
                instances.append({
                    'DBInstanceIdentifier': db.get('DBInstanceIdentifier'),
                    'Engine': engine,
                    'EngineVersion': engine_version,
                    'IsDeprecated': is_deprecated
                })
            
            return instances
            
        except ClientError as e:
            logger.error(f"Error retrieving RDS instances in {region}: {e}")
            return []
    
    def _evaluate_resource_compliance(
        self, 
        resource: Dict[str, Any], 
        aws_factory: AWSClientFactory, 
        region: str
    ) -> ComplianceResult:
        """Evaluate if RDS instance runs supported engine version."""
        db_id = resource.get('DBInstanceIdentifier', 'unknown')
        engine = resource.get('Engine', 'unknown')
        engine_version = resource.get('EngineVersion', 'unknown')
        is_deprecated = resource.get('IsDeprecated', False)
        
        if not is_deprecated:
            evaluation_reason = f"RDS instance {db_id} runs supported {engine} version {engine_version}"
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            evaluation_reason = f"RDS instance {db_id} runs deprecated {engine} version {engine_version}"
            compliance_status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceResult(
            resource_id=db_id,
            resource_type="AWS::RDS::DBInstance",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get remediation steps for RDS version support."""
        return [
            "1. Check for available engine versions:",
            "   aws rds describe-db-engine-versions \\",
            "     --engine <engine-name> \\",
            "     --query 'DBEngineVersions[?Status!=`deprecated`]'",
            "",
            "2. Upgrade RDS instance:",
            "   aws rds modify-db-instance \\",
            "     --db-instance-identifier <db-id> \\",
            "     --engine-version <new-version> \\",
            "     --apply-immediately",
            "",
            "3. Test application compatibility before upgrading",
            "",
            "Priority: HIGH - Deprecated versions lack security updates",
            "Effort: Medium - Requires testing and maintenance window",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/USER_UpgradeDBInstance.Upgrading.html"
        ]


class LambdaRuntimeSupportedAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 2.2 - Ensure Authorized Software is Currently Supported
    AWS Config Rule: lambda-runtime-supported
    
    Ensures Lambda functions use supported runtimes.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="lambda-runtime-supported",
            control_id="2.2",
            resource_types=["AWS::Lambda::Function"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get Lambda functions with runtime information."""
        if resource_type != "AWS::Lambda::Function":
            return []
        
        try:
            lambda_client = aws_factory.get_client('lambda', region)
            functions = []
            
            # Deprecated runtimes as of 2026
            deprecated_runtimes = [
                'python2.7', 'python3.6', 'python3.7',
                'nodejs10.x', 'nodejs12.x', 'nodejs14.x',
                'ruby2.5', 'ruby2.7',
                'dotnetcore2.1', 'dotnetcore3.1',
                'go1.x'
            ]
            
            paginator = lambda_client.get_paginator('list_functions')
            for page in paginator.paginate():
                for func in page.get('Functions', []):
                    runtime = func.get('Runtime', 'unknown')
                    is_deprecated = runtime in deprecated_runtimes
                    
                    functions.append({
                        'FunctionName': func.get('FunctionName'),
                        'FunctionArn': func.get('FunctionArn'),
                        'Runtime': runtime,
                        'IsDeprecated': is_deprecated
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
        """Evaluate if Lambda function uses supported runtime."""
        function_name = resource.get('FunctionName', 'unknown')
        runtime = resource.get('Runtime', 'unknown')
        is_deprecated = resource.get('IsDeprecated', False)
        
        if not is_deprecated:
            evaluation_reason = f"Lambda function {function_name} uses supported runtime: {runtime}"
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            evaluation_reason = f"Lambda function {function_name} uses deprecated runtime: {runtime}"
            compliance_status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceResult(
            resource_id=resource.get('FunctionArn', function_name),
            resource_type="AWS::Lambda::Function",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get remediation steps for Lambda runtime support."""
        return [
            "1. List functions with deprecated runtimes:",
            "   aws lambda list-functions \\",
            "     --query 'Functions[?Runtime==`python3.7`].FunctionName'",
            "",
            "2. Update function runtime:",
            "   aws lambda update-function-configuration \\",
            "     --function-name <function-name> \\",
            "     --runtime python3.11",
            "",
            "3. Test function after runtime update",
            "4. Update deployment packages if needed",
            "",
            "Priority: HIGH - Deprecated runtimes lose security support",
            "Effort: Medium - Requires testing and code updates",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/lambda/latest/dg/lambda-runtimes.html"
        ]
