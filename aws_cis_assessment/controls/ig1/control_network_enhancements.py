"""Control 3.10: Encrypt Sensitive Data in Transit - Network enhancements."""

from typing import Dict, List, Any
import logging
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class ElasticsearchNodeToNodeEncryptionCheckAssessment(BaseConfigRuleAssessment):
    """Assessment for elasticsearch-node-to-node-encryption-check AWS Config rule."""
    
    def __init__(self):
        super().__init__(
            rule_name="elasticsearch-node-to-node-encryption-check",
            control_id="3.10",
            resource_types=["AWS::Elasticsearch::Domain"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get Elasticsearch domains."""
        if resource_type != "AWS::Elasticsearch::Domain":
            return []
            
        try:
            es_client = aws_factory.get_client('es', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: es_client.list_domain_names()
            )
            
            domains = []
            for domain in response.get('DomainNames', []):
                domains.append({
                    'DomainName': domain.get('DomainName')
                })
            
            return domains
            
        except ClientError as e:
            logger.error(f"Error retrieving Elasticsearch domains in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if Elasticsearch domain has node-to-node encryption enabled."""
        domain_name = resource.get('DomainName', 'unknown')
        
        try:
            es_client = aws_factory.get_client('es', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: es_client.describe_elasticsearch_domain(DomainName=domain_name)
            )
            
            domain_status = response.get('DomainStatus', {})
            node_to_node_encryption = domain_status.get('NodeToNodeEncryptionOptions', {})
            encryption_enabled = node_to_node_encryption.get('Enabled', False)
            
            if encryption_enabled:
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = f"Elasticsearch domain {domain_name} has node-to-node encryption enabled"
            else:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = f"Elasticsearch domain {domain_name} does not have node-to-node encryption enabled"
                
        except ClientError as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Error checking node-to-node encryption for domain {domain_name}: {str(e)}"
        
        return ComplianceResult(
            resource_id=domain_name,
            resource_type="AWS::Elasticsearch::Domain",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )


class AutoScalingLaunchConfigPublicIPDisabledAssessment(BaseConfigRuleAssessment):
    """Assessment for autoscaling-launch-config-public-ip-disabled AWS Config rule."""
    
    def __init__(self):
        super().__init__(
            rule_name="autoscaling-launch-config-public-ip-disabled",
            control_id="3.3",
            resource_types=["AWS::AutoScaling::LaunchConfiguration"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get Auto Scaling launch configurations."""
        if resource_type != "AWS::AutoScaling::LaunchConfiguration":
            return []
            
        try:
            autoscaling_client = aws_factory.get_client('autoscaling', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: autoscaling_client.describe_launch_configurations()
            )
            
            launch_configs = []
            for config in response.get('LaunchConfigurations', []):
                launch_configs.append({
                    'LaunchConfigurationName': config.get('LaunchConfigurationName'),
                    'AssociatePublicIpAddress': config.get('AssociatePublicIpAddress')
                })
            
            return launch_configs
            
        except ClientError as e:
            logger.error(f"Error retrieving launch configurations in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if launch configuration has public IP assignment disabled."""
        config_name = resource.get('LaunchConfigurationName', 'unknown')
        associate_public_ip = resource.get('AssociatePublicIpAddress')
        
        if associate_public_ip is False:
            compliance_status = ComplianceStatus.COMPLIANT
            evaluation_reason = f"Launch configuration {config_name} has public IP assignment disabled"
        elif associate_public_ip is True:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = f"Launch configuration {config_name} has public IP assignment enabled"
        else:
            # None means it uses subnet default
            compliance_status = ComplianceStatus.COMPLIANT
            evaluation_reason = f"Launch configuration {config_name} uses subnet default for public IP assignment"
        
        return ComplianceResult(
            resource_id=config_name,
            resource_type="AWS::AutoScaling::LaunchConfiguration",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )


class EFSAccessPointEnforceRootDirectoryAssessment(BaseConfigRuleAssessment):
    """Assessment for efs-access-point-enforce-root-directory AWS Config rule."""
    
    def __init__(self):
        super().__init__(
            rule_name="efs-access-point-enforce-root-directory",
            control_id="3.3",
            resource_types=["AWS::EFS::AccessPoint"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get EFS access points."""
        if resource_type != "AWS::EFS::AccessPoint":
            return []
            
        try:
            efs_client = aws_factory.get_client('efs', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: efs_client.describe_access_points()
            )
            
            access_points = []
            for ap in response.get('AccessPoints', []):
                access_points.append({
                    'AccessPointId': ap.get('AccessPointId'),
                    'FileSystemId': ap.get('FileSystemId'),
                    'RootDirectory': ap.get('RootDirectory', {})
                })
            
            return access_points
            
        except ClientError as e:
            logger.error(f"Error retrieving EFS access points in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if EFS access point enforces a root directory."""
        access_point_id = resource.get('AccessPointId', 'unknown')
        root_directory = resource.get('RootDirectory', {})
        
        # Check if root directory is configured (not just "/")
        root_path = root_directory.get('Path', '/')
        
        if root_path != '/':
            compliance_status = ComplianceStatus.COMPLIANT
            evaluation_reason = f"EFS access point {access_point_id} enforces root directory: {root_path}"
        else:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = f"EFS access point {access_point_id} does not enforce a specific root directory"
        
        return ComplianceResult(
            resource_id=access_point_id,
            resource_type="AWS::EFS::AccessPoint",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )