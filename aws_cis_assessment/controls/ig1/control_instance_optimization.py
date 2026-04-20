"""Control 11.2: Perform Automated Backups - Instance optimization."""

from typing import Dict, List, Any
import logging
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class EBSOptimizedInstanceAssessment(BaseConfigRuleAssessment):
    """Assessment for ebs-optimized-instance AWS Config rule."""
    
    def __init__(self):
        super().__init__(
            rule_name="ebs-optimized-instance",
            control_id="11.2",
            resource_types=["AWS::EC2::Instance"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get EC2 instances."""
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
                        'InstanceType': instance.get('InstanceType'),
                        'EbsOptimized': instance.get('EbsOptimized', False),
                        'State': instance.get('State', {})
                    })
            
            return instances
            
        except ClientError as e:
            logger.error(f"Error retrieving EC2 instances in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if EC2 instance is EBS optimized."""
        instance_id = resource.get('InstanceId', 'unknown')
        instance_type = resource.get('InstanceType', 'unknown')
        ebs_optimized = resource.get('EbsOptimized', False)
        state = resource.get('State', {})
        state_name = state.get('Name', 'unknown')
        
        # Only evaluate running instances
        if state_name not in ['running', 'stopped']:
            return ComplianceResult(
                resource_id=instance_id,
                resource_type="AWS::EC2::Instance",
                compliance_status=ComplianceStatus.NOT_APPLICABLE,
                evaluation_reason=f"Instance {instance_id} is in state '{state_name}', not applicable for EBS optimization check",
                config_rule_name=self.rule_name,
                region=region
            )
        
        # Some instance types are EBS optimized by default
        ebs_optimized_by_default_types = [
            'c4.', 'c5.', 'c5d.', 'c5n.', 'c6i.', 'c6id.', 'c6in.',
            'm4.', 'm5.', 'm5d.', 'm5n.', 'm5dn.', 'm6i.', 'm6id.', 'm6in.',
            'r4.', 'r5.', 'r5d.', 'r5n.', 'r5dn.', 'r6i.', 'r6id.', 'r6in.',
            't3.', 't3a.', 't4g.',
            'x1.', 'x1e.', 'x2iezn.', 'x2idn.', 'x2iedn.',
            'z1d.'
        ]
        
        is_optimized_by_default = any(instance_type.startswith(prefix) for prefix in ebs_optimized_by_default_types)
        
        if ebs_optimized or is_optimized_by_default:
            compliance_status = ComplianceStatus.COMPLIANT
            if is_optimized_by_default:
                evaluation_reason = f"Instance {instance_id} ({instance_type}) is EBS optimized by default"
            else:
                evaluation_reason = f"Instance {instance_id} ({instance_type}) has EBS optimization enabled"
        else:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = f"Instance {instance_id} ({instance_type}) does not have EBS optimization enabled"
        
        return ComplianceResult(
            resource_id=instance_id,
            resource_type="AWS::EC2::Instance",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )