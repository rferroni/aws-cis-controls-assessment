"""Network and High Availability Rules - AWS Config rule assessments."""

from typing import Dict, List, Any
import logging
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class ELBCrossZoneLoadBalancingEnabledAssessment(BaseConfigRuleAssessment):
    """Assessment for elb-cross-zone-load-balancing-enabled AWS Config rule."""
    
    def __init__(self):
        super().__init__(
            rule_name="elb-cross-zone-load-balancing-enabled",
            control_id="12.2",
            resource_types=["AWS::ElasticLoadBalancing::LoadBalancer"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get Classic Load Balancers."""
        if resource_type != "AWS::ElasticLoadBalancing::LoadBalancer":
            return []
            
        try:
            elb_client = aws_factory.get_client('elb', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: elb_client.describe_load_balancers()
            )
            
            load_balancers = []
            for lb in response.get('LoadBalancerDescriptions', []):
                load_balancers.append({
                    'LoadBalancerName': lb.get('LoadBalancerName'),
                    'DNSName': lb.get('DNSName')
                })
            
            return load_balancers
            
        except ClientError as e:
            logger.error(f"Error retrieving Classic Load Balancers in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if Classic Load Balancer has cross-zone load balancing enabled."""
        lb_name = resource.get('LoadBalancerName', 'unknown')
        
        try:
            elb_client = aws_factory.get_client('elb', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: elb_client.describe_load_balancer_attributes(LoadBalancerName=lb_name)
            )
            
            attributes = response.get('LoadBalancerAttributes', {})
            cross_zone_enabled = attributes.get('CrossZoneLoadBalancing', {}).get('Enabled', False)
            
            if cross_zone_enabled:
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = f"Classic Load Balancer {lb_name} has cross-zone load balancing enabled"
            else:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = f"Classic Load Balancer {lb_name} does not have cross-zone load balancing enabled"
                
        except ClientError as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Error checking cross-zone load balancing for {lb_name}: {str(e)}"
        
        return ComplianceResult(
            resource_id=lb_name,
            resource_type="AWS::ElasticLoadBalancing::LoadBalancer",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )


class ELBDeletionProtectionEnabledAssessment(BaseConfigRuleAssessment):
    """Assessment for elb-deletion-protection-enabled AWS Config rule."""
    
    def __init__(self):
        super().__init__(
            rule_name="elb-deletion-protection-enabled",
            control_id="11.4",
            resource_types=["AWS::ElasticLoadBalancingV2::LoadBalancer"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get Application/Network Load Balancers."""
        if resource_type != "AWS::ElasticLoadBalancingV2::LoadBalancer":
            return []
            
        try:
            elbv2_client = aws_factory.get_client('elbv2', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: elbv2_client.describe_load_balancers()
            )
            
            load_balancers = []
            for lb in response.get('LoadBalancers', []):
                load_balancers.append({
                    'LoadBalancerArn': lb.get('LoadBalancerArn'),
                    'LoadBalancerName': lb.get('LoadBalancerName'),
                    'Type': lb.get('Type')
                })
            
            return load_balancers
            
        except ClientError as e:
            logger.error(f"Error retrieving ALB/NLB Load Balancers in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if ALB/NLB has deletion protection enabled."""
        lb_arn = resource.get('LoadBalancerArn', 'unknown')
        lb_name = resource.get('LoadBalancerName', 'unknown')
        
        try:
            elbv2_client = aws_factory.get_client('elbv2', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: elbv2_client.describe_load_balancer_attributes(LoadBalancerArn=lb_arn)
            )
            
            attributes = response.get('Attributes', [])
            deletion_protection_enabled = False
            
            for attr in attributes:
                if attr.get('Key') == 'deletion_protection.enabled':
                    deletion_protection_enabled = attr.get('Value', 'false').lower() == 'true'
                    break
            
            if deletion_protection_enabled:
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = f"Load Balancer {lb_name} has deletion protection enabled"
            else:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = f"Load Balancer {lb_name} does not have deletion protection enabled"
                
        except ClientError as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Error checking deletion protection for {lb_name}: {str(e)}"
        
        return ComplianceResult(
            resource_id=lb_name,
            resource_type="AWS::ElasticLoadBalancingV2::LoadBalancer",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )


class ELBv2MultipleAZAssessment(BaseConfigRuleAssessment):
    """Assessment for elbv2-multiple-az AWS Config rule."""
    
    def __init__(self):
        super().__init__(
            rule_name="elbv2-multiple-az",
            control_id="12.2",
            resource_types=["AWS::ElasticLoadBalancingV2::LoadBalancer"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get Application/Network Load Balancers."""
        if resource_type != "AWS::ElasticLoadBalancingV2::LoadBalancer":
            return []
            
        try:
            elbv2_client = aws_factory.get_client('elbv2', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: elbv2_client.describe_load_balancers()
            )
            
            load_balancers = []
            for lb in response.get('LoadBalancers', []):
                load_balancers.append({
                    'LoadBalancerArn': lb.get('LoadBalancerArn'),
                    'LoadBalancerName': lb.get('LoadBalancerName'),
                    'AvailabilityZones': lb.get('AvailabilityZones', [])
                })
            
            return load_balancers
            
        except ClientError as e:
            logger.error(f"Error retrieving ALB/NLB Load Balancers in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if ALB/NLB spans multiple availability zones."""
        lb_name = resource.get('LoadBalancerName', 'unknown')
        availability_zones = resource.get('AvailabilityZones', [])
        
        az_count = len(availability_zones)
        
        if az_count >= 2:
            compliance_status = ComplianceStatus.COMPLIANT
            evaluation_reason = f"Load Balancer {lb_name} spans {az_count} availability zones"
        else:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = f"Load Balancer {lb_name} only spans {az_count} availability zone(s), minimum 2 required"
        
        return ComplianceResult(
            resource_id=lb_name,
            resource_type="AWS::ElasticLoadBalancingV2::LoadBalancer",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )


class RDSClusterMultiAZEnabledAssessment(BaseConfigRuleAssessment):
    """Assessment for rds-cluster-multi-az-enabled AWS Config rule."""
    
    def __init__(self):
        super().__init__(
            rule_name="rds-cluster-multi-az-enabled",
            control_id="12.2",
            resource_types=["AWS::RDS::DBCluster"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get RDS clusters."""
        if resource_type != "AWS::RDS::DBCluster":
            return []
            
        try:
            rds_client = aws_factory.get_client('rds', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: rds_client.describe_db_clusters()
            )
            
            clusters = []
            for cluster in response.get('DBClusters', []):
                clusters.append({
                    'DBClusterIdentifier': cluster.get('DBClusterIdentifier'),
                    'MultiAZ': cluster.get('MultiAZ', False),
                    'AvailabilityZones': cluster.get('AvailabilityZones', [])
                })
            
            return clusters
            
        except ClientError as e:
            logger.error(f"Error retrieving RDS clusters in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if RDS cluster has Multi-AZ enabled."""
        cluster_id = resource.get('DBClusterIdentifier', 'unknown')
        multi_az = resource.get('MultiAZ', False)
        availability_zones = resource.get('AvailabilityZones', [])
        
        if multi_az or len(availability_zones) > 1:
            compliance_status = ComplianceStatus.COMPLIANT
            evaluation_reason = f"RDS cluster {cluster_id} has Multi-AZ enabled or spans multiple AZs"
        else:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = f"RDS cluster {cluster_id} does not have Multi-AZ enabled"
        
        return ComplianceResult(
            resource_id=cluster_id,
            resource_type="AWS::RDS::DBCluster",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )


class RDSInstanceDeletionProtectionEnabledAssessment(BaseConfigRuleAssessment):
    """Assessment for rds-instance-deletion-protection-enabled AWS Config rule."""
    
    def __init__(self):
        super().__init__(
            rule_name="rds-instance-deletion-protection-enabled",
            control_id="11.4",
            resource_types=["AWS::RDS::DBInstance"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get RDS instances."""
        if resource_type != "AWS::RDS::DBInstance":
            return []
            
        try:
            rds_client = aws_factory.get_client('rds', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: rds_client.describe_db_instances()
            )
            
            instances = []
            for instance in response.get('DBInstances', []):
                instances.append({
                    'DBInstanceIdentifier': instance.get('DBInstanceIdentifier'),
                    'DeletionProtection': instance.get('DeletionProtection', False)
                })
            
            return instances
            
        except ClientError as e:
            logger.error(f"Error retrieving RDS instances in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if RDS instance has deletion protection enabled."""
        instance_id = resource.get('DBInstanceIdentifier', 'unknown')
        deletion_protection = resource.get('DeletionProtection', False)
        
        if deletion_protection:
            compliance_status = ComplianceStatus.COMPLIANT
            evaluation_reason = f"RDS instance {instance_id} has deletion protection enabled"
        else:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = f"RDS instance {instance_id} does not have deletion protection enabled"
        
        return ComplianceResult(
            resource_id=instance_id,
            resource_type="AWS::RDS::DBInstance",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )


class RDSMultiAZSupportAssessment(BaseConfigRuleAssessment):
    """Assessment for rds-multi-az-support AWS Config rule."""
    
    def __init__(self):
        super().__init__(
            rule_name="rds-multi-az-support",
            control_id="12.2",
            resource_types=["AWS::RDS::DBInstance"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get RDS instances."""
        if resource_type != "AWS::RDS::DBInstance":
            return []
            
        try:
            rds_client = aws_factory.get_client('rds', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: rds_client.describe_db_instances()
            )
            
            instances = []
            for instance in response.get('DBInstances', []):
                instances.append({
                    'DBInstanceIdentifier': instance.get('DBInstanceIdentifier'),
                    'MultiAZ': instance.get('MultiAZ', False),
                    'Engine': instance.get('Engine')
                })
            
            return instances
            
        except ClientError as e:
            logger.error(f"Error retrieving RDS instances in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if RDS instance has Multi-AZ support enabled."""
        instance_id = resource.get('DBInstanceIdentifier', 'unknown')
        multi_az = resource.get('MultiAZ', False)
        engine = resource.get('Engine', 'unknown')
        
        if multi_az:
            compliance_status = ComplianceStatus.COMPLIANT
            evaluation_reason = f"RDS instance {instance_id} ({engine}) has Multi-AZ enabled"
        else:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = f"RDS instance {instance_id} ({engine}) does not have Multi-AZ enabled"
        
        return ComplianceResult(
            resource_id=instance_id,
            resource_type="AWS::RDS::DBInstance",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )


class VPCVPNTwoTunnelsUpAssessment(BaseConfigRuleAssessment):
    """Assessment for vpc-vpn-2-tunnels-up AWS Config rule."""
    
    def __init__(self):
        super().__init__(
            rule_name="vpc-vpn-2-tunnels-up",
            control_id="12.2",
            resource_types=["AWS::EC2::VPNConnection"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get VPN connections."""
        if resource_type != "AWS::EC2::VPNConnection":
            return []
            
        try:
            ec2_client = aws_factory.get_client('ec2', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: ec2_client.describe_vpn_connections()
            )
            
            vpn_connections = []
            for vpn in response.get('VpnConnections', []):
                vpn_connections.append({
                    'VpnConnectionId': vpn.get('VpnConnectionId'),
                    'State': vpn.get('State'),
                    'VgwTelemetry': vpn.get('VgwTelemetry', [])
                })
            
            return vpn_connections
            
        except ClientError as e:
            logger.error(f"Error retrieving VPN connections in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if VPN connection has both tunnels up."""
        vpn_id = resource.get('VpnConnectionId', 'unknown')
        state = resource.get('State', 'unknown')
        telemetry = resource.get('VgwTelemetry', [])
        
        if state != 'available':
            return ComplianceResult(
                resource_id=vpn_id,
                resource_type="AWS::EC2::VPNConnection",
                compliance_status=ComplianceStatus.NOT_APPLICABLE,
                evaluation_reason=f"VPN connection {vpn_id} is in state '{state}', not available",
                config_rule_name=self.rule_name,
                region=region
            )
        
        up_tunnels = 0
        for tunnel in telemetry:
            if tunnel.get('Status') == 'UP':
                up_tunnels += 1
        
        if up_tunnels >= 2:
            compliance_status = ComplianceStatus.COMPLIANT
            evaluation_reason = f"VPN connection {vpn_id} has {up_tunnels} tunnels up"
        else:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = f"VPN connection {vpn_id} has only {up_tunnels} tunnel(s) up, 2 required"
        
        return ComplianceResult(
            resource_id=vpn_id,
            resource_type="AWS::EC2::VPNConnection",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )