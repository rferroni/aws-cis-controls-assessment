"""
CIS Control 13.6 - Network Security
Ensures advanced network security controls are deployed.
"""

import logging
from typing import List, Dict, Any
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class NetworkFirewallDeployedAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 13.6 - Deny Communications with Known Malicious IP Addresses
    AWS Config Rule: network-firewall-deployed
    
    Ensures AWS Network Firewall is deployed for advanced network protection.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="network-firewall-deployed",
            control_id="13.6",
            resource_types=["AWS::EC2::VPC"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get VPCs and check for Network Firewall deployment."""
        if resource_type != "AWS::EC2::VPC":
            return []
        
        try:
            ec2_client = aws_factory.get_client('ec2', region)
            network_firewall_client = aws_factory.get_client('network-firewall', region)
            
            # Get all VPCs
            vpcs_response = ec2_client.describe_vpcs()
            vpcs = []
            
            # Get all firewalls
            try:
                firewalls_response = network_firewall_client.list_firewalls()
                firewalls = firewalls_response.get('Firewalls', [])
                firewall_vpcs = {fw.get('VpcId') for fw in firewalls}
            except ClientError:
                firewall_vpcs = set()
            
            for vpc in vpcs_response.get('Vpcs', []):
                vpc_id = vpc.get('VpcId')
                has_firewall = vpc_id in firewall_vpcs
                
                vpcs.append({
                    'VpcId': vpc_id,
                    'HasFirewall': has_firewall,
                    'IsDefault': vpc.get('IsDefault', False)
                })
            
            return vpcs
            
        except ClientError as e:
            logger.error(f"Error retrieving VPCs in {region}: {e}")
            return []
    
    def _evaluate_resource_compliance(
        self, 
        resource: Dict[str, Any], 
        aws_factory: AWSClientFactory, 
        region: str
    ) -> ComplianceResult:
        """Evaluate if VPC has Network Firewall deployed."""
        vpc_id = resource.get('VpcId', 'unknown')
        has_firewall = resource.get('HasFirewall', False)
        is_default = resource.get('IsDefault', False)
        
        # Default VPCs are often not used for production
        if is_default:
            evaluation_reason = f"VPC {vpc_id} is default VPC (typically not used for production)"
            compliance_status = ComplianceStatus.NOT_APPLICABLE
        elif has_firewall:
            evaluation_reason = f"VPC {vpc_id} has AWS Network Firewall deployed"
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            evaluation_reason = f"VPC {vpc_id} does not have AWS Network Firewall deployed"
            compliance_status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceResult(
            resource_id=vpc_id,
            resource_type="AWS::EC2::VPC",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get remediation steps for deploying Network Firewall."""
        return [
            "1. Create Network Firewall policy:",
            "   aws network-firewall create-firewall-policy \\",
            "     --firewall-policy-name production-policy \\",
            "     --firewall-policy '{...}'",
            "",
            "2. Deploy Network Firewall:",
            "   aws network-firewall create-firewall \\",
            "     --firewall-name production-firewall \\",
            "     --firewall-policy-arn <policy-arn> \\",
            "     --vpc-id <vpc-id> \\",
            "     --subnet-mappings SubnetId=<subnet-id>",
            "",
            "3. Update route tables to route traffic through firewall",
            "",
            "4. Console method:",
            "   - Navigate to VPC > Network Firewall",
            "   - Click 'Create firewall'",
            "   - Configure firewall policy and rules",
            "   - Select VPC and subnets",
            "   - Update route tables",
            "",
            "Priority: MEDIUM - Enhanced network security",
            "Effort: High - Requires network architecture changes",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/network-firewall/latest/developerguide/getting-started.html"
        ]


class Route53ResolverFirewallEnabledAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 13.6 - Deny Communications with Known Malicious IP Addresses
    AWS Config Rule: route53-resolver-firewall-enabled
    
    Ensures Route 53 Resolver DNS Firewall is enabled for DNS-level protection.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="route53-resolver-firewall-enabled",
            control_id="13.6",
            resource_types=["AWS::EC2::VPC"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get VPCs and check for Route 53 Resolver Firewall."""
        if resource_type != "AWS::EC2::VPC":
            return []
        
        try:
            ec2_client = aws_factory.get_client('ec2', region)
            route53resolver_client = aws_factory.get_client('route53resolver', region)
            
            # Get all VPCs
            vpcs_response = ec2_client.describe_vpcs()
            vpcs = []
            
            # Get firewall rule group associations
            try:
                associations_response = route53resolver_client.list_firewall_rule_group_associations()
                associations = associations_response.get('FirewallRuleGroupAssociations', [])
                protected_vpcs = {assoc.get('VpcId') for assoc in associations}
            except ClientError:
                protected_vpcs = set()
            
            for vpc in vpcs_response.get('Vpcs', []):
                vpc_id = vpc.get('VpcId')
                has_dns_firewall = vpc_id in protected_vpcs
                
                vpcs.append({
                    'VpcId': vpc_id,
                    'HasDNSFirewall': has_dns_firewall,
                    'IsDefault': vpc.get('IsDefault', False)
                })
            
            return vpcs
            
        except ClientError as e:
            logger.error(f"Error retrieving VPCs in {region}: {e}")
            return []
    
    def _evaluate_resource_compliance(
        self, 
        resource: Dict[str, Any], 
        aws_factory: AWSClientFactory, 
        region: str
    ) -> ComplianceResult:
        """Evaluate if VPC has Route 53 Resolver DNS Firewall."""
        vpc_id = resource.get('VpcId', 'unknown')
        has_dns_firewall = resource.get('HasDNSFirewall', False)
        is_default = resource.get('IsDefault', False)
        
        if is_default:
            evaluation_reason = f"VPC {vpc_id} is default VPC (typically not used for production)"
            compliance_status = ComplianceStatus.NOT_APPLICABLE
        elif has_dns_firewall:
            evaluation_reason = f"VPC {vpc_id} has Route 53 Resolver DNS Firewall enabled"
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            evaluation_reason = f"VPC {vpc_id} does not have Route 53 Resolver DNS Firewall enabled"
            compliance_status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceResult(
            resource_id=vpc_id,
            resource_type="AWS::EC2::VPC",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get remediation steps for enabling DNS Firewall."""
        return [
            "1. Create DNS Firewall rule group:",
            "   aws route53resolver create-firewall-rule-group \\",
            "     --name block-malicious-domains \\",
            "     --creator-request-id $(uuidgen)",
            "",
            "2. Add rules to block malicious domains:",
            "   aws route53resolver create-firewall-rule \\",
            "     --firewall-rule-group-id <group-id> \\",
            "     --firewall-domain-list-id <list-id> \\",
            "     --priority 100 \\",
            "     --action BLOCK",
            "",
            "3. Associate rule group with VPC:",
            "   aws route53resolver associate-firewall-rule-group \\",
            "     --firewall-rule-group-id <group-id> \\",
            "     --vpc-id <vpc-id> \\",
            "     --priority 100 \\",
            "     --name vpc-protection",
            "",
            "4. Console method:",
            "   - Navigate to Route 53 > Resolver > DNS Firewall",
            "   - Create rule group",
            "   - Add domain lists and rules",
            "   - Associate with VPCs",
            "",
            "Priority: MEDIUM - DNS-level threat protection",
            "Effort: Medium - Requires rule configuration",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resolver-dns-firewall.html"
        ]
