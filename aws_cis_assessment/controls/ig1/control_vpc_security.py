"""
CIS Control 12.2 - VPC Security Controls
Network security controls for VPC hardening and access restriction.
"""

import logging
from typing import List, Dict, Any, Optional
import boto3
from botocore.exceptions import ClientError, NoCredentialsError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class VPCDefaultSecurityGroupClosedAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 12.2 - Establish and Maintain a Secure Network Architecture
    AWS Config Rule: vpc-default-security-group-closed
    
    Ensures default security groups restrict all traffic to prevent accidental exposure.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="vpc-default-security-group-closed",
            control_id="12.2",
            resource_types=["AWS::EC2::SecurityGroup"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all default security groups in the region."""
        if resource_type != "AWS::EC2::SecurityGroup":
            return []
        
        try:
            ec2_client = aws_factory.get_client('ec2', region)
            
            # Get all default security groups
            response = ec2_client.describe_security_groups(
                Filters=[
                    {'Name': 'group-name', 'Values': ['default']}
                ]
            )
            
            security_groups = []
            for sg in response.get('SecurityGroups', []):
                group_id = sg.get('GroupId', '')
                vpc_id = sg.get('VpcId', '')
                
                # Analyze ingress and egress rules
                ingress_rules = sg.get('IpPermissions', [])
                egress_rules = sg.get('IpPermissionsEgress', [])
                
                # Check if rules allow any traffic
                has_ingress_rules = len(ingress_rules) > 0
                has_egress_rules = len([rule for rule in egress_rules 
                                      if not (rule.get('IpProtocol') == '-1' and 
                                             rule.get('IpRanges') == [{'CidrIp': '0.0.0.0/0'}])])
                
                security_groups.append({
                    'GroupId': group_id,
                    'GroupName': sg.get('GroupName', ''),
                    'VpcId': vpc_id,
                    'IngressRules': ingress_rules,
                    'EgressRules': egress_rules,
                    'HasIngressRules': has_ingress_rules,
                    'HasCustomEgressRules': has_egress_rules,
                    'IsDefaultGroup': True
                })
            
            logger.debug(f"Found {len(security_groups)} default security groups in {region}")
            return security_groups
            
        except ClientError as e:
            logger.error(f"Error retrieving default security groups from {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving default security groups from {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if default security group restricts all traffic."""
        group_id = resource.get('GroupId', 'unknown')
        vpc_id = resource.get('VpcId', 'unknown')
        has_ingress_rules = resource.get('HasIngressRules', False)
        has_custom_egress_rules = resource.get('HasCustomEgressRules', False)
        
        # Default security group should have no ingress rules and only default egress rule
        if not has_ingress_rules and not has_custom_egress_rules:
            return ComplianceResult(
                resource_id=group_id,
                resource_type="AWS::EC2::SecurityGroup",
                compliance_status=ComplianceStatus.COMPLIANT,
                evaluation_reason=f"Default security group {group_id} in VPC {vpc_id} restricts all traffic",
                config_rule_name=self.rule_name,
                region=region
            )
        else:
            issues = []
            if has_ingress_rules:
                issues.append("has ingress rules")
            if has_custom_egress_rules:
                issues.append("has custom egress rules")
            
            return ComplianceResult(
                resource_id=group_id,
                resource_type="AWS::EC2::SecurityGroup",
                compliance_status=ComplianceStatus.NON_COMPLIANT,
                evaluation_reason=f"Default security group {group_id} in VPC {vpc_id} {' and '.join(issues)}",
                config_rule_name=self.rule_name,
                region=region
            )


class RestrictedSSHAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 12.2 - Establish and Maintain a Secure Network Architecture
    AWS Config Rule: restricted-ssh
    
    Ensures security groups do not allow unrestricted SSH access from 0.0.0.0/0.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="restricted-ssh",
            control_id="12.2",
            resource_types=["AWS::EC2::SecurityGroup"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all security groups in the region."""
        if resource_type != "AWS::EC2::SecurityGroup":
            return []
        
        try:
            ec2_client = aws_factory.get_client('ec2', region)
            
            security_groups = []
            paginator = ec2_client.get_paginator('describe_security_groups')
            
            for page in paginator.paginate():
                for sg in page.get('SecurityGroups', []):
                    group_id = sg.get('GroupId', '')
                    group_name = sg.get('GroupName', '')
                    vpc_id = sg.get('VpcId', '')
                    
                    # Analyze ingress rules for SSH access
                    ingress_rules = sg.get('IpPermissions', [])
                    ssh_rules = []
                    
                    for rule in ingress_rules:
                        from_port = rule.get('FromPort')
                        to_port = rule.get('ToPort')
                        ip_protocol = rule.get('IpProtocol', '')
                        
                        # Check if rule allows SSH (port 22)
                        if (ip_protocol == 'tcp' and 
                            from_port is not None and to_port is not None and
                            from_port <= 22 <= to_port):
                            
                            # Check IP ranges for 0.0.0.0/0
                            for ip_range in rule.get('IpRanges', []):
                                cidr = ip_range.get('CidrIp', '')
                                if cidr == '0.0.0.0/0':
                                    ssh_rules.append({
                                        'FromPort': from_port,
                                        'ToPort': to_port,
                                        'CidrIp': cidr,
                                        'Description': ip_range.get('Description', '')
                                    })
                            
                            # Check IPv6 ranges for ::/0
                            for ipv6_range in rule.get('Ipv6Ranges', []):
                                cidr_ipv6 = ipv6_range.get('CidrIpv6', '')
                                if cidr_ipv6 == '::/0':
                                    ssh_rules.append({
                                        'FromPort': from_port,
                                        'ToPort': to_port,
                                        'CidrIpv6': cidr_ipv6,
                                        'Description': ipv6_range.get('Description', '')
                                    })
                    
                    security_groups.append({
                        'GroupId': group_id,
                        'GroupName': group_name,
                        'VpcId': vpc_id,
                        'SSHRules': ssh_rules,
                        'HasUnrestrictedSSH': len(ssh_rules) > 0
                    })
            
            logger.debug(f"Found {len(security_groups)} security groups in {region}")
            return security_groups
            
        except ClientError as e:
            logger.error(f"Error retrieving security groups from {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving security groups from {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if security group restricts SSH access."""
        group_id = resource.get('GroupId', 'unknown')
        group_name = resource.get('GroupName', 'unknown')
        has_unrestricted_ssh = resource.get('HasUnrestrictedSSH', False)
        ssh_rules = resource.get('SSHRules', [])
        
        if not has_unrestricted_ssh:
            return ComplianceResult(
                resource_id=group_id,
                resource_type="AWS::EC2::SecurityGroup",
                compliance_status=ComplianceStatus.COMPLIANT,
                evaluation_reason=f"Security group {group_name} ({group_id}) does not allow unrestricted SSH access",
                config_rule_name=self.rule_name,
                region=region
            )
        else:
            rule_details = []
            for rule in ssh_rules:
                if 'CidrIp' in rule:
                    rule_details.append(f"port {rule['FromPort']}-{rule['ToPort']} from {rule['CidrIp']}")
                elif 'CidrIpv6' in rule:
                    rule_details.append(f"port {rule['FromPort']}-{rule['ToPort']} from {rule['CidrIpv6']}")
            
            return ComplianceResult(
                resource_id=group_id,
                resource_type="AWS::EC2::SecurityGroup",
                compliance_status=ComplianceStatus.NON_COMPLIANT,
                evaluation_reason=f"Security group {group_name} ({group_id}) allows unrestricted SSH access: {', '.join(rule_details)}",
                config_rule_name=self.rule_name,
                region=region
            )