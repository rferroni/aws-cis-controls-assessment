"""Control 12.8: Establish and Maintain Dedicated Computing Resources for All Administrative Work assessments."""

from typing import Dict, List, Any
import logging
import json
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class APIGatewayAssociatedWithWAFAssessment(BaseConfigRuleAssessment):
    """Assessment for api-gw-associated-with-waf Config rule."""
    
    def __init__(self):
        """Initialize API Gateway associated with WAF assessment."""
        super().__init__(
            rule_name="api-gw-associated-with-waf",
            control_id="12.8",
            resource_types=["AWS::ApiGateway::Stage"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all API Gateway stages in the region."""
        if resource_type != "AWS::ApiGateway::Stage":
            return []
        
        try:
            apigateway_client = aws_factory.get_client('apigateway', region)
            
            # First get all REST APIs
            apis_response = aws_factory.aws_api_call_with_retry(
                lambda: apigateway_client.get_rest_apis()
            )
            
            stages = []
            for api in apis_response.get('items', []):
                api_id = api.get('id')
                api_name = api.get('name', 'unknown')
                
                try:
                    # Get stages for this API
                    stages_response = aws_factory.aws_api_call_with_retry(
                        lambda: apigateway_client.get_stages(restApiId=api_id)
                    )
                    
                    for stage in stages_response.get('item', []):
                        stages.append({
                            'restApiId': api_id,
                            'apiName': api_name,
                            'stageName': stage.get('stageName'),
                            'deploymentId': stage.get('deploymentId'),
                            'webAclArn': stage.get('webAclArn'),
                            'createdDate': stage.get('createdDate'),
                            'lastUpdatedDate': stage.get('lastUpdatedDate'),
                            'tags': stage.get('tags', {})
                        })
                
                except ClientError as e:
                    logger.warning(f"Could not get stages for API {api_id}: {e}")
                    continue
            
            logger.debug(f"Found {len(stages)} API Gateway stages in region {region}")
            return stages
            
        except ClientError as e:
            logger.error(f"Error retrieving API Gateway stages in region {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving API Gateway stages in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if API Gateway stage is associated with WAF."""
        api_id = resource.get('restApiId', 'unknown')
        stage_name = resource.get('stageName', 'unknown')
        api_name = resource.get('apiName', 'unknown')
        resource_id = f"{api_id}/{stage_name}"
        web_acl_arn = resource.get('webAclArn')
        
        # Check if stage is associated with a WAF Web ACL
        if web_acl_arn:
            compliance_status = ComplianceStatus.COMPLIANT
            evaluation_reason = f"API Gateway stage {stage_name} in API {api_name} is associated with WAF Web ACL: {web_acl_arn}"
        else:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = f"API Gateway stage {stage_name} in API {api_name} is not associated with any WAF Web ACL"
        
        return ComplianceResult(
            resource_id=resource_id,
            resource_type="AWS::ApiGateway::Stage",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for API Gateway WAF association."""
        return [
            "Associate API Gateway stages with AWS WAF Web ACLs for protection",
            "For each non-compliant stage:",
            "  1. Create or identify an appropriate WAF Web ACL",
            "  2. Associate the Web ACL with the API Gateway stage",
            "  3. Configure WAF rules for protection against common attacks",
            "  4. Test the WAF configuration to ensure it doesn't block legitimate traffic",
            "Create a WAF Web ACL:",
            "aws wafv2 create-web-acl --name <web-acl-name> --scope REGIONAL --default-action Allow={} --rules file://waf-rules.json",
            "Associate Web ACL with API Gateway stage:",
            "aws apigateway update-stage --rest-api-id <api-id> --stage-name <stage-name> --patch-ops op=replace,path=/webAclArn,value=<web-acl-arn>",
            "Configure common WAF rules:",
            "  - AWS Managed Rules for Core Rule Set",
            "  - AWS Managed Rules for Known Bad Inputs",
            "  - Rate limiting rules to prevent abuse",
            "  - IP reputation rules to block known malicious IPs",
            "Monitor WAF metrics and blocked requests",
            "Regularly review and update WAF rules based on threat intelligence",
            "Set up CloudWatch alarms for WAF blocked requests"
        ]


class VPCSecurityGroupOpenOnlyToAuthorizedPortsAssessment(BaseConfigRuleAssessment):
    """Assessment for vpc-sg-open-only-to-authorized-ports Config rule."""
    
    def __init__(self):
        """Initialize VPC security group authorized ports assessment."""
        super().__init__(
            rule_name="vpc-sg-open-only-to-authorized-ports",
            control_id="12.8",
            resource_types=["AWS::EC2::SecurityGroup"],
            parameters={"authorizedTcpPorts": "443,22"}
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all security groups in the region."""
        if resource_type != "AWS::EC2::SecurityGroup":
            return []
        
        try:
            ec2_client = aws_factory.get_client('ec2', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: ec2_client.describe_security_groups()
            )
            
            security_groups = []
            for sg in response.get('SecurityGroups', []):
                security_groups.append({
                    'GroupId': sg.get('GroupId'),
                    'GroupName': sg.get('GroupName'),
                    'Description': sg.get('Description'),
                    'VpcId': sg.get('VpcId'),
                    'IpPermissions': sg.get('IpPermissions', []),
                    'IpPermissionsEgress': sg.get('IpPermissionsEgress', []),
                    'Tags': sg.get('Tags', [])
                })
            
            logger.debug(f"Found {len(security_groups)} security groups in region {region}")
            return security_groups
            
        except ClientError as e:
            logger.error(f"Error retrieving security groups in region {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving security groups in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if security group is open only to authorized ports."""
        group_id = resource.get('GroupId', 'unknown')
        group_name = resource.get('GroupName', 'unknown')
        ip_permissions = resource.get('IpPermissions', [])
        
        # Get authorized ports from parameters
        authorized_ports_param = self.parameters.get('authorizedTcpPorts', '443,22')
        authorized_ports = set()
        if authorized_ports_param:
            try:
                authorized_ports = set(int(port.strip()) for port in authorized_ports_param.split(',') if port.strip())
            except ValueError:
                logger.warning(f"Invalid authorized ports parameter: {authorized_ports_param}")
                authorized_ports = {443, 22}  # Default to HTTPS and SSH
        
        # Check for unauthorized open ports
        unauthorized_rules = []
        
        for rule in ip_permissions:
            ip_protocol = rule.get('IpProtocol', '')
            from_port = rule.get('FromPort')
            to_port = rule.get('ToPort')
            ip_ranges = rule.get('IpRanges', [])
            ipv6_ranges = rule.get('Ipv6Ranges', [])
            
            # Check if rule allows access from anywhere (0.0.0.0/0 or ::/0)
            allows_public_access = False
            for ip_range in ip_ranges:
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    allows_public_access = True
                    break
            
            if not allows_public_access:
                for ipv6_range in ipv6_ranges:
                    if ipv6_range.get('CidrIpv6') == '::/0':
                        allows_public_access = True
                        break
            
            # If rule allows public access, check if ports are authorized
            if allows_public_access:
                if ip_protocol == '-1':  # All protocols
                    unauthorized_rules.append({
                        'protocol': 'All',
                        'port': 'All',
                        'from_port': 'All',
                        'to_port': 'All'
                    })
                elif ip_protocol.lower() == 'tcp' and from_port is not None and to_port is not None:
                    # Check each port in the range
                    for port in range(from_port, to_port + 1):
                        if port not in authorized_ports:
                            unauthorized_rules.append({
                                'protocol': ip_protocol,
                                'port': port,
                                'from_port': from_port,
                                'to_port': to_port
                            })
        
        if unauthorized_rules:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            unauthorized_ports = set(rule['port'] for rule in unauthorized_rules if rule['port'] != 'All')
            if unauthorized_ports:
                evaluation_reason = f"Security group {group_name} ({group_id}) allows public access to unauthorized TCP ports: {sorted(unauthorized_ports)}"
            else:
                evaluation_reason = f"Security group {group_name} ({group_id}) allows unrestricted public access to all ports"
        else:
            compliance_status = ComplianceStatus.COMPLIANT
            evaluation_reason = f"Security group {group_name} ({group_id}) only allows public access to authorized ports: {sorted(authorized_ports)}"
        
        return ComplianceResult(
            resource_id=group_id,
            resource_type="AWS::EC2::SecurityGroup",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for security group port restrictions."""
        return [
            "Restrict security group rules to authorized ports only",
            "For each non-compliant security group:",
            "  1. Review all inbound rules allowing public access (0.0.0.0/0)",
            "  2. Remove or modify rules that allow access to unauthorized ports",
            "  3. Ensure only necessary ports (like 443 for HTTPS, 22 for SSH) are open",
            "  4. Consider using more restrictive CIDR blocks instead of 0.0.0.0/0",
            "Remove unauthorized inbound rules:",
            "aws ec2 revoke-security-group-ingress --group-id <sg-id> --protocol tcp --port <port> --cidr 0.0.0.0/0",
            "Add authorized rules with specific CIDR blocks:",
            "aws ec2 authorize-security-group-ingress --group-id <sg-id> --protocol tcp --port 443 --cidr <specific-cidr>",
            "For SSH access, use bastion hosts or VPN instead of public access:",
            "aws ec2 revoke-security-group-ingress --group-id <sg-id> --protocol tcp --port 22 --cidr 0.0.0.0/0",
            "Consider using AWS Systems Manager Session Manager for secure access",
            "Implement security group rules with least privilege principle",
            "Use security group references instead of CIDR blocks where possible",
            "Regularly audit security group rules for compliance",
            "Set up CloudWatch alarms for security group changes",
            "Use AWS Config rules to monitor security group compliance"
        ]


class NoUnrestrictedRouteToIGWAssessment(BaseConfigRuleAssessment):
    """Assessment for no-unrestricted-route-to-igw Config rule."""
    
    def __init__(self):
        """Initialize no unrestricted route to IGW assessment."""
        super().__init__(
            rule_name="no-unrestricted-route-to-igw",
            control_id="12.8",
            resource_types=["AWS::EC2::RouteTable"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all route tables in the region."""
        if resource_type != "AWS::EC2::RouteTable":
            return []
        
        try:
            ec2_client = aws_factory.get_client('ec2', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: ec2_client.describe_route_tables()
            )
            
            route_tables = []
            for rt in response.get('RouteTables', []):
                route_tables.append({
                    'RouteTableId': rt.get('RouteTableId'),
                    'VpcId': rt.get('VpcId'),
                    'Routes': rt.get('Routes', []),
                    'Associations': rt.get('Associations', []),
                    'Tags': rt.get('Tags', [])
                })
            
            logger.debug(f"Found {len(route_tables)} route tables in region {region}")
            return route_tables
            
        except ClientError as e:
            logger.error(f"Error retrieving route tables in region {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving route tables in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if route table has unrestricted routes to internet gateway."""
        route_table_id = resource.get('RouteTableId', 'unknown')
        vpc_id = resource.get('VpcId', 'unknown')
        routes = resource.get('Routes', [])
        associations = resource.get('Associations', [])
        
        # Check if this route table is associated with subnets (not just main route table)
        has_subnet_associations = any(assoc.get('SubnetId') for assoc in associations)
        
        # Look for routes to internet gateway with unrestricted destination
        unrestricted_igw_routes = []
        
        for route in routes:
            destination_cidr = route.get('DestinationCidrBlock', '')
            destination_ipv6_cidr = route.get('DestinationIpv6CidrBlock', '')
            gateway_id = route.get('GatewayId', '')
            
            # Check if route goes to an internet gateway
            is_igw_route = gateway_id.startswith('igw-')
            
            # Check if destination is unrestricted (0.0.0.0/0 or ::/0)
            is_unrestricted = (destination_cidr == '0.0.0.0/0' or destination_ipv6_cidr == '::/0')
            
            if is_igw_route and is_unrestricted:
                unrestricted_igw_routes.append({
                    'destination': destination_cidr or destination_ipv6_cidr,
                    'gateway_id': gateway_id
                })
        
        if unrestricted_igw_routes:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            destinations = [route['destination'] for route in unrestricted_igw_routes]
            gateways = [route['gateway_id'] for route in unrestricted_igw_routes]
            
            if has_subnet_associations:
                evaluation_reason = f"Route table {route_table_id} in VPC {vpc_id} has unrestricted routes to internet gateway(s) {', '.join(set(gateways))} for destinations {', '.join(destinations)} and is associated with subnets"
            else:
                evaluation_reason = f"Route table {route_table_id} in VPC {vpc_id} has unrestricted routes to internet gateway(s) {', '.join(set(gateways))} for destinations {', '.join(destinations)}"
        else:
            compliance_status = ComplianceStatus.COMPLIANT
            evaluation_reason = f"Route table {route_table_id} in VPC {vpc_id} does not have unrestricted routes to internet gateway"
        
        return ComplianceResult(
            resource_id=route_table_id,
            resource_type="AWS::EC2::RouteTable",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for removing unrestricted IGW routes."""
        return [
            "Remove unrestricted routes to internet gateway from route tables",
            "For each non-compliant route table:",
            "  1. Review routes with destination 0.0.0.0/0 or ::/0 pointing to IGW",
            "  2. Determine if unrestricted internet access is necessary",
            "  3. Replace with more specific routes if possible",
            "  4. Consider using NAT Gateway for outbound-only internet access",
            "Remove unrestricted route to IGW:",
            "aws ec2 delete-route --route-table-id <route-table-id> --destination-cidr-block 0.0.0.0/0",
            "Create NAT Gateway for outbound internet access:",
            "aws ec2 create-nat-gateway --subnet-id <public-subnet-id> --allocation-id <eip-allocation-id>",
            "Add route to NAT Gateway in private subnet route table:",
            "aws ec2 create-route --route-table-id <private-route-table-id> --destination-cidr-block 0.0.0.0/0 --nat-gateway-id <nat-gateway-id>",
            "For public subnets that need internet access:",
            "  1. Ensure they are in a separate route table from private subnets",
            "  2. Use security groups and NACLs to control access",
            "  3. Consider using Application Load Balancer for web traffic",
            "Implement network segmentation best practices:",
            "  - Separate public and private subnets",
            "  - Use different route tables for different subnet types",
            "  - Implement least privilege routing",
            "Monitor route table changes with CloudTrail",
            "Set up Config rules to detect unauthorized route changes",
            "Regularly audit network architecture for security compliance"
        ]