"""Control 13.1: Centralize Security Event Alerting assessments."""

from typing import Dict, List, Any
import logging
import json
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class RestrictedIncomingTrafficAssessment(BaseConfigRuleAssessment):
    """Assessment for restricted-incoming-traffic Config rule."""
    
    def __init__(self):
        """Initialize restricted incoming traffic assessment."""
        super().__init__(
            rule_name="restricted-incoming-traffic",
            control_id="13.1",
            resource_types=["AWS::EC2::SecurityGroup"],
            parameters={
                "blockedPort1": "20",
                "blockedPort2": "21", 
                "blockedPort3": "3389",
                "blockedPort4": "3306",
                "blockedPort5": "4333"
            }
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
        """Evaluate if security group restricts incoming traffic on blocked ports."""
        group_id = resource.get('GroupId', 'unknown')
        group_name = resource.get('GroupName', 'unknown')
        ip_permissions = resource.get('IpPermissions', [])
        
        # Get blocked ports from parameters
        blocked_ports = set()
        for i in range(1, 6):  # blockedPort1 through blockedPort5
            port_param = self.parameters.get(f'blockedPort{i}')
            if port_param:
                try:
                    blocked_ports.add(int(port_param))
                except ValueError:
                    logger.warning(f"Invalid blocked port parameter: {port_param}")
        
        # Check for rules allowing unrestricted access to blocked ports
        violations = []
        
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
            
            # If rule allows public access, check if it includes blocked ports
            if allows_public_access:
                if ip_protocol == '-1':  # All protocols
                    violations.extend([{'port': port, 'protocol': 'All'} for port in blocked_ports])
                elif ip_protocol.lower() in ['tcp', 'udp'] and from_port is not None and to_port is not None:
                    # Check if any blocked ports fall within the range
                    for port in blocked_ports:
                        if from_port <= port <= to_port:
                            violations.append({
                                'port': port,
                                'protocol': ip_protocol,
                                'from_port': from_port,
                                'to_port': to_port
                            })
        
        if violations:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            violation_ports = set(v['port'] for v in violations)
            evaluation_reason = f"Security group {group_name} ({group_id}) allows unrestricted access to blocked ports: {sorted(violation_ports)}"
        else:
            compliance_status = ComplianceStatus.COMPLIANT
            evaluation_reason = f"Security group {group_name} ({group_id}) properly restricts access to blocked ports: {sorted(blocked_ports)}"
        
        return ComplianceResult(
            resource_id=group_id,
            resource_type="AWS::EC2::SecurityGroup",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for restricting incoming traffic."""
        return [
            "Remove security group rules allowing unrestricted access to blocked ports",
            "For each non-compliant security group:",
            "  1. Review inbound rules allowing public access (0.0.0.0/0 or ::/0)",
            "  2. Remove rules allowing access to commonly attacked ports (20, 21, 3389, 3306, 4333)",
            "  3. Replace with more restrictive CIDR blocks if access is needed",
            "  4. Use bastion hosts or VPN for administrative access",
            "Remove unrestricted access to FTP (port 20, 21):",
            "aws ec2 revoke-security-group-ingress --group-id <sg-id> --protocol tcp --port 20 --cidr 0.0.0.0/0",
            "aws ec2 revoke-security-group-ingress --group-id <sg-id> --protocol tcp --port 21 --cidr 0.0.0.0/0",
            "Remove unrestricted access to RDP (port 3389):",
            "aws ec2 revoke-security-group-ingress --group-id <sg-id> --protocol tcp --port 3389 --cidr 0.0.0.0/0",
            "Remove unrestricted access to MySQL (port 3306):",
            "aws ec2 revoke-security-group-ingress --group-id <sg-id> --protocol tcp --port 3306 --cidr 0.0.0.0/0",
            "Remove unrestricted access to other blocked ports:",
            "aws ec2 revoke-security-group-ingress --group-id <sg-id> --protocol tcp --port 4333 --cidr 0.0.0.0/0",
            "For necessary access, use specific CIDR blocks:",
            "aws ec2 authorize-security-group-ingress --group-id <sg-id> --protocol tcp --port <port> --cidr <specific-cidr>",
            "Implement alternative secure access methods:",
            "  - Use AWS Systems Manager Session Manager for server access",
            "  - Set up VPN or Direct Connect for administrative access",
            "  - Use bastion hosts in public subnets for secure access",
            "  - Implement Application Load Balancer for web applications",
            "Monitor security group changes with CloudTrail",
            "Set up Config rules to detect unauthorized security group changes",
            "Regularly audit security group rules for compliance"
        ]


class IncomingSSHDisabledAssessment(BaseConfigRuleAssessment):
    """Assessment for incoming-ssh-disabled Config rule."""
    
    def __init__(self):
        """Initialize incoming SSH disabled assessment."""
        super().__init__(
            rule_name="incoming-ssh-disabled",
            control_id="13.1",
            resource_types=["AWS::EC2::SecurityGroup"]
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
        """Evaluate if security group disables unrestricted SSH access."""
        group_id = resource.get('GroupId', 'unknown')
        group_name = resource.get('GroupName', 'unknown')
        ip_permissions = resource.get('IpPermissions', [])
        
        # Check for rules allowing unrestricted SSH access (port 22)
        ssh_violations = []
        
        for rule in ip_permissions:
            ip_protocol = rule.get('IpProtocol', '')
            from_port = rule.get('FromPort')
            to_port = rule.get('ToPort')
            ip_ranges = rule.get('IpRanges', [])
            ipv6_ranges = rule.get('Ipv6Ranges', [])
            
            # Check if rule allows access from anywhere (0.0.0.0/0 or ::/0)
            allows_public_access = False
            public_cidrs = []
            
            for ip_range in ip_ranges:
                if ip_range.get('CidrIp') == '0.0.0.0/0':
                    allows_public_access = True
                    public_cidrs.append('0.0.0.0/0')
            
            for ipv6_range in ipv6_ranges:
                if ipv6_range.get('CidrIpv6') == '::/0':
                    allows_public_access = True
                    public_cidrs.append('::/0')
            
            # If rule allows public access, check if it includes SSH (port 22)
            if allows_public_access:
                if ip_protocol == '-1':  # All protocols
                    ssh_violations.append({
                        'protocol': 'All',
                        'port_range': 'All',
                        'cidrs': public_cidrs
                    })
                elif ip_protocol.lower() == 'tcp' and from_port is not None and to_port is not None:
                    # Check if SSH port (22) falls within the range
                    if from_port <= 22 <= to_port:
                        ssh_violations.append({
                            'protocol': ip_protocol,
                            'port_range': f"{from_port}-{to_port}" if from_port != to_port else str(from_port),
                            'cidrs': public_cidrs
                        })
        
        if ssh_violations:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            violation_details = []
            for violation in ssh_violations:
                violation_details.append(f"{violation['protocol']}:{violation['port_range']} from {', '.join(violation['cidrs'])}")
            evaluation_reason = f"Security group {group_name} ({group_id}) allows unrestricted SSH access: {'; '.join(violation_details)}"
        else:
            compliance_status = ComplianceStatus.COMPLIANT
            evaluation_reason = f"Security group {group_name} ({group_id}) does not allow unrestricted SSH access"
        
        return ComplianceResult(
            resource_id=group_id,
            resource_type="AWS::EC2::SecurityGroup",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for disabling unrestricted SSH access."""
        return [
            "Remove security group rules allowing unrestricted SSH access",
            "For each non-compliant security group:",
            "  1. Identify rules allowing SSH access from 0.0.0.0/0 or ::/0",
            "  2. Remove unrestricted SSH access rules",
            "  3. Implement secure alternatives for SSH access",
            "  4. Use specific CIDR blocks if SSH access is required",
            "Remove unrestricted SSH access:",
            "aws ec2 revoke-security-group-ingress --group-id <sg-id> --protocol tcp --port 22 --cidr 0.0.0.0/0",
            "aws ec2 revoke-security-group-ingress --group-id <sg-id> --protocol tcp --port 22 --cidr ::/0",
            "Implement secure SSH access alternatives:",
            "1. Use AWS Systems Manager Session Manager:",
            "   - No need for SSH keys or open ports",
            "   - Centralized access logging and auditing",
            "   - aws ssm start-session --target <instance-id>",
            "2. Set up bastion host in public subnet:",
            "   - Create dedicated bastion host with restricted access",
            "   - Allow SSH only from specific IP ranges",
            "   - aws ec2 authorize-security-group-ingress --group-id <bastion-sg-id> --protocol tcp --port 22 --cidr <office-ip>/32",
            "3. Use VPN or AWS Direct Connect:",
            "   - Establish secure network connection",
            "   - Allow SSH only from VPN/Direct Connect IP ranges",
            "4. If specific CIDR access is required:",
            "   aws ec2 authorize-security-group-ingress --group-id <sg-id> --protocol tcp --port 22 --cidr <specific-ip>/32",
            "Best practices for SSH security:",
            "  - Use SSH key pairs instead of passwords",
            "  - Implement SSH key rotation policies",
            "  - Enable SSH logging and monitoring",
            "  - Use non-standard SSH ports if necessary",
            "  - Implement fail2ban or similar intrusion prevention",
            "Monitor SSH access with CloudTrail and VPC Flow Logs",
            "Set up CloudWatch alarms for SSH connection attempts",
            "Regularly audit SSH access patterns and security group changes"
        ]


class VPCFlowLogsEnabledAssessment(BaseConfigRuleAssessment):
    """Assessment for VPC Flow Logs enabled for network monitoring."""
    
    def __init__(self):
        """Initialize VPC Flow Logs enabled assessment."""
        super().__init__(
            rule_name="vpc-flow-logs-enabled",
            control_id="13.1",
            resource_types=["AWS::EC2::VPC"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all VPCs in the region."""
        if resource_type != "AWS::EC2::VPC":
            return []
        
        try:
            ec2_client = aws_factory.get_client('ec2', region)
            
            # Get all VPCs
            vpcs_response = aws_factory.aws_api_call_with_retry(
                lambda: ec2_client.describe_vpcs()
            )
            
            # Get all flow logs
            flow_logs_response = aws_factory.aws_api_call_with_retry(
                lambda: ec2_client.describe_flow_logs()
            )
            
            # Create mapping of VPC ID to flow logs
            vpc_flow_logs = {}
            for flow_log in flow_logs_response.get('FlowLogs', []):
                resource_id = flow_log.get('ResourceId')
                if resource_id and resource_id.startswith('vpc-'):
                    if resource_id not in vpc_flow_logs:
                        vpc_flow_logs[resource_id] = []
                    vpc_flow_logs[resource_id].append(flow_log)
            
            vpcs = []
            for vpc in vpcs_response.get('Vpcs', []):
                vpc_id = vpc.get('VpcId')
                vpcs.append({
                    'VpcId': vpc_id,
                    'State': vpc.get('State'),
                    'CidrBlock': vpc.get('CidrBlock'),
                    'IsDefault': vpc.get('IsDefault', False),
                    'Tags': vpc.get('Tags', []),
                    'FlowLogs': vpc_flow_logs.get(vpc_id, [])
                })
            
            logger.debug(f"Found {len(vpcs)} VPCs in region {region}")
            return vpcs
            
        except ClientError as e:
            logger.error(f"Error retrieving VPCs and flow logs in region {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving VPCs and flow logs in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if VPC has flow logs enabled."""
        vpc_id = resource.get('VpcId', 'unknown')
        vpc_state = resource.get('State', 'unknown')
        is_default = resource.get('IsDefault', False)
        flow_logs = resource.get('FlowLogs', [])
        
        # Skip deleted VPCs
        if vpc_state != 'available':
            return ComplianceResult(
                resource_id=vpc_id,
                resource_type="AWS::EC2::VPC",
                compliance_status=ComplianceStatus.NOT_APPLICABLE,
                evaluation_reason=f"VPC {vpc_id} is in state '{vpc_state}' and not available for evaluation",
                config_rule_name=self.rule_name,
                region=region
            )
        
        # Check for active flow logs
        active_flow_logs = []
        for flow_log in flow_logs:
            flow_log_status = flow_log.get('FlowLogStatus', '')
            if flow_log_status == 'ACTIVE':
                active_flow_logs.append({
                    'id': flow_log.get('FlowLogId'),
                    'traffic_type': flow_log.get('TrafficType', 'ALL'),
                    'log_destination_type': flow_log.get('LogDestinationType', 'cloud-watch-logs'),
                    'log_destination': flow_log.get('LogDestination', '')
                })
        
        if active_flow_logs:
            compliance_status = ComplianceStatus.COMPLIANT
            flow_log_details = []
            for fl in active_flow_logs:
                flow_log_details.append(f"{fl['id']} ({fl['traffic_type']} traffic to {fl['log_destination_type']})")
            
            vpc_type = "default VPC" if is_default else "VPC"
            evaluation_reason = f"{vpc_type} {vpc_id} has {len(active_flow_logs)} active flow log(s): {', '.join(flow_log_details)}"
        else:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            vpc_type = "Default VPC" if is_default else "VPC"
            if flow_logs:
                inactive_count = len(flow_logs)
                evaluation_reason = f"{vpc_type} {vpc_id} has {inactive_count} inactive flow log(s) but no active flow logs for network monitoring"
            else:
                evaluation_reason = f"{vpc_type} {vpc_id} has no flow logs enabled for network monitoring"
        
        return ComplianceResult(
            resource_id=vpc_id,
            resource_type="AWS::EC2::VPC",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for enabling VPC Flow Logs."""
        return [
            "Enable VPC Flow Logs for network monitoring and security analysis",
            "For each non-compliant VPC:",
            "  1. Create CloudWatch Log Group for flow logs (recommended)",
            "  2. Create IAM role for flow logs delivery",
            "  3. Enable flow logs for the VPC",
            "  4. Configure appropriate traffic type (ALL, ACCEPT, or REJECT)",
            "Create CloudWatch Log Group:",
            "aws logs create-log-group --log-group-name /aws/vpc/flowlogs",
            "Create IAM role for VPC Flow Logs:",
            "aws iam create-role --role-name flowlogsRole --assume-role-policy-document file://trust-policy.json",
            "aws iam put-role-policy --role-name flowlogsRole --policy-name flowlogsDeliveryRolePolicy --policy-document file://delivery-policy.json",
            "Enable VPC Flow Logs to CloudWatch:",
            "aws ec2 create-flow-logs --resource-type VPC --resource-ids <vpc-id> --traffic-type ALL --log-destination-type cloud-watch-logs --log-group-name /aws/vpc/flowlogs --deliver-logs-permission-arn arn:aws:iam::<account-id>:role/flowlogsRole",
            "Alternative: Enable VPC Flow Logs to S3:",
            "aws ec2 create-flow-logs --resource-type VPC --resource-ids <vpc-id> --traffic-type ALL --log-destination-type s3 --log-destination arn:aws:s3:::<bucket-name>/vpc-flow-logs/",
            "Configure flow log format (optional):",
            "aws ec2 create-flow-logs --resource-type VPC --resource-ids <vpc-id> --traffic-type ALL --log-destination-type cloud-watch-logs --log-group-name /aws/vpc/flowlogs --deliver-logs-permission-arn <role-arn> --log-format '${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${windowstart} ${windowend} ${action}'",
            "Best practices for VPC Flow Logs:",
            "  - Enable for ALL traffic types for comprehensive monitoring",
            "  - Use CloudWatch Logs for real-time analysis and alerting",
            "  - Use S3 for long-term storage and cost optimization",
            "  - Set up CloudWatch alarms for suspicious traffic patterns",
            "  - Implement automated analysis with Lambda functions",
            "Monitor flow logs with CloudWatch Insights:",
            "  - Analyze traffic patterns and identify anomalies",
            "  - Create dashboards for network visibility",
            "  - Set up alerts for security events",
            "Consider enabling flow logs at subnet level for granular monitoring",
            "Regularly review flow log data for security insights",
            "Implement log retention policies to manage costs"
        ]