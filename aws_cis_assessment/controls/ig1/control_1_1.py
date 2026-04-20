"""Control 1.1: Establish and Maintain Detailed Enterprise Asset Inventory assessments."""

from typing import Dict, List, Any
import logging
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class EIPAttachedAssessment(BaseConfigRuleAssessment):
    """Assessment for eip-attached Config rule - ensures Elastic IPs are attached."""
    
    def __init__(self):
        """Initialize EIP attached assessment."""
        super().__init__(
            rule_name="eip-attached",
            control_id="1.1",
            resource_types=["AWS::EC2::EIP"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all Elastic IP addresses in the region."""
        if resource_type != "AWS::EC2::EIP":
            return []
        
        try:
            ec2_client = aws_factory.get_client('ec2', region)
            
            # Use retry logic for API call
            response = aws_factory.aws_api_call_with_retry(
                lambda: ec2_client.describe_addresses()
            )
            
            eips = []
            for address in response.get('Addresses', []):
                eips.append({
                    'AllocationId': address.get('AllocationId'),
                    'PublicIp': address.get('PublicIp'),
                    'Domain': address.get('Domain', 'standard'),
                    'InstanceId': address.get('InstanceId'),
                    'NetworkInterfaceId': address.get('NetworkInterfaceId'),
                    'AssociationId': address.get('AssociationId'),
                    'Tags': address.get('Tags', [])
                })
            
            logger.debug(f"Found {len(eips)} Elastic IPs in region {region}")
            return eips
            
        except ClientError as e:
            logger.error(f"Error retrieving Elastic IPs in region {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving Elastic IPs in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if Elastic IP is attached to an instance or network interface."""
        allocation_id = resource.get('AllocationId', 'unknown')
        public_ip = resource.get('PublicIp', 'unknown')
        
        # Check if EIP is attached to an instance or network interface
        is_attached = bool(resource.get('InstanceId') or resource.get('NetworkInterfaceId'))
        
        if is_attached:
            compliance_status = ComplianceStatus.COMPLIANT
            evaluation_reason = f"EIP {public_ip} is attached to instance/ENI"
            if resource.get('InstanceId'):
                evaluation_reason += f" (Instance: {resource.get('InstanceId')})"
            if resource.get('NetworkInterfaceId'):
                evaluation_reason += f" (ENI: {resource.get('NetworkInterfaceId')})"
        else:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = f"EIP {public_ip} is not attached to any instance or network interface"
        
        return ComplianceResult(
            resource_id=allocation_id or public_ip,
            resource_type="AWS::EC2::EIP",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for unattached EIPs."""
        return [
            "Identify unattached Elastic IP addresses in your AWS account",
            "For each unattached EIP, determine if it's still needed:",
            "  - If needed: Attach the EIP to an EC2 instance or Elastic Network Interface",
            "  - If not needed: Release the EIP to avoid unnecessary charges",
            "Use AWS CLI: aws ec2 associate-address --allocation-id <eip-id> --instance-id <instance-id>",
            "Or use AWS CLI: aws ec2 release-address --allocation-id <eip-id>",
            "Monitor EIP usage regularly to prevent future unattached EIPs"
        ]


class EC2StoppedInstanceAssessment(BaseConfigRuleAssessment):
    """Assessment for ec2-stopped-instance Config rule - checks for long-stopped instances."""
    
    def __init__(self, allowed_days: int = 30):
        """Initialize EC2 stopped instance assessment."""
        super().__init__(
            rule_name="ec2-stopped-instance",
            control_id="1.1",
            resource_types=["AWS::EC2::Instance"],
            parameters={"allowedDays": allowed_days}
        )
        self.allowed_days = allowed_days
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all EC2 instances in the region."""
        if resource_type != "AWS::EC2::Instance":
            return []
        
        try:
            ec2_client = aws_factory.get_client('ec2', region)
            
            # Get all instances (running and stopped)
            response = aws_factory.aws_api_call_with_retry(
                lambda: ec2_client.describe_instances()
            )
            
            instances = []
            for reservation in response.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instances.append({
                        'InstanceId': instance.get('InstanceId'),
                        'State': instance.get('State', {}),
                        'LaunchTime': instance.get('LaunchTime'),
                        'StateTransitionReason': instance.get('StateTransitionReason'),
                        'InstanceType': instance.get('InstanceType'),
                        'Tags': instance.get('Tags', [])
                    })
            
            logger.debug(f"Found {len(instances)} EC2 instances in region {region}")
            return instances
            
        except ClientError as e:
            logger.error(f"Error retrieving EC2 instances in region {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving EC2 instances in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if EC2 instance has been stopped for too long."""
        instance_id = resource.get('InstanceId', 'unknown')
        state = resource.get('State', {})
        state_name = state.get('Name', 'unknown')
        
        # Only evaluate stopped instances
        if state_name != 'stopped':
            return ComplianceResult(
                resource_id=instance_id,
                resource_type="AWS::EC2::Instance",
                compliance_status=ComplianceStatus.NOT_APPLICABLE,
                evaluation_reason=f"Instance {instance_id} is in state '{state_name}', not stopped",
                config_rule_name=self.rule_name,
                region=region
            )
        
        # Parse state transition reason to get stop time
        # Format: "User initiated (2023-01-01 12:00:00 GMT)"
        state_reason = resource.get('StateTransitionReason', '')
        
        try:
            from datetime import datetime, timezone
            import re
            
            # Extract timestamp from state transition reason
            timestamp_match = re.search(r'\(([^)]+)\)', state_reason)
            if timestamp_match:
                timestamp_str = timestamp_match.group(1)
                # Try to parse the timestamp
                try:
                    # Handle different timestamp formats
                    for fmt in ['%Y-%m-%d %H:%M:%S %Z', '%Y-%m-%d %H:%M:%S GMT']:
                        try:
                            stop_time = datetime.strptime(timestamp_str, fmt)
                            if stop_time.tzinfo is None:
                                stop_time = stop_time.replace(tzinfo=timezone.utc)
                            break
                        except ValueError:
                            continue
                    else:
                        # If parsing fails, assume compliant
                        return ComplianceResult(
                            resource_id=instance_id,
                            resource_type="AWS::EC2::Instance",
                            compliance_status=ComplianceStatus.COMPLIANT,
                            evaluation_reason=f"Could not parse stop time from: {state_reason}",
                            config_rule_name=self.rule_name,
                            region=region
                        )
                    
                    # Calculate days stopped
                    now = datetime.now(timezone.utc)
                    days_stopped = (now - stop_time).days
                    
                    if days_stopped > self.allowed_days:
                        compliance_status = ComplianceStatus.NON_COMPLIANT
                        evaluation_reason = f"Instance {instance_id} has been stopped for {days_stopped} days (allowed: {self.allowed_days})"
                    else:
                        compliance_status = ComplianceStatus.COMPLIANT
                        evaluation_reason = f"Instance {instance_id} has been stopped for {days_stopped} days (within allowed: {self.allowed_days})"
                    
                except Exception as e:
                    logger.warning(f"Error parsing stop time for instance {instance_id}: {e}")
                    compliance_status = ComplianceStatus.COMPLIANT
                    evaluation_reason = f"Could not determine stop duration for instance {instance_id}"
            else:
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = f"Could not extract stop time from state reason: {state_reason}"
            
        except ImportError:
            # Fallback if datetime parsing fails
            compliance_status = ComplianceStatus.COMPLIANT
            evaluation_reason = f"Instance {instance_id} is stopped but duration could not be determined"
        
        return ComplianceResult(
            resource_id=instance_id,
            resource_type="AWS::EC2::Instance",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for long-stopped instances."""
        return [
            f"Identify EC2 instances that have been stopped for more than {self.allowed_days} days",
            "Review each long-stopped instance to determine if it's still needed:",
            "  - If needed: Start the instance or create an AMI and terminate the instance",
            "  - If not needed: Terminate the instance to avoid storage costs",
            "Use AWS CLI: aws ec2 terminate-instances --instance-ids <instance-id>",
            "Or create AMI first: aws ec2 create-image --instance-id <instance-id> --name <ami-name>",
            "Set up automated monitoring to alert on long-stopped instances",
            "Consider using AWS Instance Scheduler for automated start/stop"
        ]


class VPCNetworkACLUnusedAssessment(BaseConfigRuleAssessment):
    """Assessment for vpc-network-acl-unused-check Config rule - ensures NACLs are in use."""
    
    def __init__(self):
        """Initialize VPC Network ACL unused assessment."""
        super().__init__(
            rule_name="vpc-network-acl-unused-check",
            control_id="1.1",
            resource_types=["AWS::EC2::NetworkAcl"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all Network ACLs in the region."""
        if resource_type != "AWS::EC2::NetworkAcl":
            return []
        
        try:
            ec2_client = aws_factory.get_client('ec2', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: ec2_client.describe_network_acls()
            )
            
            nacls = []
            for nacl in response.get('NetworkAcls', []):
                nacls.append({
                    'NetworkAclId': nacl.get('NetworkAclId'),
                    'VpcId': nacl.get('VpcId'),
                    'IsDefault': nacl.get('IsDefault', False),
                    'Associations': nacl.get('Associations', []),
                    'Tags': nacl.get('Tags', [])
                })
            
            logger.debug(f"Found {len(nacls)} Network ACLs in region {region}")
            return nacls
            
        except ClientError as e:
            logger.error(f"Error retrieving Network ACLs in region {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving Network ACLs in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if Network ACL is in use (associated with subnets)."""
        nacl_id = resource.get('NetworkAclId', 'unknown')
        is_default = resource.get('IsDefault', False)
        associations = resource.get('Associations', [])
        
        # Default NACLs are always considered compliant
        if is_default:
            return ComplianceResult(
                resource_id=nacl_id,
                resource_type="AWS::EC2::NetworkAcl",
                compliance_status=ComplianceStatus.COMPLIANT,
                evaluation_reason=f"Network ACL {nacl_id} is the default NACL",
                config_rule_name=self.rule_name,
                region=region
            )
        
        # Check if NACL has subnet associations
        if associations:
            compliance_status = ComplianceStatus.COMPLIANT
            subnet_count = len(associations)
            evaluation_reason = f"Network ACL {nacl_id} is associated with {subnet_count} subnet(s)"
        else:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = f"Network ACL {nacl_id} is not associated with any subnets"
        
        return ComplianceResult(
            resource_id=nacl_id,
            resource_type="AWS::EC2::NetworkAcl",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for unused Network ACLs."""
        return [
            "Identify Network ACLs that are not associated with any subnets",
            "For each unused Network ACL, determine if it's still needed:",
            "  - If needed: Associate the NACL with appropriate subnets",
            "  - If not needed: Delete the unused Network ACL",
            "Use AWS CLI: aws ec2 replace-network-acl-association --association-id <assoc-id> --network-acl-id <nacl-id>",
            "Or delete unused: aws ec2 delete-network-acl --network-acl-id <nacl-id>",
            "Review Network ACL rules to ensure they provide appropriate security",
            "Document the purpose of each custom Network ACL"
        ]


class EC2InstanceManagedBySSMAssessment(BaseConfigRuleAssessment):
    """Assessment for ec2-instance-managed-by-systems-manager Config rule."""
    
    def __init__(self):
        """Initialize EC2 instance managed by SSM assessment."""
        super().__init__(
            rule_name="ec2-instance-managed-by-systems-manager",
            control_id="1.1",
            resource_types=["AWS::EC2::Instance"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all EC2 instances in the region."""
        if resource_type != "AWS::EC2::Instance":
            return []
        
        try:
            ec2_client = aws_factory.get_client('ec2', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: ec2_client.describe_instances(
                    Filters=[
                        {'Name': 'instance-state-name', 'Values': ['running', 'stopped']}
                    ]
                )
            )
            
            instances = []
            for reservation in response.get('Reservations', []):
                for instance in reservation.get('Instances', []):
                    instances.append({
                        'InstanceId': instance.get('InstanceId'),
                        'State': instance.get('State', {}),
                        'Platform': instance.get('Platform'),  # Windows instances have this set
                        'IamInstanceProfile': instance.get('IamInstanceProfile'),
                        'Tags': instance.get('Tags', [])
                    })
            
            logger.debug(f"Found {len(instances)} EC2 instances in region {region}")
            return instances
            
        except ClientError as e:
            logger.error(f"Error retrieving EC2 instances in region {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving EC2 instances in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if EC2 instance is managed by Systems Manager."""
        instance_id = resource.get('InstanceId', 'unknown')
        state = resource.get('State', {})
        state_name = state.get('Name', 'unknown')
        
        # Only evaluate running instances
        if state_name not in ['running']:
            return ComplianceResult(
                resource_id=instance_id,
                resource_type="AWS::EC2::Instance",
                compliance_status=ComplianceStatus.NOT_APPLICABLE,
                evaluation_reason=f"Instance {instance_id} is in state '{state_name}', not running",
                config_rule_name=self.rule_name,
                region=region
            )
        
        try:
            # Check if instance is managed by SSM
            ssm_client = aws_factory.get_client('ssm', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: ssm_client.describe_instance_information(
                    Filters=[
                        {'Key': 'InstanceIds', 'Values': [instance_id]}
                    ]
                )
            )
            
            managed_instances = response.get('InstanceInformationList', [])
            
            if managed_instances:
                # Instance is managed by SSM
                instance_info = managed_instances[0]
                ping_status = instance_info.get('PingStatus', 'Unknown')
                agent_version = instance_info.get('AgentVersion', 'Unknown')
                
                if ping_status == 'Online':
                    compliance_status = ComplianceStatus.COMPLIANT
                    evaluation_reason = f"Instance {instance_id} is managed by SSM (Agent: {agent_version}, Status: {ping_status})"
                else:
                    compliance_status = ComplianceStatus.NON_COMPLIANT
                    evaluation_reason = f"Instance {instance_id} is registered with SSM but status is {ping_status}"
            else:
                # Instance is not managed by SSM
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = f"Instance {instance_id} is not managed by Systems Manager"
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code in ['AccessDenied', 'UnauthorizedOperation']:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Insufficient permissions to check SSM status for instance {instance_id}"
            else:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Error checking SSM status for instance {instance_id}: {str(e)}"
        except Exception as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Unexpected error checking SSM status for instance {instance_id}: {str(e)}"
        
        return ComplianceResult(
            resource_id=instance_id,
            resource_type="AWS::EC2::Instance",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for instances not managed by SSM."""
        return [
            "Identify EC2 instances that are not managed by Systems Manager",
            "For each unmanaged instance:",
            "  1. Ensure the instance has an IAM role with SSM permissions",
            "  2. Attach the AmazonSSMManagedInstanceCore policy to the role",
            "  3. Install or update the SSM Agent (pre-installed on Amazon Linux 2, Ubuntu 16.04+, Windows)",
            "  4. Verify the instance appears in Systems Manager console",
            "Use AWS CLI to check SSM status: aws ssm describe-instance-information",
            "Create IAM role: aws iam create-role --role-name SSMRole --assume-role-policy-document file://trust-policy.json",
            "Attach policy: aws iam attach-role-policy --role-name SSMRole --policy-arn arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
            "Associate role with instance: aws ec2 associate-iam-instance-profile --instance-id <instance-id> --iam-instance-profile Name=SSMRole"
        ]


class EC2SecurityGroupAttachedAssessment(BaseConfigRuleAssessment):
    """Assessment for ec2-security-group-attached-to-eni Config rule."""
    
    def __init__(self):
        """Initialize EC2 security group attached assessment."""
        super().__init__(
            rule_name="ec2-security-group-attached-to-eni",
            control_id="1.1",
            resource_types=["AWS::EC2::SecurityGroup"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all Security Groups in the region."""
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
                    'VpcId': sg.get('VpcId'),
                    'Description': sg.get('Description'),
                    'Tags': sg.get('Tags', [])
                })
            
            logger.debug(f"Found {len(security_groups)} Security Groups in region {region}")
            return security_groups
            
        except ClientError as e:
            logger.error(f"Error retrieving Security Groups in region {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving Security Groups in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if Security Group is attached to network interfaces."""
        group_id = resource.get('GroupId', 'unknown')
        group_name = resource.get('GroupName', 'unknown')
        
        # Skip default security groups as they're always considered compliant
        if group_name == 'default':
            return ComplianceResult(
                resource_id=group_id,
                resource_type="AWS::EC2::SecurityGroup",
                compliance_status=ComplianceStatus.COMPLIANT,
                evaluation_reason=f"Security Group {group_id} is the default security group",
                config_rule_name=self.rule_name,
                region=region
            )
        
        try:
            ec2_client = aws_factory.get_client('ec2', region)
            
            # Check if security group is attached to any network interfaces
            response = aws_factory.aws_api_call_with_retry(
                lambda: ec2_client.describe_network_interfaces(
                    Filters=[
                        {'Name': 'group-id', 'Values': [group_id]}
                    ]
                )
            )
            
            network_interfaces = response.get('NetworkInterfaces', [])
            
            if network_interfaces:
                compliance_status = ComplianceStatus.COMPLIANT
                eni_count = len(network_interfaces)
                evaluation_reason = f"Security Group {group_id} is attached to {eni_count} network interface(s)"
            else:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = f"Security Group {group_id} is not attached to any network interfaces"
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code in ['AccessDenied', 'UnauthorizedOperation']:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Insufficient permissions to check network interfaces for security group {group_id}"
            else:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Error checking network interfaces for security group {group_id}: {str(e)}"
        except Exception as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Unexpected error checking network interfaces for security group {group_id}: {str(e)}"
        
        return ComplianceResult(
            resource_id=group_id,
            resource_type="AWS::EC2::SecurityGroup",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for unattached security groups."""
        return [
            "Identify Security Groups that are not attached to any network interfaces",
            "For each unattached Security Group, determine if it's still needed:",
            "  - If needed: Attach the security group to appropriate EC2 instances or ENIs",
            "  - If not needed: Delete the unused security group",
            "Use AWS CLI: aws ec2 modify-instance-attribute --instance-id <instance-id> --groups <sg-id>",
            "Or delete unused: aws ec2 delete-security-group --group-id <sg-id>",
            "Review security group rules to ensure they follow least privilege principle",
            "Document the purpose of each custom security group",
            "Set up monitoring to alert on unused security groups"
        ]