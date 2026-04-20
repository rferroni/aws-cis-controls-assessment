"""
CIS Control 8.2 - VPC Flow Logs
Ensures VPC Flow Logs are enabled for network traffic visibility.
"""

import logging
from typing import List, Dict, Any
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class VPCFlowLogsEnabledAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 8.2 - Collect Audit Logs
    AWS Config Rule: vpc-flow-logs-enabled
    
    Ensures VPC Flow Logs are enabled for network traffic monitoring.
    Flow Logs capture information about IP traffic going to and from
    network interfaces in VPCs, essential for security analysis and troubleshooting.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="vpc-flow-logs-enabled",
            control_id="8.2",
            resource_types=["AWS::EC2::VPC"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get VPCs and their Flow Logs configuration."""
        if resource_type != "AWS::EC2::VPC":
            return []
        
        try:
            ec2_client = aws_factory.get_client('ec2', region)
            
            # Get all VPCs
            vpcs_response = ec2_client.describe_vpcs()
            vpcs = vpcs_response.get('Vpcs', [])
            
            if not vpcs:
                return []
            
            # Get all Flow Logs
            flow_logs_response = ec2_client.describe_flow_logs()
            flow_logs = flow_logs_response.get('FlowLogs', [])
            
            # Create a mapping of VPC ID to Flow Logs
            vpc_flow_logs = {}
            for flow_log in flow_logs:
                resource_id = flow_log.get('ResourceId', '')
                if resource_id.startswith('vpc-'):
                    if resource_id not in vpc_flow_logs:
                        vpc_flow_logs[resource_id] = []
                    vpc_flow_logs[resource_id].append(flow_log)
            
            # Build resource list with Flow Log status
            vpc_resources = []
            for vpc in vpcs:
                vpc_id = vpc.get('VpcId', '')
                vpc_flow_log_list = vpc_flow_logs.get(vpc_id, [])
                
                # Check if any active Flow Logs exist
                active_flow_logs = [
                    fl for fl in vpc_flow_log_list 
                    if fl.get('FlowLogStatus') == 'ACTIVE'
                ]
                
                vpc_resources.append({
                    'VpcId': vpc_id,
                    'IsDefault': vpc.get('IsDefault', False),
                    'CidrBlock': vpc.get('CidrBlock', ''),
                    'State': vpc.get('State', ''),
                    'Region': region,
                    'FlowLogs': active_flow_logs,
                    'HasActiveFlowLogs': len(active_flow_logs) > 0,
                    'Tags': vpc.get('Tags', [])
                })
            
            return vpc_resources
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'UnauthorizedOperation':
                logger.warning(f"Access denied to describe VPCs/Flow Logs in {region}")
            else:
                logger.error(f"Error describing VPCs/Flow Logs in {region}: {e}")
            return []
    
    def _evaluate_resource_compliance(
        self, 
        resource: Dict[str, Any], 
        aws_factory: AWSClientFactory, 
        region: str
    ) -> ComplianceResult:
        """Evaluate if VPC has Flow Logs enabled."""
        vpc_id = resource.get('VpcId', '')
        has_flow_logs = resource.get('HasActiveFlowLogs', False)
        flow_logs = resource.get('FlowLogs', [])
        is_default = resource.get('IsDefault', False)
        
        # Check if VPC has active Flow Logs
        is_compliant = has_flow_logs
        
        if is_compliant:
            # Provide details about the Flow Logs
            flow_log_details = []
            for fl in flow_logs:
                destination = fl.get('LogDestinationType', 'unknown')
                traffic_type = fl.get('TrafficType', 'unknown')
                flow_log_details.append(f"{traffic_type} to {destination}")
            
            evaluation_reason = (
                f"VPC {vpc_id} has {len(flow_logs)} active Flow Log(s) enabled: "
                f"{', '.join(flow_log_details)}"
            )
            if is_default:
                evaluation_reason += " (Default VPC)"
            
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            evaluation_reason = f"VPC {vpc_id} does not have Flow Logs enabled."
            if is_default:
                evaluation_reason += " (Default VPC - should be monitored)"
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
        """Get remediation steps for enabling VPC Flow Logs."""
        return [
            "1. Enable VPC Flow Logs in the AWS Console:",
            "   - Navigate to VPC service",
            "   - Select the VPC",
            "   - Click 'Actions' > 'Create flow log'",
            "   - Configure:",
            "     * Filter: ALL (captures accepted and rejected traffic)",
            "     * Destination: CloudWatch Logs or S3",
            "     * IAM role: Create or select role with permissions",
            "   - Click 'Create flow log'",
            "",
            "2. Enable Flow Logs using AWS CLI (CloudWatch Logs):",
            "   # Create IAM role first (one-time setup)",
            "   aws iam create-role \\",
            "     --role-name VPCFlowLogsRole \\",
            "     --assume-role-policy-document file://trust-policy.json",
            "",
            "   # Create Flow Log",
            "   aws ec2 create-flow-logs \\",
            "     --resource-type VPC \\",
            "     --resource-ids <vpc-id> \\",
            "     --traffic-type ALL \\",
            "     --log-destination-type cloud-watch-logs \\",
            "     --log-group-name /aws/vpc/flowlogs \\",
            "     --deliver-logs-permission-arn <role-arn> \\",
            "     --region <region>",
            "",
            "3. Enable Flow Logs using AWS CLI (S3):",
            "   aws ec2 create-flow-logs \\",
            "     --resource-type VPC \\",
            "     --resource-ids <vpc-id> \\",
            "     --traffic-type ALL \\",
            "     --log-destination-type s3 \\",
            "     --log-destination arn:aws:s3:::<bucket-name> \\",
            "     --region <region>",
            "",
            "4. Best practices:",
            "   - Enable for ALL traffic (not just ACCEPT or REJECT)",
            "   - Use S3 for cost-effective long-term storage",
            "   - Use CloudWatch Logs for real-time analysis and alerting",
            "   - Set appropriate log retention (30-90 days minimum)",
            "   - Enable for all VPCs, including default VPC",
            "",
            "5. Analyze Flow Logs:",
            "   - Use CloudWatch Insights for queries",
            "   - Use Athena for S3-based logs",
            "   - Look for:",
            "     * Rejected traffic (potential attacks)",
            "     * Unusual traffic patterns",
            "     * Data exfiltration attempts",
            "     * Unauthorized access attempts",
            "",
            "6. Cost optimization:",
            "   - Flow Logs incur charges for data ingestion and storage",
            "   - Use sampling if full capture is too expensive",
            "   - Archive old logs to S3 Glacier",
            "",
            "Priority: HIGH - Network visibility is essential for security",
            "Effort: Low - Can be enabled in minutes per VPC",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs.html"
        ]
