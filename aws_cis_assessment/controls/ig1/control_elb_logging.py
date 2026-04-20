"""
CIS Control 8.2 - ELB Access Logging
Ensures ELB access logs are enabled for load balancer traffic visibility.
"""

import logging
from typing import List, Dict, Any
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class ELBLoggingEnabledAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 8.2 - Collect Audit Logs
    AWS Config Rule: elb-logging-enabled
    
    Ensures Elastic Load Balancer access logs are enabled.
    Access logs capture detailed information about requests sent to the load balancer,
    essential for security analysis, troubleshooting, and compliance.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="elb-logging-enabled",
            control_id="8.2",
            resource_types=["AWS::ElasticLoadBalancingV2::LoadBalancer"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get load balancers and their logging configuration."""
        if resource_type != "AWS::ElasticLoadBalancingV2::LoadBalancer":
            return []
        
        try:
            elbv2_client = aws_factory.get_client('elbv2', region)
            
            # Get all load balancers
            response = elbv2_client.describe_load_balancers()
            load_balancers = response.get('LoadBalancers', [])
            
            if not load_balancers:
                return []
            
            # Get attributes for each load balancer
            lb_resources = []
            for lb in load_balancers:
                lb_arn = lb.get('LoadBalancerArn', '')
                
                try:
                    # Get load balancer attributes
                    attrs_response = elbv2_client.describe_load_balancer_attributes(
                        LoadBalancerArn=lb_arn
                    )
                    attributes = attrs_response.get('Attributes', [])
                    
                    # Check if access logs are enabled
                    logging_enabled = False
                    s3_bucket = ''
                    s3_prefix = ''
                    
                    for attr in attributes:
                        if attr.get('Key') == 'access_logs.s3.enabled':
                            logging_enabled = attr.get('Value', 'false').lower() == 'true'
                        elif attr.get('Key') == 'access_logs.s3.bucket':
                            s3_bucket = attr.get('Value', '')
                        elif attr.get('Key') == 'access_logs.s3.prefix':
                            s3_prefix = attr.get('Value', '')
                    
                    lb_resources.append({
                        'LoadBalancerArn': lb_arn,
                        'LoadBalancerName': lb.get('LoadBalancerName', ''),
                        'Type': lb.get('Type', ''),
                        'Scheme': lb.get('Scheme', ''),
                        'State': lb.get('State', {}).get('Code', ''),
                        'Region': region,
                        'LoggingEnabled': logging_enabled,
                        'S3Bucket': s3_bucket,
                        'S3Prefix': s3_prefix
                    })
                    
                except ClientError as e:
                    logger.warning(f"Error getting attributes for load balancer {lb_arn}: {e}")
                    continue
            
            return lb_resources
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'AccessDenied':
                logger.warning(f"Access denied to describe load balancers in {region}")
            else:
                logger.error(f"Error describing load balancers in {region}: {e}")
            return []
    
    def _evaluate_resource_compliance(
        self, 
        resource: Dict[str, Any], 
        aws_factory: AWSClientFactory, 
        region: str
    ) -> ComplianceResult:
        """Evaluate if load balancer has access logging enabled."""
        lb_arn = resource.get('LoadBalancerArn', '')
        lb_name = resource.get('LoadBalancerName', '')
        logging_enabled = resource.get('LoggingEnabled', False)
        s3_bucket = resource.get('S3Bucket', '')
        lb_type = resource.get('Type', '')
        
        # Check if logging is enabled
        is_compliant = logging_enabled and s3_bucket
        
        if is_compliant:
            evaluation_reason = (
                f"Load balancer '{lb_name}' ({lb_type}) has access logging enabled. "
                f"Logs are stored in S3 bucket: {s3_bucket}"
            )
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            if not logging_enabled:
                evaluation_reason = f"Load balancer '{lb_name}' ({lb_type}) does not have access logging enabled."
            else:
                evaluation_reason = f"Load balancer '{lb_name}' ({lb_type}) has logging enabled but no S3 bucket configured."
            compliance_status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceResult(
            resource_id=lb_arn,
            resource_type="AWS::ElasticLoadBalancingV2::LoadBalancer",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get remediation steps for enabling ELB access logging."""
        return [
            "1. Enable ELB access logging in the AWS Console:",
            "   - Navigate to EC2 > Load Balancers",
            "   - Select the load balancer",
            "   - Click 'Actions' > 'Edit attributes'",
            "   - Under 'Access logs', click 'Enable'",
            "   - Specify S3 bucket name (bucket must exist)",
            "   - Optionally specify S3 prefix",
            "   - Click 'Save'",
            "",
            "2. Create S3 bucket for logs (if needed):",
            "   aws s3 mb s3://<bucket-name> --region <region>",
            "",
            "3. Add bucket policy to allow ELB to write logs:",
            "   # Get ELB service account ID for your region from AWS docs",
            "   # Apply this policy to your S3 bucket:",
            "   {",
            '     "Version": "2012-10-17",',
            '     "Statement": [{',
            '       "Effect": "Allow",',
            '       "Principal": {"AWS": "arn:aws:iam::<elb-account-id>:root"},',
            '       "Action": "s3:PutObject",',
            '       "Resource": "arn:aws:s3:::<bucket-name>/*"',
            "     }]",
            "   }",
            "",
            "4. Enable access logging using AWS CLI:",
            "   aws elbv2 modify-load-balancer-attributes \\",
            "     --load-balancer-arn <lb-arn> \\",
            "     --attributes \\",
            "       Key=access_logs.s3.enabled,Value=true \\",
            "       Key=access_logs.s3.bucket,Value=<bucket-name> \\",
            "       Key=access_logs.s3.prefix,Value=<prefix> \\",
            "     --region <region>",
            "",
            "5. Best practices:",
            "   - Use a dedicated S3 bucket for logs",
            "   - Enable S3 bucket encryption",
            "   - Set appropriate lifecycle policies (30-90 days retention)",
            "   - Use S3 Intelligent-Tiering or Glacier for cost optimization",
            "   - Enable for all load balancers (ALB, NLB, CLB)",
            "",
            "6. Analyze access logs:",
            "   - Use Athena to query logs",
            "   - Look for:",
            "     * Unusual traffic patterns",
            "     * Failed requests (4xx, 5xx errors)",
            "     * Potential attacks (SQL injection, XSS)",
            "     * Performance issues",
            "",
            "Priority: HIGH - Load balancer logs are essential for security and troubleshooting",
            "Effort: Low - Can be enabled in minutes per load balancer",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html"
        ]
