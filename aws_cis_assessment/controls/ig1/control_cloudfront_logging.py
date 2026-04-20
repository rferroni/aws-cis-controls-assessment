"""
CIS Control 8.2 - CloudFront Access Logging
Ensures CloudFront distributions have access logging enabled.
"""

import logging
from typing import List, Dict, Any
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class CloudFrontLoggingEnabledAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 8.2 - Collect Audit Logs
    AWS Config Rule: cloudfront-logging-enabled
    
    Ensures CloudFront distributions have access logging enabled.
    Access logs contain detailed information about every request made to the distribution,
    essential for security analysis, troubleshooting, and compliance.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="cloudfront-logging-enabled",
            control_id="8.2",
            resource_types=["AWS::CloudFront::Distribution"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get CloudFront distributions and their logging configuration."""
        if resource_type != "AWS::CloudFront::Distribution":
            return []
        
        # CloudFront is a global service, only query from us-east-1
        if region != 'us-east-1':
            return []
        
        try:
            cloudfront_client = aws_factory.get_client('cloudfront', 'us-east-1')
            
            # List all distributions
            response = cloudfront_client.list_distributions()
            distribution_list = response.get('DistributionList', {})
            distributions = distribution_list.get('Items', [])
            
            if not distributions:
                return []
            
            # Get detailed configuration for each distribution
            dist_resources = []
            for dist in distributions:
                dist_id = dist.get('Id', '')
                dist_arn = dist.get('ARN', '')
                
                try:
                    # Get full distribution configuration
                    dist_response = cloudfront_client.get_distribution(Id=dist_id)
                    dist_config = dist_response.get('Distribution', {}).get('DistributionConfig', {})
                    
                    # Check logging configuration
                    logging_config = dist_config.get('Logging', {})
                    logging_enabled = logging_config.get('Enabled', False)
                    s3_bucket = logging_config.get('Bucket', '')
                    log_prefix = logging_config.get('Prefix', '')
                    
                    dist_resources.append({
                        'DistributionId': dist_id,
                        'DistributionArn': dist_arn,
                        'DomainName': dist.get('DomainName', ''),
                        'Status': dist.get('Status', ''),
                        'Enabled': dist.get('Enabled', False),
                        'Region': 'global',  # CloudFront is global
                        'LoggingEnabled': logging_enabled,
                        'S3Bucket': s3_bucket,
                        'LogPrefix': log_prefix,
                        'Comment': dist_config.get('Comment', '')
                    })
                    
                except ClientError as e:
                    logger.warning(f"Error getting distribution {dist_id} details: {e}")
                    continue
            
            return dist_resources
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'AccessDenied':
                logger.warning(f"Access denied to CloudFront")
            else:
                logger.error(f"Error listing CloudFront distributions: {e}")
            return []
    
    def _evaluate_resource_compliance(
        self, 
        resource: Dict[str, Any], 
        aws_factory: AWSClientFactory, 
        region: str
    ) -> ComplianceResult:
        """Evaluate if CloudFront distribution has logging enabled."""
        dist_id = resource.get('DistributionId', '')
        dist_arn = resource.get('DistributionArn', '')
        domain_name = resource.get('DomainName', '')
        logging_enabled = resource.get('LoggingEnabled', False)
        s3_bucket = resource.get('S3Bucket', '')
        dist_enabled = resource.get('Enabled', False)
        
        # Check if logging is enabled
        is_compliant = logging_enabled and s3_bucket
        
        if is_compliant:
            evaluation_reason = (
                f"CloudFront distribution {dist_id} ({domain_name}) has access logging enabled. "
                f"Logs are stored in S3 bucket: {s3_bucket}"
            )
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            if not dist_enabled:
                evaluation_reason = f"CloudFront distribution {dist_id} is disabled."
                compliance_status = ComplianceStatus.NOT_APPLICABLE
            elif not logging_enabled:
                evaluation_reason = f"CloudFront distribution {dist_id} ({domain_name}) does not have access logging enabled."
                compliance_status = ComplianceStatus.NON_COMPLIANT
            else:
                evaluation_reason = f"CloudFront distribution {dist_id} ({domain_name}) has logging enabled but no S3 bucket configured."
                compliance_status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceResult(
            resource_id=dist_arn,
            resource_type="AWS::CloudFront::Distribution",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region='global'
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get remediation steps for enabling CloudFront access logging."""
        return [
            "1. Enable CloudFront access logging in the AWS Console:",
            "   - Navigate to CloudFront service",
            "   - Select the distribution",
            "   - Click 'Edit'",
            "   - Under 'Standard logging', select 'On'",
            "   - Specify S3 bucket for logs (must be in same account)",
            "   - Optionally specify log prefix",
            "   - Click 'Save changes'",
            "",
            "2. Create S3 bucket for logs (if needed):",
            "   aws s3 mb s3://<bucket-name> --region us-east-1",
            "",
            "3. Add bucket policy to allow CloudFront to write logs:",
            "   {",
            '     "Version": "2012-10-17",',
            '     "Statement": [{',
            '       "Effect": "Allow",',
            '       "Principal": {"Service": "cloudfront.amazonaws.com"},',
            '       "Action": "s3:PutObject",',
            '       "Resource": "arn:aws:s3:::<bucket-name>/*",',
            '       "Condition": {',
            '         "StringEquals": {',
            '           "AWS:SourceAccount": "<account-id>"',
            "         }",
            "       }",
            "     }]",
            "   }",
            "",
            "4. Enable access logging using AWS CLI:",
            "   # First, get current distribution config",
            "   aws cloudfront get-distribution-config \\",
            "     --id <distribution-id> > dist-config.json",
            "",
            "   # Edit dist-config.json to add logging:",
            '   "Logging": {',
            '     "Enabled": true,',
            '     "IncludeCookies": false,',
            '     "Bucket": "<bucket-name>.s3.amazonaws.com",',
            '     "Prefix": "cloudfront-logs/"',
            "   }",
            "",
            "   # Update distribution",
            "   aws cloudfront update-distribution \\",
            "     --id <distribution-id> \\",
            "     --distribution-config file://dist-config.json \\",
            "     --if-match <etag>",
            "",
            "5. Best practices:",
            "   - Use a dedicated S3 bucket for logs",
            "   - Enable S3 bucket encryption",
            "   - Set lifecycle policies (30-90 days retention)",
            "   - Use S3 Intelligent-Tiering for cost optimization",
            "   - Enable for all distributions",
            "   - Include cookies in logs if needed for analysis",
            "",
            "6. Analyze access logs:",
            "   - Use Athena to query logs",
            "   - Look for:",
            "     * Geographic distribution of requests",
            "     * Most requested content",
            "     * Error rates (4xx, 5xx)",
            "     * Potential DDoS attacks",
            "     * Cache hit/miss ratios",
            "",
            "7. Note: CloudFront logs may take up to 24 hours to appear",
            "",
            "Priority: HIGH - CloudFront logs are essential for security and performance analysis",
            "Effort: Low - Can be enabled in minutes per distribution",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/AmazonCloudFront/latest/DeveloperGuide/AccessLogs.html"
        ]
