"""
CIS Control 8.2 - WAF Logging
Ensures AWS WAF web ACLs have logging enabled.
"""

import logging
from typing import List, Dict, Any
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class WAFLoggingEnabledAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 8.2 - Collect Audit Logs
    AWS Config Rule: waf-logging-enabled
    
    Ensures AWS WAF web ACLs have logging enabled.
    WAF logs contain detailed information about requests analyzed by the web ACL,
    essential for security analysis, threat detection, and compliance.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="waf-logging-enabled",
            control_id="8.2",
            resource_types=["AWS::WAFv2::WebACL"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get WAF web ACLs and their logging configuration."""
        if resource_type != "AWS::WAFv2::WebACL":
            return []
        
        try:
            wafv2_client = aws_factory.get_client('wafv2', region)
            
            # List regional web ACLs
            web_acls = []
            try:
                response = wafv2_client.list_web_acls(Scope='REGIONAL')
                web_acls.extend(response.get('WebACLs', []))
            except ClientError as e:
                logger.debug(f"Error listing regional web ACLs in {region}: {e}")
            
            # For us-east-1, also check CloudFront (CLOUDFRONT scope)
            if region == 'us-east-1':
                try:
                    cf_response = wafv2_client.list_web_acls(Scope='CLOUDFRONT')
                    cloudfront_acls = cf_response.get('WebACLs', [])
                    for acl in cloudfront_acls:
                        acl['Scope'] = 'CLOUDFRONT'
                    web_acls.extend(cloudfront_acls)
                except ClientError as e:
                    logger.debug(f"Error listing CloudFront web ACLs: {e}")
            
            if not web_acls:
                return []
            
            # Get logging configuration for each web ACL
            acl_resources = []
            for acl in web_acls:
                acl_arn = acl.get('ARN', '')
                acl_name = acl.get('Name', '')
                acl_scope = acl.get('Scope', 'REGIONAL')
                
                try:
                    # Get logging configuration
                    logging_config = None
                    log_destinations = []
                    
                    try:
                        log_response = wafv2_client.get_logging_configuration(
                            ResourceArn=acl_arn
                        )
                        logging_config = log_response.get('LoggingConfiguration', {})
                        log_destinations = logging_config.get('LogDestinationConfigs', [])
                    except ClientError as e:
                        error_code = e.response.get('Error', {}).get('Code', '')
                        if error_code != 'WAFNonexistentItemException':
                            logger.debug(f"Error getting logging config for {acl_name}: {e}")
                    
                    acl_resources.append({
                        'WebACLArn': acl_arn,
                        'WebACLName': acl_name,
                        'WebACLId': acl.get('Id', ''),
                        'Scope': acl_scope,
                        'Region': region if acl_scope == 'REGIONAL' else 'global',
                        'LoggingEnabled': len(log_destinations) > 0,
                        'LogDestinations': log_destinations
                    })
                    
                except ClientError as e:
                    logger.warning(f"Error processing web ACL {acl_name}: {e}")
                    continue
            
            return acl_resources
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'AccessDeniedException':
                logger.warning(f"Access denied to WAFv2 in {region}")
            else:
                logger.error(f"Error listing WAF web ACLs in {region}: {e}")
            return []
    
    def _evaluate_resource_compliance(
        self, 
        resource: Dict[str, Any], 
        aws_factory: AWSClientFactory, 
        region: str
    ) -> ComplianceResult:
        """Evaluate if WAF web ACL has logging enabled."""
        acl_arn = resource.get('WebACLArn', '')
        acl_name = resource.get('WebACLName', '')
        logging_enabled = resource.get('LoggingEnabled', False)
        log_destinations = resource.get('LogDestinations', [])
        scope = resource.get('Scope', 'REGIONAL')
        
        # Check if logging is enabled
        is_compliant = logging_enabled and len(log_destinations) > 0
        
        if is_compliant:
            # Determine destination type
            dest_types = []
            for dest in log_destinations:
                if 'logs' in dest:
                    dest_types.append('CloudWatch Logs')
                elif 'firehose' in dest:
                    dest_types.append('Kinesis Firehose')
                elif 's3' in dest:
                    dest_types.append('S3')
            
            evaluation_reason = (
                f"WAF web ACL '{acl_name}' ({scope}) has logging enabled. "
                f"Destinations: {', '.join(dest_types)}"
            )
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            evaluation_reason = f"WAF web ACL '{acl_name}' ({scope}) does not have logging enabled."
            compliance_status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceResult(
            resource_id=acl_arn,
            resource_type="AWS::WAFv2::WebACL",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=resource.get('Region', region)
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get remediation steps for enabling WAF logging."""
        return [
            "1. Enable WAF logging in the AWS Console:",
            "   - Navigate to WAF & Shield service",
            "   - Select 'Web ACLs'",
            "   - Select the web ACL",
            "   - Click 'Logging and metrics' tab",
            "   - Click 'Enable logging'",
            "   - Choose log destination:",
            "     * CloudWatch Logs log group",
            "     * Kinesis Data Firehose delivery stream",
            "     * S3 bucket",
            "   - Click 'Enable logging'",
            "",
            "2. Create log destination (if needed):",
            "   # For CloudWatch Logs",
            "   aws logs create-log-group \\",
            "     --log-group-name aws-waf-logs-<name> \\",
            "     --region <region>",
            "",
            "   # For Kinesis Firehose (more complex, see AWS docs)",
            "",
            "3. Enable WAF logging using AWS CLI:",
            "   aws wafv2 put-logging-configuration \\",
            "     --logging-configuration '{",
            '       "ResourceArn": "<web-acl-arn>",',
            '       "LogDestinationConfigs": [',
            '         "arn:aws:logs:<region>:<account-id>:log-group:aws-waf-logs-<name>"',
            "       ]",
            "     }' \\",
            "     --region <region>",
            "",
            "4. For CloudFront web ACLs (use us-east-1):",
            "   aws wafv2 put-logging-configuration \\",
            "     --logging-configuration '{",
            '       "ResourceArn": "<web-acl-arn>",',
            '       "LogDestinationConfigs": [',
            '         "arn:aws:logs:us-east-1:<account-id>:log-group:aws-waf-logs-<name>"',
            "       ]",
            "     }' \\",
            "     --region us-east-1",
            "",
            "5. Best practices:",
            "   - Use CloudWatch Logs for real-time analysis",
            "   - Use Kinesis Firehose + S3 for long-term storage",
            "   - Set appropriate log retention (30-90 days)",
            "   - Enable for all web ACLs (regional and CloudFront)",
            "   - Use log filtering to reduce volume if needed",
            "",
            "6. Analyze WAF logs:",
            "   - Use CloudWatch Insights for queries",
            "   - Use Athena for S3-based logs",
            "   - Look for:",
            "     * Blocked requests (potential attacks)",
            "     * Rule match patterns",
            "     * Geographic distribution of threats",
            "     * Rate-based rule triggers",
            "     * False positives (legitimate traffic blocked)",
            "",
            "7. Important notes:",
            "   - Log group name must start with 'aws-waf-logs-'",
            "   - CloudFront web ACLs must log to us-east-1",
            "   - Logging incurs CloudWatch Logs charges",
            "",
            "Priority: HIGH - WAF logs are critical for threat detection",
            "Effort: Low - Can be enabled in minutes per web ACL",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/waf/latest/developerguide/logging.html"
        ]
