"""
CIS Control 3.1 - Amazon Macie Data Protection
Ensures Amazon Macie is enabled for sensitive data discovery.
"""

import logging
from typing import List, Dict, Any
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class MacieEnabledAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 3.1 - Establish and Maintain a Data Management Process
    AWS Config Rule: macie-enabled
    
    Ensures Amazon Macie is enabled for automated sensitive data discovery.
    Macie uses machine learning to discover, classify, and protect sensitive
    data in S3 buckets, including PII, financial data, and credentials.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="macie-enabled",
            control_id="3.1",
            resource_types=["AWS::Macie::Session"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get Amazon Macie configuration for the region."""
        if resource_type != "AWS::Macie::Session":
            return []
        
        try:
            macie_client = aws_factory.get_client('macie2', region)
            
            # Check if Macie is enabled by getting session status
            try:
                session_response = macie_client.get_macie_session()
                
                status = session_response.get('status', 'DISABLED')
                finding_publishing_frequency = session_response.get('findingPublishingFrequency', 'UNKNOWN')
                
                return [{
                    'MacieSessionId': f"macie-{region}",
                    'Status': status,
                    'Region': region,
                    'AccountId': aws_factory.get_account_info().get('account_id', 'unknown'),
                    'FindingPublishingFrequency': finding_publishing_frequency,
                    'ServiceRole': session_response.get('serviceRole', ''),
                    'CreatedAt': session_response.get('createdAt', '')
                }]
                
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', '')
                if error_code in ['ResourceNotFoundException', 'AccessDeniedException']:
                    # Macie not enabled or no access
                    return [{
                        'MacieSessionId': 'none',
                        'Status': 'DISABLED',
                        'Region': region,
                        'AccountId': aws_factory.get_account_info().get('account_id', 'unknown'),
                        'FindingPublishingFrequency': 'UNKNOWN'
                    }]
                raise
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'AccessDeniedException':
                logger.warning(f"Access denied to Macie in {region}")
            else:
                logger.error(f"Error checking Macie status in {region}: {e}")
            return []
    
    def _evaluate_resource_compliance(
        self, 
        resource: Dict[str, Any], 
        aws_factory: AWSClientFactory, 
        region: str
    ) -> ComplianceResult:
        """Evaluate if Amazon Macie is enabled."""
        macie_id = resource.get('MacieSessionId', 'none')
        status = resource.get('Status', 'DISABLED')
        finding_frequency = resource.get('FindingPublishingFrequency', 'UNKNOWN')
        
        # Check if Macie is enabled
        is_compliant = status == 'ENABLED'
        
        if is_compliant:
            evaluation_reason = (
                f"Amazon Macie is enabled in {region}. "
                f"Finding publishing frequency: {finding_frequency}"
            )
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            if macie_id == 'none' or status == 'DISABLED':
                evaluation_reason = f"Amazon Macie is not enabled in {region}."
            elif status == 'PAUSED':
                evaluation_reason = f"Amazon Macie is paused in {region}."
            else:
                evaluation_reason = f"Amazon Macie status is {status} in {region}."
            compliance_status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceResult(
            resource_id=macie_id,
            resource_type="AWS::Macie::Session",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get remediation steps for enabling Amazon Macie."""
        return [
            "1. Enable Amazon Macie in the AWS Console:",
            "   - Navigate to Amazon Macie service",
            "   - Click 'Get Started' or 'Enable Macie'",
            "   - Review service permissions and pricing",
            "   - Click 'Enable Macie'",
            "",
            "2. Enable Macie using AWS CLI:",
            "   aws macie2 enable-macie \\",
            "     --finding-publishing-frequency FIFTEEN_MINUTES \\",
            "     --status ENABLED \\",
            "     --region <region>",
            "",
            "3. Configure S3 bucket discovery:",
            "   - Macie automatically discovers all S3 buckets",
            "   - Review bucket inventory in Macie console",
            "   - Identify buckets containing sensitive data",
            "",
            "4. Create sensitive data discovery jobs:",
            "   - Create classification jobs for high-priority buckets",
            "   - Schedule recurring jobs for continuous monitoring",
            "   - Use managed data identifiers (PII, credentials, financial data)",
            "   - Create custom data identifiers for organization-specific patterns",
            "",
            "5. Configure findings and alerts:",
            "   - Review Macie findings in the console",
            "   - Create EventBridge rules to route findings to SNS/Slack",
            "   - Integrate with Security Hub for centralized findings",
            "   - Set up automated remediation for critical findings",
            "",
            "6. Review and act on findings:",
            "   - Critical findings: Immediate action required",
            "   - High findings: Review within 24 hours",
            "   - Medium/Low findings: Review weekly",
            "",
            "7. Optimize costs:",
            "   - Macie charges per GB scanned and per bucket monitored",
            "   - Focus discovery jobs on high-risk buckets",
            "   - Use sampling for large datasets",
            "",
            "Priority: HIGH - Sensitive data discovery is critical for compliance",
            "Effort: Medium - Initial setup is quick, ongoing effort for job configuration",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/macie/latest/user/what-is-macie.html"
        ]
