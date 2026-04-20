"""
CIS Control 6.1 - IAM Access Analyzer
Ensures IAM Access Analyzer is enabled for access control validation.
"""

import logging
from typing import List, Dict, Any
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class IAMAccessAnalyzerEnabledAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 6.1 - Establish an Access Granting Process
    AWS Config Rule: iam-access-analyzer-enabled
    
    Ensures IAM Access Analyzer is enabled to identify resources shared with
    external entities. Access Analyzer helps identify unintended access to
    resources and data, which is a security risk.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="iam-access-analyzer-enabled",
            control_id="6.1",
            resource_types=["AWS::AccessAnalyzer::Analyzer"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get IAM Access Analyzer configuration for the region."""
        if resource_type != "AWS::AccessAnalyzer::Analyzer":
            return []
        
        try:
            access_analyzer_client = aws_factory.get_client('accessanalyzer', region)
            
            # List all analyzers in the region
            try:
                response = access_analyzer_client.list_analyzers()
                analyzers = response.get('analyzers', [])
                
                if not analyzers:
                    # No analyzer found
                    return [{
                        'AnalyzerArn': 'none',
                        'AnalyzerName': 'none',
                        'Status': 'NOT_ENABLED',
                        'Type': 'UNKNOWN',
                        'Region': region,
                        'AccountId': aws_factory.get_account_info().get('account_id', 'unknown')
                    }]
                
                # Return all analyzers
                analyzer_resources = []
                for analyzer in analyzers:
                    analyzer_resources.append({
                        'AnalyzerArn': analyzer.get('arn', ''),
                        'AnalyzerName': analyzer.get('name', ''),
                        'Status': analyzer.get('status', 'UNKNOWN'),
                        'Type': analyzer.get('type', 'UNKNOWN'),
                        'Region': region,
                        'AccountId': aws_factory.get_account_info().get('account_id', 'unknown'),
                        'CreatedAt': analyzer.get('createdAt', ''),
                        'LastResourceAnalyzed': analyzer.get('lastResourceAnalyzed', ''),
                        'LastResourceAnalyzedAt': analyzer.get('lastResourceAnalyzedAt', '')
                    })
                
                return analyzer_resources
                
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', '')
                if error_code in ['ResourceNotFoundException', 'AccessDeniedException']:
                    # No analyzer or no access
                    return [{
                        'AnalyzerArn': 'none',
                        'AnalyzerName': 'none',
                        'Status': 'NOT_ENABLED',
                        'Type': 'UNKNOWN',
                        'Region': region,
                        'AccountId': aws_factory.get_account_info().get('account_id', 'unknown')
                    }]
                raise
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'AccessDeniedException':
                logger.warning(f"Access denied to IAM Access Analyzer in {region}")
            else:
                logger.error(f"Error checking IAM Access Analyzer status in {region}: {e}")
            return []
    
    def _evaluate_resource_compliance(
        self, 
        resource: Dict[str, Any], 
        aws_factory: AWSClientFactory, 
        region: str
    ) -> ComplianceResult:
        """Evaluate if IAM Access Analyzer is enabled."""
        analyzer_name = resource.get('AnalyzerName', 'none')
        analyzer_arn = resource.get('AnalyzerArn', 'none')
        status = resource.get('Status', 'NOT_ENABLED')
        analyzer_type = resource.get('Type', 'UNKNOWN')
        
        # Check if Access Analyzer is enabled and active
        is_compliant = status == 'ACTIVE' and analyzer_type in ['ACCOUNT', 'ORGANIZATION']
        
        if is_compliant:
            evaluation_reason = (
                f"IAM Access Analyzer '{analyzer_name}' is active in {region}. "
                f"Type: {analyzer_type}"
            )
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            if analyzer_name == 'none' or status == 'NOT_ENABLED':
                evaluation_reason = f"IAM Access Analyzer is not enabled in {region}."
            elif status == 'CREATING':
                evaluation_reason = f"IAM Access Analyzer '{analyzer_name}' is being created in {region}."
                compliance_status = ComplianceStatus.NON_COMPLIANT
            elif status == 'FAILED':
                evaluation_reason = f"IAM Access Analyzer '{analyzer_name}' failed to create in {region}."
                compliance_status = ComplianceStatus.NON_COMPLIANT
            else:
                evaluation_reason = f"IAM Access Analyzer '{analyzer_name}' status is {status} in {region}."
                compliance_status = ComplianceStatus.NON_COMPLIANT
            
            if not is_compliant:
                compliance_status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceResult(
            resource_id=analyzer_arn if analyzer_arn != 'none' else 'none',
            resource_type="AWS::AccessAnalyzer::Analyzer",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get remediation steps for enabling IAM Access Analyzer."""
        return [
            "1. Enable IAM Access Analyzer in the AWS Console:",
            "   - Navigate to IAM service",
            "   - Click 'Access analyzer' in the left menu",
            "   - Click 'Create analyzer'",
            "   - Choose analyzer type:",
            "     * Account: Analyzes resources in current account",
            "     * Organization: Analyzes resources across AWS Organization",
            "   - Enter analyzer name",
            "   - Click 'Create analyzer'",
            "",
            "2. Enable Access Analyzer using AWS CLI:",
            "   # For account-level analyzer",
            "   aws accessanalyzer create-analyzer \\",
            "     --analyzer-name MyAccountAnalyzer \\",
            "     --type ACCOUNT \\",
            "     --region <region>",
            "",
            "   # For organization-level analyzer (requires AWS Organizations)",
            "   aws accessanalyzer create-analyzer \\",
            "     --analyzer-name MyOrgAnalyzer \\",
            "     --type ORGANIZATION \\",
            "     --region <region>",
            "",
            "3. Review findings:",
            "   - Access Analyzer automatically scans resources",
            "   - Review findings in IAM console under 'Access analyzer'",
            "   - Findings show resources accessible from outside your account/org",
            "",
            "4. Resolve findings:",
            "   - Active findings: Resources with external access",
            "   - Archived findings: Previously resolved or accepted risks",
            "   - For each finding:",
            "     * Review the resource and access path",
            "     * Determine if access is intended",
            "     * If unintended: Remove the external access",
            "     * If intended: Archive the finding with justification",
            "",
            "5. Set up notifications:",
            "   - Create EventBridge rules to route findings to SNS/Slack",
            "   - Configure alerts for new findings",
            "",
            "6. Best practices:",
            "   - Enable in all regions where you have resources",
            "   - Review findings weekly",
            "   - Use organization analyzer for centralized visibility",
            "   - Integrate with Security Hub for consolidated findings",
            "",
            "Priority: HIGH - Unintended external access is a critical security risk",
            "Effort: Low - Can be enabled in minutes",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/IAM/latest/UserGuide/what-is-access-analyzer.html"
        ]
