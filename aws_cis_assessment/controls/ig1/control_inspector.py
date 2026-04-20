"""
CIS Control 7.1 - Amazon Inspector Vulnerability Management
Ensures Amazon Inspector is enabled for vulnerability scanning.
"""

import logging
from typing import List, Dict, Any
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class InspectorEnabledAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 7.1 - Establish and Maintain a Vulnerability Management Process
    AWS Config Rule: inspector-enabled
    
    Ensures Amazon Inspector v2 is enabled for automated vulnerability scanning.
    Inspector scans EC2 instances, container images, and Lambda functions for
    software vulnerabilities and network exposure.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="inspector-enabled",
            control_id="7.1",
            resource_types=["AWS::Inspector::AssessmentTarget"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get Amazon Inspector configuration for the region."""
        if resource_type != "AWS::Inspector::AssessmentTarget":
            return []
        
        try:
            inspector_client = aws_factory.get_client('inspector2', region)
            
            # Check if Inspector is enabled by getting account status
            try:
                status_response = inspector_client.batch_get_account_status(
                    accountIds=[aws_factory.get_account_info().get('account_id', '')]
                )
                
                accounts = status_response.get('accounts', [])
                if not accounts:
                    # Inspector not enabled
                    return [{
                        'InspectorId': 'none',
                        'Status': 'DISABLED',
                        'Region': region,
                        'AccountId': aws_factory.get_account_info().get('account_id', 'unknown'),
                        'ResourceTypes': []
                    }]
                
                account_status = accounts[0]
                state = account_status.get('state', {}).get('status', 'DISABLED')
                
                # Get coverage statistics
                coverage_response = inspector_client.list_coverage(
                    maxResults=1  # Just checking if any resources are covered
                )
                
                covered_resources = coverage_response.get('coveredResources', [])
                has_coverage = len(covered_resources) > 0
                
                # Get resource types being scanned
                resource_state = account_status.get('resourceState', {})
                enabled_resource_types = [
                    rt for rt, status in resource_state.items() 
                    if status.get('status') == 'ENABLED'
                ]
                
                return [{
                    'InspectorId': f"inspector-{region}",
                    'Status': state,
                    'Region': region,
                    'AccountId': aws_factory.get_account_info().get('account_id', 'unknown'),
                    'ResourceTypes': enabled_resource_types,
                    'HasCoverage': has_coverage
                }]
                
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', '')
                if error_code == 'ResourceNotFoundException':
                    # Inspector not enabled
                    return [{
                        'InspectorId': 'none',
                        'Status': 'DISABLED',
                        'Region': region,
                        'AccountId': aws_factory.get_account_info().get('account_id', 'unknown'),
                        'ResourceTypes': []
                    }]
                raise
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'AccessDeniedException':
                logger.warning(f"Access denied to Inspector in {region}")
            else:
                logger.error(f"Error checking Inspector status in {region}: {e}")
            return []
    
    def _evaluate_resource_compliance(
        self, 
        resource: Dict[str, Any], 
        aws_factory: AWSClientFactory, 
        region: str
    ) -> ComplianceResult:
        """Evaluate if Amazon Inspector is enabled."""
        inspector_id = resource.get('InspectorId', 'none')
        status = resource.get('Status', 'DISABLED')
        resource_types = resource.get('ResourceTypes', [])
        
        # Check if Inspector is enabled
        is_compliant = status == 'ENABLED' and len(resource_types) > 0
        
        if is_compliant:
            evaluation_reason = (
                f"Amazon Inspector is enabled in {region}. "
                f"Scanning resource types: {', '.join(resource_types)}"
            )
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            if inspector_id == 'none' or status == 'DISABLED':
                evaluation_reason = f"Amazon Inspector is not enabled in {region}."
            elif len(resource_types) == 0:
                evaluation_reason = f"Amazon Inspector is enabled but no resource types are being scanned in {region}."
            else:
                evaluation_reason = f"Amazon Inspector status is {status} in {region}."
            compliance_status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceResult(
            resource_id=inspector_id,
            resource_type="AWS::Inspector::AssessmentTarget",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get remediation steps for enabling Amazon Inspector."""
        return [
            "1. Enable Amazon Inspector v2 in the AWS Console:",
            "   - Navigate to Amazon Inspector service",
            "   - Click 'Get Started' or 'Enable Inspector'",
            "   - Select resource types to scan:",
            "     * EC2 instances (for OS vulnerabilities)",
            "     * ECR container images (for container vulnerabilities)",
            "     * Lambda functions (for code vulnerabilities)",
            "   - Click 'Enable'",
            "",
            "2. Enable Inspector using AWS CLI:",
            "   aws inspector2 enable \\",
            "     --resource-types EC2 ECR LAMBDA \\",
            "     --region <region>",
            "",
            "3. Verify Inspector is scanning resources:",
            "   aws inspector2 list-coverage \\",
            "     --region <region>",
            "",
            "4. Configure finding aggregation (optional):",
            "   - Set up cross-region aggregation for centralized findings",
            "   - Configure finding suppression rules for false positives",
            "",
            "5. Set up notifications:",
            "   - Create EventBridge rules to route findings to SNS/Slack",
            "   - Configure Security Hub integration for centralized findings",
            "",
            "6. Review findings regularly:",
            "   - Critical and High severity findings should be addressed immediately",
            "   - Medium findings within 30 days",
            "   - Low findings within 90 days",
            "",
            "Priority: HIGH - Vulnerability scanning is critical for security",
            "Effort: Low - Can be enabled in minutes, ongoing effort for remediation",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/inspector/latest/user/getting_started_tutorial.html"
        ]
