"""
CIS Control 10.1 - GuardDuty Malware Defense
Ensures GuardDuty is enabled for threat detection and malware defense.
"""

import logging
from typing import List, Dict, Any
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class GuardDutyEnabledAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 6.2 - Establish and Maintain a Secure Network Architecture
    AWS Config Rule: guardduty-enabled-centralized
    
    Ensures GuardDuty is enabled for threat detection and malware defense.
    GuardDuty provides intelligent threat detection by analyzing VPC Flow Logs,
    CloudTrail events, and DNS logs to identify malicious activity.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="guardduty-enabled-centralized",
            control_id="6.2",
            resource_types=["AWS::GuardDuty::Detector"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get GuardDuty detector configuration for the region."""
        if resource_type != "AWS::GuardDuty::Detector":
            return []
        
        try:
            guardduty_client = aws_factory.get_client('guardduty', region)
            
            # List all detectors in the region
            response = guardduty_client.list_detectors()
            detector_ids = response.get('DetectorIds', [])
            
            if not detector_ids:
                # No detector found - return a placeholder resource for non-compliance
                return [{
                    'DetectorId': 'none',
                    'Status': 'DISABLED',
                    'Region': region,
                    'AccountId': aws_factory.get_account_info().get('account_id', 'unknown')
                }]
            
            # Get details for each detector
            detectors = []
            for detector_id in detector_ids:
                try:
                    detector_response = guardduty_client.get_detector(DetectorId=detector_id)
                    
                    detectors.append({
                        'DetectorId': detector_id,
                        'Status': detector_response.get('Status', 'UNKNOWN'),
                        'FindingPublishingFrequency': detector_response.get('FindingPublishingFrequency', 'UNKNOWN'),
                        'DataSources': detector_response.get('DataSources', {}),
                        'Region': region,
                        'AccountId': aws_factory.get_account_info().get('account_id', 'unknown')
                    })
                    
                except ClientError as e:
                    logger.warning(f"Error getting detector {detector_id} details: {e}")
                    continue
            
            return detectors if detectors else [{
                'DetectorId': 'none',
                'Status': 'DISABLED',
                'Region': region,
                'AccountId': aws_factory.get_account_info().get('account_id', 'unknown')
            }]
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'AccessDeniedException':
                logger.warning(f"Access denied to GuardDuty in {region}")
            else:
                logger.error(f"Error listing GuardDuty detectors in {region}: {e}")
            return []
    
    def _evaluate_resource_compliance(
        self, 
        resource: Dict[str, Any], 
        aws_factory: AWSClientFactory, 
        region: str
    ) -> ComplianceResult:
        """Evaluate if GuardDuty is enabled."""
        detector_id = resource.get('DetectorId', 'none')
        status = resource.get('Status', 'DISABLED')
        
        # Check if GuardDuty is enabled
        is_compliant = status == 'ENABLED'
        
        if is_compliant:
            evaluation_reason = (
                f"GuardDuty detector {detector_id} is enabled in {region}. "
                f"Finding publishing frequency: {resource.get('FindingPublishingFrequency', 'UNKNOWN')}"
            )
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            if detector_id == 'none':
                evaluation_reason = f"GuardDuty is not enabled in {region}. No detector found."
            else:
                evaluation_reason = f"GuardDuty detector {detector_id} is disabled in {region}."
            compliance_status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceResult(
            resource_id=detector_id,
            resource_type="AWS::GuardDuty::Detector",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get remediation steps for enabling GuardDuty."""
        return [
            "1. Enable GuardDuty in the AWS Console:",
            "   - Navigate to GuardDuty service",
            "   - Click 'Get Started' or 'Enable GuardDuty'",
            "   - Review and accept the service terms",
            "   - Click 'Enable GuardDuty'",
            "",
            "2. Enable GuardDuty using AWS CLI:",
            "   aws guardduty create-detector --enable --region <region>",
            "",
            "3. Configure finding publishing frequency (optional):",
            "   aws guardduty update-detector \\",
            "     --detector-id <detector-id> \\",
            "     --finding-publishing-frequency FIFTEEN_MINUTES \\",
            "     --region <region>",
            "",
            "4. Enable additional data sources (recommended):",
            "   - S3 Protection: Monitors S3 data events",
            "   - EKS Protection: Monitors Kubernetes audit logs",
            "   - Malware Protection: Scans EBS volumes",
            "",
            "5. Set up notifications:",
            "   - Create an SNS topic for GuardDuty findings",
            "   - Configure EventBridge rules to route findings",
            "",
            "Priority: HIGH - GuardDuty provides critical threat detection",
            "Effort: Low - Can be enabled in minutes",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_settingup.html"
        ]
