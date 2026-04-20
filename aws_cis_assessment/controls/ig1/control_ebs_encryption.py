"""
CIS Control 3.11 - EBS Encryption by Default
Ensures EBS encryption by default is enabled for data at rest protection.
"""

import logging
from typing import List, Dict, Any
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class EBSEncryptionByDefaultAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 3.11 - Encrypt Sensitive Data at Rest
    AWS Config Rule: ebs-encryption-by-default
    
    Ensures EBS encryption by default is enabled at the account level.
    When enabled, all new EBS volumes and snapshots are automatically encrypted,
    protecting data at rest without requiring manual configuration.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="ebs-encryption-by-default",
            control_id="3.11",
            resource_types=["AWS::::Account"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get EBS encryption by default status for the account in this region."""
        if resource_type != "AWS::::Account":
            return []
        
        try:
            ec2_client = aws_factory.get_client('ec2', region)
            
            # Get EBS encryption by default status
            response = ec2_client.get_ebs_encryption_by_default()
            encryption_enabled = response.get('EbsEncryptionByDefault', False)
            
            # Get default KMS key if encryption is enabled
            default_kms_key = None
            if encryption_enabled:
                try:
                    key_response = ec2_client.get_ebs_default_kms_key_id()
                    default_kms_key = key_response.get('KmsKeyId', '')
                except ClientError:
                    pass
            
            return [{
                'AccountId': aws_factory.get_account_info().get('account_id', 'unknown'),
                'Region': region,
                'EbsEncryptionByDefault': encryption_enabled,
                'DefaultKmsKeyId': default_kms_key
            }]
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'UnauthorizedOperation':
                logger.warning(f"Access denied to check EBS encryption by default in {region}")
            else:
                logger.error(f"Error checking EBS encryption by default in {region}: {e}")
            return []
    
    def _evaluate_resource_compliance(
        self, 
        resource: Dict[str, Any], 
        aws_factory: AWSClientFactory, 
        region: str
    ) -> ComplianceResult:
        """Evaluate if EBS encryption by default is enabled."""
        account_id = resource.get('AccountId', 'unknown')
        encryption_enabled = resource.get('EbsEncryptionByDefault', False)
        kms_key = resource.get('DefaultKmsKeyId', '')
        
        # Check if encryption by default is enabled
        is_compliant = encryption_enabled
        
        if is_compliant:
            if kms_key:
                evaluation_reason = (
                    f"EBS encryption by default is enabled in {region}. "
                    f"Default KMS key: {kms_key}"
                )
            else:
                evaluation_reason = (
                    f"EBS encryption by default is enabled in {region} "
                    f"using AWS managed key (aws/ebs)."
                )
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            evaluation_reason = f"EBS encryption by default is not enabled in {region}."
            compliance_status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceResult(
            resource_id=f"{account_id}-{region}",
            resource_type="AWS::::Account",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get remediation steps for enabling EBS encryption by default."""
        return [
            "1. Enable EBS encryption by default in the AWS Console:",
            "   - Navigate to EC2 service",
            "   - Click 'Account Attributes' in the left menu",
            "   - Click 'EBS encryption'",
            "   - Click 'Manage'",
            "   - Check 'Enable' for 'Always encrypt new EBS volumes'",
            "   - Optionally select a custom KMS key (recommended)",
            "   - Click 'Update EBS encryption'",
            "",
            "2. Enable using AWS CLI (with AWS managed key):",
            "   aws ec2 enable-ebs-encryption-by-default \\",
            "     --region <region>",
            "",
            "3. Enable using AWS CLI (with custom KMS key):",
            "   # First, enable encryption by default",
            "   aws ec2 enable-ebs-encryption-by-default \\",
            "     --region <region>",
            "",
            "   # Then, set the default KMS key",
            "   aws ec2 modify-ebs-default-kms-key-id \\",
            "     --kms-key-id <kms-key-id> \\",
            "     --region <region>",
            "",
            "4. Enable in all regions (recommended):",
            "   # Script to enable in all regions",
            "   for region in $(aws ec2 describe-regions --query 'Regions[].RegionName' --output text); do",
            "     echo \"Enabling EBS encryption in $region\"",
            "     aws ec2 enable-ebs-encryption-by-default --region $region",
            "   done",
            "",
            "5. Best practices:",
            "   - Enable in ALL regions where you use EC2",
            "   - Use customer-managed KMS keys for better control",
            "   - Set up KMS key rotation",
            "   - Grant appropriate IAM permissions for KMS key usage",
            "   - Document the KMS key used in each region",
            "",
            "6. Important notes:",
            "   - Only affects NEW volumes created after enabling",
            "   - Existing unencrypted volumes remain unencrypted",
            "   - To encrypt existing volumes:",
            "     * Create encrypted snapshot from unencrypted volume",
            "     * Create new encrypted volume from encrypted snapshot",
            "     * Replace the unencrypted volume",
            "   - No performance impact from encryption",
            "   - No additional cost for encryption (KMS key costs apply)",
            "",
            "7. Verify encryption is working:",
            "   # Create a test volume",
            "   aws ec2 create-volume \\",
            "     --availability-zone <az> \\",
            "     --size 1 \\",
            "     --region <region>",
            "",
            "   # Check if it's encrypted",
            "   aws ec2 describe-volumes \\",
            "     --volume-ids <volume-id> \\",
            "     --query 'Volumes[0].Encrypted' \\",
            "     --region <region>",
            "",
            "Priority: HIGH - Data at rest encryption is critical for compliance",
            "Effort: Very Low - Can be enabled in seconds per region",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html"
        ]
