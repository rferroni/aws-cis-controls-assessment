"""Control 3.3: Configure Data Access Control Lists - S3 enhancements."""

from typing import Dict, List, Any
import logging
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class S3AccountLevelPublicAccessBlocksPeriodicAssessment(BaseConfigRuleAssessment):
    """Assessment for s3-account-level-public-access-blocks-periodic AWS Config rule."""
    
    def __init__(self):
        super().__init__(
            rule_name="s3-account-level-public-access-blocks-periodic",
            control_id="3.3",
            resource_types=["AWS::::Account"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get account-level resource for S3 public access block check."""
        if resource_type != "AWS::::Account":
            return []
            
        # Return a single account resource
        return [{'AccountId': aws_factory.account_id}]
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if account has S3 public access blocks configured."""
        account_id = resource.get('AccountId', 'unknown')
        
        try:
            s3control_client = aws_factory.get_client('s3control', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: s3control_client.get_public_access_block(AccountId=account_id)
            )
            
            config = response.get('PublicAccessBlockConfiguration', {})
            block_public_acls = config.get('BlockPublicAcls', False)
            ignore_public_acls = config.get('IgnorePublicAcls', False)
            block_public_policy = config.get('BlockPublicPolicy', False)
            restrict_public_buckets = config.get('RestrictPublicBuckets', False)
            
            if all([block_public_acls, ignore_public_acls, block_public_policy, restrict_public_buckets]):
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = f"Account {account_id} has all S3 public access blocks enabled"
            else:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                missing = []
                if not block_public_acls:
                    missing.append('BlockPublicAcls')
                if not ignore_public_acls:
                    missing.append('IgnorePublicAcls')
                if not block_public_policy:
                    missing.append('BlockPublicPolicy')
                if not restrict_public_buckets:
                    missing.append('RestrictPublicBuckets')
                evaluation_reason = f"Account {account_id} is missing S3 public access blocks: {', '.join(missing)}"
                
        except ClientError as e:
            if e.response.get('Error', {}).get('Code') == 'NoSuchPublicAccessBlockConfiguration':
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = f"Account {account_id} does not have S3 public access blocks configured"
            else:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Error checking S3 public access blocks for account {account_id}: {str(e)}"
        
        return ComplianceResult(
            resource_id=account_id,
            resource_type="AWS::::Account",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )


class S3BucketPublicWriteProhibitedAssessment(BaseConfigRuleAssessment):
    """Assessment for s3-bucket-public-write-prohibited AWS Config rule."""
    
    def __init__(self):
        super().__init__(
            rule_name="s3-bucket-public-write-prohibited",
            control_id="3.3",
            resource_types=["AWS::S3::Bucket"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get S3 buckets."""
        if resource_type != "AWS::S3::Bucket":
            return []
            
        try:
            s3_client = aws_factory.get_client('s3', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: s3_client.list_buckets()
            )
            
            buckets = []
            for bucket in response.get('Buckets', []):
                buckets.append({
                    'Name': bucket.get('Name'),
                    'CreationDate': bucket.get('CreationDate')
                })
            
            return buckets
            
        except ClientError as e:
            logger.error(f"Error retrieving S3 buckets: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if S3 bucket prohibits public write access."""
        bucket_name = resource.get('Name', 'unknown')
        
        try:
            s3_client = aws_factory.get_client('s3', region)
            
            # Check bucket ACL
            try:
                acl_response = aws_factory.aws_api_call_with_retry(
                    lambda: s3_client.get_bucket_acl(Bucket=bucket_name)
                )
                
                grants = acl_response.get('Grants', [])
                public_write_found = False
                
                for grant in grants:
                    grantee = grant.get('Grantee', {})
                    permission = grant.get('Permission', '')
                    
                    # Check for public write permissions
                    if (grantee.get('Type') == 'Group' and 
                        grantee.get('URI') in [
                            'http://acs.amazonaws.com/groups/global/AllUsers',
                            'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
                        ] and 
                        permission in ['WRITE', 'WRITE_ACP', 'FULL_CONTROL']):
                        public_write_found = True
                        break
                
                if not public_write_found:
                    compliance_status = ComplianceStatus.COMPLIANT
                    evaluation_reason = f"S3 bucket {bucket_name} does not allow public write access"
                else:
                    compliance_status = ComplianceStatus.NON_COMPLIANT
                    evaluation_reason = f"S3 bucket {bucket_name} allows public write access"
                    
            except ClientError as e:
                if e.response.get('Error', {}).get('Code') in ['AccessDenied', 'NoSuchBucket']:
                    compliance_status = ComplianceStatus.ERROR
                    evaluation_reason = f"Cannot access ACL for bucket {bucket_name}: {str(e)}"
                else:
                    raise
                    
        except ClientError as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Error checking public write access for bucket {bucket_name}: {str(e)}"
        
        return ComplianceResult(
            resource_id=bucket_name,
            resource_type="AWS::S3::Bucket",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )