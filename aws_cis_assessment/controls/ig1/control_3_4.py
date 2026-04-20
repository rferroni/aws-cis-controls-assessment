"""Control 3.4: Enforce Data Retention assessments."""

from typing import Dict, List, Any
import logging
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class S3VersionLifecyclePolicyAssessment(BaseConfigRuleAssessment):
    """Assessment for s3-version-lifecycle-policy-check Config rule."""
    
    def __init__(self):
        """Initialize S3 version lifecycle policy assessment."""
        super().__init__(
            rule_name="s3-version-lifecycle-policy-check",
            control_id="3.4",
            resource_types=["AWS::S3::Bucket"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all S3 buckets."""
        if resource_type != "AWS::S3::Bucket":
            return []
        
        try:
            s3_client = aws_factory.get_client('s3', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: s3_client.list_buckets()
            )
            
            buckets = []
            for bucket in response.get('Buckets', []):
                bucket_name = bucket.get('Name')
                
                # Check if bucket is in the current region
                try:
                    bucket_location = aws_factory.aws_api_call_with_retry(
                        lambda: s3_client.get_bucket_location(Bucket=bucket_name)
                    )
                    bucket_region = bucket_location.get('LocationConstraint') or 'us-east-1'
                    
                    if bucket_region == region or (region == 'us-east-1' and bucket_region is None):
                        buckets.append({
                            'BucketName': bucket_name,
                            'CreationDate': bucket.get('CreationDate')
                        })
                except ClientError as e:
                    # Skip buckets we can't access
                    logger.debug(f"Cannot access bucket {bucket_name}: {e}")
                    continue
            
            logger.debug(f"Found {len(buckets)} S3 buckets in region {region}")
            return buckets
            
        except ClientError as e:
            logger.error(f"Error retrieving S3 buckets: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving S3 buckets: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if S3 bucket has lifecycle policy configured."""
        bucket_name = resource.get('BucketName', 'unknown')
        
        try:
            s3_client = aws_factory.get_client('s3', region)
            
            # Check if bucket has lifecycle configuration
            try:
                lifecycle_response = aws_factory.aws_api_call_with_retry(
                    lambda: s3_client.get_bucket_lifecycle_configuration(Bucket=bucket_name)
                )
                
                rules = lifecycle_response.get('Rules', [])
                
                # Check if there are any lifecycle rules
                if rules:
                    # Check for versioning-related rules
                    has_version_rules = False
                    rule_details = []
                    
                    for rule in rules:
                        if rule.get('Status') == 'Enabled':
                            rule_id = rule.get('Id', 'unnamed')
                            rule_details.append(rule_id)
                            
                            # Check for noncurrent version transitions or expiration
                            if (rule.get('NoncurrentVersionTransitions') or 
                                rule.get('NoncurrentVersionExpiration')):
                                has_version_rules = True
                    
                    if has_version_rules:
                        compliance_status = ComplianceStatus.COMPLIANT
                        evaluation_reason = f"Bucket {bucket_name} has lifecycle policy with version management rules: {', '.join(rule_details)}"
                    else:
                        compliance_status = ComplianceStatus.NON_COMPLIANT
                        evaluation_reason = f"Bucket {bucket_name} has lifecycle policy but no version management rules"
                else:
                    compliance_status = ComplianceStatus.NON_COMPLIANT
                    evaluation_reason = f"Bucket {bucket_name} has no enabled lifecycle rules"
                    
            except ClientError as lifecycle_error:
                if lifecycle_error.response.get('Error', {}).get('Code') == 'NoSuchLifecycleConfiguration':
                    compliance_status = ComplianceStatus.NON_COMPLIANT
                    evaluation_reason = f"Bucket {bucket_name} has no lifecycle configuration"
                else:
                    raise lifecycle_error
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code in ['AccessDenied', 'NoSuchBucket']:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Cannot access bucket {bucket_name}: {error_code}"
            else:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Error checking lifecycle policy for bucket {bucket_name}: {str(e)}"
        except Exception as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Unexpected error checking lifecycle policy for bucket {bucket_name}: {str(e)}"
        
        return ComplianceResult(
            resource_id=bucket_name,
            resource_type="AWS::S3::Bucket",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for S3 lifecycle policies."""
        return [
            "Identify S3 buckets without lifecycle policies or version management rules",
            "For each bucket, configure appropriate lifecycle policies:",
            "  1. Go to the S3 console",
            "  2. Select the bucket",
            "  3. Go to Management > Lifecycle rules",
            "  4. Create a new lifecycle rule",
            "  5. Configure transitions for current and noncurrent versions",
            "  6. Set expiration policies for old versions",
            "Use AWS CLI: aws s3api put-bucket-lifecycle-configuration",
            "Consider cost optimization by transitioning old versions to cheaper storage classes",
            "Set up monitoring for lifecycle rule effectiveness"
        ]


class CloudWatchLogGroupRetentionAssessment(BaseConfigRuleAssessment):
    """Assessment for cw-loggroup-retention-period-check Config rule."""
    
    def __init__(self, min_retention_days: int = 30):
        """Initialize CloudWatch log group retention assessment."""
        super().__init__(
            rule_name="cw-loggroup-retention-period-check",
            control_id="3.4",
            resource_types=["AWS::Logs::LogGroup"],
            parameters={"minRetentionTime": min_retention_days}
        )
        self.min_retention_days = min_retention_days
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all CloudWatch log groups in the region."""
        if resource_type != "AWS::Logs::LogGroup":
            return []
        
        try:
            logs_client = aws_factory.get_client('logs', region)
            
            log_groups = []
            paginator = logs_client.get_paginator('describe_log_groups')
            
            for page in paginator.paginate():
                for log_group in page.get('logGroups', []):
                    log_groups.append({
                        'LogGroupName': log_group.get('logGroupName'),
                        'RetentionInDays': log_group.get('retentionInDays'),
                        'CreationTime': log_group.get('creationTime'),
                        'StoredBytes': log_group.get('storedBytes', 0)
                    })
            
            logger.debug(f"Found {len(log_groups)} CloudWatch log groups in region {region}")
            return log_groups
            
        except ClientError as e:
            logger.error(f"Error retrieving CloudWatch log groups in region {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving CloudWatch log groups in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if CloudWatch log group has appropriate retention period."""
        log_group_name = resource.get('LogGroupName', 'unknown')
        retention_days = resource.get('RetentionInDays')
        
        if retention_days is None:
            # No retention policy means logs are kept indefinitely
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = f"Log group {log_group_name} has no retention policy (logs kept indefinitely)"
        elif retention_days >= self.min_retention_days:
            compliance_status = ComplianceStatus.COMPLIANT
            evaluation_reason = f"Log group {log_group_name} has {retention_days} days retention (meets minimum {self.min_retention_days} days)"
        else:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = f"Log group {log_group_name} has {retention_days} days retention (below minimum {self.min_retention_days} days)"
        
        return ComplianceResult(
            resource_id=log_group_name,
            resource_type="AWS::Logs::LogGroup",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for CloudWatch log group retention."""
        return [
            f"Identify CloudWatch log groups without retention policies or with retention below {self.min_retention_days} days",
            "For each log group, set appropriate retention period:",
            "  1. Go to the CloudWatch console",
            "  2. Navigate to Logs > Log groups",
            "  3. Select the log group",
            "  4. Go to Actions > Edit retention setting",
            "  5. Set retention period based on compliance requirements",
            f"Use AWS CLI: aws logs put-retention-policy --log-group-name <name> --retention-in-days {self.min_retention_days}",
            "Consider cost implications of longer retention periods",
            "Set up automated retention policy management for new log groups"
        ]