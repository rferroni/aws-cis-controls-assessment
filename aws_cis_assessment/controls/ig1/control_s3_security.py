"""
CIS Control 3.3 - S3 Security Controls
Critical S3 security rules for data protection and access control.
"""

import logging
from typing import List, Dict, Any, Optional
import boto3
import json
from botocore.exceptions import ClientError, NoCredentialsError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class S3BucketSSLRequestsOnlyAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 3.3 - Configure Data Access Control Lists
    AWS Config Rule: s3-bucket-ssl-requests-only
    
    Ensures S3 buckets require SSL/TLS for all requests to protect data in transit.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="s3-bucket-ssl-requests-only",
            control_id="3.3",
            resource_types=["AWS::S3::Bucket"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all S3 buckets (only from us-east-1 to avoid duplicates)."""
        if resource_type != "AWS::S3::Bucket":
            return []
        
        # S3 is global, only check from us-east-1 to avoid duplicate checks
        if region != 'us-east-1':
            return []
        
        try:
            s3_client = aws_factory.get_client('s3', region)
            
            response = s3_client.list_buckets()
            buckets = []
            
            for bucket in response.get('Buckets', []):
                bucket_name = bucket['Name']
                
                try:
                    # Get bucket policy to check for SSL enforcement
                    has_ssl_policy = False
                    ssl_policy_statements = []
                    
                    try:
                        policy_response = s3_client.get_bucket_policy(Bucket=bucket_name)
                        policy_doc = json.loads(policy_response['Policy'])
                        statements = policy_doc.get('Statement', [])
                        
                        for statement in statements:
                            if isinstance(statement, dict):
                                effect = statement.get('Effect', '')
                                condition = statement.get('Condition', {})
                                
                                # Check for SSL enforcement conditions
                                if effect == 'Deny':
                                    # Check for aws:SecureTransport condition
                                    bool_conditions = condition.get('Bool', {})
                                    if 'aws:SecureTransport' in bool_conditions:
                                        secure_transport = bool_conditions['aws:SecureTransport']
                                        if secure_transport == 'false' or secure_transport is False:
                                            has_ssl_policy = True
                                            ssl_policy_statements.append(statement)
                    
                    except ClientError as e:
                        if e.response.get('Error', {}).get('Code') != 'NoSuchBucketPolicy':
                            raise e
                    
                    buckets.append({
                        'BucketName': bucket_name,
                        'HasSSLPolicy': has_ssl_policy,
                        'SSLPolicyStatements': ssl_policy_statements
                    })
                
                except ClientError as e:
                    error_code = e.response.get('Error', {}).get('Code', '')
                    if error_code in ['NoSuchBucket', 'AccessDenied']:
                        continue
                    else:
                        logger.warning(f"Error checking S3 bucket {bucket_name}: {e}")
                        continue
            
            logger.debug(f"Found {len(buckets)} S3 buckets from {region}")
            return buckets
            
        except ClientError as e:
            logger.error(f"Error retrieving S3 buckets from {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving S3 buckets from {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if S3 bucket requires SSL/TLS for requests."""
        bucket_name = resource.get('BucketName', 'unknown')
        has_ssl_policy = resource.get('HasSSLPolicy', False)
        
        if has_ssl_policy:
            return ComplianceResult(
                resource_id=bucket_name,
                resource_type="AWS::S3::Bucket",
                compliance_status=ComplianceStatus.COMPLIANT,
                evaluation_reason="S3 bucket has policy requiring SSL/TLS for requests",
                config_rule_name=self.rule_name,
                region=region
            )
        else:
            return ComplianceResult(
                resource_id=bucket_name,
                resource_type="AWS::S3::Bucket",
                compliance_status=ComplianceStatus.NON_COMPLIANT,
                evaluation_reason="S3 bucket does not require SSL/TLS for requests",
                config_rule_name=self.rule_name,
                region=region
            )


class S3BucketServerSideEncryptionEnabledAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 3.3 - Configure Data Access Control Lists
    AWS Config Rule: s3-bucket-server-side-encryption-enabled
    
    Ensures S3 buckets have server-side encryption enabled to protect data at rest.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="s3-bucket-server-side-encryption-enabled",
            control_id="3.3",
            resource_types=["AWS::S3::Bucket"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all S3 buckets with encryption configuration."""
        if resource_type != "AWS::S3::Bucket":
            return []
        
        # S3 is global, only check from us-east-1 to avoid duplicate checks
        if region != 'us-east-1':
            return []
        
        try:
            s3_client = aws_factory.get_client('s3', region)
            
            response = s3_client.list_buckets()
            buckets = []
            
            for bucket in response.get('Buckets', []):
                bucket_name = bucket['Name']
                
                try:
                    # Get bucket encryption configuration
                    has_encryption = False
                    encryption_rules = []
                    
                    try:
                        encryption_response = s3_client.get_bucket_encryption(Bucket=bucket_name)
                        encryption_config = encryption_response.get('ServerSideEncryptionConfiguration', {})
                        rules = encryption_config.get('Rules', [])
                        
                        if rules:
                            has_encryption = True
                            for rule in rules:
                                sse_algorithm = rule.get('ApplyServerSideEncryptionByDefault', {}).get('SSEAlgorithm', '')
                                kms_key_id = rule.get('ApplyServerSideEncryptionByDefault', {}).get('KMSMasterKeyID', '')
                                encryption_rules.append({
                                    'SSEAlgorithm': sse_algorithm,
                                    'KMSMasterKeyID': kms_key_id
                                })
                    
                    except ClientError as e:
                        if e.response.get('Error', {}).get('Code') != 'ServerSideEncryptionConfigurationNotFoundError':
                            raise e
                    
                    buckets.append({
                        'BucketName': bucket_name,
                        'HasEncryption': has_encryption,
                        'EncryptionRules': encryption_rules
                    })
                
                except ClientError as e:
                    error_code = e.response.get('Error', {}).get('Code', '')
                    if error_code in ['NoSuchBucket', 'AccessDenied']:
                        continue
                    else:
                        logger.warning(f"Error checking S3 bucket {bucket_name}: {e}")
                        continue
            
            logger.debug(f"Found {len(buckets)} S3 buckets from {region}")
            return buckets
            
        except ClientError as e:
            logger.error(f"Error retrieving S3 buckets from {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving S3 buckets from {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if S3 bucket has server-side encryption enabled."""
        bucket_name = resource.get('BucketName', 'unknown')
        has_encryption = resource.get('HasEncryption', False)
        encryption_rules = resource.get('EncryptionRules', [])
        
        if has_encryption:
            encryption_details = []
            for rule in encryption_rules:
                algorithm = rule.get('SSEAlgorithm', 'Unknown')
                encryption_details.append(algorithm)
            
            return ComplianceResult(
                resource_id=bucket_name,
                resource_type="AWS::S3::Bucket",
                compliance_status=ComplianceStatus.COMPLIANT,
                evaluation_reason=f"S3 bucket has server-side encryption enabled: {', '.join(encryption_details)}",
                config_rule_name=self.rule_name,
                region=region
            )
        else:
            return ComplianceResult(
                resource_id=bucket_name,
                resource_type="AWS::S3::Bucket",
                compliance_status=ComplianceStatus.NON_COMPLIANT,
                evaluation_reason="S3 bucket does not have server-side encryption enabled",
                config_rule_name=self.rule_name,
                region=region
            )


class S3BucketLoggingEnabledAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 3.3 - Configure Data Access Control Lists
    AWS Config Rule: s3-bucket-logging-enabled
    
    Ensures S3 buckets have access logging enabled for audit and compliance.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="s3-bucket-logging-enabled",
            control_id="3.3",
            resource_types=["AWS::S3::Bucket"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all S3 buckets with logging configuration."""
        if resource_type != "AWS::S3::Bucket":
            return []
        
        # S3 is global, only check from us-east-1 to avoid duplicate checks
        if region != 'us-east-1':
            return []
        
        try:
            s3_client = aws_factory.get_client('s3', region)
            
            response = s3_client.list_buckets()
            buckets = []
            
            for bucket in response.get('Buckets', []):
                bucket_name = bucket['Name']
                
                try:
                    # Get bucket logging configuration
                    logging_response = s3_client.get_bucket_logging(Bucket=bucket_name)
                    logging_config = logging_response.get('LoggingEnabled', {})
                    
                    has_logging = bool(logging_config)
                    target_bucket = logging_config.get('TargetBucket', '') if has_logging else ''
                    target_prefix = logging_config.get('TargetPrefix', '') if has_logging else ''
                    
                    buckets.append({
                        'BucketName': bucket_name,
                        'HasLogging': has_logging,
                        'TargetBucket': target_bucket,
                        'TargetPrefix': target_prefix
                    })
                
                except ClientError as e:
                    error_code = e.response.get('Error', {}).get('Code', '')
                    if error_code in ['NoSuchBucket', 'AccessDenied']:
                        continue
                    else:
                        logger.warning(f"Error checking S3 bucket {bucket_name}: {e}")
                        continue
            
            logger.debug(f"Found {len(buckets)} S3 buckets from {region}")
            return buckets
            
        except ClientError as e:
            logger.error(f"Error retrieving S3 buckets from {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving S3 buckets from {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if S3 bucket has access logging enabled."""
        bucket_name = resource.get('BucketName', 'unknown')
        has_logging = resource.get('HasLogging', False)
        target_bucket = resource.get('TargetBucket', '')
        
        if has_logging:
            return ComplianceResult(
                resource_id=bucket_name,
                resource_type="AWS::S3::Bucket",
                compliance_status=ComplianceStatus.COMPLIANT,
                evaluation_reason=f"S3 bucket has access logging enabled (target: {target_bucket})",
                config_rule_name=self.rule_name,
                region=region
            )
        else:
            return ComplianceResult(
                resource_id=bucket_name,
                resource_type="AWS::S3::Bucket",
                compliance_status=ComplianceStatus.NON_COMPLIANT,
                evaluation_reason="S3 bucket does not have access logging enabled",
                config_rule_name=self.rule_name,
                region=region
            )


class S3BucketVersioningEnabledAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 3.4 - Enforce Data Retention
    AWS Config Rule: s3-bucket-versioning-enabled
    
    Ensures S3 buckets have versioning enabled for data protection and recovery.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="s3-bucket-versioning-enabled",
            control_id="3.4",
            resource_types=["AWS::S3::Bucket"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all S3 buckets with versioning configuration."""
        if resource_type != "AWS::S3::Bucket":
            return []
        
        # S3 is global, only check from us-east-1 to avoid duplicate checks
        if region != 'us-east-1':
            return []
        
        try:
            s3_client = aws_factory.get_client('s3', region)
            
            response = s3_client.list_buckets()
            buckets = []
            
            for bucket in response.get('Buckets', []):
                bucket_name = bucket['Name']
                
                try:
                    # Get bucket versioning configuration
                    versioning_response = s3_client.get_bucket_versioning(Bucket=bucket_name)
                    versioning_status = versioning_response.get('Status', 'Disabled')
                    mfa_delete = versioning_response.get('MfaDelete', 'Disabled')
                    
                    buckets.append({
                        'BucketName': bucket_name,
                        'VersioningStatus': versioning_status,
                        'MfaDelete': mfa_delete,
                        'IsVersioningEnabled': versioning_status == 'Enabled'
                    })
                
                except ClientError as e:
                    error_code = e.response.get('Error', {}).get('Code', '')
                    if error_code in ['NoSuchBucket', 'AccessDenied']:
                        continue
                    else:
                        logger.warning(f"Error checking S3 bucket {bucket_name}: {e}")
                        continue
            
            logger.debug(f"Found {len(buckets)} S3 buckets from {region}")
            return buckets
            
        except ClientError as e:
            logger.error(f"Error retrieving S3 buckets from {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving S3 buckets from {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if S3 bucket has versioning enabled."""
        bucket_name = resource.get('BucketName', 'unknown')
        versioning_status = resource.get('VersioningStatus', 'Disabled')
        is_versioning_enabled = resource.get('IsVersioningEnabled', False)
        
        if is_versioning_enabled:
            return ComplianceResult(
                resource_id=bucket_name,
                resource_type="AWS::S3::Bucket",
                compliance_status=ComplianceStatus.COMPLIANT,
                evaluation_reason=f"S3 bucket has versioning enabled (status: {versioning_status})",
                config_rule_name=self.rule_name,
                region=region
            )
        else:
            return ComplianceResult(
                resource_id=bucket_name,
                resource_type="AWS::S3::Bucket",
                compliance_status=ComplianceStatus.NON_COMPLIANT,
                evaluation_reason=f"S3 bucket does not have versioning enabled (status: {versioning_status})",
                config_rule_name=self.rule_name,
                region=region
            )