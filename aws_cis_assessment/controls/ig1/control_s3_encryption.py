"""
CIS Control 3.11 - S3 Default Encryption with KMS
Ensures S3 buckets have default encryption enabled with customer-managed KMS keys for data at rest protection.
"""

import logging
from typing import List, Dict, Any
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class S3DefaultEncryptionKMSAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 3.11 - Encrypt Sensitive Data at Rest
    AWS Config Rule: s3-default-encryption-kms
    
    Ensures S3 buckets have default encryption enabled with customer-managed KMS keys.
    While SSE-S3 provides encryption, using customer-managed KMS keys provides
    better control, auditability, and compliance capabilities.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="s3-default-encryption-kms",
            control_id="3.11",
            resource_types=["AWS::S3::Bucket"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all S3 buckets and their encryption configuration."""
        if resource_type != "AWS::S3::Bucket":
            return []
        
        try:
            # S3 is a global service, but we only want to list buckets once
            # Only process in us-east-1 to avoid duplicate evaluations
            if region != 'us-east-1':
                return []
            
            s3_client = aws_factory.get_client('s3', region)
            
            buckets = []
            
            # List all buckets
            response = s3_client.list_buckets()
            bucket_list = response.get('Buckets', [])
            
            # Get encryption configuration for each bucket
            for bucket in bucket_list:
                bucket_name = bucket.get('Name', '')
                
                try:
                    # Get bucket encryption configuration
                    try:
                        encryption_response = s3_client.get_bucket_encryption(Bucket=bucket_name)
                        rules = encryption_response.get('ServerSideEncryptionConfiguration', {}).get('Rules', [])
                        
                        if rules:
                            # Get the first rule (typically only one)
                            rule = rules[0]
                            sse_algorithm = rule.get('ApplyServerSideEncryptionByDefault', {}).get('SSEAlgorithm', '')
                            kms_key_id = rule.get('ApplyServerSideEncryptionByDefault', {}).get('KMSMasterKeyID', '')
                            bucket_key_enabled = rule.get('BucketKeyEnabled', False)
                            
                            # Determine encryption type
                            if sse_algorithm == 'aws:kms':
                                encryption_type = 'KMS'
                                encrypted_with_kms = True
                            elif sse_algorithm == 'AES256':
                                encryption_type = 'SSE-S3'
                                encrypted_with_kms = False
                            else:
                                encryption_type = sse_algorithm
                                encrypted_with_kms = False
                        else:
                            encryption_type = 'NONE'
                            encrypted_with_kms = False
                            kms_key_id = ''
                            bucket_key_enabled = False
                    
                    except ClientError as e:
                        error_code = e.response.get('Error', {}).get('Code', '')
                        if error_code == 'ServerSideEncryptionConfigurationNotFoundError':
                            # No encryption configured
                            encryption_type = 'NONE'
                            encrypted_with_kms = False
                            kms_key_id = ''
                            bucket_key_enabled = False
                        else:
                            # Access denied or other error
                            logger.warning(f"Error getting encryption for bucket {bucket_name}: {e}")
                            continue
                    
                    # Get bucket location
                    try:
                        location_response = s3_client.get_bucket_location(Bucket=bucket_name)
                        bucket_region = location_response.get('LocationConstraint') or 'us-east-1'
                    except ClientError:
                        bucket_region = 'unknown'
                    
                    buckets.append({
                        'BucketName': bucket_name,
                        'EncryptionType': encryption_type,
                        'EncryptedWithKMS': encrypted_with_kms,
                        'KMSMasterKeyID': kms_key_id,
                        'BucketKeyEnabled': bucket_key_enabled,
                        'BucketRegion': bucket_region,
                        'CreationDate': bucket.get('CreationDate', '')
                    })
                    
                except ClientError as e:
                    error_code = e.response.get('Error', {}).get('Code', '')
                    if error_code in ['NoSuchBucket', 'AccessDenied']:
                        logger.debug(f"Cannot access bucket {bucket_name}: {error_code}")
                    else:
                        logger.warning(f"Error processing bucket {bucket_name}: {e}")
                    continue
            
            logger.debug(f"Found {len(buckets)} S3 buckets")
            return buckets
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'AccessDenied':
                logger.warning(f"Access denied to list S3 buckets")
            else:
                logger.error(f"Error retrieving S3 buckets: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error retrieving S3 buckets: {e}")
            return []
    
    def _evaluate_resource_compliance(
        self, 
        resource: Dict[str, Any], 
        aws_factory: AWSClientFactory, 
        region: str
    ) -> ComplianceResult:
        """Evaluate if S3 bucket has default encryption enabled with KMS."""
        bucket_name = resource.get('BucketName', 'unknown')
        encrypted_with_kms = resource.get('EncryptedWithKMS', False)
        encryption_type = resource.get('EncryptionType', 'NONE')
        kms_key_id = resource.get('KMSMasterKeyID', '')
        bucket_key_enabled = resource.get('BucketKeyEnabled', False)
        bucket_region = resource.get('BucketRegion', 'unknown')
        
        # Check if bucket is encrypted with customer-managed KMS key
        is_compliant = encrypted_with_kms
        
        if is_compliant:
            bucket_key_info = " (S3 Bucket Key enabled)" if bucket_key_enabled else ""
            if kms_key_id:
                evaluation_reason = (
                    f"S3 bucket '{bucket_name}' (region: {bucket_region}) has default encryption "
                    f"enabled with customer-managed KMS key: {kms_key_id}{bucket_key_info}"
                )
            else:
                evaluation_reason = (
                    f"S3 bucket '{bucket_name}' (region: {bucket_region}) has default encryption "
                    f"enabled with KMS{bucket_key_info}"
                )
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            if encryption_type == 'SSE-S3':
                evaluation_reason = (
                    f"S3 bucket '{bucket_name}' (region: {bucket_region}) is encrypted with SSE-S3 (AES256). "
                    f"Consider using customer-managed KMS keys for better control and auditability."
                )
            elif encryption_type == 'NONE':
                evaluation_reason = (
                    f"S3 bucket '{bucket_name}' (region: {bucket_region}) does not have default encryption enabled."
                )
            else:
                evaluation_reason = (
                    f"S3 bucket '{bucket_name}' (region: {bucket_region}) is not encrypted with "
                    f"customer-managed KMS key. Current encryption: {encryption_type}"
                )
            compliance_status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceResult(
            resource_id=bucket_name,
            resource_type="AWS::S3::Bucket",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get remediation steps for enabling S3 KMS encryption."""
        return [
            "1. Enable KMS encryption on an existing S3 bucket using AWS CLI:",
            "   aws s3api put-bucket-encryption \\",
            "     --bucket <bucket-name> \\",
            "     --server-side-encryption-configuration '{",
            '       "Rules": [{',
            '         "ApplyServerSideEncryptionByDefault": {',
            '           "SSEAlgorithm": "aws:kms",',
            '           "KMSMasterKeyID": "<kms-key-id>"',
            "         },",
            '         "BucketKeyEnabled": true',
            "       }]",
            "     }'",
            "",
            "2. Enable KMS encryption with S3 Bucket Key (recommended for cost savings):",
            "   # S3 Bucket Key reduces KMS API calls by up to 99%",
            "   aws s3api put-bucket-encryption \\",
            "     --bucket <bucket-name> \\",
            "     --server-side-encryption-configuration '{",
            '       "Rules": [{',
            '         "ApplyServerSideEncryptionByDefault": {',
            '           "SSEAlgorithm": "aws:kms",',
            '           "KMSMasterKeyID": "arn:aws:kms:<region>:<account-id>:key/<key-id>"',
            "         },",
            '         "BucketKeyEnabled": true',
            "       }]",
            "     }'",
            "",
            "3. Verify encryption configuration:",
            "   aws s3api get-bucket-encryption \\",
            "     --bucket <bucket-name>",
            "",
            "4. Console method:",
            "   - Navigate to S3 service",
            "   - Select the bucket",
            "   - Click 'Properties' tab",
            "   - Scroll to 'Default encryption'",
            "   - Click 'Edit'",
            "   - Select 'Server-side encryption with AWS Key Management Service keys (SSE-KMS)'",
            "   - Choose 'AWS KMS key'",
            "   - Select 'Choose from your AWS KMS keys' or 'Enter AWS KMS key ARN'",
            "   - Select or enter your KMS key",
            "   - Check 'Bucket Key' (recommended)",
            "   - Click 'Save changes'",
            "",
            "5. Create a customer-managed KMS key for S3 if you don't have one:",
            "   aws kms create-key \\",
            "     --description 'S3 bucket encryption key' \\",
            "     --key-policy file://s3-key-policy.json \\",
            "     --region <region>",
            "",
            "   # Create an alias for easier reference",
            "   aws kms create-alias \\",
            "     --alias-name alias/s3-encryption \\",
            "     --target-key-id <key-id> \\",
            "     --region <region>",
            "",
            "6. Example KMS key policy for S3 (s3-key-policy.json):",
            "   {",
            '     "Version": "2012-10-17",',
            '     "Statement": [',
            "       {",
            '         "Sid": "Enable IAM User Permissions",',
            '         "Effect": "Allow",',
            '         "Principal": {"AWS": "arn:aws:iam::<account-id>:root"},',
            '         "Action": "kms:*",',
            '         "Resource": "*"',
            "       },",
            "       {",
            '         "Sid": "Allow S3 to use the key",',
            '         "Effect": "Allow",',
            '         "Principal": {"Service": "s3.amazonaws.com"},',
            '         "Action": [',
            '           "kms:Decrypt",',
            '           "kms:GenerateDataKey"',
            "         ],",
            '         "Resource": "*"',
            "       },",
            "       {",
            '         "Sid": "Allow users to encrypt/decrypt objects",',
            '         "Effect": "Allow",',
            '         "Principal": {"AWS": "arn:aws:iam::<account-id>:root"},',
            '         "Action": [',
            '           "kms:Decrypt",',
            '           "kms:GenerateDataKey",',
            '           "kms:DescribeKey"',
            "         ],",
            '         "Resource": "*",',
            '         "Condition": {',
            '           "StringEquals": {',
            '             "kms:ViaService": "s3.<region>.amazonaws.com"',
            "           }",
            "         }",
            "       }",
            "     ]",
            "   }",
            "",
            "7. Enable encryption on multiple buckets (script):",
            "   #!/bin/bash",
            "   KMS_KEY_ID='<kms-key-id>'",
            "   ",
            "   # Get all bucket names",
            "   aws s3api list-buckets --query 'Buckets[].Name' --output text | \\",
            "   while read bucket; do",
            "     echo \"Enabling encryption on $bucket\"",
            "     aws s3api put-bucket-encryption \\",
            "       --bucket \"$bucket\" \\",
            "       --server-side-encryption-configuration '{",
            '         "Rules": [{',
            '           "ApplyServerSideEncryptionByDefault": {',
            '             "SSEAlgorithm": "aws:kms",',
            '             "KMSMasterKeyID": "'"$KMS_KEY_ID"'"',
            "           },",
            '           "BucketKeyEnabled": true',
            "         }]",
            "       }'",
            "   done",
            "",
            "8. Best practices:",
            "   - Use customer-managed KMS keys for all production buckets",
            "   - Enable S3 Bucket Key to reduce KMS costs (up to 99% reduction)",
            "   - Enable automatic key rotation for KMS keys",
            "   - Use separate KMS keys for different data classifications",
            "   - Grant appropriate IAM permissions for KMS key usage",
            "   - Document the KMS key used for each bucket",
            "   - Monitor KMS key usage with CloudWatch",
            "   - Set up CloudTrail logging for KMS key operations",
            "   - Consider using bucket policies to enforce encryption",
            "",
            "9. Enforce encryption with bucket policy (deny unencrypted uploads):",
            "   {",
            '     "Version": "2012-10-17",',
            '     "Statement": [{',
            '       "Sid": "DenyUnencryptedObjectUploads",',
            '       "Effect": "Deny",',
            '       "Principal": "*",',
            '       "Action": "s3:PutObject",',
            '       "Resource": "arn:aws:s3:::<bucket-name>/*",',
            '       "Condition": {',
            '         "StringNotEquals": {',
            '           "s3:x-amz-server-side-encryption": "aws:kms"',
            "         }",
            "       }",
            "     }]",
            "   }",
            "",
            "10. Important notes:",
            "    - Default encryption applies to NEW objects only",
            "    - Existing objects remain with their current encryption",
            "    - To encrypt existing objects, copy them in place:",
            "      aws s3 cp s3://<bucket>/ s3://<bucket>/ \\",
            "        --recursive \\",
            "        --sse aws:kms \\",
            "        --sse-kms-key-id <kms-key-id> \\",
            "        --metadata-directive REPLACE",
            "    - S3 Bucket Key significantly reduces KMS costs",
            "    - Performance impact is negligible",
            "    - KMS key must be in the same region as the bucket",
            "    - Cross-region replication can use different KMS keys",
            "",
            "11. Cost considerations:",
            "    - SSE-S3: No additional cost",
            "    - SSE-KMS without Bucket Key: $0.03 per 10,000 requests",
            "    - SSE-KMS with Bucket Key: Up to 99% cost reduction",
            "    - Customer-managed KMS keys: $1/month per key",
            "    - Always enable S3 Bucket Key to minimize costs",
            "",
            "12. Verify encryption after configuration:",
            "    # Check bucket encryption",
            "    aws s3api get-bucket-encryption \\",
            "      --bucket <bucket-name> \\",
            "      --query 'ServerSideEncryptionConfiguration.Rules[0]' \\",
            "      --output table",
            "",
            "    # Upload a test object and verify it's encrypted",
            "    echo 'test' > test.txt",
            "    aws s3 cp test.txt s3://<bucket-name>/",
            "    aws s3api head-object \\",
            "      --bucket <bucket-name> \\",
            "      --key test.txt \\",
            "      --query '{Encryption:ServerSideEncryption,KMSKeyId:SSEKMSKeyId}'",
            "",
            "Priority: HIGH - S3 encryption is critical for data protection and compliance",
            "Effort: Low - Can be enabled with a single API call, no downtime",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html"
        ]
