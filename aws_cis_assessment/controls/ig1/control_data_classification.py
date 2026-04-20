"""
CIS Control 3.12 - Data Classification
Ensures proper data classification tagging across AWS resources.
"""

import logging
from typing import List, Dict, Any
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class DataClassificationTaggingAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 3.12 - Segment Data Processing and Storage Based on Sensitivity
    AWS Config Rule: data-classification-tagging
    
    Ensures data resources have proper classification tags.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="data-classification-tagging",
            control_id="3.12",
            resource_types=["AWS::RDS::DBInstance", "AWS::DynamoDB::Table"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get data resources and check for classification tags."""
        resources = []
        
        try:
            if resource_type == "AWS::RDS::DBInstance":
                rds_client = aws_factory.get_client('rds', region)
                response = rds_client.describe_db_instances()
                
                for db in response.get('DBInstances', []):
                    tags = {tag['Key']: tag['Value'] for tag in db.get('TagList', [])}
                    
                    has_classification = bool(
                        tags.get('DataClassification') or 
                        tags.get('Sensitivity') or
                        tags.get('Compliance')
                    )
                    
                    resources.append({
                        'ResourceId': db.get('DBInstanceIdentifier'),
                        'ResourceType': 'AWS::RDS::DBInstance',
                        'Tags': tags,
                        'HasClassification': has_classification
                    })
            
            elif resource_type == "AWS::DynamoDB::Table":
                dynamodb_client = aws_factory.get_client('dynamodb', region)
                response = dynamodb_client.list_tables()
                
                for table_name in response.get('TableNames', []):
                    try:
                        table_arn = f"arn:aws:dynamodb:{region}:*:table/{table_name}"
                        tags_response = dynamodb_client.list_tags_of_resource(ResourceArn=table_arn)
                        tags = {tag['Key']: tag['Value'] for tag in tags_response.get('Tags', [])}
                        
                        has_classification = bool(
                            tags.get('DataClassification') or 
                            tags.get('Sensitivity') or
                            tags.get('Compliance')
                        )
                        
                        resources.append({
                            'ResourceId': table_name,
                            'ResourceType': 'AWS::DynamoDB::Table',
                            'Tags': tags,
                            'HasClassification': has_classification
                        })
                    except ClientError:
                        continue
            
            return resources
            
        except ClientError as e:
            logger.error(f"Error retrieving {resource_type} in {region}: {e}")
            return []
    
    def _evaluate_resource_compliance(
        self, 
        resource: Dict[str, Any], 
        aws_factory: AWSClientFactory, 
        region: str
    ) -> ComplianceResult:
        """Evaluate if resource has classification tags."""
        resource_id = resource.get('ResourceId', 'unknown')
        resource_type = resource.get('ResourceType', 'Unknown')
        has_classification = resource.get('HasClassification', False)
        
        if has_classification:
            evaluation_reason = f"Resource {resource_id} has data classification tags"
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            evaluation_reason = f"Resource {resource_id} missing classification tags (DataClassification, Sensitivity, or Compliance)"
            compliance_status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceResult(
            resource_id=resource_id,
            resource_type=resource_type,
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get remediation steps for data classification tagging."""
        return [
            "1. Tag RDS instance with classification:",
            "   aws rds add-tags-to-resource \\",
            "     --resource-name <db-arn> \\",
            "     --tags Key=DataClassification,Value=confidential \\",
            "            Key=Sensitivity,Value=high \\",
            "            Key=Compliance,Value=pci-dss",
            "",
            "2. Tag DynamoDB table:",
            "   aws dynamodb tag-resource \\",
            "     --resource-arn <table-arn> \\",
            "     --tags Key=DataClassification,Value=confidential",
            "",
            "3. Recommended classification levels:",
            "   - Public: Non-sensitive data",
            "   - Internal: Internal use only",
            "   - Confidential: Sensitive business data",
            "   - Restricted: Highly sensitive (PII, PHI, PCI)",
            "",
            "Priority: HIGH - Critical for data governance",
            "Effort: Low - Simple tagging operation",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/general/latest/gr/aws_tagging.html"
        ]


class S3BucketClassificationTagsAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 3.12 - Segment Data Processing and Storage Based on Sensitivity
    AWS Config Rule: s3-bucket-classification-tags
    
    Ensures S3 buckets have proper data classification tags.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="s3-bucket-classification-tags",
            control_id="3.12",
            resource_types=["AWS::S3::Bucket"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get S3 buckets and check for classification tags."""
        if resource_type != "AWS::S3::Bucket":
            return []
        
        # S3 is global, only process in us-east-1
        if region != 'us-east-1':
            return []
        
        try:
            s3_client = aws_factory.get_client('s3', region)
            
            response = s3_client.list_buckets()
            buckets = []
            
            for bucket in response.get('Buckets', []):
                bucket_name = bucket.get('Name')
                
                try:
                    tags_response = s3_client.get_bucket_tagging(Bucket=bucket_name)
                    tags = {tag['Key']: tag['Value'] for tag in tags_response.get('TagSet', [])}
                except ClientError as e:
                    if e.response.get('Error', {}).get('Code') == 'NoSuchTagSet':
                        tags = {}
                    else:
                        continue
                
                has_classification = bool(
                    tags.get('DataClassification') or 
                    tags.get('Sensitivity') or
                    tags.get('Compliance')
                )
                
                buckets.append({
                    'BucketName': bucket_name,
                    'Tags': tags,
                    'HasClassification': has_classification
                })
            
            return buckets
            
        except ClientError as e:
            logger.error(f"Error retrieving S3 buckets: {e}")
            return []
    
    def _evaluate_resource_compliance(
        self, 
        resource: Dict[str, Any], 
        aws_factory: AWSClientFactory, 
        region: str
    ) -> ComplianceResult:
        """Evaluate if S3 bucket has classification tags."""
        bucket_name = resource.get('BucketName', 'unknown')
        has_classification = resource.get('HasClassification', False)
        
        if has_classification:
            evaluation_reason = f"S3 bucket '{bucket_name}' has data classification tags"
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            evaluation_reason = f"S3 bucket '{bucket_name}' missing classification tags (DataClassification, Sensitivity, or Compliance)"
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
        """Get remediation steps for S3 bucket classification."""
        return [
            "1. Tag S3 bucket with classification:",
            "   aws s3api put-bucket-tagging \\",
            "     --bucket <bucket-name> \\",
            "     --tagging 'TagSet=[{Key=DataClassification,Value=confidential},{Key=Sensitivity,Value=high}]'",
            "",
            "2. Tag multiple buckets (script):",
            "   for bucket in $(aws s3api list-buckets --query 'Buckets[].Name' --output text); do",
            "     aws s3api put-bucket-tagging --bucket $bucket \\",
            "       --tagging 'TagSet=[{Key=DataClassification,Value=internal}]'",
            "   done",
            "",
            "3. Classification guidelines:",
            "   - Public: Publicly accessible data",
            "   - Internal: Internal business data",
            "   - Confidential: Sensitive business information",
            "   - Restricted: Regulated data (PII, PHI, PCI, etc.)",
            "",
            "Priority: HIGH - Essential for data governance",
            "Effort: Low - Simple tagging",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-tagging.html"
        ]
