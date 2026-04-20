"""
CIS Control 3.11 - DynamoDB Table Encryption with KMS
Ensures DynamoDB tables are encrypted with customer-managed KMS keys for data at rest protection.
"""

import logging
from typing import List, Dict, Any
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class DynamoDBTableEncryptedKMSAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 3.11 - Encrypt Sensitive Data at Rest
    AWS Config Rule: dynamodb-table-encrypted-kms
    
    Ensures DynamoDB tables are encrypted with customer-managed KMS keys.
    While DynamoDB encrypts all tables by default with AWS owned keys,
    using customer-managed KMS keys provides better control and auditability.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="dynamodb-table-encrypted-kms",
            control_id="3.11",
            resource_types=["AWS::DynamoDB::Table"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all DynamoDB tables in the region."""
        if resource_type != "AWS::DynamoDB::Table":
            return []
        
        try:
            dynamodb_client = aws_factory.get_client('dynamodb', region)
            
            tables = []
            
            # List all tables
            paginator = dynamodb_client.get_paginator('list_tables')
            table_names = []
            
            for page in paginator.paginate():
                table_names.extend(page.get('TableNames', []))
            
            # Get details for each table
            for table_name in table_names:
                try:
                    response = dynamodb_client.describe_table(TableName=table_name)
                    table = response.get('Table', {})
                    
                    # Get SSE (Server-Side Encryption) description
                    sse_description = table.get('SSEDescription', {})
                    sse_status = sse_description.get('Status', 'DISABLED')
                    sse_type = sse_description.get('SSEType', '')
                    kms_key_arn = sse_description.get('KMSMasterKeyArn', '')
                    
                    # Determine encryption type
                    # SSEType can be: KMS (customer-managed), DEFAULT (AWS owned), or empty
                    if sse_status == 'ENABLED' and sse_type == 'KMS':
                        encryption_type = 'KMS'
                        encrypted_with_kms = True
                    elif sse_status == 'ENABLED':
                        # Default encryption with AWS owned keys
                        encryption_type = 'DEFAULT'
                        encrypted_with_kms = False
                    else:
                        # Older tables might not have SSE explicitly enabled
                        # but DynamoDB encrypts all tables by default with AWS owned keys
                        encryption_type = 'DEFAULT'
                        encrypted_with_kms = False
                    
                    tables.append({
                        'TableName': table_name,
                        'TableArn': table.get('TableArn', ''),
                        'TableStatus': table.get('TableStatus', ''),
                        'SSEStatus': sse_status,
                        'SSEType': sse_type,
                        'KMSMasterKeyArn': kms_key_arn,
                        'EncryptionType': encryption_type,
                        'EncryptedWithKMS': encrypted_with_kms,
                        'ItemCount': table.get('ItemCount', 0),
                        'TableSizeBytes': table.get('TableSizeBytes', 0)
                    })
                    
                except ClientError as e:
                    error_code = e.response.get('Error', {}).get('Code', '')
                    if error_code == 'ResourceNotFoundException':
                        logger.debug(f"Table {table_name} not found in {region} - may have been deleted")
                    else:
                        logger.warning(f"Error describing table {table_name}: {e}")
                    continue
            
            logger.debug(f"Found {len(tables)} DynamoDB tables in {region}")
            return tables
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'AccessDeniedException':
                logger.warning(f"Access denied to list DynamoDB tables in {region}")
            else:
                logger.error(f"Error retrieving DynamoDB tables from {region}: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error retrieving DynamoDB tables from {region}: {e}")
            return []
    
    def _evaluate_resource_compliance(
        self, 
        resource: Dict[str, Any], 
        aws_factory: AWSClientFactory, 
        region: str
    ) -> ComplianceResult:
        """Evaluate if DynamoDB table is encrypted with customer-managed KMS key."""
        table_name = resource.get('TableName', 'unknown')
        encrypted_with_kms = resource.get('EncryptedWithKMS', False)
        encryption_type = resource.get('EncryptionType', 'UNKNOWN')
        kms_key_arn = resource.get('KMSMasterKeyArn', '')
        table_status = resource.get('TableStatus', '')
        
        # Check if table is encrypted with customer-managed KMS key
        is_compliant = encrypted_with_kms
        
        if is_compliant:
            evaluation_reason = (
                f"DynamoDB table '{table_name}' is encrypted with customer-managed KMS key: "
                f"{kms_key_arn}"
            )
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            if encryption_type == 'DEFAULT':
                evaluation_reason = (
                    f"DynamoDB table '{table_name}' is encrypted with AWS owned keys (default encryption). "
                    f"Consider using customer-managed KMS keys for better control and auditability. "
                    f"Status: {table_status}"
                )
            else:
                evaluation_reason = (
                    f"DynamoDB table '{table_name}' is not encrypted with customer-managed KMS key. "
                    f"Encryption type: {encryption_type}. Status: {table_status}"
                )
            compliance_status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceResult(
            resource_id=table_name,
            resource_type="AWS::DynamoDB::Table",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get remediation steps for enabling DynamoDB KMS encryption."""
        return [
            "1. IMPORTANT: You CAN enable KMS encryption on an existing table.",
            "   However, this requires updating the table and may cause brief unavailability.",
            "",
            "2. Enable KMS encryption on an existing table using AWS CLI:",
            "   aws dynamodb update-table \\",
            "     --table-name <table-name> \\",
            "     --sse-specification Enabled=true,SSEType=KMS,KMSMasterKeyId=<kms-key-id> \\",
            "     --region <region>",
            "",
            "3. Wait for the table update to complete:",
            "   aws dynamodb describe-table \\",
            "     --table-name <table-name> \\",
            "     --query 'Table.TableStatus' \\",
            "     --output text \\",
            "     --region <region>",
            "",
            "   # Status should be 'ACTIVE' when complete",
            "",
            "4. Verify KMS encryption is enabled:",
            "   aws dynamodb describe-table \\",
            "     --table-name <table-name> \\",
            "     --query 'Table.SSEDescription' \\",
            "     --region <region>",
            "",
            "5. For NEW tables, enable KMS encryption at creation:",
            "   aws dynamodb create-table \\",
            "     --table-name <table-name> \\",
            "     --attribute-definitions AttributeName=id,AttributeType=S \\",
            "     --key-schema AttributeName=id,KeyType=HASH \\",
            "     --billing-mode PAY_PER_REQUEST \\",
            "     --sse-specification Enabled=true,SSEType=KMS,KMSMasterKeyId=<kms-key-id> \\",
            "     --region <region>",
            "",
            "6. Console method for existing tables:",
            "   - Navigate to DynamoDB service",
            "   - Select the table",
            "   - Click 'Additional settings' tab",
            "   - Under 'Encryption at rest', click 'Manage encryption'",
            "   - Select 'AWS Key Management Service key (KMS)'",
            "   - Choose 'Select from your AWS KMS keys' or 'Enter KMS key ARN'",
            "   - Select or enter your KMS key",
            "   - Click 'Save changes'",
            "",
            "7. Create a customer-managed KMS key if you don't have one:",
            "   aws kms create-key \\",
            "     --description 'DynamoDB encryption key' \\",
            "     --key-policy file://key-policy.json \\",
            "     --region <region>",
            "",
            "   # Create an alias for easier reference",
            "   aws kms create-alias \\",
            "     --alias-name alias/dynamodb-encryption \\",
            "     --target-key-id <key-id> \\",
            "     --region <region>",
            "",
            "8. Example KMS key policy (key-policy.json):",
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
            '         "Sid": "Allow DynamoDB to use the key",',
            '         "Effect": "Allow",',
            '         "Principal": {"Service": "dynamodb.amazonaws.com"},',
            '         "Action": ["kms:Decrypt", "kms:DescribeKey", "kms:CreateGrant"],',
            '         "Resource": "*",',
            '         "Condition": {',
            '           "StringEquals": {"kms:ViaService": "dynamodb.<region>.amazonaws.com"}',
            "         }",
            "       }",
            "     ]",
            "   }",
            "",
            "9. Best practices:",
            "   - Use customer-managed KMS keys for all production tables",
            "   - Enable automatic key rotation for KMS keys",
            "   - Grant appropriate IAM permissions for KMS key usage",
            "   - Use separate KMS keys for different environments (dev/staging/prod)",
            "   - Document the KMS key used for each table",
            "   - Monitor KMS key usage with CloudWatch",
            "   - Set up CloudTrail logging for KMS key operations",
            "",
            "10. Important notes:",
            "    - Encryption can be changed from AWS owned to KMS without data migration",
            "    - Changing encryption type may cause brief table unavailability",
            "    - Once KMS encryption is enabled, you can change the KMS key",
            "    - You cannot disable encryption (only change the key type)",
            "    - Global tables must use the same encryption type across all regions",
            "    - Backups inherit encryption from source table",
            "    - Point-in-time recovery (PITR) backups use the same encryption",
            "    - Performance impact is negligible",
            "    - KMS key costs apply (per API call pricing)",
            "",
            "11. Cost considerations:",
            "    - AWS owned keys: No additional cost",
            "    - Customer-managed KMS keys: $1/month per key + API call costs",
            "    - API calls are typically minimal for DynamoDB encryption",
            "    - Consider using one KMS key for multiple tables to reduce costs",
            "",
            "12. Verify encryption after update:",
            "    # Check SSE status",
            "    aws dynamodb describe-table \\",
            "      --table-name <table-name> \\",
            "      --query 'Table.SSEDescription.{Status:Status,Type:SSEType,Key:KMSMasterKeyArn}' \\",
            "      --output table \\",
            "      --region <region>",
            "",
            "Priority: MEDIUM - KMS encryption provides better control but AWS owned keys still encrypt data",
            "Effort: Low - Can be enabled with a single API call, minimal downtime",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/EncryptionAtRest.html"
        ]
