"""
CIS Control 2.13, 2.14, 2.11 - Messaging and Data Event Encryption
Ensures SNS topics, SQS queues use KMS encryption and CloudTrail logs S3 data events.
"""

import logging
from typing import List, Dict, Any
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class SNSEncryptedKMSAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 2.13 - Encrypt Sensitive Data at Rest
    AWS Config Rule: sns-encrypted-kms
    
    Ensures SNS topics are encrypted with customer-managed KMS keys.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="sns-encrypted-kms",
            control_id="2.13",
            resource_types=["AWS::SNS::Topic"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all SNS topics and their encryption configuration."""
        if resource_type != "AWS::SNS::Topic":
            return []
        
        try:
            sns_client = aws_factory.get_client('sns', region)
            topics = []
            
            # List all topics
            paginator = sns_client.get_paginator('list_topics')
            for page in paginator.paginate():
                for topic in page.get('Topics', []):
                    topic_arn = topic.get('TopicArn', '')
                    
                    try:
                        # Get topic attributes
                        attrs_response = sns_client.get_topic_attributes(TopicArn=topic_arn)
                        attributes = attrs_response.get('Attributes', {})
                        
                        kms_key_id = attributes.get('KmsMasterKeyId', '')
                        encrypted_with_kms = bool(kms_key_id)
                        
                        topics.append({
                            'TopicArn': topic_arn,
                            'TopicName': topic_arn.split(':')[-1],
                            'KmsMasterKeyId': kms_key_id,
                            'EncryptedWithKMS': encrypted_with_kms
                        })
                    
                    except ClientError as e:
                        logger.warning(f"Error getting attributes for topic {topic_arn}: {e}")
                        continue
            
            logger.debug(f"Found {len(topics)} SNS topics in {region}")
            return topics
            
        except ClientError as e:
            logger.error(f"Error retrieving SNS topics in {region}: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error retrieving SNS topics in {region}: {e}")
            return []
    
    def _evaluate_resource_compliance(
        self, 
        resource: Dict[str, Any], 
        aws_factory: AWSClientFactory, 
        region: str
    ) -> ComplianceResult:
        """Evaluate if SNS topic is encrypted with KMS."""
        topic_arn = resource.get('TopicArn', 'unknown')
        topic_name = resource.get('TopicName', 'unknown')
        encrypted_with_kms = resource.get('EncryptedWithKMS', False)
        kms_key_id = resource.get('KmsMasterKeyId', '')
        
        if encrypted_with_kms:
            evaluation_reason = (
                f"SNS topic '{topic_name}' is encrypted with KMS key: {kms_key_id}"
            )
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            evaluation_reason = (
                f"SNS topic '{topic_name}' is not encrypted with a KMS key"
            )
            compliance_status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceResult(
            resource_id=topic_arn,
            resource_type="AWS::SNS::Topic",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get remediation steps for enabling SNS KMS encryption."""
        return [
            "1. Enable KMS encryption on an existing SNS topic:",
            "   aws sns set-topic-attributes \\",
            "     --topic-arn <topic-arn> \\",
            "     --attribute-name KmsMasterKeyId \\",
            "     --attribute-value <kms-key-id>",
            "",
            "2. Create a new encrypted SNS topic:",
            "   aws sns create-topic \\",
            "     --name <topic-name> \\",
            "     --attributes KmsMasterKeyId=<kms-key-id>",
            "",
            "3. Console method:",
            "   - Navigate to SNS service",
            "   - Select the topic",
            "   - Click 'Edit'",
            "   - Expand 'Encryption'",
            "   - Select 'Enable encryption'",
            "   - Choose your KMS key",
            "   - Click 'Save changes'",
            "",
            "4. Verify encryption:",
            "   aws sns get-topic-attributes \\",
            "     --topic-arn <topic-arn> \\",
            "     --query 'Attributes.KmsMasterKeyId'",
            "",
            "Priority: HIGH - Encryption protects message data at rest",
            "Effort: Low - Single API call per topic",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/sns/latest/dg/sns-server-side-encryption.html"
        ]


class SQSQueueEncryptedAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 2.14 - Encrypt Sensitive Data at Rest
    AWS Config Rule: sqs-queue-encrypted
    
    Ensures SQS queues are encrypted at rest.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="sqs-queue-encrypted",
            control_id="2.14",
            resource_types=["AWS::SQS::Queue"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all SQS queues and their encryption configuration."""
        if resource_type != "AWS::SQS::Queue":
            return []
        
        try:
            sqs_client = aws_factory.get_client('sqs', region)
            queues = []
            
            # List all queues
            response = sqs_client.list_queues()
            queue_urls = response.get('QueueUrls', [])
            
            for queue_url in queue_urls:
                try:
                    # Get queue attributes
                    attrs_response = sqs_client.get_queue_attributes(
                        QueueUrl=queue_url,
                        AttributeNames=['All']
                    )
                    attributes = attrs_response.get('Attributes', {})
                    
                    kms_key_id = attributes.get('KmsMasterKeyId', '')
                    encrypted = bool(kms_key_id)
                    queue_name = queue_url.split('/')[-1]
                    
                    queues.append({
                        'QueueUrl': queue_url,
                        'QueueName': queue_name,
                        'KmsMasterKeyId': kms_key_id,
                        'Encrypted': encrypted
                    })
                
                except ClientError as e:
                    logger.warning(f"Error getting attributes for queue {queue_url}: {e}")
                    continue
            
            logger.debug(f"Found {len(queues)} SQS queues in {region}")
            return queues
            
        except ClientError as e:
            logger.error(f"Error retrieving SQS queues in {region}: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error retrieving SQS queues in {region}: {e}")
            return []
    
    def _evaluate_resource_compliance(
        self, 
        resource: Dict[str, Any], 
        aws_factory: AWSClientFactory, 
        region: str
    ) -> ComplianceResult:
        """Evaluate if SQS queue is encrypted."""
        queue_url = resource.get('QueueUrl', 'unknown')
        queue_name = resource.get('QueueName', 'unknown')
        encrypted = resource.get('Encrypted', False)
        kms_key_id = resource.get('KmsMasterKeyId', '')
        
        if encrypted:
            evaluation_reason = (
                f"SQS queue '{queue_name}' is encrypted with KMS key: {kms_key_id}"
            )
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            evaluation_reason = (
                f"SQS queue '{queue_name}' is not encrypted"
            )
            compliance_status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceResult(
            resource_id=queue_url,
            resource_type="AWS::SQS::Queue",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get remediation steps for enabling SQS encryption."""
        return [
            "1. Enable encryption on an existing SQS queue:",
            "   aws sqs set-queue-attributes \\",
            "     --queue-url <queue-url> \\",
            "     --attributes KmsMasterKeyId=<kms-key-id>",
            "",
            "2. Create a new encrypted SQS queue:",
            "   aws sqs create-queue \\",
            "     --queue-name <queue-name> \\",
            "     --attributes KmsMasterKeyId=<kms-key-id>",
            "",
            "3. Console method:",
            "   - Navigate to SQS service",
            "   - Select the queue",
            "   - Click 'Edit'",
            "   - Expand 'Encryption'",
            "   - Select 'Enabled'",
            "   - Choose your KMS key",
            "   - Click 'Save'",
            "",
            "4. Verify encryption:",
            "   aws sqs get-queue-attributes \\",
            "     --queue-url <queue-url> \\",
            "     --attribute-names KmsMasterKeyId",
            "",
            "Priority: HIGH - Encryption protects message data at rest",
            "Effort: Low - Single API call per queue",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/AWSSimpleQueueService/latest/SQSDeveloperGuide/sqs-server-side-encryption.html"
        ]


class CloudTrailS3DataEventsEnabledAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 2.11 - Audit Log Management
    AWS Config Rule: cloudtrail-s3-dataevents-enabled
    
    Ensures CloudTrail logs S3 data events for monitoring object-level operations.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="cloudtrail-s3-dataevents-enabled",
            control_id="2.11",
            resource_types=["AWS::CloudTrail::Trail"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all CloudTrail trails and their event selector configuration."""
        if resource_type != "AWS::CloudTrail::Trail":
            return []
        
        try:
            cloudtrail_client = aws_factory.get_client('cloudtrail', region)
            trails = []
            
            # List all trails
            response = cloudtrail_client.list_trails()
            trail_list = response.get('Trails', [])
            
            for trail_info in trail_list:
                trail_arn = trail_info.get('TrailARN', '')
                trail_name = trail_info.get('Name', '')
                
                try:
                    # Get event selectors
                    selectors_response = cloudtrail_client.get_event_selectors(TrailName=trail_name)
                    event_selectors = selectors_response.get('EventSelectors', [])
                    
                    # Check if S3 data events are enabled
                    s3_data_events_enabled = False
                    for selector in event_selectors:
                        data_resources = selector.get('DataResources', [])
                        for resource in data_resources:
                            if resource.get('Type') == 'AWS::S3::Object':
                                s3_data_events_enabled = True
                                break
                        if s3_data_events_enabled:
                            break
                    
                    trails.append({
                        'TrailARN': trail_arn,
                        'TrailName': trail_name,
                        'S3DataEventsEnabled': s3_data_events_enabled,
                        'EventSelectors': event_selectors
                    })
                
                except ClientError as e:
                    logger.warning(f"Error getting event selectors for trail {trail_name}: {e}")
                    continue
            
            logger.debug(f"Found {len(trails)} CloudTrail trails in {region}")
            return trails
            
        except ClientError as e:
            logger.error(f"Error retrieving CloudTrail trails in {region}: {e}")
            return []
        except Exception as e:
            logger.error(f"Unexpected error retrieving CloudTrail trails in {region}: {e}")
            return []
    
    def _evaluate_resource_compliance(
        self, 
        resource: Dict[str, Any], 
        aws_factory: AWSClientFactory, 
        region: str
    ) -> ComplianceResult:
        """Evaluate if CloudTrail trail logs S3 data events."""
        trail_arn = resource.get('TrailARN', 'unknown')
        trail_name = resource.get('TrailName', 'unknown')
        s3_data_events_enabled = resource.get('S3DataEventsEnabled', False)
        
        if s3_data_events_enabled:
            evaluation_reason = (
                f"CloudTrail trail '{trail_name}' has S3 data events logging enabled"
            )
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            evaluation_reason = (
                f"CloudTrail trail '{trail_name}' does not have S3 data events logging enabled"
            )
            compliance_status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceResult(
            resource_id=trail_arn,
            resource_type="AWS::CloudTrail::Trail",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get remediation steps for enabling CloudTrail S3 data events."""
        return [
            "1. Enable S3 data events on an existing CloudTrail trail:",
            "   aws cloudtrail put-event-selectors \\",
            "     --trail-name <trail-name> \\",
            "     --event-selectors '[{",
            '       "ReadWriteType": "All",',
            '       "IncludeManagementEvents": true,',
            '       "DataResources": [{',
            '         "Type": "AWS::S3::Object",',
            '         "Values": ["arn:aws:s3:::<bucket-name>/*"]',
            "       }]",
            "     }]'",
            "",
            "2. Enable for all S3 buckets:",
            "   aws cloudtrail put-event-selectors \\",
            "     --trail-name <trail-name> \\",
            "     --event-selectors '[{",
            '       "ReadWriteType": "All",',
            '       "IncludeManagementEvents": true,',
            '       "DataResources": [{',
            '         "Type": "AWS::S3::Object",',
            '         "Values": ["arn:aws:s3:::*/*"]',
            "       }]",
            "     }]'",
            "",
            "3. Console method:",
            "   - Navigate to CloudTrail service",
            "   - Select the trail",
            "   - Click 'Edit'",
            "   - Under 'Data events', click 'Add data event type'",
            "   - Select 'S3'",
            "   - Choose 'All current and future S3 buckets' or specific buckets",
            "   - Select 'Read' and 'Write' events",
            "   - Click 'Save changes'",
            "",
            "4. Verify configuration:",
            "   aws cloudtrail get-event-selectors \\",
            "     --trail-name <trail-name>",
            "",
            "Priority: MEDIUM - Important for S3 audit logging",
            "Effort: Low - Single API call, but note additional CloudTrail costs",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/awscloudtrail/latest/userguide/logging-data-events-with-cloudtrail.html"
        ]
