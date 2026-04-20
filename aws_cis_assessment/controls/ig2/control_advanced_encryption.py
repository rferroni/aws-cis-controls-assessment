"""Control 3.11: Encrypt Sensitive Data at Rest - Advanced encryption assessments."""

from typing import Dict, List, Any
import logging
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class SecretsManagerUsingCMKAssessment(BaseConfigRuleAssessment):
    """Assessment for secretsmanager-using-cmk AWS Config rule."""
    
    def __init__(self):
        super().__init__(
            rule_name="secretsmanager-using-cmk",
            control_id="3.11",
            resource_types=["AWS::SecretsManager::Secret"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get Secrets Manager secrets."""
        if resource_type != "AWS::SecretsManager::Secret":
            return []
            
        try:
            secrets_client = aws_factory.get_client('secretsmanager', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: secrets_client.list_secrets()
            )
            
            secrets = []
            for secret in response.get('SecretList', []):
                secrets.append({
                    'Name': secret.get('Name'),
                    'ARN': secret.get('ARN'),
                    'KmsKeyId': secret.get('KmsKeyId')
                })
            
            return secrets
            
        except ClientError as e:
            logger.error(f"Error retrieving Secrets Manager secrets in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if secret uses customer-managed KMS key."""
        secret_name = resource.get('Name', 'unknown')
        kms_key_id = resource.get('KmsKeyId')
        
        if kms_key_id and not kms_key_id.startswith('alias/aws/secretsmanager'):
            compliance_status = ComplianceStatus.COMPLIANT
            evaluation_reason = f"Secret {secret_name} uses customer-managed KMS key"
        else:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = f"Secret {secret_name} uses AWS managed key or no encryption"
        
        return ComplianceResult(
            resource_id=secret_name,
            resource_type="AWS::SecretsManager::Secret",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )


class SNSEncryptedKMSAssessment(BaseConfigRuleAssessment):
    """Assessment for sns-encrypted-kms AWS Config rule."""
    
    def __init__(self):
        super().__init__(
            rule_name="sns-encrypted-kms",
            control_id="3.11",
            resource_types=["AWS::SNS::Topic"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get SNS topics."""
        if resource_type != "AWS::SNS::Topic":
            return []
            
        try:
            sns_client = aws_factory.get_client('sns', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: sns_client.list_topics()
            )
            
            topics = []
            for topic in response.get('Topics', []):
                topic_arn = topic.get('TopicArn')
                topics.append({
                    'TopicArn': topic_arn,
                    'TopicName': topic_arn.split(':')[-1] if topic_arn else 'unknown'
                })
            
            return topics
            
        except ClientError as e:
            logger.error(f"Error retrieving SNS topics in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if SNS topic is encrypted with KMS."""
        topic_arn = resource.get('TopicArn', 'unknown')
        topic_name = resource.get('TopicName', 'unknown')
        
        try:
            sns_client = aws_factory.get_client('sns', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: sns_client.get_topic_attributes(TopicArn=topic_arn)
            )
            
            attributes = response.get('Attributes', {})
            kms_key_id = attributes.get('KmsMasterKeyId')
            
            if kms_key_id:
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = f"SNS topic {topic_name} is encrypted with KMS"
            else:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = f"SNS topic {topic_name} is not encrypted with KMS"
                
        except ClientError as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Error checking encryption for SNS topic {topic_name}: {str(e)}"
        
        return ComplianceResult(
            resource_id=topic_name,
            resource_type="AWS::SNS::Topic",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )


class SQSQueueEncryptedKMSAssessment(BaseConfigRuleAssessment):
    """Assessment for sqs-queue-encrypted-kms AWS Config rule."""
    
    def __init__(self):
        super().__init__(
            rule_name="sqs-queue-encrypted-kms",
            control_id="3.11",
            resource_types=["AWS::SQS::Queue"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get SQS queues."""
        if resource_type != "AWS::SQS::Queue":
            return []
            
        try:
            sqs_client = aws_factory.get_client('sqs', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: sqs_client.list_queues()
            )
            
            queues = []
            for queue_url in response.get('QueueUrls', []):
                queue_name = queue_url.split('/')[-1]
                queues.append({
                    'QueueUrl': queue_url,
                    'QueueName': queue_name
                })
            
            return queues
            
        except ClientError as e:
            logger.error(f"Error retrieving SQS queues in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if SQS queue is encrypted with KMS."""
        queue_url = resource.get('QueueUrl', 'unknown')
        queue_name = resource.get('QueueName', 'unknown')
        
        try:
            sqs_client = aws_factory.get_client('sqs', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: sqs_client.get_queue_attributes(
                    QueueUrl=queue_url,
                    AttributeNames=['KmsMasterKeyId']
                )
            )
            
            attributes = response.get('Attributes', {})
            kms_key_id = attributes.get('KmsMasterKeyId')
            
            if kms_key_id:
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = f"SQS queue {queue_name} is encrypted with KMS"
            else:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = f"SQS queue {queue_name} is not encrypted with KMS"
                
        except ClientError as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Error checking encryption for SQS queue {queue_name}: {str(e)}"
        
        return ComplianceResult(
            resource_id=queue_name,
            resource_type="AWS::SQS::Queue",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )


class KinesisStreamEncryptedAssessment(BaseConfigRuleAssessment):
    """Assessment for kinesis-stream-encrypted AWS Config rule."""
    
    def __init__(self):
        super().__init__(
            rule_name="kinesis-stream-encrypted",
            control_id="3.11",
            resource_types=["AWS::Kinesis::Stream"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get Kinesis streams."""
        if resource_type != "AWS::Kinesis::Stream":
            return []
            
        try:
            kinesis_client = aws_factory.get_client('kinesis', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: kinesis_client.list_streams()
            )
            
            streams = []
            for stream_name in response.get('StreamNames', []):
                streams.append({
                    'StreamName': stream_name
                })
            
            return streams
            
        except ClientError as e:
            logger.error(f"Error retrieving Kinesis streams in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if Kinesis stream is encrypted."""
        stream_name = resource.get('StreamName', 'unknown')
        
        try:
            kinesis_client = aws_factory.get_client('kinesis', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: kinesis_client.describe_stream(StreamName=stream_name)
            )
            
            stream_description = response.get('StreamDescription', {})
            encryption_type = stream_description.get('EncryptionType')
            
            if encryption_type == 'KMS':
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = f"Kinesis stream {stream_name} is encrypted with KMS"
            else:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = f"Kinesis stream {stream_name} is not encrypted"
                
        except ClientError as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Error checking encryption for Kinesis stream {stream_name}: {str(e)}"
        
        return ComplianceResult(
            resource_id=stream_name,
            resource_type="AWS::Kinesis::Stream",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )


class ElasticsearchEncryptedAtRestAssessment(BaseConfigRuleAssessment):
    """Assessment for elasticsearch-encrypted-at-rest AWS Config rule."""
    
    def __init__(self):
        super().__init__(
            rule_name="elasticsearch-encrypted-at-rest",
            control_id="3.11",
            resource_types=["AWS::Elasticsearch::Domain"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get Elasticsearch domains."""
        if resource_type != "AWS::Elasticsearch::Domain":
            return []
            
        try:
            es_client = aws_factory.get_client('es', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: es_client.list_domain_names()
            )
            
            domains = []
            for domain in response.get('DomainNames', []):
                domains.append({
                    'DomainName': domain.get('DomainName')
                })
            
            return domains
            
        except ClientError as e:
            logger.error(f"Error retrieving Elasticsearch domains in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if Elasticsearch domain has encryption at rest enabled."""
        domain_name = resource.get('DomainName', 'unknown')
        
        try:
            es_client = aws_factory.get_client('es', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: es_client.describe_elasticsearch_domain(DomainName=domain_name)
            )
            
            domain_status = response.get('DomainStatus', {})
            encryption_config = domain_status.get('EncryptionAtRestOptions', {})
            encryption_enabled = encryption_config.get('Enabled', False)
            
            if encryption_enabled:
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = f"Elasticsearch domain {domain_name} has encryption at rest enabled"
            else:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = f"Elasticsearch domain {domain_name} does not have encryption at rest enabled"
                
        except ClientError as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Error checking encryption for Elasticsearch domain {domain_name}: {str(e)}"
        
        return ComplianceResult(
            resource_id=domain_name,
            resource_type="AWS::Elasticsearch::Domain",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )