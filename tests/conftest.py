"""
Pytest fixtures for Phase 1 CIS Controls IG1 expansion tests.

This module provides common fixtures for testing security services,
logging, and encryption controls.
"""

import pytest
from unittest.mock import Mock, MagicMock
from datetime import datetime


@pytest.fixture
def mock_aws_factory():
    """Mock AWS client factory for testing."""
    factory = Mock()
    factory.region = "us-east-1"
    return factory


@pytest.fixture
def mock_guardduty_client():
    """Mock GuardDuty client."""
    client = Mock()
    client.list_detectors = Mock(return_value={'DetectorIds': ['detector-123']})
    client.get_detector = Mock(return_value={
        'Status': 'ENABLED',
        'FindingPublishingFrequency': 'FIFTEEN_MINUTES'
    })
    return client


@pytest.fixture
def mock_inspector_client():
    """Mock Inspector v2 client."""
    client = Mock()
    client.list_coverage = Mock(return_value={
        'coveredResources': [{'resourceId': 'i-123', 'scanStatus': {'statusCode': 'ACTIVE'}}]
    })
    client.get_configuration = Mock(return_value={'state': 'ENABLED'})
    return client


@pytest.fixture
def mock_macie_client():
    """Mock Macie client."""
    client = Mock()
    client.get_macie_session = Mock(return_value={
        'status': 'ENABLED',
        'findingPublishingFrequency': 'FIFTEEN_MINUTES'
    })
    return client


@pytest.fixture
def mock_access_analyzer_client():
    """Mock IAM Access Analyzer client."""
    client = Mock()
    client.list_analyzers = Mock(return_value={
        'analyzers': [{'name': 'analyzer-1', 'status': 'ACTIVE', 'type': 'ACCOUNT'}]
    })
    return client


@pytest.fixture
def mock_ec2_client():
    """Mock EC2 client."""
    client = Mock()
    client.describe_vpcs = Mock(return_value={
        'Vpcs': [{'VpcId': 'vpc-123', 'IsDefault': False}]
    })
    client.describe_flow_logs = Mock(return_value={
        'FlowLogs': [{'FlowLogId': 'fl-123', 'ResourceId': 'vpc-123', 'FlowLogStatus': 'ACTIVE'}]
    })
    client.get_ebs_encryption_by_default = Mock(return_value={'EbsEncryptionByDefault': True})
    return client


@pytest.fixture
def mock_elbv2_client():
    """Mock ELBv2 client."""
    client = Mock()
    client.describe_load_balancers = Mock(return_value={
        'LoadBalancers': [{'LoadBalancerArn': 'arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/my-lb/50dc6c495c0c9188'}]
    })
    client.describe_load_balancer_attributes = Mock(return_value={
        'Attributes': [{'Key': 'access_logs.s3.enabled', 'Value': 'true'}]
    })
    return client


@pytest.fixture
def mock_cloudfront_client():
    """Mock CloudFront client."""
    client = Mock()
    client.list_distributions = Mock(return_value={
        'DistributionList': {
            'Items': [{'Id': 'E123', 'ARN': 'arn:aws:cloudfront::123456789012:distribution/E123'}]
        }
    })
    client.get_distribution = Mock(return_value={
        'Distribution': {
            'DistributionConfig': {
                'Logging': {'Enabled': True, 'Bucket': 'my-logs.s3.amazonaws.com'}
            }
        }
    })
    return client


@pytest.fixture
def mock_wafv2_client():
    """Mock WAFv2 client."""
    client = Mock()
    client.list_web_acls = Mock(return_value={
        'WebACLs': [{'Name': 'my-waf', 'Id': 'waf-123', 'ARN': 'arn:aws:wafv2:us-east-1:123456789012:regional/webacl/my-waf/waf-123'}]
    })
    client.get_logging_configuration = Mock(return_value={
        'LoggingConfiguration': {
            'ResourceArn': 'arn:aws:wafv2:us-east-1:123456789012:regional/webacl/my-waf/waf-123',
            'LogDestinationConfigs': ['arn:aws:logs:us-east-1:123456789012:log-group:aws-waf-logs']
        }
    })
    return client


@pytest.fixture
def mock_rds_client():
    """Mock RDS client."""
    client = Mock()
    client.describe_db_instances = Mock(return_value={
        'DBInstances': [{
            'DBInstanceIdentifier': 'my-db',
            'DBInstanceArn': 'arn:aws:rds:us-east-1:123456789012:db:my-db',
            'StorageEncrypted': True,
            'KmsKeyId': 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012'
        }]
    })
    return client


@pytest.fixture
def mock_efs_client():
    """Mock EFS client."""
    client = Mock()
    client.describe_file_systems = Mock(return_value={
        'FileSystems': [{
            'FileSystemId': 'fs-123',
            'FileSystemArn': 'arn:aws:elasticfilesystem:us-east-1:123456789012:file-system/fs-123',
            'Encrypted': True,
            'KmsKeyId': 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012'
        }]
    })
    return client


@pytest.fixture
def mock_dynamodb_client():
    """Mock DynamoDB client."""
    client = Mock()
    client.list_tables = Mock(return_value={'TableNames': ['my-table']})
    client.describe_table = Mock(return_value={
        'Table': {
            'TableName': 'my-table',
            'TableArn': 'arn:aws:dynamodb:us-east-1:123456789012:table/my-table',
            'SSEDescription': {
                'Status': 'ENABLED',
                'SSEType': 'KMS',
                'KMSMasterKeyArn': 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012'
            }
        }
    })
    return client


@pytest.fixture
def mock_s3_client():
    """Mock S3 client."""
    client = Mock()
    client.list_buckets = Mock(return_value={
        'Buckets': [{'Name': 'my-bucket', 'CreationDate': datetime.now()}]
    })
    client.get_bucket_encryption = Mock(return_value={
        'ServerSideEncryptionConfiguration': {
            'Rules': [{
                'ApplyServerSideEncryptionByDefault': {
                    'SSEAlgorithm': 'aws:kms',
                    'KMSMasterKeyID': 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012'
                }
            }]
        }
    })
    return client
