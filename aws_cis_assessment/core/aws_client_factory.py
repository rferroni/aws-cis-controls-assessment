"""AWS Client Factory for managing AWS service clients with credential handling."""

import boto3
import time
import random
from typing import Dict, List, Optional, Any
from botocore.exceptions import ClientError, NoCredentialsError, PartialCredentialsError
from botocore.config import Config
import logging

logger = logging.getLogger(__name__)


class AWSClientFactory:
    """Centralized AWS service client management with credential handling."""
    
    def __init__(self, credentials: Optional[Dict[str, str]] = None, regions: Optional[List[str]] = None):
        """Initialize with AWS credentials and target regions.
        
        Args:
            credentials: Optional dict with AWS credentials (access_key_id, secret_access_key, session_token)
            regions: List of AWS regions to support. If None, uses current region.
        """
        self.credentials = credentials or {}
        self.regions = regions or ['us-east-1']  # Default to us-east-1 if not specified
        self._clients = {}  # Cache for boto3 clients
        self._session = None
        self._account_info = None
        
        # Configure boto3 with retry settings
        self._config = Config(
            retries={
                'max_attempts': 3,
                'mode': 'adaptive'
            },
            max_pool_connections=50
        )
        
        # Initialize session
        self._initialize_session()
    
    def _initialize_session(self):
        """Initialize boto3 session with provided credentials."""
        try:
            if self.credentials:
                # Check if profile_name is provided
                if 'profile_name' in self.credentials:
                    self._session = boto3.Session(
                        profile_name=self.credentials['profile_name'],
                        region_name=self.regions[0] if self.regions else None
                    )
                else:
                    # Use explicit credentials
                    self._session = boto3.Session(
                        aws_access_key_id=self.credentials.get('aws_access_key_id'),
                        aws_secret_access_key=self.credentials.get('aws_secret_access_key'),
                        aws_session_token=self.credentials.get('aws_session_token'),
                        region_name=self.regions[0] if self.regions else None
                    )
            else:
                # Use default credential chain
                self._session = boto3.Session(
                    region_name=self.regions[0] if self.regions else None
                )
            
            logger.info("AWS session initialized successfully")
            
        except Exception as e:
            logger.error(f"Failed to initialize AWS session: {e}")
            raise
    
    def get_client(self, service_name: str, region: Optional[str] = None, 
                   allow_global_region: bool = False) -> boto3.client:
        """Get AWS service client for specified service and region.
        
        Args:
            service_name: AWS service name (e.g., 'ec2', 'iam', 's3')
            region: AWS region. If None, uses first region from regions list.
            allow_global_region: If True, allows us-east-1 even if not in regions list.
                               This is used for account-level and global resources that
                               must be evaluated in us-east-1 regardless of configured regions.
            
        Returns:
            Boto3 client for the specified service
            
        Raises:
            ValueError: If region is not in supported regions list (unless allow_global_region=True for us-east-1)
            ClientError: If client creation fails
        """
        if region is None:
            region = self.regions[0]
        
        # Allow us-east-1 for global/account-level resources even if not in regions list
        if allow_global_region and region == 'us-east-1':
            # us-east-1 is allowed for global resources
            logger.debug(f"Allowing global region us-east-1 for {service_name} (not in configured regions)")
        elif region not in self.regions:
            raise ValueError(f"Region {region} not in supported regions: {self.regions}")
        
        # Create cache key
        cache_key = f"{service_name}_{region}"
        
        # Return cached client if available
        if cache_key in self._clients:
            return self._clients[cache_key]
        
        try:
            # Create new client
            client = self._session.client(
                service_name,
                region_name=region,
                config=self._config
            )
            
            # Cache the client
            self._clients[cache_key] = client
            
            logger.debug(f"Created {service_name} client for region {region}")
            return client
            
        except Exception as e:
            logger.error(f"Failed to create {service_name} client for region {region}: {e}")
            raise
    
    def validate_credentials(self) -> bool:
        """Validate AWS credentials and permissions.
        
        Returns:
            True if credentials are valid, False otherwise
        """
        try:
            sts_client = self.get_client('sts')
            response = sts_client.get_caller_identity()
            
            # Store account info for later use
            self._account_info = {
                'account_id': response.get('Account'),
                'user_id': response.get('UserId'),
                'arn': response.get('Arn')
            }
            
            logger.info(f"Credentials validated for account: {self._account_info['account_id']}")
            return True
            
        except (NoCredentialsError, PartialCredentialsError) as e:
            logger.error(f"Invalid credentials: {e}")
            return False
        except ClientError as e:
            logger.error(f"AWS API error during credential validation: {e}")
            return False
        except Exception as e:
            logger.error(f"Unexpected error during credential validation: {e}")
            return False
    
    def get_account_info(self) -> Dict[str, str]:
        """Get AWS account ID and caller identity information.
        
        Returns:
            Dictionary with account_id, user_id, and arn
            
        Raises:
            RuntimeError: If credentials haven't been validated yet
        """
        if self._account_info is None:
            if not self.validate_credentials():
                raise RuntimeError("Failed to validate credentials")
        
        return self._account_info.copy()
    
    @property
    def account_id(self) -> str:
        """Get AWS account ID.
        
        Returns:
            AWS account ID string
            
        Raises:
            RuntimeError: If credentials haven't been validated yet
        """
        if self._account_info is None:
            if not self.validate_credentials():
                raise RuntimeError("Failed to validate credentials")
        
        return self._account_info['account_id']
    
    def test_service_access(self, service_name: str, region: Optional[str] = None) -> bool:
        """Test access to a specific AWS service.
        
        Args:
            service_name: AWS service name to test
            region: AWS region to test. If None, uses first region.
            
        Returns:
            True if service is accessible, False otherwise
        """
        try:
            client = self.get_client(service_name, region)
            
            # Test with a simple, low-cost API call for each service
            test_calls = {
                'ec2': lambda c: c.describe_regions(),
                'iam': lambda c: c.get_account_summary(),
                's3': lambda c: c.list_buckets(),
                'rds': lambda c: c.describe_db_instances(MaxRecords=1),
                'cloudtrail': lambda c: c.describe_trails(),
                'config': lambda c: c.describe_configuration_recorders(),
                'guardduty': lambda c: c.list_detectors(MaxResults=1),
                'organizations': lambda c: c.describe_organization(),
                'ssm': lambda c: c.describe_instance_information(MaxResults=1),
                'elb': lambda c: c.describe_load_balancers(PageSize=1),
                'elbv2': lambda c: c.describe_load_balancers(PageSize=1),
                'apigateway': lambda c: c.get_rest_apis(limit=1),
                'apigatewayv2': lambda c: c.get_apis(MaxResults='1'),
                'kms': lambda c: c.list_keys(Limit=1),
                'backup': lambda c: c.list_backup_vaults(MaxResults=1),
                'dynamodb': lambda c: c.list_tables(Limit=1)
            }
            
            if service_name in test_calls:
                test_calls[service_name](client)
            else:
                # Generic test - try to get service's waiter names
                client.waiter_names
            
            logger.debug(f"Service {service_name} is accessible in region {region}")
            return True
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code in ['AccessDenied', 'UnauthorizedOperation']:
                logger.debug(f"Access denied for {service_name} in region {region}")
            else:
                logger.debug(f"Service {service_name} test failed in region {region}: {error_code}")
            return False
        except Exception as e:
            # Don't log parameter validation errors as warnings - they're expected for some services
            if "Parameter validation failed" in str(e):
                logger.debug(f"Parameter validation issue for {service_name} in region {region}: {e}")
            else:
                logger.warning(f"Unexpected error testing {service_name} in region {region}: {e}")
            return False
    
    def get_available_regions(self, service_name: str) -> List[str]:
        """Get list of regions where a service is available.
        
        Args:
            service_name: AWS service name
            
        Returns:
            List of region names where service is available
        """
        available_regions = []
        
        for region in self.regions:
            if self.test_service_access(service_name, region):
                available_regions.append(region)
        
        return available_regions
    
    def aws_api_call_with_retry(self, func, max_retries: int = 3, base_delay: float = 1.0) -> Any:
        """Execute AWS API call with exponential backoff retry logic.
        
        Args:
            func: Function to execute (should be a lambda or callable)
            max_retries: Maximum number of retry attempts
            base_delay: Base delay in seconds for exponential backoff
            
        Returns:
            Result of the function call
            
        Raises:
            ClientError: If all retries are exhausted
        """
        for attempt in range(max_retries + 1):
            try:
                return func()
                
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', '')
                
                # Retry on throttling errors
                if error_code in ['Throttling', 'RequestLimitExceeded', 'TooManyRequestsException']:
                    if attempt < max_retries:
                        # Exponential backoff with jitter
                        delay = base_delay * (2 ** attempt) + random.uniform(0, 1)
                        logger.warning(f"API throttled, retrying in {delay:.2f} seconds (attempt {attempt + 1}/{max_retries + 1})")
                        time.sleep(delay)
                        continue
                
                # Don't retry on other errors
                raise
                
            except Exception as e:
                # Log connection errors at DEBUG level (expected for cross-region S3 buckets)
                error_str = str(e)
                if "Could not connect to the endpoint URL" in error_str or "Connection" in error_str:
                    logger.debug(f"Connection error in AWS API call (may be cross-region resource): {e}")
                else:
                    logger.error(f"Non-retryable error in AWS API call: {e}")
                raise
        
        # This should never be reached due to the raise in the loop
        raise ClientError(
            error_response={'Error': {'Code': 'MaxRetriesExceeded', 'Message': 'Maximum retries exceeded'}},
            operation_name='aws_api_call_with_retry'
        )
    
    def get_supported_services(self) -> List[str]:
        """Get list of AWS services supported by this client factory.
        
        Returns:
            List of supported AWS service names
        """
        return [
            'ec2', 'iam', 's3', 'rds', 'cloudtrail', 'cloudwatch', 'logs',
            'config', 'guardduty', 'inspector', 'kms', 'organizations',
            'ssm', 'securityhub', 'macie2', 'backup', 'dynamodb',
            'elb', 'elbv2', 'apigateway',
            'apigatewayv2', 'redshift', 'efs', 'sns', 'sqs', 'lambda',
            'ecs', 'ecr', 'codebuild', 'elasticsearch', 'opensearch'
        ]
    
    def get_enabled_regions(self) -> List[str]:
        """Get list of enabled AWS regions for the current account.
        
        Returns:
            List of enabled AWS region names
        """
        try:
            ec2_client = self.get_client('ec2', 'us-east-1')
            response = ec2_client.describe_regions()
            return [region['RegionName'] for region in response['Regions']]
        except Exception as e:
            logger.warning(f"Could not retrieve enabled regions: {e}")
            # Return default region as fallback
            return ['us-east-1']
    
    def cleanup(self):
        """Clean up resources and close connections."""
        self._clients.clear()
        logger.info("AWS client factory cleaned up")