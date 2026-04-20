"""Control 2.2: Ensure Authorized Software is Currently Supported assessments."""

from typing import Dict, List, Any
import logging
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class ElasticBeanstalkManagedUpdatesEnabledAssessment(BaseConfigRuleAssessment):
    """Assessment for elastic-beanstalk-managed-updates-enabled Config rule."""
    
    def __init__(self):
        """Initialize Elastic Beanstalk managed updates assessment."""
        super().__init__(
            rule_name="elastic-beanstalk-managed-updates-enabled",
            control_id="2.2",
            resource_types=["AWS::ElasticBeanstalk::Environment"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all Elastic Beanstalk environments in the region."""
        if resource_type != "AWS::ElasticBeanstalk::Environment":
            return []
        
        try:
            eb_client = aws_factory.get_client('elasticbeanstalk', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: eb_client.describe_environments()
            )
            
            environments = []
            for env in response.get('Environments', []):
                if env.get('Status') not in ['Terminated', 'Terminating']:
                    environments.append({
                        'EnvironmentId': env.get('EnvironmentId'),
                        'EnvironmentName': env.get('EnvironmentName'),
                        'ApplicationName': env.get('ApplicationName'),
                        'Status': env.get('Status'),
                        'PlatformArn': env.get('PlatformArn')
                    })
            
            logger.debug(f"Found {len(environments)} Elastic Beanstalk environments in region {region}")
            return environments
            
        except ClientError as e:
            logger.error(f"Error retrieving Elastic Beanstalk environments in region {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving Elastic Beanstalk environments in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if Elastic Beanstalk environment has managed updates enabled."""
        env_id = resource.get('EnvironmentId', 'unknown')
        env_name = resource.get('EnvironmentName', 'unknown')
        
        try:
            eb_client = aws_factory.get_client('elasticbeanstalk', region)
            
            # Get configuration settings for the environment
            response = aws_factory.aws_api_call_with_retry(
                lambda: eb_client.describe_configuration_settings(
                    ApplicationName=resource.get('ApplicationName'),
                    EnvironmentName=env_name
                )
            )
            
            managed_updates_enabled = False
            update_level = None
            
            for config in response.get('ConfigurationSettings', []):
                for option in config.get('OptionSettings', []):
                    if (option.get('Namespace') == 'aws:elasticbeanstalk:managedactions' and
                        option.get('OptionName') == 'ManagedActionsEnabled'):
                        managed_updates_enabled = option.get('Value', '').lower() == 'true'
                    elif (option.get('Namespace') == 'aws:elasticbeanstalk:managedactions:platformupdate' and
                          option.get('OptionName') == 'UpdateLevel'):
                        update_level = option.get('Value')
            
            if managed_updates_enabled:
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = f"Environment {env_name} has managed platform updates enabled"
                if update_level:
                    evaluation_reason += f" (Update level: {update_level})"
            else:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = f"Environment {env_name} does not have managed platform updates enabled"
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code in ['AccessDenied', 'UnauthorizedOperation']:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Insufficient permissions to check managed updates for environment {env_name}"
            else:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Error checking managed updates for environment {env_name}: {str(e)}"
        except Exception as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Unexpected error checking managed updates for environment {env_name}: {str(e)}"
        
        return ComplianceResult(
            resource_id=env_id,
            resource_type="AWS::ElasticBeanstalk::Environment",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for Elastic Beanstalk managed updates."""
        return [
            "Identify Elastic Beanstalk environments without managed platform updates enabled",
            "For each environment, enable managed platform updates:",
            "  1. Go to the Elastic Beanstalk console",
            "  2. Select the environment",
            "  3. Go to Configuration > Managed platform updates",
            "  4. Enable managed platform updates",
            "  5. Configure update level (patch or minor)",
            "  6. Set maintenance window preferences",
            "Use AWS CLI: aws elasticbeanstalk put-configuration-template with managed actions enabled",
            "Monitor platform update notifications and apply updates during maintenance windows"
        ]


class ECSFargateLatestPlatformVersionAssessment(BaseConfigRuleAssessment):
    """Assessment for ecs-fargate-latest-platform-version Config rule."""
    
    def __init__(self):
        """Initialize ECS Fargate platform version assessment."""
        super().__init__(
            rule_name="ecs-fargate-latest-platform-version",
            control_id="2.2",
            resource_types=["AWS::ECS::Service"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all ECS services using Fargate in the region."""
        if resource_type != "AWS::ECS::Service":
            return []
        
        try:
            ecs_client = aws_factory.get_client('ecs', region)
            
            # Get all clusters
            clusters_response = aws_factory.aws_api_call_with_retry(
                lambda: ecs_client.list_clusters()
            )
            
            services = []
            for cluster_arn in clusters_response.get('clusterArns', []):
                # Get services in each cluster
                services_response = aws_factory.aws_api_call_with_retry(
                    lambda: ecs_client.list_services(cluster=cluster_arn)
                )
                
                if services_response.get('serviceArns'):
                    # Get detailed service information
                    services_detail = aws_factory.aws_api_call_with_retry(
                        lambda: ecs_client.describe_services(
                            cluster=cluster_arn,
                            services=services_response['serviceArns']
                        )
                    )
                    
                    for service in services_detail.get('services', []):
                        # Only include Fargate services
                        if service.get('launchType') == 'FARGATE' or 'FARGATE' in service.get('capacityProviderStrategy', []):
                            services.append({
                                'ServiceArn': service.get('serviceArn'),
                                'ServiceName': service.get('serviceName'),
                                'ClusterArn': cluster_arn,
                                'LaunchType': service.get('launchType'),
                                'PlatformVersion': service.get('platformVersion'),
                                'TaskDefinition': service.get('taskDefinition'),
                                'Status': service.get('status')
                            })
            
            logger.debug(f"Found {len(services)} ECS Fargate services in region {region}")
            return services
            
        except ClientError as e:
            logger.error(f"Error retrieving ECS services in region {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving ECS services in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if ECS Fargate service uses the latest platform version."""
        service_arn = resource.get('ServiceArn', 'unknown')
        service_name = resource.get('ServiceName', 'unknown')
        platform_version = resource.get('PlatformVersion', 'LATEST')
        
        # LATEST is the recommended setting as it automatically uses the most recent platform version
        if platform_version == 'LATEST':
            compliance_status = ComplianceStatus.COMPLIANT
            evaluation_reason = f"ECS service {service_name} uses LATEST platform version"
        else:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = f"ECS service {service_name} uses specific platform version {platform_version} instead of LATEST"
        
        return ComplianceResult(
            resource_id=service_arn,
            resource_type="AWS::ECS::Service",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for ECS Fargate platform versions."""
        return [
            "Identify ECS Fargate services not using the LATEST platform version",
            "For each service, update to use LATEST platform version:",
            "  1. Go to the ECS console",
            "  2. Select the cluster and service",
            "  3. Update the service configuration",
            "  4. Set Platform version to LATEST",
            "  5. Deploy the updated service",
            "Use AWS CLI: aws ecs update-service --cluster <cluster> --service <service> --platform-version LATEST",
            "Monitor service deployments to ensure successful updates",
            "Set up automated deployment pipelines to use LATEST platform version by default"
        ]