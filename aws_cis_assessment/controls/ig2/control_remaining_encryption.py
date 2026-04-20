"""Remaining Encryption Rules - AWS Config rule assessments."""

from typing import Dict, List, Any
import logging
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class OpenSearchEncryptedAtRestAssessment(BaseConfigRuleAssessment):
    """Assessment for opensearch-encrypted-at-rest AWS Config rule."""
    
    def __init__(self):
        super().__init__(
            rule_name="opensearch-encrypted-at-rest",
            control_id="3.11",
            resource_types=["AWS::OpenSearch::Domain"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get OpenSearch domains."""
        if resource_type != "AWS::OpenSearch::Domain":
            return []
            
        try:
            opensearch_client = aws_factory.get_client('opensearch', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: opensearch_client.list_domain_names()
            )
            
            domains = []
            for domain in response.get('DomainNames', []):
                domains.append({
                    'DomainName': domain.get('DomainName')
                })
            
            return domains
            
        except ClientError as e:
            logger.error(f"Error retrieving OpenSearch domains in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if OpenSearch domain has encryption at rest enabled."""
        domain_name = resource.get('DomainName', 'unknown')
        
        try:
            opensearch_client = aws_factory.get_client('opensearch', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: opensearch_client.describe_domain(DomainName=domain_name)
            )
            
            domain_status = response.get('DomainStatus', {})
            encryption_config = domain_status.get('EncryptionAtRestOptions', {})
            encryption_enabled = encryption_config.get('Enabled', False)
            
            if encryption_enabled:
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = f"OpenSearch domain {domain_name} has encryption at rest enabled"
            else:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = f"OpenSearch domain {domain_name} does not have encryption at rest enabled"
                
        except ClientError as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Error checking encryption for OpenSearch domain {domain_name}: {str(e)}"
        
        return ComplianceResult(
            resource_id=domain_name,
            resource_type="AWS::OpenSearch::Domain",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )


class OpenSearchNodeToNodeEncryptionCheckAssessment(BaseConfigRuleAssessment):
    """Assessment for opensearch-node-to-node-encryption-check AWS Config rule."""
    
    def __init__(self):
        super().__init__(
            rule_name="opensearch-node-to-node-encryption-check",
            control_id="3.10",
            resource_types=["AWS::OpenSearch::Domain"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get OpenSearch domains."""
        if resource_type != "AWS::OpenSearch::Domain":
            return []
            
        try:
            opensearch_client = aws_factory.get_client('opensearch', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: opensearch_client.list_domain_names()
            )
            
            domains = []
            for domain in response.get('DomainNames', []):
                domains.append({
                    'DomainName': domain.get('DomainName')
                })
            
            return domains
            
        except ClientError as e:
            logger.error(f"Error retrieving OpenSearch domains in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if OpenSearch domain has node-to-node encryption enabled."""
        domain_name = resource.get('DomainName', 'unknown')
        
        try:
            opensearch_client = aws_factory.get_client('opensearch', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: opensearch_client.describe_domain(DomainName=domain_name)
            )
            
            domain_status = response.get('DomainStatus', {})
            node_to_node_encryption = domain_status.get('NodeToNodeEncryptionOptions', {})
            encryption_enabled = node_to_node_encryption.get('Enabled', False)
            
            if encryption_enabled:
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = f"OpenSearch domain {domain_name} has node-to-node encryption enabled"
            else:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = f"OpenSearch domain {domain_name} does not have node-to-node encryption enabled"
                
        except ClientError as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Error checking node-to-node encryption for domain {domain_name}: {str(e)}"
        
        return ComplianceResult(
            resource_id=domain_name,
            resource_type="AWS::OpenSearch::Domain",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )


class RedshiftClusterKMSEnabledAssessment(BaseConfigRuleAssessment):
    """Assessment for redshift-cluster-kms-enabled AWS Config rule."""
    
    def __init__(self):
        super().__init__(
            rule_name="redshift-cluster-kms-enabled",
            control_id="3.11",
            resource_types=["AWS::Redshift::Cluster"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get Redshift clusters."""
        if resource_type != "AWS::Redshift::Cluster":
            return []
            
        try:
            redshift_client = aws_factory.get_client('redshift', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: redshift_client.describe_clusters()
            )
            
            clusters = []
            for cluster in response.get('Clusters', []):
                clusters.append({
                    'ClusterIdentifier': cluster.get('ClusterIdentifier'),
                    'Encrypted': cluster.get('Encrypted', False),
                    'KmsKeyId': cluster.get('KmsKeyId')
                })
            
            return clusters
            
        except ClientError as e:
            logger.error(f"Error retrieving Redshift clusters in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if Redshift cluster uses KMS encryption."""
        cluster_id = resource.get('ClusterIdentifier', 'unknown')
        encrypted = resource.get('Encrypted', False)
        kms_key_id = resource.get('KmsKeyId')
        
        if encrypted and kms_key_id:
            compliance_status = ComplianceStatus.COMPLIANT
            evaluation_reason = f"Redshift cluster {cluster_id} is encrypted with KMS key"
        elif encrypted:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = f"Redshift cluster {cluster_id} is encrypted but not using KMS"
        else:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = f"Redshift cluster {cluster_id} is not encrypted"
        
        return ComplianceResult(
            resource_id=cluster_id,
            resource_type="AWS::Redshift::Cluster",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )


class SageMakerEndpointConfigurationKMSKeyConfiguredAssessment(BaseConfigRuleAssessment):
    """Assessment for sagemaker-endpoint-configuration-kms-key-configured AWS Config rule."""
    
    def __init__(self):
        super().__init__(
            rule_name="sagemaker-endpoint-configuration-kms-key-configured",
            control_id="3.11",
            resource_types=["AWS::SageMaker::EndpointConfig"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get SageMaker endpoint configurations."""
        if resource_type != "AWS::SageMaker::EndpointConfig":
            return []
            
        try:
            sagemaker_client = aws_factory.get_client('sagemaker', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: sagemaker_client.list_endpoint_configs()
            )
            
            configs = []
            for config in response.get('EndpointConfigs', []):
                configs.append({
                    'EndpointConfigName': config.get('EndpointConfigName'),
                    'EndpointConfigArn': config.get('EndpointConfigArn')
                })
            
            return configs
            
        except ClientError as e:
            logger.error(f"Error retrieving SageMaker endpoint configs in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if SageMaker endpoint configuration uses KMS encryption."""
        config_name = resource.get('EndpointConfigName', 'unknown')
        
        try:
            sagemaker_client = aws_factory.get_client('sagemaker', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: sagemaker_client.describe_endpoint_config(EndpointConfigName=config_name)
            )
            
            kms_key_id = response.get('KmsKeyId')
            
            if kms_key_id:
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = f"SageMaker endpoint config {config_name} uses KMS encryption"
            else:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = f"SageMaker endpoint config {config_name} does not use KMS encryption"
                
        except ClientError as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Error checking KMS config for endpoint config {config_name}: {str(e)}"
        
        return ComplianceResult(
            resource_id=config_name,
            resource_type="AWS::SageMaker::EndpointConfig",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )


class SageMakerNotebookInstanceKMSKeyConfiguredAssessment(BaseConfigRuleAssessment):
    """Assessment for sagemaker-notebook-instance-kms-key-configured AWS Config rule."""
    
    def __init__(self):
        super().__init__(
            rule_name="sagemaker-notebook-instance-kms-key-configured",
            control_id="3.11",
            resource_types=["AWS::SageMaker::NotebookInstance"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get SageMaker notebook instances."""
        if resource_type != "AWS::SageMaker::NotebookInstance":
            return []
            
        try:
            sagemaker_client = aws_factory.get_client('sagemaker', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: sagemaker_client.list_notebook_instances()
            )
            
            instances = []
            for instance in response.get('NotebookInstances', []):
                instances.append({
                    'NotebookInstanceName': instance.get('NotebookInstanceName'),
                    'NotebookInstanceArn': instance.get('NotebookInstanceArn')
                })
            
            return instances
            
        except ClientError as e:
            logger.error(f"Error retrieving SageMaker notebook instances in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if SageMaker notebook instance uses KMS encryption."""
        instance_name = resource.get('NotebookInstanceName', 'unknown')
        
        try:
            sagemaker_client = aws_factory.get_client('sagemaker', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: sagemaker_client.describe_notebook_instance(NotebookInstanceName=instance_name)
            )
            
            kms_key_id = response.get('KmsKeyId')
            
            if kms_key_id:
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = f"SageMaker notebook instance {instance_name} uses KMS encryption"
            else:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = f"SageMaker notebook instance {instance_name} does not use KMS encryption"
                
        except ClientError as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Error checking KMS config for notebook instance {instance_name}: {str(e)}"
        
        return ComplianceResult(
            resource_id=instance_name,
            resource_type="AWS::SageMaker::NotebookInstance",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )


class CodeBuildProjectArtifactEncryptionAssessment(BaseConfigRuleAssessment):
    """Assessment for codebuild-project-artifact-encryption AWS Config rule."""
    
    def __init__(self):
        super().__init__(
            rule_name="codebuild-project-artifact-encryption",
            control_id="3.11",
            resource_types=["AWS::CodeBuild::Project"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get CodeBuild projects."""
        if resource_type != "AWS::CodeBuild::Project":
            return []
            
        try:
            codebuild_client = aws_factory.get_client('codebuild', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: codebuild_client.list_projects()
            )
            
            projects = []
            for project_name in response.get('projects', []):
                projects.append({
                    'name': project_name
                })
            
            return projects
            
        except ClientError as e:
            logger.error(f"Error retrieving CodeBuild projects in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if CodeBuild project has artifact encryption enabled."""
        project_name = resource.get('name', 'unknown')
        
        try:
            codebuild_client = aws_factory.get_client('codebuild', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: codebuild_client.batch_get_projects(names=[project_name])
            )
            
            projects = response.get('projects', [])
            if projects:
                project = projects[0]
                artifacts = project.get('artifacts', {})
                encryption_disabled = artifacts.get('encryptionDisabled', False)
                
                if not encryption_disabled:
                    compliance_status = ComplianceStatus.COMPLIANT
                    evaluation_reason = f"CodeBuild project {project_name} has artifact encryption enabled"
                else:
                    compliance_status = ComplianceStatus.NON_COMPLIANT
                    evaluation_reason = f"CodeBuild project {project_name} has artifact encryption disabled"
            else:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Could not retrieve details for CodeBuild project {project_name}"
                
        except ClientError as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Error checking artifact encryption for project {project_name}: {str(e)}"
        
        return ComplianceResult(
            resource_id=project_name,
            resource_type="AWS::CodeBuild::Project",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )