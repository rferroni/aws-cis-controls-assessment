"""CodeBuild Security Rules - AWS Config rule assessments."""

from typing import Dict, List, Any
import logging
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class CodeBuildProjectEnvironmentPrivilegedCheckAssessment(BaseConfigRuleAssessment):
    """Assessment for codebuild-project-environment-privileged-check AWS Config rule."""
    
    def __init__(self):
        super().__init__(
            rule_name="codebuild-project-environment-privileged-check",
            control_id="3.3",
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
        """Evaluate if CodeBuild project environment is not running in privileged mode."""
        project_name = resource.get('name', 'unknown')
        
        try:
            codebuild_client = aws_factory.get_client('codebuild', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: codebuild_client.batch_get_projects(names=[project_name])
            )
            
            projects = response.get('projects', [])
            if projects:
                project = projects[0]
                environment = project.get('environment', {})
                privileged_mode = environment.get('privilegedMode', False)
                
                if not privileged_mode:
                    compliance_status = ComplianceStatus.COMPLIANT
                    evaluation_reason = f"CodeBuild project {project_name} is not running in privileged mode"
                else:
                    compliance_status = ComplianceStatus.NON_COMPLIANT
                    evaluation_reason = f"CodeBuild project {project_name} is running in privileged mode"
            else:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Could not retrieve details for CodeBuild project {project_name}"
                
        except ClientError as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Error checking privileged mode for project {project_name}: {str(e)}"
        
        return ComplianceResult(
            resource_id=project_name,
            resource_type="AWS::CodeBuild::Project",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )


class CodeBuildProjectEnvVarAWSCredCheckAssessment(BaseConfigRuleAssessment):
    """Assessment for codebuild-project-envvar-awscred-check AWS Config rule."""
    
    def __init__(self):
        super().__init__(
            rule_name="codebuild-project-envvar-awscred-check",
            control_id="3.3",
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
        """Evaluate if CodeBuild project does not expose AWS credentials in environment variables."""
        project_name = resource.get('name', 'unknown')
        
        try:
            codebuild_client = aws_factory.get_client('codebuild', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: codebuild_client.batch_get_projects(names=[project_name])
            )
            
            projects = response.get('projects', [])
            if projects:
                project = projects[0]
                environment = project.get('environment', {})
                env_vars = environment.get('environmentVariables', [])
                
                # Check for AWS credential environment variables
                aws_cred_vars = ['AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN']
                exposed_creds = []
                
                for env_var in env_vars:
                    var_name = env_var.get('name', '')
                    var_type = env_var.get('type', 'PLAINTEXT')
                    
                    if var_name in aws_cred_vars and var_type == 'PLAINTEXT':
                        exposed_creds.append(var_name)
                
                if not exposed_creds:
                    compliance_status = ComplianceStatus.COMPLIANT
                    evaluation_reason = f"CodeBuild project {project_name} does not expose AWS credentials in environment variables"
                else:
                    compliance_status = ComplianceStatus.NON_COMPLIANT
                    evaluation_reason = f"CodeBuild project {project_name} exposes AWS credentials: {', '.join(exposed_creds)}"
            else:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Could not retrieve details for CodeBuild project {project_name}"
                
        except ClientError as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Error checking environment variables for project {project_name}: {str(e)}"
        
        return ComplianceResult(
            resource_id=project_name,
            resource_type="AWS::CodeBuild::Project",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )


class CodeBuildProjectSourceRepoURLCheckAssessment(BaseConfigRuleAssessment):
    """Assessment for codebuild-project-source-repo-url-check AWS Config rule."""
    
    def __init__(self):
        super().__init__(
            rule_name="codebuild-project-source-repo-url-check",
            control_id="3.3",
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
        """Evaluate if CodeBuild project source repository URL is from approved sources."""
        project_name = resource.get('name', 'unknown')
        
        try:
            codebuild_client = aws_factory.get_client('codebuild', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: codebuild_client.batch_get_projects(names=[project_name])
            )
            
            projects = response.get('projects', [])
            if projects:
                project = projects[0]
                source = project.get('source', {})
                source_type = source.get('type', '')
                location = source.get('location', '')
                
                # Define approved source types and patterns
                approved_sources = [
                    'CODECOMMIT',
                    'CODEPIPELINE',
                    'S3'
                ]
                
                # Check for GitHub/Bitbucket with HTTPS
                if source_type in ['GITHUB', 'BITBUCKET', 'GITHUB_ENTERPRISE']:
                    if location.startswith('https://'):
                        compliance_status = ComplianceStatus.COMPLIANT
                        evaluation_reason = f"CodeBuild project {project_name} uses secure HTTPS source URL"
                    else:
                        compliance_status = ComplianceStatus.NON_COMPLIANT
                        evaluation_reason = f"CodeBuild project {project_name} uses insecure source URL (not HTTPS)"
                elif source_type in approved_sources:
                    compliance_status = ComplianceStatus.COMPLIANT
                    evaluation_reason = f"CodeBuild project {project_name} uses approved source type: {source_type}"
                else:
                    compliance_status = ComplianceStatus.NON_COMPLIANT
                    evaluation_reason = f"CodeBuild project {project_name} uses unapproved source type: {source_type}"
            else:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Could not retrieve details for CodeBuild project {project_name}"
                
        except ClientError as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Error checking source repository for project {project_name}: {str(e)}"
        
        return ComplianceResult(
            resource_id=project_name,
            resource_type="AWS::CodeBuild::Project",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )