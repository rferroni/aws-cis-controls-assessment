"""Control 3.10: Encrypt Sensitive Data in Transit assessments."""

from typing import Dict, List, Any
import logging
import json
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class APIGatewaySSLEnabledAssessment(BaseConfigRuleAssessment):
    """Assessment for api-gw-ssl-enabled Config rule - ensures API Gateway stages have SSL certificates."""
    
    def __init__(self):
        """Initialize API Gateway SSL enabled assessment."""
        super().__init__(
            rule_name="api-gw-ssl-enabled",
            control_id="3.10",
            resource_types=["AWS::ApiGateway::Stage"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all API Gateway stages in the region."""
        if resource_type != "AWS::ApiGateway::Stage":
            return []
        
        try:
            apigateway_client = aws_factory.get_client('apigateway', region)
            
            # First get all REST APIs
            apis_response = aws_factory.aws_api_call_with_retry(
                lambda: apigateway_client.get_rest_apis()
            )
            
            stages = []
            for api in apis_response.get('items', []):
                api_id = api.get('id')
                api_name = api.get('name', 'Unknown')
                
                try:
                    # Get stages for each API
                    stages_response = aws_factory.aws_api_call_with_retry(
                        lambda: apigateway_client.get_stages(restApiId=api_id)
                    )
                    
                    for stage in stages_response.get('item', []):
                        stages.append({
                            'restApiId': api_id,
                            'apiName': api_name,
                            'stageName': stage.get('stageName'),
                            'clientCertificateId': stage.get('clientCertificateId'),
                            'methodSettings': stage.get('methodSettings', {}),
                            'tags': stage.get('tags', {})
                        })
                        
                except ClientError as e:
                    logger.warning(f"Could not get stages for API {api_id}: {e}")
                    continue
            
            logger.debug(f"Found {len(stages)} API Gateway stages in region {region}")
            return stages
            
        except ClientError as e:
            logger.error(f"Error retrieving API Gateway stages in region {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving API Gateway stages in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if API Gateway stage has SSL certificate configured."""
        api_id = resource.get('restApiId', 'unknown')
        stage_name = resource.get('stageName', 'unknown')
        api_name = resource.get('apiName', 'Unknown')
        client_cert_id = resource.get('clientCertificateId')
        method_settings = resource.get('methodSettings', {})
        
        resource_id = f"{api_id}/{stage_name}"
        
        # Check if client certificate is configured
        has_client_cert = bool(client_cert_id)
        
        # Check if HTTPS is required in method settings
        https_required = False
        for method_key, settings in method_settings.items():
            if settings.get('requireAuthorizationForCacheControl', False):
                https_required = True
                break
        
        # For this rule, we primarily check for client certificate
        if has_client_cert:
            compliance_status = ComplianceStatus.COMPLIANT
            evaluation_reason = f"API Gateway stage {stage_name} (API: {api_name}) has client certificate configured: {client_cert_id}"
        else:
            # Check if this is a public API that might not need client certificates
            # For now, we'll mark as non-compliant if no client certificate
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = f"API Gateway stage {stage_name} (API: {api_name}) does not have a client certificate configured"
        
        return ComplianceResult(
            resource_id=resource_id,
            resource_type="AWS::ApiGateway::Stage",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for API Gateway SSL configuration."""
        return [
            "Identify API Gateway stages without SSL certificates configured",
            "For each non-compliant stage:",
            "  1. Generate or import a client certificate in API Gateway",
            "  2. Associate the client certificate with the stage",
            "  3. Configure method settings to require HTTPS",
            "Use AWS CLI: aws apigateway generate-client-certificate --description 'Client cert for API'",
            "Associate certificate: aws apigateway update-stage --rest-api-id <api-id> --stage-name <stage> --patch-ops op=replace,path=/clientCertificateId,value=<cert-id>",
            "Configure custom domain with SSL certificate for production APIs",
            "Enable CloudTrail logging for API Gateway to monitor SSL usage",
            "Review API Gateway access logs to ensure HTTPS usage"
        ]


class ALBHTTPToHTTPSRedirectionAssessment(BaseConfigRuleAssessment):
    """Assessment for alb-http-to-https-redirection-check Config rule."""
    
    def __init__(self):
        """Initialize ALB HTTP to HTTPS redirection assessment."""
        super().__init__(
            rule_name="alb-http-to-https-redirection-check",
            control_id="3.10",
            resource_types=["AWS::ElasticLoadBalancingV2::LoadBalancer"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all Application Load Balancers in the region."""
        if resource_type != "AWS::ElasticLoadBalancingV2::LoadBalancer":
            return []
        
        try:
            elbv2_client = aws_factory.get_client('elbv2', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: elbv2_client.describe_load_balancers()
            )
            
            albs = []
            for lb in response.get('LoadBalancers', []):
                # Only include Application Load Balancers
                if lb.get('Type') == 'application':
                    albs.append({
                        'LoadBalancerArn': lb.get('LoadBalancerArn'),
                        'LoadBalancerName': lb.get('LoadBalancerName'),
                        'DNSName': lb.get('DNSName'),
                        'Scheme': lb.get('Scheme'),
                        'State': lb.get('State', {}),
                        'Type': lb.get('Type')
                    })
            
            logger.debug(f"Found {len(albs)} Application Load Balancers in region {region}")
            return albs
            
        except ClientError as e:
            logger.error(f"Error retrieving ALBs in region {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving ALBs in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if ALB has HTTP to HTTPS redirection configured."""
        lb_arn = resource.get('LoadBalancerArn', 'unknown')
        lb_name = resource.get('LoadBalancerName', 'unknown')
        
        try:
            elbv2_client = aws_factory.get_client('elbv2', region)
            
            # Get listeners for this load balancer
            listeners_response = aws_factory.aws_api_call_with_retry(
                lambda: elbv2_client.describe_listeners(LoadBalancerArn=lb_arn)
            )
            
            listeners = listeners_response.get('Listeners', [])
            http_listeners = []
            https_listeners = []
            http_redirect_listeners = []
            
            for listener in listeners:
                protocol = listener.get('Protocol', '')
                port = listener.get('Port', 0)
                
                if protocol == 'HTTP':
                    http_listeners.append(listener)
                    
                    # Check if this HTTP listener has redirect actions
                    default_actions = listener.get('DefaultActions', [])
                    for action in default_actions:
                        if action.get('Type') == 'redirect':
                            redirect_config = action.get('RedirectConfig', {})
                            if redirect_config.get('Protocol') == 'HTTPS':
                                http_redirect_listeners.append(listener)
                                break
                
                elif protocol == 'HTTPS':
                    https_listeners.append(listener)
            
            # Evaluate compliance
            if not http_listeners:
                # No HTTP listeners, so no redirection needed
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = f"ALB {lb_name} has no HTTP listeners"
            elif len(http_redirect_listeners) == len(http_listeners):
                # All HTTP listeners have HTTPS redirection
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = f"ALB {lb_name} has HTTP to HTTPS redirection configured for all HTTP listeners"
            else:
                # Some HTTP listeners don't have HTTPS redirection
                non_redirect_count = len(http_listeners) - len(http_redirect_listeners)
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = f"ALB {lb_name} has {non_redirect_count} HTTP listener(s) without HTTPS redirection"
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code in ['AccessDenied', 'UnauthorizedOperation']:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Insufficient permissions to check listeners for ALB {lb_name}"
            else:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Error checking listeners for ALB {lb_name}: {str(e)}"
        except Exception as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Unexpected error checking listeners for ALB {lb_name}: {str(e)}"
        
        return ComplianceResult(
            resource_id=lb_arn,
            resource_type="AWS::ElasticLoadBalancingV2::LoadBalancer",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for ALB HTTP to HTTPS redirection."""
        return [
            "Identify Application Load Balancers with HTTP listeners that don't redirect to HTTPS",
            "For each non-compliant ALB:",
            "  1. Modify HTTP listeners to add redirect actions",
            "  2. Configure redirect to HTTPS with appropriate status code (301 or 302)",
            "  3. Ensure HTTPS listeners are configured with valid SSL certificates",
            "Use AWS CLI: aws elbv2 modify-listener --listener-arn <listener-arn> --default-actions Type=redirect,RedirectConfig='{Protocol=HTTPS,Port=443,StatusCode=HTTP_301}'",
            "Create HTTPS listener if not exists: aws elbv2 create-listener --load-balancer-arn <lb-arn> --protocol HTTPS --port 443 --certificates CertificateArn=<cert-arn>",
            "Test redirection by accessing HTTP URLs and verifying HTTPS redirect",
            "Update security groups to allow HTTPS traffic (port 443)",
            "Consider removing HTTP listeners entirely if HTTPS-only is acceptable"
        ]


class ELBTLSHTTPSListenersOnlyAssessment(BaseConfigRuleAssessment):
    """Assessment for elb-tls-https-listeners-only Config rule."""
    
    def __init__(self):
        """Initialize ELB TLS/HTTPS listeners only assessment."""
        super().__init__(
            rule_name="elb-tls-https-listeners-only",
            control_id="3.10",
            resource_types=["AWS::ElasticLoadBalancing::LoadBalancer"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all Classic Load Balancers in the region."""
        if resource_type != "AWS::ElasticLoadBalancing::LoadBalancer":
            return []
        
        try:
            elb_client = aws_factory.get_client('elb', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: elb_client.describe_load_balancers()
            )
            
            elbs = []
            for lb in response.get('LoadBalancerDescriptions', []):
                elbs.append({
                    'LoadBalancerName': lb.get('LoadBalancerName'),
                    'DNSName': lb.get('DNSName'),
                    'Scheme': lb.get('Scheme'),
                    'ListenerDescriptions': lb.get('ListenerDescriptions', []),
                    'AvailabilityZones': lb.get('AvailabilityZones', [])
                })
            
            logger.debug(f"Found {len(elbs)} Classic Load Balancers in region {region}")
            return elbs
            
        except ClientError as e:
            logger.error(f"Error retrieving Classic ELBs in region {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving Classic ELBs in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if ELB uses only TLS/HTTPS listeners."""
        lb_name = resource.get('LoadBalancerName', 'unknown')
        listener_descriptions = resource.get('ListenerDescriptions', [])
        
        secure_protocols = ['HTTPS', 'SSL', 'TLS']
        insecure_protocols = ['HTTP', 'TCP']
        
        secure_listeners = []
        insecure_listeners = []
        
        for listener_desc in listener_descriptions:
            listener = listener_desc.get('Listener', {})
            protocol = listener.get('Protocol', '')
            load_balancer_port = listener.get('LoadBalancerPort', 0)
            
            if protocol in secure_protocols:
                secure_listeners.append({
                    'protocol': protocol,
                    'port': load_balancer_port
                })
            elif protocol in insecure_protocols:
                # For TCP, we need to check the port to determine if it's likely secure
                if protocol == 'TCP' and load_balancer_port in [443, 8443, 9443]:
                    # TCP on HTTPS ports is likely secure
                    secure_listeners.append({
                        'protocol': protocol,
                        'port': load_balancer_port
                    })
                else:
                    insecure_listeners.append({
                        'protocol': protocol,
                        'port': load_balancer_port
                    })
        
        # Evaluate compliance
        if not listener_descriptions:
            compliance_status = ComplianceStatus.NOT_APPLICABLE
            evaluation_reason = f"ELB {lb_name} has no listeners configured"
        elif not insecure_listeners:
            compliance_status = ComplianceStatus.COMPLIANT
            secure_count = len(secure_listeners)
            evaluation_reason = f"ELB {lb_name} uses only secure protocols ({secure_count} secure listener(s))"
        else:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            insecure_count = len(insecure_listeners)
            insecure_details = [f"{l['protocol']}:{l['port']}" for l in insecure_listeners]
            evaluation_reason = f"ELB {lb_name} has {insecure_count} insecure listener(s): {', '.join(insecure_details)}"
        
        return ComplianceResult(
            resource_id=lb_name,
            resource_type="AWS::ElasticLoadBalancing::LoadBalancer",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for ELB secure listeners."""
        return [
            "Identify Classic Load Balancers with insecure listeners (HTTP, TCP on non-secure ports)",
            "For each non-compliant ELB:",
            "  1. Create HTTPS/SSL listeners to replace HTTP/insecure TCP listeners",
            "  2. Upload or import SSL certificates for HTTPS/SSL listeners",
            "  3. Update security groups to allow HTTPS/SSL traffic",
            "  4. Remove or modify insecure listeners",
            "Use AWS CLI: aws elb create-load-balancer-listeners --load-balancer-name <lb-name> --listeners Protocol=HTTPS,LoadBalancerPort=443,InstanceProtocol=HTTP,InstancePort=80,SSLCertificateId=<cert-arn>",
            "Delete insecure listeners: aws elb delete-load-balancer-listeners --load-balancer-name <lb-name> --load-balancer-ports 80",
            "Test connectivity after changes to ensure applications work correctly",
            "Consider migrating to Application Load Balancer (ALB) for better SSL/TLS features",
            "Update DNS records and application configurations to use HTTPS URLs"
        ]


class S3BucketSSLRequestsOnlyAssessment(BaseConfigRuleAssessment):
    """Assessment for s3-bucket-ssl-requests-only Config rule."""
    
    def __init__(self):
        """Initialize S3 bucket SSL requests only assessment."""
        super().__init__(
            rule_name="s3-bucket-ssl-requests-only",
            control_id="3.10",
            resource_types=["AWS::S3::Bucket"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all S3 buckets (S3 is global but we'll check from this region)."""
        if resource_type != "AWS::S3::Bucket":
            return []
        
        try:
            s3_client = aws_factory.get_client('s3', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: s3_client.list_buckets()
            )
            
            buckets = []
            for bucket in response.get('Buckets', []):
                bucket_name = bucket.get('Name')
                
                # Get bucket location to determine if we should evaluate it from this region
                try:
                    location_response = aws_factory.aws_api_call_with_retry(
                        lambda: s3_client.get_bucket_location(Bucket=bucket_name)
                    )
                    bucket_region = location_response.get('LocationConstraint')
                    
                    # Handle special case where us-east-1 returns None
                    if bucket_region is None:
                        bucket_region = 'us-east-1'
                    
                    # Only include buckets in this region or if we're in us-east-1 (global)
                    if bucket_region == region or region == 'us-east-1':
                        buckets.append({
                            'Name': bucket_name,
                            'CreationDate': bucket.get('CreationDate'),
                            'Region': bucket_region
                        })
                        
                except ClientError as e:
                    # If we can't get bucket location, skip this bucket
                    logger.warning(f"Could not get location for bucket {bucket_name}: {e}")
                    continue
            
            logger.debug(f"Found {len(buckets)} S3 buckets accessible from region {region}")
            return buckets
            
        except ClientError as e:
            logger.error(f"Error retrieving S3 buckets from region {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving S3 buckets from region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if S3 bucket has policy requiring SSL requests."""
        bucket_name = resource.get('Name', 'unknown')
        bucket_region = resource.get('Region', region)
        
        try:
            # Use the bucket's region for API calls
            s3_client = aws_factory.get_client('s3', bucket_region)
            
            # Get bucket policy
            try:
                policy_response = aws_factory.aws_api_call_with_retry(
                    lambda: s3_client.get_bucket_policy(Bucket=bucket_name)
                )
                
                policy_document = policy_response.get('Policy', '{}')
                policy = json.loads(policy_document)
                
                # Check if policy denies non-SSL requests
                has_ssl_deny_policy = self._check_ssl_deny_policy(policy)
                
                if has_ssl_deny_policy:
                    compliance_status = ComplianceStatus.COMPLIANT
                    evaluation_reason = f"S3 bucket {bucket_name} has policy requiring SSL requests"
                else:
                    compliance_status = ComplianceStatus.NON_COMPLIANT
                    evaluation_reason = f"S3 bucket {bucket_name} does not have policy requiring SSL requests"
                
            except ClientError as e:
                error_code = e.response.get('Error', {}).get('Code', '')
                if error_code == 'NoSuchBucketPolicy':
                    compliance_status = ComplianceStatus.NON_COMPLIANT
                    evaluation_reason = f"S3 bucket {bucket_name} has no bucket policy (SSL not required)"
                elif error_code in ['AccessDenied', 'UnauthorizedOperation']:
                    compliance_status = ComplianceStatus.ERROR
                    evaluation_reason = f"Insufficient permissions to check bucket policy for {bucket_name}"
                else:
                    compliance_status = ComplianceStatus.ERROR
                    evaluation_reason = f"Error checking bucket policy for {bucket_name}: {str(e)}"
            
        except Exception as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Unexpected error checking SSL policy for bucket {bucket_name}: {str(e)}"
        
        return ComplianceResult(
            resource_id=bucket_name,
            resource_type="AWS::S3::Bucket",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=bucket_region
        )
    
    def _check_ssl_deny_policy(self, policy: Dict[str, Any]) -> bool:
        """Check if bucket policy denies non-SSL requests."""
        statements = policy.get('Statement', [])
        
        for statement in statements:
            effect = statement.get('Effect', '')
            condition = statement.get('Condition', {})
            
            # Look for Deny statements with SSL condition
            if effect == 'Deny':
                # Check for aws:SecureTransport condition
                bool_conditions = condition.get('Bool', {})
                if 'aws:SecureTransport' in bool_conditions:
                    secure_transport = bool_conditions['aws:SecureTransport']
                    # Policy should deny when SecureTransport is false
                    if secure_transport == 'false' or secure_transport is False:
                        return True
        
        return False
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for S3 SSL-only policy."""
        return [
            "Identify S3 buckets without SSL-only access policies",
            "For each non-compliant bucket:",
            "  1. Create or update bucket policy to deny non-SSL requests",
            "  2. Add condition 'aws:SecureTransport': 'false' with Effect: Deny",
            "  3. Test policy to ensure it works correctly",
            "Example bucket policy to deny non-SSL requests:",
            '''{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureConnections",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::BUCKET_NAME",
        "arn:aws:s3:::BUCKET_NAME/*"
      ],
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    }
  ]
}''',
            "Use AWS CLI: aws s3api put-bucket-policy --bucket <bucket-name> --policy file://ssl-only-policy.json",
            "Test with HTTP request to verify denial",
            "Update applications to use HTTPS for S3 access"
        ]


class RedshiftRequireTLSSSLAssessment(BaseConfigRuleAssessment):
    """Assessment for redshift-require-tls-ssl Config rule."""
    
    def __init__(self):
        """Initialize Redshift require TLS/SSL assessment."""
        super().__init__(
            rule_name="redshift-require-tls-ssl",
            control_id="3.10",
            resource_types=["AWS::Redshift::Cluster"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all Redshift clusters in the region."""
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
                    'ClusterStatus': cluster.get('ClusterStatus'),
                    'NodeType': cluster.get('NodeType'),
                    'NumberOfNodes': cluster.get('NumberOfNodes'),
                    'Endpoint': cluster.get('Endpoint', {}),
                    'ClusterParameterGroups': cluster.get('ClusterParameterGroups', []),
                    'Tags': cluster.get('Tags', [])
                })
            
            logger.debug(f"Found {len(clusters)} Redshift clusters in region {region}")
            return clusters
            
        except ClientError as e:
            logger.error(f"Error retrieving Redshift clusters in region {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving Redshift clusters in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if Redshift cluster requires TLS/SSL connections."""
        cluster_id = resource.get('ClusterIdentifier', 'unknown')
        cluster_status = resource.get('ClusterStatus', 'unknown')
        parameter_groups = resource.get('ClusterParameterGroups', [])
        
        # Skip clusters that are not available
        if cluster_status not in ['available']:
            return ComplianceResult(
                resource_id=cluster_id,
                resource_type="AWS::Redshift::Cluster",
                compliance_status=ComplianceStatus.NOT_APPLICABLE,
                evaluation_reason=f"Redshift cluster {cluster_id} is in status '{cluster_status}', not available",
                config_rule_name=self.rule_name,
                region=region
            )
        
        try:
            redshift_client = aws_factory.get_client('redshift', region)
            
            # Check parameter groups for require_ssl setting
            ssl_required = False
            checked_groups = []
            
            for param_group in parameter_groups:
                group_name = param_group.get('ParameterGroupName')
                if group_name:
                    checked_groups.append(group_name)
                    
                    try:
                        # Get parameters for this group
                        params_response = aws_factory.aws_api_call_with_retry(
                            lambda: redshift_client.describe_cluster_parameters(
                                ParameterGroupName=group_name,
                                Source='user'
                            )
                        )
                        
                        parameters = params_response.get('Parameters', [])
                        
                        # Look for require_ssl parameter
                        for param in parameters:
                            if param.get('ParameterName') == 'require_ssl':
                                param_value = param.get('ParameterValue', 'false')
                                if param_value.lower() == 'true':
                                    ssl_required = True
                                    break
                        
                        if ssl_required:
                            break
                            
                    except ClientError as e:
                        logger.warning(f"Could not get parameters for group {group_name}: {e}")
                        continue
            
            # Evaluate compliance
            if ssl_required:
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = f"Redshift cluster {cluster_id} has require_ssl parameter set to true"
            else:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                if checked_groups:
                    evaluation_reason = f"Redshift cluster {cluster_id} does not have require_ssl parameter set to true (checked groups: {', '.join(checked_groups)})"
                else:
                    evaluation_reason = f"Redshift cluster {cluster_id} has no parameter groups to check for SSL requirement"
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code in ['AccessDenied', 'UnauthorizedOperation']:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Insufficient permissions to check parameters for Redshift cluster {cluster_id}"
            else:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Error checking SSL parameters for Redshift cluster {cluster_id}: {str(e)}"
        except Exception as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Unexpected error checking SSL parameters for Redshift cluster {cluster_id}: {str(e)}"
        
        return ComplianceResult(
            resource_id=cluster_id,
            resource_type="AWS::Redshift::Cluster",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for Redshift SSL requirement."""
        return [
            "Identify Redshift clusters without SSL requirement enabled",
            "For each non-compliant cluster:",
            "  1. Create or modify cluster parameter group to set require_ssl=true",
            "  2. Apply the parameter group to the cluster",
            "  3. Reboot the cluster to apply the parameter change",
            "Use AWS CLI: aws redshift create-cluster-parameter-group --parameter-group-name ssl-required-group --parameter-group-family redshift-1.0 --description 'Parameter group requiring SSL'",
            "Set parameter: aws redshift modify-cluster-parameter-group --parameter-group-name ssl-required-group --parameters ParameterName=require_ssl,ParameterValue=true",
            "Apply to cluster: aws redshift modify-cluster --cluster-identifier <cluster-id> --cluster-parameter-group-name ssl-required-group",
            "Reboot cluster: aws redshift reboot-cluster --cluster-identifier <cluster-id>",
            "Update client applications to use SSL connections",
            "Test connectivity with SSL to ensure applications work correctly",
            "Monitor cluster performance after enabling SSL requirement"
        ]