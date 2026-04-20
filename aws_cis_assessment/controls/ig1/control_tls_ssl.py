"""
CIS Control 2.8-2.10, 2.12, 4.9 - TLS/SSL Encryption Controls
Ensures data in transit is encrypted using TLS/SSL protocols.
"""

import logging
from typing import List, Dict, Any
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class ALBHTTPToHTTPSRedirectionAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 3.10 - Encrypt Sensitive Data in Transit
    AWS Config Rule: alb-http-to-https-redirection-check
    
    Ensures Application Load Balancers redirect HTTP traffic to HTTPS.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="alb-http-to-https-redirection-check",
            control_id="3.10",
            resource_types=["AWS::ElasticLoadBalancingV2::LoadBalancer"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all ALBs and check for HTTP to HTTPS redirection."""
        if resource_type != "AWS::ElasticLoadBalancingV2::LoadBalancer":
            return []
        
        try:
            elbv2_client = aws_factory.get_client('elbv2', region)
            
            load_balancers = []
            paginator = elbv2_client.get_paginator('describe_load_balancers')
            
            for page in paginator.paginate():
                for lb in page.get('LoadBalancers', []):
                    lb_arn = lb.get('LoadBalancerArn', '')
                    lb_name = lb.get('LoadBalancerName', '')
                    lb_type = lb.get('Type', '')
                    
                    # Only check Application Load Balancers
                    if lb_type != 'application':
                        continue
                    
                    # Get listeners for this ALB
                    listeners_response = elbv2_client.describe_listeners(LoadBalancerArn=lb_arn)
                    listeners = listeners_response.get('Listeners', [])
                    
                    http_listeners = []
                    has_http_redirect = False
                    
                    for listener in listeners:
                        protocol = listener.get('Protocol', '')
                        listener_arn = listener.get('ListenerArn', '')
                        
                        if protocol == 'HTTP':
                            # Check if this HTTP listener has redirect action
                            default_actions = listener.get('DefaultActions', [])
                            for action in default_actions:
                                if action.get('Type') == 'redirect':
                                    redirect_config = action.get('RedirectConfig', {})
                                    if redirect_config.get('Protocol') == 'HTTPS':
                                        has_http_redirect = True
                                        break
                            
                            http_listeners.append({
                                'ListenerArn': listener_arn,
                                'Port': listener.get('Port', 0),
                                'HasRedirect': has_http_redirect
                            })
                    
                    if http_listeners:  # Only include ALBs with HTTP listeners
                        load_balancers.append({
                            'LoadBalancerArn': lb_arn,
                            'LoadBalancerName': lb_name,
                            'HTTPListeners': http_listeners,
                            'HasHTTPRedirect': has_http_redirect
                        })
            
            logger.debug(f"Found {len(load_balancers)} ALBs with HTTP listeners in {region}")
            return load_balancers
            
        except ClientError as e:
            logger.error(f"Error retrieving ALBs from {region}: {e}")
            return []
    
    def _evaluate_resource_compliance(
        self, 
        resource: Dict[str, Any], 
        aws_factory: AWSClientFactory, 
        region: str
    ) -> ComplianceResult:
        """Evaluate if ALB redirects HTTP to HTTPS."""
        lb_arn = resource.get('LoadBalancerArn', 'unknown')
        lb_name = resource.get('LoadBalancerName', '')
        has_http_redirect = resource.get('HasHTTPRedirect', False)
        http_listeners = resource.get('HTTPListeners', [])
        
        if has_http_redirect:
            evaluation_reason = (
                f"ALB '{lb_name}' has HTTP to HTTPS redirection configured on {len(http_listeners)} listener(s)."
            )
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            evaluation_reason = (
                f"ALB '{lb_name}' has {len(http_listeners)} HTTP listener(s) without HTTPS redirection. "
                f"HTTP traffic should be redirected to HTTPS."
            )
            compliance_status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceResult(
            resource_id=lb_arn,
            resource_type="AWS::ElasticLoadBalancingV2::LoadBalancer",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get remediation steps for configuring HTTP to HTTPS redirection."""
        return [
            "1. Configure HTTP to HTTPS redirection via Console:",
            "   - Navigate to EC2 > Load Balancers",
            "   - Select the ALB",
            "   - Click 'Listeners' tab",
            "   - Select HTTP:80 listener",
            "   - Click 'Edit'",
            "   - Remove existing default action",
            "   - Add action: 'Redirect to...'",
            "   - Protocol: HTTPS",
            "   - Port: 443",
            "   - Status code: 301 (Permanent) or 302 (Temporary)",
            "   - Click 'Save'",
            "",
            "2. Configure via AWS CLI:",
            "   aws elbv2 modify-listener \\",
            "     --listener-arn <listener-arn> \\",
            "     --default-actions Type=redirect,RedirectConfig='{Protocol=HTTPS,Port=443,StatusCode=HTTP_301}' \\",
            "     --region <region>",
            "",
            "3. Create new HTTP listener with redirect:",
            "   aws elbv2 create-listener \\",
            "     --load-balancer-arn <lb-arn> \\",
            "     --protocol HTTP \\",
            "     --port 80 \\",
            "     --default-actions Type=redirect,RedirectConfig='{Protocol=HTTPS,Port=443,StatusCode=HTTP_301}' \\",
            "     --region <region>",
            "",
            "4. Best practices:",
            "   - Use 301 (permanent) redirect for production",
            "   - Ensure HTTPS listener (443) exists",
            "   - Use valid SSL/TLS certificate",
            "   - Enable HTTP/2 for better performance",
            "   - Consider HSTS headers for additional security",
            "",
            "Priority: HIGH - Unencrypted HTTP traffic exposes data",
            "Effort: Low - Simple listener configuration change",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/listener-update-rules.html"
        ]


class ELBTLSHTTPSListenersOnlyAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 2.9 - Encrypt Sensitive Data in Transit
    AWS Config Rule: elb-tls-https-listeners-only
    
    Ensures ELBs only use HTTPS/TLS listeners for encrypted communication.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="elb-tls-https-listeners-only",
            control_id="2.9",
            resource_types=["AWS::ElasticLoadBalancingV2::LoadBalancer"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all ELBs and check listener protocols."""
        if resource_type != "AWS::ElasticLoadBalancingV2::LoadBalancer":
            return []
        
        try:
            elbv2_client = aws_factory.get_client('elbv2', region)
            
            load_balancers = []
            paginator = elbv2_client.get_paginator('describe_load_balancers')
            
            for page in paginator.paginate():
                for lb in page.get('LoadBalancers', []):
                    lb_arn = lb.get('LoadBalancerArn', '')
                    lb_name = lb.get('LoadBalancerName', '')
                    
                    # Get listeners
                    listeners_response = elbv2_client.describe_listeners(LoadBalancerArn=lb_arn)
                    listeners = listeners_response.get('Listeners', [])
                    
                    listener_protocols = []
                    has_non_tls = False
                    
                    for listener in listeners:
                        protocol = listener.get('Protocol', '')
                        listener_protocols.append(protocol)
                        
                        if protocol not in ['HTTPS', 'TLS']:
                            has_non_tls = True
                    
                    load_balancers.append({
                        'LoadBalancerArn': lb_arn,
                        'LoadBalancerName': lb_name,
                        'ListenerProtocols': listener_protocols,
                        'HasNonTLS': has_non_tls,
                        'OnlyTLS': not has_non_tls and len(listener_protocols) > 0
                    })
            
            logger.debug(f"Found {len(load_balancers)} ELBs in {region}")
            return load_balancers
            
        except ClientError as e:
            logger.error(f"Error retrieving ELBs from {region}: {e}")
            return []
    
    def _evaluate_resource_compliance(
        self, 
        resource: Dict[str, Any], 
        aws_factory: AWSClientFactory, 
        region: str
    ) -> ComplianceResult:
        """Evaluate if ELB only uses TLS/HTTPS listeners."""
        lb_arn = resource.get('LoadBalancerArn', 'unknown')
        lb_name = resource.get('LoadBalancerName', '')
        only_tls = resource.get('OnlyTLS', False)
        protocols = resource.get('ListenerProtocols', [])
        
        if only_tls:
            evaluation_reason = (
                f"ELB '{lb_name}' only uses secure protocols: {', '.join(protocols)}"
            )
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            non_tls = [p for p in protocols if p not in ['HTTPS', 'TLS']]
            evaluation_reason = (
                f"ELB '{lb_name}' has non-TLS listeners: {', '.join(non_tls)}. "
                f"Only HTTPS/TLS listeners should be used."
            )
            compliance_status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceResult(
            resource_id=lb_arn,
            resource_type="AWS::ElasticLoadBalancingV2::LoadBalancer",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get remediation steps for using only TLS/HTTPS listeners."""
        return [
            "1. Replace HTTP listeners with HTTPS:",
            "   - Delete HTTP listener or configure redirect (see alb-http-to-https-redirection)",
            "   - Create HTTPS listener with SSL certificate",
            "",
            "2. Create HTTPS listener via CLI:",
            "   aws elbv2 create-listener \\",
            "     --load-balancer-arn <lb-arn> \\",
            "     --protocol HTTPS \\",
            "     --port 443 \\",
            "     --certificates CertificateArn=<cert-arn> \\",
            "     --default-actions Type=forward,TargetGroupArn=<target-group-arn> \\",
            "     --region <region>",
            "",
            "3. Configure SSL/TLS policy:",
            "   aws elbv2 modify-listener \\",
            "     --listener-arn <listener-arn> \\",
            "     --ssl-policy ELBSecurityPolicy-TLS-1-2-2017-01 \\",
            "     --region <region>",
            "",
            "4. Best practices:",
            "   - Use TLS 1.2 or higher",
            "   - Use strong cipher suites",
            "   - Obtain certificates from AWS Certificate Manager",
            "   - Enable automatic certificate renewal",
            "",
            "Priority: HIGH - Unencrypted listeners expose data in transit",
            "Effort: Medium - Requires SSL certificate and listener reconfiguration",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/elasticloadbalancing/latest/application/create-https-listener.html"
        ]



class RDSSSLConnectionRequiredAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 2.10 - Encrypt Sensitive Data in Transit
    AWS Config Rule: rds-ssl-connection-required
    
    Ensures RDS instances require SSL/TLS connections.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="rds-ssl-connection-required",
            control_id="2.10",
            resource_types=["AWS::RDS::DBInstance"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get RDS instances and check SSL requirement."""
        if resource_type != "AWS::RDS::DBInstance":
            return []
        
        try:
            rds_client = aws_factory.get_client('rds', region)
            
            instances = []
            paginator = rds_client.get_paginator('describe_db_instances')
            
            for page in paginator.paginate():
                for db in page.get('DBInstances', []):
                    db_id = db.get('DBInstanceIdentifier', '')
                    engine = db.get('Engine', '')
                    
                    # Check parameter group for SSL requirement
                    param_groups = db.get('DBParameterGroups', [])
                    ssl_required = False
                    
                    for pg in param_groups:
                        pg_name = pg.get('DBParameterGroupName', '')
                        try:
                            params = rds_client.describe_db_parameters(
                                DBParameterGroupName=pg_name,
                                Source='user'
                            )
                            for param in params.get('Parameters', []):
                                param_name = param.get('ParameterName', '')
                                param_value = param.get('ParameterValue', '')
                                
                                # Check engine-specific SSL parameters
                                if engine.startswith('postgres') and param_name == 'rds.force_ssl' and param_value == '1':
                                    ssl_required = True
                                elif engine.startswith('mysql') and param_name == 'require_secure_transport' and param_value == '1':
                                    ssl_required = True
                        except ClientError:
                            pass
                    
                    instances.append({
                        'DBInstanceIdentifier': db_id,
                        'Engine': engine,
                        'SSLRequired': ssl_required
                    })
            
            return instances
        except ClientError as e:
            logger.error(f"Error retrieving RDS instances: {e}")
            return []
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if RDS requires SSL."""
        db_id = resource.get('DBInstanceIdentifier', 'unknown')
        ssl_required = resource.get('SSLRequired', False)
        engine = resource.get('Engine', '')
        
        if ssl_required:
            return ComplianceResult(
                resource_id=db_id,
                resource_type="AWS::RDS::DBInstance",
                compliance_status=ComplianceStatus.COMPLIANT,
                evaluation_reason=f"RDS instance '{db_id}' ({engine}) requires SSL connections.",
                config_rule_name=self.rule_name,
                region=region
            )
        else:
            return ComplianceResult(
                resource_id=db_id,
                resource_type="AWS::RDS::DBInstance",
                compliance_status=ComplianceStatus.NON_COMPLIANT,
                evaluation_reason=f"RDS instance '{db_id}' ({engine}) does not require SSL connections.",
                config_rule_name=self.rule_name,
                region=region
            )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        return [
            "1. For PostgreSQL, set rds.force_ssl=1 in parameter group",
            "2. For MySQL, set require_secure_transport=1",
            "3. Reboot instance to apply changes",
            "Priority: HIGH",
            "Effort: Low",
            "AWS Documentation: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/UsingWithRDS.SSL.html"
        ]


class APIGatewaySSLEnabledAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 2.12 - Encrypt Sensitive Data in Transit
    AWS Config Rule: api-gateway-ssl-enabled
    
    Ensures API Gateway stages use SSL/TLS certificates.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="api-gateway-ssl-enabled",
            control_id="2.12",
            resource_types=["AWS::ApiGateway::Stage"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get API Gateway stages and check SSL configuration."""
        if resource_type != "AWS::ApiGateway::Stage":
            return []
        
        try:
            apigw_client = aws_factory.get_client('apigateway', region)
            
            stages = []
            apis = apigw_client.get_rest_apis().get('items', [])
            
            for api in apis:
                api_id = api.get('id', '')
                api_name = api.get('name', '')
                
                api_stages = apigw_client.get_stages(restApiId=api_id).get('item', [])
                
                for stage in api_stages:
                    stage_name = stage.get('stageName', '')
                    client_cert_id = stage.get('clientCertificateId', '')
                    
                    stages.append({
                        'RestApiId': api_id,
                        'ApiName': api_name,
                        'StageName': stage_name,
                        'HasClientCertificate': bool(client_cert_id),
                        'ClientCertificateId': client_cert_id
                    })
            
            return stages
        except ClientError as e:
            logger.error(f"Error retrieving API Gateway stages: {e}")
            return []
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if API Gateway stage has SSL enabled."""
        api_id = resource.get('RestApiId', 'unknown')
        stage_name = resource.get('StageName', '')
        has_cert = resource.get('HasClientCertificate', False)
        
        # API Gateway always uses HTTPS, but client certificates provide additional security
        return ComplianceResult(
            resource_id=f"{api_id}/{stage_name}",
            resource_type="AWS::ApiGateway::Stage",
            compliance_status=ComplianceStatus.COMPLIANT if has_cert else ComplianceStatus.NON_COMPLIANT,
            evaluation_reason=f"API Gateway stage '{stage_name}' {'has' if has_cert else 'does not have'} client certificate configured.",
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        return [
            "1. Generate client certificate in API Gateway",
            "2. Associate certificate with stage",
            "3. Configure backend to validate certificate",
            "Priority: MEDIUM",
            "Effort: Medium",
            "AWS Documentation: https://docs.aws.amazon.com/apigateway/latest/developerguide/getting-started-client-side-ssl-authentication.html"
        ]


class RedshiftRequireTLSSSLAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 4.9 - Encrypt Sensitive Data in Transit
    AWS Config Rule: redshift-require-tls-ssl
    
    Ensures Redshift clusters require SSL/TLS connections.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="redshift-require-tls-ssl",
            control_id="4.9",
            resource_types=["AWS::Redshift::Cluster"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get Redshift clusters and check SSL requirement."""
        if resource_type != "AWS::Redshift::Cluster":
            return []
        
        try:
            redshift_client = aws_factory.get_client('redshift', region)
            
            clusters = []
            paginator = redshift_client.get_paginator('describe_clusters')
            
            for page in paginator.paginate():
                for cluster in page.get('Clusters', []):
                    cluster_id = cluster.get('ClusterIdentifier', '')
                    param_group_name = cluster.get('ClusterParameterGroups', [{}])[0].get('ParameterGroupName', '')
                    
                    ssl_required = False
                    if param_group_name:
                        try:
                            params = redshift_client.describe_cluster_parameters(
                                ParameterGroupName=param_group_name
                            )
                            for param in params.get('Parameters', []):
                                if param.get('ParameterName') == 'require_ssl' and param.get('ParameterValue') == 'true':
                                    ssl_required = True
                        except ClientError:
                            pass
                    
                    clusters.append({
                        'ClusterIdentifier': cluster_id,
                        'ParameterGroupName': param_group_name,
                        'SSLRequired': ssl_required
                    })
            
            return clusters
        except ClientError as e:
            logger.error(f"Error retrieving Redshift clusters: {e}")
            return []
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if Redshift requires SSL."""
        cluster_id = resource.get('ClusterIdentifier', 'unknown')
        ssl_required = resource.get('SSLRequired', False)
        
        return ComplianceResult(
            resource_id=cluster_id,
            resource_type="AWS::Redshift::Cluster",
            compliance_status=ComplianceStatus.COMPLIANT if ssl_required else ComplianceStatus.NON_COMPLIANT,
            evaluation_reason=f"Redshift cluster '{cluster_id}' {'requires' if ssl_required else 'does not require'} SSL connections.",
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        return [
            "1. Modify cluster parameter group to set require_ssl=true",
            "2. Reboot cluster to apply changes",
            "Priority: HIGH",
            "Effort: Low",
            "AWS Documentation: https://docs.aws.amazon.com/redshift/latest/mgmt/connecting-ssl-support.html"
        ]
