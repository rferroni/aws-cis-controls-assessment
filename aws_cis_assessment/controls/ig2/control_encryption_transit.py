"""Control 3.10: Encrypt Sensitive Data in Transit assessments."""

from typing import Dict, List, Any
import logging
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class ELBACMCertificateRequiredAssessment(BaseConfigRuleAssessment):
    """Assessment for elb-acm-certificate-required Config rule."""
    
    def __init__(self):
        """Initialize ELB ACM certificate assessment."""
        super().__init__(
            rule_name="elb-acm-certificate-required",
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
            
            load_balancers = []
            for lb in response.get('LoadBalancerDescriptions', []):
                load_balancers.append({
                    'LoadBalancerName': lb.get('LoadBalancerName'),
                    'DNSName': lb.get('DNSName'),
                    'Scheme': lb.get('Scheme'),
                    'ListenerDescriptions': lb.get('ListenerDescriptions', []),
                    'VPCId': lb.get('VPCId')
                })
            
            logger.debug(f"Found {len(load_balancers)} Classic Load Balancers in region {region}")
            return load_balancers
            
        except ClientError as e:
            logger.error(f"Error retrieving Classic Load Balancers in region {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving Classic Load Balancers in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if Classic Load Balancer uses ACM certificates for HTTPS/SSL listeners."""
        lb_name = resource.get('LoadBalancerName', 'unknown')
        listener_descriptions = resource.get('ListenerDescriptions', [])
        
        https_listeners = []
        non_acm_listeners = []
        
        for listener_desc in listener_descriptions:
            listener = listener_desc.get('Listener', {})
            protocol = listener.get('Protocol', '')
            ssl_certificate_id = listener.get('SSLCertificateId', '')
            
            if protocol in ['HTTPS', 'SSL']:
                https_listeners.append({
                    'Protocol': protocol,
                    'LoadBalancerPort': listener.get('LoadBalancerPort'),
                    'SSLCertificateId': ssl_certificate_id
                })
                
                # Check if certificate is from ACM (ACM ARNs contain 'acm')
                if ssl_certificate_id and 'acm' not in ssl_certificate_id.lower():
                    non_acm_listeners.append({
                        'Protocol': protocol,
                        'LoadBalancerPort': listener.get('LoadBalancerPort'),
                        'SSLCertificateId': ssl_certificate_id
                    })
        
        if not https_listeners:
            compliance_status = ComplianceStatus.NOT_APPLICABLE
            evaluation_reason = f"Load Balancer {lb_name} has no HTTPS/SSL listeners"
        elif non_acm_listeners:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            listener_details = [f"{l['Protocol']}:{l['LoadBalancerPort']}" for l in non_acm_listeners]
            evaluation_reason = f"Load Balancer {lb_name} has {len(non_acm_listeners)} HTTPS/SSL listener(s) not using ACM certificates: {', '.join(listener_details)}"
        else:
            compliance_status = ComplianceStatus.COMPLIANT
            evaluation_reason = f"Load Balancer {lb_name} has {len(https_listeners)} HTTPS/SSL listener(s) using ACM certificates"
        
        return ComplianceResult(
            resource_id=lb_name,
            resource_type="AWS::ElasticLoadBalancing::LoadBalancer",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for ELB ACM certificates."""
        return [
            "Identify Classic Load Balancers with HTTPS/SSL listeners not using ACM certificates",
            "For each non-compliant load balancer:",
            "  1. Request or import a certificate in AWS Certificate Manager",
            "  2. Update the load balancer listener to use the ACM certificate",
            "  3. Test the SSL/TLS configuration",
            "  4. Remove the old certificate if it's no longer needed",
            "Use AWS CLI: aws acm request-certificate --domain-name <domain>",
            "Use AWS CLI: aws elb set-load-balancer-listener-ssl-certificate --load-balancer-name <name> --load-balancer-port <port> --ssl-certificate-id <acm-arn>",
            "Enable automatic certificate renewal for ACM certificates",
            "Monitor certificate expiration dates and renewal status"
        ]


class ELBv2ACMCertificateRequiredAssessment(BaseConfigRuleAssessment):
    """Assessment for elbv2-acm-certificate-required Config rule."""
    
    def __init__(self):
        """Initialize ELBv2 ACM certificate assessment."""
        super().__init__(
            rule_name="elbv2-acm-certificate-required",
            control_id="3.10",
            resource_types=["AWS::ElasticLoadBalancingV2::LoadBalancer"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all Application/Network Load Balancers in the region."""
        if resource_type != "AWS::ElasticLoadBalancingV2::LoadBalancer":
            return []
        
        try:
            elbv2_client = aws_factory.get_client('elbv2', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: elbv2_client.describe_load_balancers()
            )
            
            load_balancers = []
            for lb in response.get('LoadBalancers', []):
                load_balancers.append({
                    'LoadBalancerArn': lb.get('LoadBalancerArn'),
                    'LoadBalancerName': lb.get('LoadBalancerName'),
                    'DNSName': lb.get('DNSName'),
                    'Scheme': lb.get('Scheme'),
                    'Type': lb.get('Type'),
                    'VpcId': lb.get('VpcId')
                })
            
            logger.debug(f"Found {len(load_balancers)} Application/Network Load Balancers in region {region}")
            return load_balancers
            
        except ClientError as e:
            logger.error(f"Error retrieving Application/Network Load Balancers in region {region}: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving Application/Network Load Balancers in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if ALB/NLB uses ACM certificates for HTTPS/TLS listeners."""
        lb_arn = resource.get('LoadBalancerArn', 'unknown')
        lb_name = resource.get('LoadBalancerName', 'unknown')
        lb_type = resource.get('Type', 'unknown')
        
        try:
            elbv2_client = aws_factory.get_client('elbv2', region)
            
            # Get listeners for the load balancer
            listeners_response = aws_factory.aws_api_call_with_retry(
                lambda: elbv2_client.describe_listeners(LoadBalancerArn=lb_arn)
            )
            
            https_listeners = []
            non_acm_listeners = []
            
            for listener in listeners_response.get('Listeners', []):
                protocol = listener.get('Protocol', '')
                port = listener.get('Port')
                certificates = listener.get('Certificates', [])
                
                if protocol in ['HTTPS', 'TLS']:
                    https_listeners.append({
                        'Protocol': protocol,
                        'Port': port,
                        'Certificates': certificates
                    })
                    
                    # Check if any certificate is not from ACM
                    for cert in certificates:
                        cert_arn = cert.get('CertificateArn', '')
                        if cert_arn and 'acm' not in cert_arn.lower():
                            non_acm_listeners.append({
                                'Protocol': protocol,
                                'Port': port,
                                'CertificateArn': cert_arn
                            })
            
            if not https_listeners:
                compliance_status = ComplianceStatus.NOT_APPLICABLE
                evaluation_reason = f"Load Balancer {lb_name} has no HTTPS/TLS listeners"
            elif non_acm_listeners:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                listener_details = [f"{l['Protocol']}:{l['Port']}" for l in non_acm_listeners]
                evaluation_reason = f"Load Balancer {lb_name} has {len(non_acm_listeners)} HTTPS/TLS listener(s) not using ACM certificates: {', '.join(listener_details)}"
            else:
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = f"Load Balancer {lb_name} has {len(https_listeners)} HTTPS/TLS listener(s) using ACM certificates"
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code in ['AccessDenied', 'LoadBalancerNotFound']:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Cannot access load balancer {lb_name}: {error_code}"
            else:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Error checking load balancer {lb_name}: {str(e)}"
        except Exception as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Unexpected error checking load balancer {lb_name}: {str(e)}"
        
        return ComplianceResult(
            resource_id=lb_arn,
            resource_type="AWS::ElasticLoadBalancingV2::LoadBalancer",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for ELBv2 ACM certificates."""
        return [
            "Identify Application/Network Load Balancers with HTTPS/TLS listeners not using ACM certificates",
            "For each non-compliant load balancer:",
            "  1. Request or import a certificate in AWS Certificate Manager",
            "  2. Update the listener to use the ACM certificate",
            "  3. Test the SSL/TLS configuration",
            "  4. Remove the old certificate if it's no longer needed",
            "Use AWS CLI: aws acm request-certificate --domain-name <domain>",
            "Use AWS CLI: aws elbv2 modify-listener --listener-arn <arn> --certificates CertificateArn=<acm-arn>",
            "Enable automatic certificate renewal for ACM certificates",
            "Monitor certificate expiration dates and renewal status"
        ]


class OpenSearchHTTPSRequiredAssessment(BaseConfigRuleAssessment):
    """Assessment for opensearch-https-required Config rule."""
    
    def __init__(self):
        """Initialize OpenSearch HTTPS assessment."""
        super().__init__(
            rule_name="opensearch-https-required",
            control_id="3.10",
            resource_types=["AWS::OpenSearch::Domain"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all OpenSearch domains in the region."""
        if resource_type != "AWS::OpenSearch::Domain":
            return []
        
        try:
            opensearch_client = aws_factory.get_client('opensearch', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: opensearch_client.list_domain_names()
            )
            
            domains = []
            for domain in response.get('DomainNames', []):
                domain_name = domain.get('DomainName')
                if domain_name:
                    domains.append({
                        'DomainName': domain_name,
                        'EngineType': domain.get('EngineType', 'OpenSearch')
                    })
            
            logger.debug(f"Found {len(domains)} OpenSearch domains in region {region}")
            return domains
            
        except ClientError as e:
            # Try Elasticsearch service if OpenSearch is not available
            if e.response.get('Error', {}).get('Code') in ['UnknownOperationException', 'InvalidAction']:
                try:
                    es_client = aws_factory.get_client('es', region)
                    response = aws_factory.aws_api_call_with_retry(
                        lambda: es_client.list_domain_names()
                    )
                    
                    domains = []
                    for domain in response.get('DomainNames', []):
                        domain_name = domain.get('DomainName')
                        if domain_name:
                            domains.append({
                                'DomainName': domain_name,
                                'EngineType': 'Elasticsearch'
                            })
                    
                    logger.debug(f"Found {len(domains)} Elasticsearch domains in region {region}")
                    return domains
                except ClientError as es_error:
                    logger.error(f"Error retrieving Elasticsearch domains in region {region}: {es_error}")
                    raise es_error
            else:
                logger.error(f"Error retrieving OpenSearch domains in region {region}: {e}")
                raise
        except Exception as e:
            logger.error(f"Unexpected error retrieving OpenSearch domains in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if OpenSearch domain requires HTTPS."""
        domain_name = resource.get('DomainName', 'unknown')
        engine_type = resource.get('EngineType', 'OpenSearch')
        
        try:
            if engine_type == 'Elasticsearch':
                client = aws_factory.get_client('es', region)
                response = aws_factory.aws_api_call_with_retry(
                    lambda: client.describe_elasticsearch_domain(DomainName=domain_name)
                )
                domain_config = response.get('DomainStatus', {})
            else:
                client = aws_factory.get_client('opensearch', region)
                response = aws_factory.aws_api_call_with_retry(
                    lambda: client.describe_domain(DomainName=domain_name)
                )
                domain_config = response.get('DomainStatus', {})
            
            # Check domain endpoint options
            domain_endpoint_options = domain_config.get('DomainEndpointOptions', {})
            enforce_https = domain_endpoint_options.get('EnforceHTTPS', False)
            
            if enforce_https:
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = f"{engine_type} domain {domain_name} enforces HTTPS"
            else:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = f"{engine_type} domain {domain_name} does not enforce HTTPS"
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code in ['AccessDenied', 'ResourceNotFoundException']:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Cannot access {engine_type} domain {domain_name}: {error_code}"
            else:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Error checking {engine_type} domain {domain_name}: {str(e)}"
        except Exception as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Unexpected error checking {engine_type} domain {domain_name}: {str(e)}"
        
        return ComplianceResult(
            resource_id=domain_name,
            resource_type="AWS::OpenSearch::Domain",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get specific remediation steps for OpenSearch HTTPS enforcement."""
        return [
            "Identify OpenSearch/Elasticsearch domains that do not enforce HTTPS",
            "For each non-compliant domain:",
            "  1. Plan for a maintenance window as this requires domain update",
            "  2. Update domain configuration to enforce HTTPS",
            "  3. Update applications to use HTTPS endpoints only",
            "  4. Test connectivity and functionality",
            "  5. Monitor domain health after the change",
            "Use AWS CLI: aws opensearch update-domain-config --domain-name <name> --domain-endpoint-options EnforceHTTPS=true",
            "Use AWS CLI: aws es update-elasticsearch-domain-config --domain-name <name> --domain-endpoint-options EnforceHTTPS=true",
            "Consider enabling node-to-node encryption for additional security",
            "Update security groups and NACLs to allow only HTTPS traffic"
        ]