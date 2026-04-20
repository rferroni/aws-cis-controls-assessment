"""Remaining AWS Config Rules - Final implementation."""

from typing import Dict, List, Any
import logging
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class ACMCertificateExpirationCheckAssessment(BaseConfigRuleAssessment):
    """Assessment for acm-certificate-expiration-check AWS Config rule."""
    
    def __init__(self):
        super().__init__(
            rule_name="acm-certificate-expiration-check",
            control_id="4.1",
            resource_types=["AWS::ACM::Certificate"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get ACM certificates."""
        if resource_type != "AWS::ACM::Certificate":
            return []
            
        try:
            acm_client = aws_factory.get_client('acm', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: acm_client.list_certificates()
            )
            
            certificates = []
            for cert in response.get('CertificateSummaryList', []):
                certificates.append({
                    'CertificateArn': cert.get('CertificateArn'),
                    'DomainName': cert.get('DomainName')
                })
            
            return certificates
            
        except ClientError as e:
            logger.error(f"Error retrieving ACM certificates in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if ACM certificate is not expired or expiring soon."""
        cert_arn = resource.get('CertificateArn', 'unknown')
        domain_name = resource.get('DomainName', 'unknown')
        
        try:
            acm_client = aws_factory.get_client('acm', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: acm_client.describe_certificate(CertificateArn=cert_arn)
            )
            
            certificate = response.get('Certificate', {})
            not_after = certificate.get('NotAfter')
            status = certificate.get('Status')
            
            if status == 'EXPIRED':
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = f"ACM certificate {domain_name} is expired"
            elif not_after:
                from datetime import datetime, timezone, timedelta
                
                # Check if certificate expires within 30 days
                expiry_date = not_after
                if expiry_date.tzinfo is None:
                    expiry_date = expiry_date.replace(tzinfo=timezone.utc)
                
                now = datetime.now(timezone.utc)
                days_until_expiry = (expiry_date - now).days
                
                if days_until_expiry <= 30:
                    compliance_status = ComplianceStatus.NON_COMPLIANT
                    evaluation_reason = f"ACM certificate {domain_name} expires in {days_until_expiry} days"
                else:
                    compliance_status = ComplianceStatus.COMPLIANT
                    evaluation_reason = f"ACM certificate {domain_name} expires in {days_until_expiry} days"
            else:
                compliance_status = ComplianceStatus.ERROR
                evaluation_reason = f"Could not determine expiry date for certificate {domain_name}"
                
        except ClientError as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Error checking certificate expiration for {domain_name}: {str(e)}"
        
        return ComplianceResult(
            resource_id=domain_name,
            resource_type="AWS::ACM::Certificate",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )


class DynamoDBAutoScalingEnabledAssessment(BaseConfigRuleAssessment):
    """Assessment for dynamodb-autoscaling-enabled AWS Config rule."""
    
    def __init__(self):
        super().__init__(
            rule_name="dynamodb-autoscaling-enabled",
            control_id="12.2",
            resource_types=["AWS::DynamoDB::Table"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get DynamoDB tables."""
        if resource_type != "AWS::DynamoDB::Table":
            return []
            
        try:
            dynamodb_client = aws_factory.get_client('dynamodb', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: dynamodb_client.list_tables()
            )
            
            tables = []
            for table_name in response.get('TableNames', []):
                tables.append({
                    'TableName': table_name
                })
            
            return tables
            
        except ClientError as e:
            logger.error(f"Error retrieving DynamoDB tables in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if DynamoDB table has auto scaling enabled."""
        table_name = resource.get('TableName', 'unknown')
        
        try:
            # Check if table has auto scaling targets
            autoscaling_client = aws_factory.get_client('application-autoscaling', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: autoscaling_client.describe_scalable_targets(
                    ServiceNamespace='dynamodb',
                    ResourceIds=[f'table/{table_name}']
                )
            )
            
            scalable_targets = response.get('ScalableTargets', [])
            
            if scalable_targets:
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = f"DynamoDB table {table_name} has auto scaling enabled"
            else:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = f"DynamoDB table {table_name} does not have auto scaling enabled"
                
        except ClientError as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Error checking auto scaling for table {table_name}: {str(e)}"
        
        return ComplianceResult(
            resource_id=table_name,
            resource_type="AWS::DynamoDB::Table",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )


class RedshiftEnhancedVPCRoutingEnabledAssessment(BaseConfigRuleAssessment):
    """Assessment for redshift-enhanced-vpc-routing-enabled AWS Config rule."""
    
    def __init__(self):
        super().__init__(
            rule_name="redshift-enhanced-vpc-routing-enabled",
            control_id="3.3",
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
                    'EnhancedVpcRouting': cluster.get('EnhancedVpcRouting', False)
                })
            
            return clusters
            
        except ClientError as e:
            logger.error(f"Error retrieving Redshift clusters in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if Redshift cluster has enhanced VPC routing enabled."""
        cluster_id = resource.get('ClusterIdentifier', 'unknown')
        enhanced_vpc_routing = resource.get('EnhancedVpcRouting', False)
        
        if enhanced_vpc_routing:
            compliance_status = ComplianceStatus.COMPLIANT
            evaluation_reason = f"Redshift cluster {cluster_id} has enhanced VPC routing enabled"
        else:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = f"Redshift cluster {cluster_id} does not have enhanced VPC routing enabled"
        
        return ComplianceResult(
            resource_id=cluster_id,
            resource_type="AWS::Redshift::Cluster",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )


class RestrictedCommonPortsAssessment(BaseConfigRuleAssessment):
    """Assessment for restricted-common-ports AWS Config rule."""
    
    def __init__(self):
        super().__init__(
            rule_name="restricted-common-ports",
            control_id="3.3",
            resource_types=["AWS::EC2::SecurityGroup"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get Security Groups."""
        if resource_type != "AWS::EC2::SecurityGroup":
            return []
            
        try:
            ec2_client = aws_factory.get_client('ec2', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: ec2_client.describe_security_groups()
            )
            
            security_groups = []
            for sg in response.get('SecurityGroups', []):
                security_groups.append({
                    'GroupId': sg.get('GroupId'),
                    'GroupName': sg.get('GroupName'),
                    'IpPermissions': sg.get('IpPermissions', [])
                })
            
            return security_groups
            
        except ClientError as e:
            logger.error(f"Error retrieving Security Groups in region {region}: {e}")
            raise
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if Security Group restricts access to common ports."""
        group_id = resource.get('GroupId', 'unknown')
        group_name = resource.get('GroupName', 'unknown')
        ip_permissions = resource.get('IpPermissions', [])
        
        # Common ports that should be restricted
        restricted_ports = [20, 21, 22, 23, 25, 53, 80, 110, 135, 143, 443, 993, 995, 1433, 1521, 3306, 3389, 5432, 5984, 6379, 8020, 8086, 8888, 9042, 9160, 9200, 9300, 11211, 27017, 27018, 27019]
        
        violations = []
        
        for permission in ip_permissions:
            from_port = permission.get('FromPort')
            to_port = permission.get('ToPort')
            ip_ranges = permission.get('IpRanges', [])
            
            # Check if any restricted ports are open to 0.0.0.0/0
            for ip_range in ip_ranges:
                cidr = ip_range.get('CidrIp', '')
                if cidr == '0.0.0.0/0':
                    # Check if any restricted ports are in the range
                    if from_port is not None and to_port is not None:
                        for port in restricted_ports:
                            if from_port <= port <= to_port:
                                violations.append(f"Port {port} open to 0.0.0.0/0")
        
        if not violations:
            compliance_status = ComplianceStatus.COMPLIANT
            evaluation_reason = f"Security Group {group_name} does not expose restricted ports to 0.0.0.0/0"
        else:
            compliance_status = ComplianceStatus.NON_COMPLIANT
            evaluation_reason = f"Security Group {group_name} has violations: {'; '.join(violations[:3])}"  # Limit to first 3
        
        return ComplianceResult(
            resource_id=group_id,
            resource_type="AWS::EC2::SecurityGroup",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )


class AuditLogPolicyExistsAssessment(BaseConfigRuleAssessment):
    """Assessment for audit-log-policy-exists AWS Config rule (Process check)."""
    
    def __init__(self):
        super().__init__(
            rule_name="audit-log-policy-exists (Process check)",
            control_id="8.1",
            resource_types=["AWS::::Account"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get account-level resource for audit log policy check."""
        if resource_type != "AWS::::Account":
            return []
            
        # Return a single account resource
        return [{'AccountId': aws_factory.account_id}]
    
    def _evaluate_resource_compliance(self, resource: Dict[str, Any], aws_factory: AWSClientFactory, region: str) -> ComplianceResult:
        """Evaluate if account has audit log management policy (process check)."""
        account_id = resource.get('AccountId', 'unknown')
        
        # This is a process check - we can only verify if CloudTrail is configured
        # as a proxy for audit log policy existence
        try:
            cloudtrail_client = aws_factory.get_client('cloudtrail', region)
            
            response = aws_factory.aws_api_call_with_retry(
                lambda: cloudtrail_client.describe_trails()
            )
            
            trails = response.get('trailList', [])
            active_trails = [trail for trail in trails if trail.get('IsLogging', False)]
            
            if active_trails:
                compliance_status = ComplianceStatus.COMPLIANT
                evaluation_reason = f"Account {account_id} has {len(active_trails)} active CloudTrail(s) indicating audit log policy implementation"
            else:
                compliance_status = ComplianceStatus.NON_COMPLIANT
                evaluation_reason = f"Account {account_id} has no active CloudTrail, indicating lack of audit log policy"
                
        except ClientError as e:
            compliance_status = ComplianceStatus.ERROR
            evaluation_reason = f"Error checking audit log policy for account {account_id}: {str(e)}"
        
        return ComplianceResult(
            resource_id=account_id,
            resource_type="AWS::::Account",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )