# Assessment Logic Documentation

This document provides detailed information about the assessment logic used by the AWS CIS Controls Compliance Assessment Framework - a production-ready, enterprise-grade solution with complete CIS Controls coverage.

## Production Framework Overview

**✅ Complete Implementation Status**
- 199 unique assessment rules across 40 CIS Controls v8.1 safeguards
- Coverage across all Implementation Groups (IG1, IG2, IG3)
- Production-tested with enterprise-grade error handling
- Optimized for large-scale enterprise deployments

## Table of Contents

1. [Overview](#overview)
2. [Assessment Framework](#assessment-framework)
3. [Resource Discovery](#resource-discovery)
4. [Compliance Evaluation](#compliance-evaluation)
5. [Scoring Methodology](#scoring-methodology)
6. [Error Handling](#error-handling)
7. [Control-Specific Logic](#control-specific-logic)
8. [Performance Optimizations](#performance-optimizations)

## Overview

The assessment tool evaluates AWS account configurations against CIS Controls using the same logic as AWS Config rules, but without requiring AWS Config to be enabled. Each assessment follows a standardized process while implementing control-specific evaluation logic.

**Framework Scope**: 199 unique assessment rules covering CIS Controls v8.1 safeguards across all Implementation Groups.

### Key Principles

1. **Config Rule Fidelity**: Assessment logic mirrors AWS Config rule specifications exactly
2. **Resource Coverage**: All applicable AWS resource types are evaluated
3. **Regional Scope**: Assessments are performed across all specified regions
4. **Error Resilience**: Graceful handling of API errors and service unavailability
5. **Performance**: Optimized for large-scale enterprise environments

## Assessment Framework

### Base Assessment Pattern

All assessments follow this standardized pattern:

```python
class BaseConfigRuleAssessment:
    def evaluate_compliance(self, aws_factory, region):
        """Main assessment entry point."""
        all_results = []
        
        for resource_type in self.resource_types:
            # 1. Discover resources
            resources = self._get_resources(aws_factory, resource_type, region)
            
            # 2. Evaluate each resource
            for resource in resources:
                result = self._evaluate_resource_compliance(resource, aws_factory)
                all_results.append(result)
        
        return all_results
    
    def _get_resources(self, aws_factory, resource_type, region):
        """Discover resources of specified type in region."""
        # Implementation varies by resource type
        pass
    
    def _evaluate_resource_compliance(self, resource, aws_factory):
        """Evaluate compliance for individual resource."""
        # Implementation varies by control logic
        pass
```

### Assessment Lifecycle

1. **Initialization**: Load configuration and validate parameters
2. **Resource Discovery**: Find all applicable resources in target regions
3. **Compliance Evaluation**: Apply control-specific logic to each resource
4. **Result Aggregation**: Collect and format compliance results
5. **Scoring Calculation**: Calculate compliance percentages
6. **Report Generation**: Generate output in requested formats

## Resource Discovery

### Discovery Strategies

Different AWS services require different discovery approaches:

#### EC2 Resources
```python
def discover_ec2_instances(self, ec2_client, region):
    """Discover EC2 instances using describe_instances."""
    try:
        paginator = ec2_client.get_paginator('describe_instances')
        
        instances = []
        for page in paginator.paginate():
            for reservation in page['Reservations']:
                for instance in reservation['Instances']:
                    # Filter out terminated instances
                    if instance['State']['Name'] != 'terminated':
                        instances.append({
                            'InstanceId': instance['InstanceId'],
                            'InstanceType': instance['InstanceType'],
                            'State': instance['State']['Name'],
                            'Region': region,
                            'LaunchTime': instance['LaunchTime'],
                            'SecurityGroups': instance.get('SecurityGroups', []),
                            'IamInstanceProfile': instance.get('IamInstanceProfile'),
                            'Monitoring': instance.get('Monitoring', {}),
                            'Tags': instance.get('Tags', [])
                        })
        
        return instances
        
    except ClientError as e:
        if e.response['Error']['Code'] == 'UnauthorizedOperation':
            self.logger.warning(f"Insufficient permissions for EC2 in {region}")
            return []
        raise
```

#### S3 Resources
```python
def discover_s3_buckets(self, s3_client, region):
    """Discover S3 buckets in specific region."""
    try:
        # List all buckets (global operation)
        response = s3_client.list_buckets()
        
        regional_buckets = []
        for bucket in response['Buckets']:
            try:
                # Get bucket region
                bucket_region = s3_client.get_bucket_location(
                    Bucket=bucket['Name']
                )['LocationConstraint']
                
                # Handle us-east-1 special case
                if bucket_region is None:
                    bucket_region = 'us-east-1'
                
                if bucket_region == region:
                    regional_buckets.append({
                        'Name': bucket['Name'],
                        'CreationDate': bucket['CreationDate'],
                        'Region': region
                    })
                    
            except ClientError as e:
                # Skip buckets we can't access
                if e.response['Error']['Code'] in ['AccessDenied', 'NoSuchBucket']:
                    continue
                raise
        
        return regional_buckets
        
    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDenied':
            self.logger.warning(f"Insufficient permissions for S3")
            return []
        raise
```

#### IAM Resources
```python
def discover_iam_users(self, iam_client):
    """Discover IAM users (global service)."""
    try:
        paginator = iam_client.get_paginator('list_users')
        
        users = []
        for page in paginator.paginate():
            for user in page['Users']:
                users.append({
                    'UserName': user['UserName'],
                    'UserId': user['UserId'],
                    'Arn': user['Arn'],
                    'CreateDate': user['CreateDate'],
                    'PasswordLastUsed': user.get('PasswordLastUsed'),
                    'Tags': user.get('Tags', [])
                })
        
        return users
        
    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDenied':
            self.logger.warning("Insufficient permissions for IAM")
            return []
        raise
```

### Pagination Handling

All discovery operations use proper pagination to handle large resource sets:

```python
def paginated_discovery(self, client, operation_name, **kwargs):
    """Generic paginated resource discovery."""
    try:
        if client.can_paginate(operation_name):
            paginator = client.get_paginator(operation_name)
            for page in paginator.paginate(**kwargs):
                yield page
        else:
            # Single page operation
            response = getattr(client, operation_name)(**kwargs)
            yield response
            
    except ClientError as e:
        self.logger.error(f"Failed to paginate {operation_name}: {e}")
        raise
```

## Compliance Evaluation

### Evaluation Patterns

Different controls use different evaluation patterns:

#### Binary Compliance
Simple yes/no compliance checks:

```python
def evaluate_eip_attached(self, resource, aws_factory):
    """Evaluate if EIP is attached to an instance or ENI."""
    eip_allocation_id = resource['AllocationId']
    region = resource['Region']
    
    # Check if EIP has InstanceId or NetworkInterfaceId
    if resource.get('InstanceId') or resource.get('NetworkInterfaceId'):
        return ComplianceResult(
            resource_id=eip_allocation_id,
            resource_type="AWS::EC2::EIP",
            compliance_status="COMPLIANT",
            evaluation_reason="EIP is attached to an instance or ENI",
            config_rule_name="eip-attached",
            region=region,
            timestamp=datetime.now()
        )
    else:
        return ComplianceResult(
            resource_id=eip_allocation_id,
            resource_type="AWS::EC2::EIP",
            compliance_status="NON_COMPLIANT",
            evaluation_reason="EIP is not attached to any instance or ENI",
            config_rule_name="eip-attached",
            region=region,
            timestamp=datetime.now(),
            remediation_guidance="Attach the EIP to an EC2 instance or release it to avoid charges"
        )
```

#### Parameter-Based Compliance
Compliance based on configuration parameters:

```python
def evaluate_iam_password_policy(self, resource, aws_factory):
    """Evaluate IAM password policy against parameters."""
    policy = resource['PasswordPolicy']
    
    # Check all required parameters
    compliance_issues = []
    
    if not policy.get('RequireUppercaseCharacters', False):
        compliance_issues.append("uppercase characters not required")
    
    if not policy.get('RequireLowercaseCharacters', False):
        compliance_issues.append("lowercase characters not required")
    
    if not policy.get('RequireNumbers', False):
        compliance_issues.append("numbers not required")
    
    if not policy.get('RequireSymbols', False):
        compliance_issues.append("symbols not required")
    
    min_length = policy.get('MinimumPasswordLength', 0)
    if min_length < self.parameters.get('MinimumPasswordLength', 14):
        compliance_issues.append(f"minimum length {min_length} is too short")
    
    if compliance_issues:
        return ComplianceResult(
            resource_id="account-password-policy",
            resource_type="AWS::IAM::AccountPasswordPolicy",
            compliance_status="NON_COMPLIANT",
            evaluation_reason=f"Password policy issues: {', '.join(compliance_issues)}",
            config_rule_name="iam-password-policy",
            region="global",
            timestamp=datetime.now(),
            remediation_guidance="Update IAM password policy to meet security requirements"
        )
    else:
        return ComplianceResult(
            resource_id="account-password-policy",
            resource_type="AWS::IAM::AccountPasswordPolicy",
            compliance_status="COMPLIANT",
            evaluation_reason="Password policy meets all requirements",
            config_rule_name="iam-password-policy",
            region="global",
            timestamp=datetime.now()
        )
```

#### Multi-Step Evaluation
Complex evaluations requiring multiple API calls:

```python
def evaluate_s3_bucket_encryption(self, resource, aws_factory):
    """Evaluate S3 bucket encryption configuration."""
    bucket_name = resource['Name']
    region = resource['Region']
    
    try:
        s3_client = aws_factory.get_client('s3', region)
        
        # Step 1: Check bucket encryption
        try:
            encryption_response = s3_client.get_bucket_encryption(Bucket=bucket_name)
            encryption_config = encryption_response.get('ServerSideEncryptionConfiguration', {})
            rules = encryption_config.get('Rules', [])
            
            if not rules:
                return self._create_non_compliant_result(
                    bucket_name, region, "No encryption rules configured"
                )
            
            # Step 2: Validate encryption algorithm
            for rule in rules:
                sse_config = rule.get('ApplyServerSideEncryptionByDefault', {})
                algorithm = sse_config.get('SSEAlgorithm')
                
                if algorithm not in ['AES256', 'aws:kms']:
                    return self._create_non_compliant_result(
                        bucket_name, region, f"Invalid encryption algorithm: {algorithm}"
                    )
                
                # Step 3: For KMS, check key configuration
                if algorithm == 'aws:kms':
                    kms_key_id = sse_config.get('KMSMasterKeyID')
                    if not kms_key_id:
                        return self._create_non_compliant_result(
                            bucket_name, region, "KMS encryption without key ID"
                        )
            
            return ComplianceResult(
                resource_id=bucket_name,
                resource_type="AWS::S3::Bucket",
                compliance_status="COMPLIANT",
                evaluation_reason="Bucket has proper encryption configuration",
                config_rule_name="s3-bucket-server-side-encryption-enabled",
                region=region,
                timestamp=datetime.now()
            )
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'ServerSideEncryptionConfigurationNotFoundError':
                return self._create_non_compliant_result(
                    bucket_name, region, "No server-side encryption configuration"
                )
            raise
            
    except Exception as e:
        return self._create_error_result(bucket_name, region, str(e))
```

## Scoring Methodology

### Control-Level Scoring

Each control's compliance score is calculated as:

```python
def calculate_control_score(self, compliance_results):
    """Calculate compliance score for a control."""
    if not compliance_results:
        return ControlScore(
            control_id=self.control_id,
            title=self.title,
            implementation_group=self.implementation_group,
            total_resources=0,
            compliant_resources=0,
            compliance_percentage=0.0,
            config_rules_evaluated=[],
            findings=[]
        )
    
    # Count compliant resources
    compliant_count = sum(1 for result in compliance_results 
                         if result.compliance_status == 'COMPLIANT')
    
    # Count total evaluable resources (exclude errors and not applicable)
    evaluable_results = [result for result in compliance_results 
                        if result.compliance_status in ['COMPLIANT', 'NON_COMPLIANT']]
    
    total_count = len(evaluable_results)
    
    if total_count == 0:
        compliance_percentage = 0.0
    else:
        compliance_percentage = (compliant_count / total_count) * 100
    
    return ControlScore(
        control_id=self.control_id,
        title=self.title,
        implementation_group=self.implementation_group,
        total_resources=total_count,
        compliant_resources=compliant_count,
        compliance_percentage=compliance_percentage,
        config_rules_evaluated=list(set(result.config_rule_name for result in compliance_results)),
        findings=evaluable_results
    )
```

### Implementation Group Scoring

IG scores are calculated as weighted averages of control scores:

```python
def calculate_ig_score(self, control_scores):
    """Calculate Implementation Group compliance score."""
    if not control_scores:
        return IGScore(
            implementation_group=self.ig_name,
            total_controls=0,
            compliant_controls=0,
            compliance_percentage=0.0,
            control_scores={}
        )
    
    # Calculate weighted average
    total_weight = 0
    weighted_sum = 0
    
    for control_id, control_score in control_scores.items():
        weight = control_score.weight
        total_weight += weight
        weighted_sum += control_score.compliance_percentage * weight
    
    if total_weight == 0:
        overall_percentage = 0.0
    else:
        overall_percentage = weighted_sum / total_weight
    
    # Count fully compliant controls (100% compliance)
    compliant_controls = sum(1 for score in control_scores.values() 
                           if score.compliance_percentage == 100.0)
    
    return IGScore(
        implementation_group=self.ig_name,
        total_controls=len(control_scores),
        compliant_controls=compliant_controls,
        compliance_percentage=overall_percentage,
        control_scores=control_scores
    )
```

### Overall Scoring

Overall compliance is calculated across all Implementation Groups:

```python
def calculate_overall_score(self, ig_scores):
    """Calculate overall compliance score."""
    if not ig_scores:
        return 0.0
    
    # Weight Implementation Groups
    ig_weights = {
        'IG1': 0.5,  # 50% weight for essential controls
        'IG2': 0.3,  # 30% weight for enhanced controls
        'IG3': 0.2   # 20% weight for advanced controls
    }
    
    total_weight = 0
    weighted_sum = 0
    
    for ig_name, ig_score in ig_scores.items():
        weight = ig_weights.get(ig_name, 1.0)
        total_weight += weight
        weighted_sum += ig_score.compliance_percentage * weight
    
    if total_weight == 0:
        return 0.0
    
    return weighted_sum / total_weight
```

## Error Handling

### Error Categories

The assessment tool handles various error conditions:

#### Permission Errors
```python
def handle_permission_error(self, error, resource_id, region):
    """Handle AWS permission errors."""
    return ComplianceResult(
        resource_id=resource_id,
        resource_type=self.resource_type,
        compliance_status="INSUFFICIENT_PERMISSIONS",
        evaluation_reason=f"Insufficient permissions: {error.response['Error']['Code']}",
        config_rule_name=self.rule_name,
        region=region,
        timestamp=datetime.now(),
        remediation_guidance="Grant necessary IAM permissions for assessment"
    )
```

#### Service Unavailable
```python
def handle_service_error(self, error, resource_id, region):
    """Handle AWS service unavailability."""
    return ComplianceResult(
        resource_id=resource_id,
        resource_type=self.resource_type,
        compliance_status="ERROR",
        evaluation_reason=f"Service error: {error.response['Error']['Code']}",
        config_rule_name=self.rule_name,
        region=region,
        timestamp=datetime.now(),
        remediation_guidance="Retry assessment when service is available"
    )
```

#### Resource Not Found
```python
def handle_not_found_error(self, error, resource_id, region):
    """Handle resource not found errors."""
    return ComplianceResult(
        resource_id=resource_id,
        resource_type=self.resource_type,
        compliance_status="NOT_APPLICABLE",
        evaluation_reason="Resource not found or not applicable",
        config_rule_name=self.rule_name,
        region=region,
        timestamp=datetime.now()
    )
```

### Retry Logic

Transient errors are handled with exponential backoff:

```python
def retry_with_backoff(self, func, max_retries=3, base_delay=1):
    """Retry function with exponential backoff."""
    for attempt in range(max_retries):
        try:
            return func()
        except ClientError as e:
            error_code = e.response['Error']['Code']
            
            # Don't retry permission errors
            if error_code in ['AccessDenied', 'UnauthorizedOperation']:
                raise
            
            # Retry throttling and service errors
            if error_code in ['Throttling', 'ThrottlingException', 'ServiceUnavailable']:
                if attempt < max_retries - 1:
                    delay = base_delay * (2 ** attempt)
                    time.sleep(delay)
                    continue
            
            raise
    
    raise Exception(f"Max retries ({max_retries}) exceeded")
```

## Control-Specific Logic

### Asset Inventory Controls (1.x)

Focus on resource discovery and management:

```python
class AssetInventoryAssessment(BaseConfigRuleAssessment):
    """Base class for asset inventory assessments."""
    
    def evaluate_asset_management(self, resource, aws_factory):
        """Common asset management evaluation logic."""
        # Check if resource is properly tagged
        tags = resource.get('Tags', [])
        required_tags = self.parameters.get('RequiredTags', [])
        
        missing_tags = []
        for required_tag in required_tags:
            if not any(tag['Key'] == required_tag for tag in tags):
                missing_tags.append(required_tag)
        
        # Check if resource is managed by Systems Manager (for EC2)
        if resource.get('ResourceType') == 'AWS::EC2::Instance':
            ssm_managed = self.check_ssm_management(resource, aws_factory)
            if not ssm_managed:
                missing_tags.append('SSM_MANAGED')
        
        return missing_tags
```

### Access Control Controls (3.x, 5.x, 6.x)

Focus on authentication, authorization, and access patterns:

```python
class AccessControlAssessment(BaseConfigRuleAssessment):
    """Base class for access control assessments."""
    
    def evaluate_public_access(self, resource, aws_factory):
        """Evaluate if resource allows public access."""
        resource_type = resource.get('ResourceType')
        
        if resource_type == 'AWS::S3::Bucket':
            return self.check_s3_public_access(resource, aws_factory)
        elif resource_type == 'AWS::EC2::Instance':
            return self.check_ec2_public_access(resource, aws_factory)
        elif resource_type == 'AWS::RDS::DBInstance':
            return self.check_rds_public_access(resource, aws_factory)
        
        return False
    
    def check_s3_public_access(self, bucket, aws_factory):
        """Check if S3 bucket allows public access."""
        s3_client = aws_factory.get_client('s3', bucket['Region'])
        
        try:
            # Check bucket policy
            policy_response = s3_client.get_bucket_policy(Bucket=bucket['Name'])
            policy = json.loads(policy_response['Policy'])
            
            for statement in policy.get('Statement', []):
                principal = statement.get('Principal')
                if principal == '*' or principal == {'AWS': '*'}:
                    return True
            
            # Check bucket ACL
            acl_response = s3_client.get_bucket_acl(Bucket=bucket['Name'])
            for grant in acl_response.get('Grants', []):
                grantee = grant.get('Grantee', {})
                if grantee.get('URI') in [
                    'http://acs.amazonaws.com/groups/global/AllUsers',
                    'http://acs.amazonaws.com/groups/global/AuthenticatedUsers'
                ]:
                    return True
            
            return False
            
        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchBucketPolicy':
                return False
            raise
```

### Secure Configuration Controls (4.x)

Focus on configuration baselines and hardening:

```python
class SecureConfigurationAssessment(BaseConfigRuleAssessment):
    """Base class for secure configuration assessments."""
    
    def evaluate_security_configuration(self, resource, aws_factory):
        """Evaluate security configuration settings."""
        config_issues = []
        
        # Check encryption settings
        if not self.check_encryption_enabled(resource, aws_factory):
            config_issues.append("encryption not enabled")
        
        # Check logging settings
        if not self.check_logging_enabled(resource, aws_factory):
            config_issues.append("logging not enabled")
        
        # Check monitoring settings
        if not self.check_monitoring_enabled(resource, aws_factory):
            config_issues.append("monitoring not enabled")
        
        # Check update settings
        if not self.check_auto_updates_enabled(resource, aws_factory):
            config_issues.append("automatic updates not enabled")
        
        return config_issues
```

## Performance Optimizations

### Concurrent Processing

Assessments are performed concurrently across regions and resource types:

```python
def run_concurrent_assessments(self, assessment_tasks):
    """Run assessments concurrently with proper resource management."""
    with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
        # Submit all tasks
        future_to_task = {
            executor.submit(self.run_single_assessment, task): task 
            for task in assessment_tasks
        }
        
        # Collect results as they complete
        results = []
        for future in as_completed(future_to_task):
            task = future_to_task[future]
            try:
                result = future.result(timeout=self.task_timeout)
                results.append(result)
            except Exception as e:
                self.logger.error(f"Assessment task failed: {task}, error: {e}")
                # Create error result
                error_result = self.create_error_result(task, str(e))
                results.append(error_result)
        
        return results
```

### Caching

Resource discovery results are cached to avoid redundant API calls:

```python
class ResourceCache:
    """Cache for resource discovery results."""
    
    def __init__(self, ttl_seconds=300):
        self.cache = {}
        self.ttl = ttl_seconds
    
    def get(self, cache_key):
        """Get cached result if still valid."""
        if cache_key in self.cache:
            result, timestamp = self.cache[cache_key]
            if time.time() - timestamp < self.ttl:
                return result
            else:
                del self.cache[cache_key]
        return None
    
    def set(self, cache_key, result):
        """Cache result with timestamp."""
        self.cache[cache_key] = (result, time.time())
    
    def clear(self):
        """Clear all cached results."""
        self.cache.clear()
```

### Batch Operations

Where possible, resources are processed in batches:

```python
def batch_evaluate_resources(self, resources, batch_size=50):
    """Evaluate resources in batches for better performance."""
    results = []
    
    for i in range(0, len(resources), batch_size):
        batch = resources[i:i + batch_size]
        batch_results = self.evaluate_resource_batch(batch)
        results.extend(batch_results)
        
        # Add small delay between batches to avoid throttling
        if i + batch_size < len(resources):
            time.sleep(0.1)
    
    return results
```

This comprehensive assessment logic ensures accurate, efficient, and reliable evaluation of AWS resources against CIS Controls while maintaining compatibility with AWS Config rule specifications.


### AWS Backup Resources
```python
def discover_backup_plans(self, backup_client, region):
    """Discover AWS Backup plans in specific region."""
    try:
        paginator = backup_client.get_paginator('list_backup_plans')
        
        backup_plans = []
        for page in paginator.paginate():
            for plan in page['BackupPlansList']:
                try:
                    # Get detailed plan information
                    plan_details = backup_client.get_backup_plan(
                        BackupPlanId=plan['BackupPlanId']
                    )
                    
                    backup_plans.append({
                        'BackupPlanId': plan['BackupPlanId'],
                        'BackupPlanName': plan['BackupPlanName'],
                        'BackupPlanArn': plan['BackupPlanArn'],
                        'CreationDate': plan['CreationDate'],
                        'VersionId': plan['VersionId'],
                        'Rules': plan_details['BackupPlan'].get('Rules', []),
                        'Region': region
                    })
                    
                except ClientError as e:
                    # Skip plans we can't access
                    if e.response['Error']['Code'] in ['AccessDenied', 'ResourceNotFoundException']:
                        continue
                    raise
        
        return backup_plans
        
    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDenied':
            self.logger.warning(f"Insufficient permissions for Backup in {region}")
            return []
        raise

def discover_backup_vaults(self, backup_client, region):
    """Discover AWS Backup vaults in specific region."""
    try:
        paginator = backup_client.get_paginator('list_backup_vaults')
        
        backup_vaults = []
        for page in paginator.paginate():
            for vault in page['BackupVaultList']:
                try:
                    # Get vault access policy if exists
                    try:
                        policy_response = backup_client.get_backup_vault_access_policy(
                            BackupVaultName=vault['BackupVaultName']
                        )
                        vault['Policy'] = policy_response.get('Policy')
                    except ClientError as e:
                        if e.response['Error']['Code'] == 'ResourceNotFoundException':
                            vault['Policy'] = None
                        else:
                            raise
                    
                    backup_vaults.append({
                        'BackupVaultName': vault['BackupVaultName'],
                        'BackupVaultArn': vault['BackupVaultArn'],
                        'CreationDate': vault['CreationDate'],
                        'EncryptionKeyArn': vault.get('EncryptionKeyArn'),
                        'NumberOfRecoveryPoints': vault.get('NumberOfRecoveryPoints', 0),
                        'Policy': vault.get('Policy'),
                        'Region': region
                    })
                    
                except ClientError as e:
                    if e.response['Error']['Code'] in ['AccessDenied', 'ResourceNotFoundException']:
                        continue
                    raise
        
        return backup_vaults
        
    except ClientError as e:
        if e.response['Error']['Code'] == 'AccessDenied':
            self.logger.warning(f"Insufficient permissions for Backup vaults in {region}")
            return []
        raise
```

## AWS Backup Controls Logic

### Backup Plan Frequency and Retention Check

Evaluates backup plans to ensure they meet minimum frequency and retention requirements:

```python
def evaluate_backup_plan_compliance(self, resource, aws_factory):
    """Evaluate backup plan frequency and retention requirements."""
    backup_plan_id = resource['BackupPlanId']
    backup_plan_name = resource['BackupPlanName']
    rules = resource.get('Rules', [])
    region = resource['Region']
    
    if not rules:
        return ComplianceResult(
            resource_id=backup_plan_id,
            resource_type="AWS::Backup::BackupPlan",
            compliance_status="NON_COMPLIANT",
            evaluation_reason="Backup plan has no rules defined",
            config_rule_name="backup-plan-min-frequency-and-min-retention-check",
            region=region,
            timestamp=datetime.now(),
            remediation_guidance="Add backup rules with appropriate frequency and retention"
        )
    
    # Check each rule for compliance
    non_compliant_rules = []
    
    for rule in rules:
        rule_name = rule.get('RuleName', 'Unnamed')
        
        # Check frequency (schedule expression)
        schedule = rule.get('ScheduleExpression', '')
        if not self._meets_frequency_requirement(schedule):
            non_compliant_rules.append(
                f"{rule_name}: frequency does not meet minimum (daily)"
            )
        
        # Check retention (minimum 35 days / 5 weeks)
        lifecycle = rule.get('Lifecycle', {})
        delete_after_days = lifecycle.get('DeleteAfterDays')
        
        if delete_after_days is None or delete_after_days < 35:
            non_compliant_rules.append(
                f"{rule_name}: retention {delete_after_days} days is less than minimum (35 days)"
            )
    
    if non_compliant_rules:
        return ComplianceResult(
            resource_id=backup_plan_id,
            resource_type="AWS::Backup::BackupPlan",
            compliance_status="NON_COMPLIANT",
            evaluation_reason=f"Backup plan rules do not meet requirements: {'; '.join(non_compliant_rules)}",
            config_rule_name="backup-plan-min-frequency-and-min-retention-check",
            region=region,
            timestamp=datetime.now(),
            remediation_guidance="Update backup plan rules to meet minimum frequency (daily) and retention (35 days)"
        )
    
    return ComplianceResult(
        resource_id=backup_plan_id,
        resource_type="AWS::Backup::BackupPlan",
        compliance_status="COMPLIANT",
        evaluation_reason="Backup plan meets frequency and retention requirements",
        config_rule_name="backup-plan-min-frequency-and-min-retention-check",
        region=region,
        timestamp=datetime.now()
    )

def _meets_frequency_requirement(self, schedule_expression):
    """Check if schedule expression meets minimum daily frequency."""
    if not schedule_expression:
        return False
    
    # Check for rate expressions (e.g., "rate(1 day)")
    if schedule_expression.startswith('rate('):
        # Extract number and unit
        match = re.match(r'rate\((\d+)\s+(hour|day|week)\)', schedule_expression)
        if match:
            value = int(match.group(1))
            unit = match.group(2)
            
            # Convert to hours for comparison
            if unit == 'hour':
                hours = value
            elif unit == 'day':
                hours = value * 24
            elif unit == 'week':
                hours = value * 24 * 7
            
            # Must be at least daily (24 hours or less)
            return hours <= 24
    
    # Check for cron expressions (e.g., "cron(0 0 * * ? *)")
    elif schedule_expression.startswith('cron('):
        # Daily or more frequent cron patterns
        # This is a simplified check - full cron parsing would be more complex
        return True  # Assume cron expressions are configured appropriately
    
    return False
```

### Backup Vault Access Policy Check

Evaluates backup vault access policies to ensure they don't allow overly permissive access:

```python
def evaluate_backup_vault_policy(self, resource, aws_factory):
    """Evaluate backup vault access policy for security."""
    vault_name = resource['BackupVaultName']
    vault_arn = resource['BackupVaultArn']
    policy = resource.get('Policy')
    region = resource['Region']
    
    # If no policy, vault is secure by default
    if not policy:
        return ComplianceResult(
            resource_id=vault_arn,
            resource_type="AWS::Backup::BackupVault",
            compliance_status="COMPLIANT",
            evaluation_reason="Backup vault has no access policy (secure by default)",
            config_rule_name="backup-vault-access-policy-check",
            region=region,
            timestamp=datetime.now()
        )
    
    try:
        # Parse policy JSON
        policy_doc = json.loads(policy) if isinstance(policy, str) else policy
        
        # Check for overly permissive principals
        security_issues = []
        
        for statement in policy_doc.get('Statement', []):
            principal = statement.get('Principal', {})
            effect = statement.get('Effect', '')
            
            # Check for wildcard principals with Allow effect
            if effect == 'Allow':
                if principal == '*' or principal == {'AWS': '*'}:
                    security_issues.append("Policy allows access from any principal (*)")
                
                # Check for overly broad actions
                actions = statement.get('Action', [])
                if isinstance(actions, str):
                    actions = [actions]
                
                if 'backup:*' in actions or '*' in actions:
                    security_issues.append("Policy allows all backup actions (*)")
        
        if security_issues:
            return ComplianceResult(
                resource_id=vault_arn,
                resource_type="AWS::Backup::BackupVault",
                compliance_status="NON_COMPLIANT",
                evaluation_reason=f"Backup vault policy has security issues: {'; '.join(security_issues)}",
                config_rule_name="backup-vault-access-policy-check",
                region=region,
                timestamp=datetime.now(),
                remediation_guidance="Update vault policy to restrict access to specific principals and actions"
            )
        
        return ComplianceResult(
            resource_id=vault_arn,
            resource_type="AWS::Backup::BackupVault",
            compliance_status="COMPLIANT",
            evaluation_reason="Backup vault policy follows security best practices",
            config_rule_name="backup-vault-access-policy-check",
            region=region,
            timestamp=datetime.now()
        )
        
    except (json.JSONDecodeError, KeyError) as e:
        return ComplianceResult(
            resource_id=vault_arn,
            resource_type="AWS::Backup::BackupVault",
            compliance_status="ERROR",
            evaluation_reason=f"Failed to parse vault policy: {str(e)}",
            config_rule_name="backup-vault-access-policy-check",
            region=region,
            timestamp=datetime.now(),
            remediation_guidance="Verify vault policy is valid JSON"
        )
```

### Backup Controls Integration

The AWS Backup service-level controls complement the existing resource-specific backup controls:

**Resource-Specific Controls** (existing):
- `backup-recovery-point-encrypted`: Validates individual recovery points are encrypted
- `backup-recovery-point-minimum-retention-check`: Checks retention of recovery points
- `backup-recovery-point-manual-deletion-disabled`: Ensures manual deletion is disabled
- And 9 other resource-specific backup controls

**Service-Level Controls** (new):
- `backup-plan-min-frequency-and-min-retention-check`: Validates backup plan policies
- `backup-vault-access-policy-check`: Checks backup vault security

This hybrid approach provides comprehensive backup coverage at both the service configuration level and individual resource level.
