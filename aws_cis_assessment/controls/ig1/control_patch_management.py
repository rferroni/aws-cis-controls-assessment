"""
CIS Control 2.1-2.3 - Patch Management Controls
Ensures systems are properly patched and patch compliance is maintained.
"""

import logging
from typing import List, Dict, Any
from botocore.exceptions import ClientError

from aws_cis_assessment.controls.base_control import BaseConfigRuleAssessment
from aws_cis_assessment.core.models import ComplianceResult, ComplianceStatus
from aws_cis_assessment.core.aws_client_factory import AWSClientFactory

logger = logging.getLogger(__name__)


class SSMPatchManagerEnabledAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 2.1 - Establish and Maintain a Software Inventory
    AWS Config Rule: ssm-patch-manager-enabled
    
    Ensures AWS Systems Manager Patch Manager is configured with patch baselines
    for automated patch management across EC2 instances.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="ssm-patch-manager-enabled",
            control_id="2.1",
            resource_types=["AWS::::Account"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get SSM Patch Manager configuration for the account."""
        if resource_type != "AWS::::Account":
            return []
        
        try:
            ssm_client = aws_factory.get_client('ssm', region)
            
            # Get all patch baselines
            baselines = []
            paginator = ssm_client.get_paginator('describe_patch_baselines')
            
            for page in paginator.paginate():
                baselines.extend(page.get('BaselineIdentities', []))
            
            # Get default patch baseline for each OS
            default_baselines = {}
            for os_type in ['WINDOWS', 'AMAZON_LINUX', 'AMAZON_LINUX_2', 'UBUNTU', 'REDHAT_ENTERPRISE_LINUX', 
                           'SUSE', 'CENTOS', 'ORACLE_LINUX', 'DEBIAN', 'MACOS']:
                try:
                    response = ssm_client.get_default_patch_baseline(OperatingSystem=os_type)
                    default_baselines[os_type] = response.get('BaselineId', '')
                except ClientError:
                    # No default baseline for this OS type
                    pass
            
            # Check if any patch baselines are configured
            has_baselines = len(baselines) > 0
            has_default_baselines = len(default_baselines) > 0
            
            return [{
                'AccountId': aws_factory.get_account_info().get('account_id', 'unknown'),
                'Region': region,
                'TotalBaselines': len(baselines),
                'Baselines': baselines[:10],  # Limit to first 10 for display
                'DefaultBaselines': default_baselines,
                'HasBaselines': has_baselines,
                'HasDefaultBaselines': has_default_baselines
            }]
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'AccessDeniedException':
                logger.warning(f"Access denied to check SSM Patch Manager in {region}")
            else:
                logger.error(f"Error checking SSM Patch Manager in {region}: {e}")
            return []
    
    def _evaluate_resource_compliance(
        self, 
        resource: Dict[str, Any], 
        aws_factory: AWSClientFactory, 
        region: str
    ) -> ComplianceResult:
        """Evaluate if SSM Patch Manager is properly configured."""
        account_id = resource.get('AccountId', 'unknown')
        has_baselines = resource.get('HasBaselines', False)
        has_default_baselines = resource.get('HasDefaultBaselines', False)
        total_baselines = resource.get('TotalBaselines', 0)
        default_baselines = resource.get('DefaultBaselines', {})
        
        # Check if patch management is configured
        is_compliant = has_baselines and has_default_baselines
        
        if is_compliant:
            os_list = ', '.join(default_baselines.keys())
            evaluation_reason = (
                f"SSM Patch Manager is configured in {region} with {total_baselines} patch baseline(s). "
                f"Default baselines configured for: {os_list}"
            )
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            if not has_baselines:
                evaluation_reason = f"No patch baselines configured in SSM Patch Manager in {region}."
            elif not has_default_baselines:
                evaluation_reason = (
                    f"SSM Patch Manager has {total_baselines} baseline(s) but no default baselines "
                    f"are configured for any operating systems in {region}."
                )
            else:
                evaluation_reason = f"SSM Patch Manager is not properly configured in {region}."
            compliance_status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceResult(
            resource_id=f"{account_id}-{region}",
            resource_type="AWS::::Account",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get remediation steps for configuring SSM Patch Manager."""
        return [
            "1. Configure SSM Patch Manager with default patch baselines:",
            "   # Set default patch baseline for Amazon Linux 2",
            "   aws ssm register-default-patch-baseline \\",
            "     --baseline-id <baseline-id> \\",
            "     --region <region>",
            "",
            "2. Create a custom patch baseline (example for Amazon Linux 2):",
            "   aws ssm create-patch-baseline \\",
            "     --name 'AmazonLinux2-CustomBaseline' \\",
            "     --operating-system AMAZON_LINUX_2 \\",
            "     --approval-rules 'PatchRules=[{PatchFilterGroup={PatchFilters=[{Key=CLASSIFICATION,Values=[Security,Bugfix]},{Key=SEVERITY,Values=[Critical,Important]}]},ApprovalAfterDays=7}]' \\",
            "     --description 'Custom patch baseline for Amazon Linux 2' \\",
            "     --region <region>",
            "",
            "3. Register the custom baseline as default:",
            "   aws ssm register-default-patch-baseline \\",
            "     --baseline-id <baseline-id-from-step-2> \\",
            "     --region <region>",
            "",
            "4. Create patch baselines for all OS types in use:",
            "   # Windows",
            "   aws ssm create-patch-baseline \\",
            "     --name 'Windows-CustomBaseline' \\",
            "     --operating-system WINDOWS \\",
            "     --approval-rules 'PatchRules=[{PatchFilterGroup={PatchFilters=[{Key=CLASSIFICATION,Values=[SecurityUpdates,CriticalUpdates]},{Key=MSRC_SEVERITY,Values=[Critical,Important]}]},ApprovalAfterDays=7}]' \\",
            "     --region <region>",
            "",
            "   # Ubuntu",
            "   aws ssm create-patch-baseline \\",
            "     --name 'Ubuntu-CustomBaseline' \\",
            "     --operating-system UBUNTU \\",
            "     --approval-rules 'PatchRules=[{PatchFilterGroup={PatchFilters=[{Key=PRIORITY,Values=[Required,Important]}]},ApprovalAfterDays=7}]' \\",
            "     --region <region>",
            "",
            "5. Console method:",
            "   - Navigate to AWS Systems Manager",
            "   - Click 'Patch Manager' in the left menu",
            "   - Click 'Configure patching'",
            "   - Select 'Patch baselines'",
            "   - Click 'Create patch baseline'",
            "   - Configure baseline settings:",
            "     * Name and description",
            "     * Operating system",
            "     * Approval rules (auto-approve after X days)",
            "     * Patch exceptions (if needed)",
            "   - Click 'Create patch baseline'",
            "   - Set as default: Actions > Set default patch baseline",
            "",
            "6. Create a maintenance window for automated patching:",
            "   aws ssm create-maintenance-window \\",
            "     --name 'PatchingWindow' \\",
            "     --schedule 'cron(0 2 ? * SUN *)' \\",
            "     --duration 4 \\",
            "     --cutoff 1 \\",
            "     --allow-unassociated-targets \\",
            "     --region <region>",
            "",
            "7. Register targets for the maintenance window:",
            "   aws ssm register-target-with-maintenance-window \\",
            "     --window-id <window-id> \\",
            "     --target-type INSTANCE \\",
            "     --targets 'Key=tag:Patch Group,Values=Production' \\",
            "     --region <region>",
            "",
            "8. Register a patch task:",
            "   aws ssm register-task-with-maintenance-window \\",
            "     --window-id <window-id> \\",
            "     --target-id <target-id> \\",
            "     --task-type RUN_COMMAND \\",
            "     --task-arn AWS-RunPatchBaseline \\",
            "     --service-role-arn <role-arn> \\",
            "     --task-invocation-parameters 'RunCommand={Parameters={Operation=[Install]}}' \\",
            "     --priority 1 \\",
            "     --max-concurrency 50% \\",
            "     --max-errors 10% \\",
            "     --region <region>",
            "",
            "9. Best practices:",
            "   - Create separate patch baselines for different environments (dev/staging/prod)",
            "   - Use patch groups to organize instances",
            "   - Set appropriate approval delays (7 days for production)",
            "   - Configure maintenance windows during off-peak hours",
            "   - Enable SNS notifications for patch operations",
            "   - Monitor patch compliance with AWS Config",
            "   - Test patches in non-production first",
            "",
            "10. Verify configuration:",
            "    # List all patch baselines",
            "    aws ssm describe-patch-baselines --region <region>",
            "",
            "    # Get default baseline for an OS",
            "    aws ssm get-default-patch-baseline \\",
            "      --operating-system AMAZON_LINUX_2 \\",
            "      --region <region>",
            "",
            "Priority: HIGH - Patch management is critical for security",
            "Effort: Medium - Requires baseline configuration and maintenance windows",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/systems-manager/latest/userguide/systems-manager-patch.html"
        ]



class SSMPatchBaselineConfiguredAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 2.2 - Ensure Authorized Software is Currently Supported
    AWS Config Rule: ssm-patch-baseline-configured
    
    Ensures SSM patch baselines are properly configured with appropriate
    approval rules and patch filters for security updates.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="ssm-patch-baseline-configured",
            control_id="2.2",
            resource_types=["AWS::SSM::PatchBaseline"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get all SSM patch baselines in the region."""
        if resource_type != "AWS::SSM::PatchBaseline":
            return []
        
        try:
            ssm_client = aws_factory.get_client('ssm', region)
            
            baselines = []
            paginator = ssm_client.get_paginator('describe_patch_baselines')
            
            for page in paginator.paginate(Filters=[{'Key': 'OWNER', 'Values': ['Self']}]):
                for baseline_identity in page.get('BaselineIdentities', []):
                    baseline_id = baseline_identity.get('BaselineId', '')
                    
                    try:
                        # Get detailed baseline information
                        response = ssm_client.get_patch_baseline(BaselineId=baseline_id)
                        
                        baseline_name = response.get('Name', '')
                        operating_system = response.get('OperatingSystem', '')
                        approval_rules = response.get('ApprovalRules', {})
                        patch_groups = response.get('PatchGroups', [])
                        
                        # Check if baseline has approval rules
                        has_approval_rules = bool(approval_rules.get('PatchRules', []))
                        
                        baselines.append({
                            'BaselineId': baseline_id,
                            'BaselineName': baseline_name,
                            'OperatingSystem': operating_system,
                            'ApprovalRules': approval_rules,
                            'HasApprovalRules': has_approval_rules,
                            'PatchGroups': patch_groups,
                            'Description': response.get('Description', '')
                        })
                        
                    except ClientError as e:
                        logger.warning(f"Error getting baseline {baseline_id}: {e}")
                        continue
            
            logger.debug(f"Found {len(baselines)} custom patch baselines in {region}")
            return baselines
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'AccessDeniedException':
                logger.warning(f"Access denied to list patch baselines in {region}")
            else:
                logger.error(f"Error retrieving patch baselines from {region}: {e}")
            return []
    
    def _evaluate_resource_compliance(
        self, 
        resource: Dict[str, Any], 
        aws_factory: AWSClientFactory, 
        region: str
    ) -> ComplianceResult:
        """Evaluate if patch baseline is properly configured."""
        baseline_id = resource.get('BaselineId', 'unknown')
        baseline_name = resource.get('BaselineName', '')
        operating_system = resource.get('OperatingSystem', '')
        has_approval_rules = resource.get('HasApprovalRules', False)
        approval_rules = resource.get('ApprovalRules', {})
        
        # Check if baseline has proper approval rules
        is_compliant = has_approval_rules
        
        if is_compliant:
            patch_rules = approval_rules.get('PatchRules', [])
            rule_count = len(patch_rules)
            evaluation_reason = (
                f"Patch baseline '{baseline_name}' ({operating_system}) is properly configured "
                f"with {rule_count} approval rule(s)."
            )
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            evaluation_reason = (
                f"Patch baseline '{baseline_name}' ({operating_system}) does not have approval rules configured. "
                f"Approval rules are required to automatically approve patches."
            )
            compliance_status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceResult(
            resource_id=baseline_id,
            resource_type="AWS::SSM::PatchBaseline",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get remediation steps for configuring patch baseline approval rules."""
        return [
            "1. Update an existing patch baseline with approval rules:",
            "   aws ssm update-patch-baseline \\",
            "     --baseline-id <baseline-id> \\",
            "     --approval-rules 'PatchRules=[{",
            "       PatchFilterGroup={",
            "         PatchFilters=[",
            "           {Key=CLASSIFICATION,Values=[Security,Bugfix]},",
            "           {Key=SEVERITY,Values=[Critical,Important]}",
            "         ]",
            "       },",
            "       ApprovalAfterDays=7,",
            "       ComplianceLevel=CRITICAL",
            "     }]' \\",
            "     --region <region>",
            "",
            "2. Console method:",
            "   - Navigate to AWS Systems Manager",
            "   - Click 'Patch Manager' > 'Patch baselines'",
            "   - Select the baseline",
            "   - Click 'Actions' > 'Modify patch baseline'",
            "   - Under 'Approval rules', click 'Add rule'",
            "   - Configure the rule:",
            "     * Product: Select OS/product",
            "     * Classification: Select patch types (Security, Bugfix, etc.)",
            "     * Severity: Select severity levels (Critical, Important, etc.)",
            "     * Auto-approval: Set days to wait before auto-approval",
            "     * Compliance reporting: Set compliance level",
            "   - Click 'Add rule'",
            "   - Click 'Save changes'",
            "",
            "3. Example approval rules for different OS types:",
            "   # Windows - Security and Critical Updates",
            "   PatchRules=[{",
            "     PatchFilterGroup={",
            "       PatchFilters=[",
            "         {Key=CLASSIFICATION,Values=[SecurityUpdates,CriticalUpdates]},",
            "         {Key=MSRC_SEVERITY,Values=[Critical,Important]}",
            "       ]",
            "     },",
            "     ApprovalAfterDays=7",
            "   }]",
            "",
            "   # Linux - Security and Bugfix patches",
            "   PatchRules=[{",
            "     PatchFilterGroup={",
            "       PatchFilters=[",
            "         {Key=CLASSIFICATION,Values=[Security,Bugfix]},",
            "         {Key=SEVERITY,Values=[Critical,Important]}",
            "       ]",
            "     },",
            "     ApprovalAfterDays=7",
            "   }]",
            "",
            "4. Best practices for approval rules:",
            "   - Auto-approve security patches after 7 days for production",
            "   - Auto-approve immediately for non-production environments",
            "   - Include both Security and Bugfix classifications",
            "   - Focus on Critical and Important severity levels",
            "   - Set compliance level to CRITICAL for security patches",
            "   - Create separate rules for different patch types",
            "",
            "5. Verify baseline configuration:",
            "   aws ssm get-patch-baseline \\",
            "     --baseline-id <baseline-id> \\",
            "     --region <region>",
            "",
            "Priority: HIGH - Proper patch baseline configuration is essential",
            "Effort: Low - Can be configured quickly via CLI or Console",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/systems-manager/latest/userguide/patch-manager-approval-rules.html"
        ]



class EC2PatchComplianceStatusAssessment(BaseConfigRuleAssessment):
    """
    CIS Control 2.3 - Address Unauthorized Software
    AWS Config Rule: ec2-patch-compliance-status
    
    Ensures EC2 instances managed by Systems Manager have compliant patch status
    and are up to date with approved patches.
    """
    
    def __init__(self):
        super().__init__(
            rule_name="ec2-patch-compliance-status",
            control_id="2.3",
            resource_types=["AWS::EC2::Instance"]
        )
    
    def _get_resources(self, aws_factory: AWSClientFactory, resource_type: str, region: str) -> List[Dict[str, Any]]:
        """Get patch compliance status for all SSM-managed EC2 instances."""
        if resource_type != "AWS::EC2::Instance":
            return []
        
        try:
            ssm_client = aws_factory.get_client('ssm', region)
            
            instances = []
            paginator = ssm_client.get_paginator('describe_instance_patch_states')
            
            for page in paginator.paginate():
                for instance_state in page.get('InstancePatchStates', []):
                    instance_id = instance_state.get('InstanceId', '')
                    patch_group = instance_state.get('PatchGroup', '')
                    baseline_id = instance_state.get('BaselineId', '')
                    operation = instance_state.get('Operation', '')
                    operation_end_time = instance_state.get('OperationEndTime', '')
                    
                    # Get patch counts
                    installed_count = instance_state.get('InstalledCount', 0)
                    installed_other_count = instance_state.get('InstalledOtherCount', 0)
                    installed_pending_reboot_count = instance_state.get('InstalledPendingRebootCount', 0)
                    installed_rejected_count = instance_state.get('InstalledRejectedCount', 0)
                    missing_count = instance_state.get('MissingCount', 0)
                    failed_count = instance_state.get('FailedCount', 0)
                    not_applicable_count = instance_state.get('NotApplicableCount', 0)
                    
                    # Determine compliance status
                    is_compliant = (missing_count == 0 and failed_count == 0 and 
                                  installed_pending_reboot_count == 0)
                    
                    instances.append({
                        'InstanceId': instance_id,
                        'PatchGroup': patch_group,
                        'BaselineId': baseline_id,
                        'Operation': operation,
                        'OperationEndTime': str(operation_end_time) if operation_end_time else '',
                        'InstalledCount': installed_count,
                        'InstalledPendingRebootCount': installed_pending_reboot_count,
                        'MissingCount': missing_count,
                        'FailedCount': failed_count,
                        'IsCompliant': is_compliant
                    })
            
            logger.debug(f"Found {len(instances)} SSM-managed instances with patch state in {region}")
            return instances
            
        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', '')
            if error_code == 'AccessDeniedException':
                logger.warning(f"Access denied to check patch compliance in {region}")
            else:
                logger.error(f"Error retrieving patch compliance from {region}: {e}")
            return []
    
    def _evaluate_resource_compliance(
        self, 
        resource: Dict[str, Any], 
        aws_factory: AWSClientFactory, 
        region: str
    ) -> ComplianceResult:
        """Evaluate if EC2 instance has compliant patch status."""
        instance_id = resource.get('InstanceId', 'unknown')
        is_compliant = resource.get('IsCompliant', False)
        missing_count = resource.get('MissingCount', 0)
        failed_count = resource.get('FailedCount', 0)
        pending_reboot_count = resource.get('InstalledPendingRebootCount', 0)
        installed_count = resource.get('InstalledCount', 0)
        patch_group = resource.get('PatchGroup', 'None')
        
        if is_compliant:
            evaluation_reason = (
                f"EC2 instance '{instance_id}' (Patch Group: {patch_group}) is patch compliant. "
                f"Installed patches: {installed_count}, Missing: 0, Failed: 0"
            )
            compliance_status = ComplianceStatus.COMPLIANT
        else:
            issues = []
            if missing_count > 0:
                issues.append(f"{missing_count} missing patch(es)")
            if failed_count > 0:
                issues.append(f"{failed_count} failed patch(es)")
            if pending_reboot_count > 0:
                issues.append(f"{pending_reboot_count} patch(es) pending reboot")
            
            evaluation_reason = (
                f"EC2 instance '{instance_id}' (Patch Group: {patch_group}) is not patch compliant. "
                f"Issues: {', '.join(issues)}"
            )
            compliance_status = ComplianceStatus.NON_COMPLIANT
        
        return ComplianceResult(
            resource_id=instance_id,
            resource_type="AWS::EC2::Instance",
            compliance_status=compliance_status,
            evaluation_reason=evaluation_reason,
            config_rule_name=self.rule_name,
            region=region
        )
    
    def _get_rule_remediation_steps(self) -> List[str]:
        """Get remediation steps for achieving patch compliance."""
        return [
            "1. Install missing patches on non-compliant instances:",
            "   aws ssm send-command \\",
            "     --document-name 'AWS-RunPatchBaseline' \\",
            "     --instance-ids <instance-id> \\",
            "     --parameters 'Operation=Install' \\",
            "     --region <region>",
            "",
            "2. Scan for patch compliance without installing:",
            "   aws ssm send-command \\",
            "     --document-name 'AWS-RunPatchBaseline' \\",
            "     --instance-ids <instance-id> \\",
            "     --parameters 'Operation=Scan' \\",
            "     --region <region>",
            "",
            "3. Check patch compliance status:",
            "   aws ssm describe-instance-patch-states \\",
            "     --instance-ids <instance-id> \\",
            "     --region <region>",
            "",
            "4. Get detailed patch information:",
            "   aws ssm describe-instance-patches \\",
            "     --instance-id <instance-id> \\",
            "     --region <region>",
            "",
            "5. Console method:",
            "   - Navigate to AWS Systems Manager",
            "   - Click 'Patch Manager' in the left menu",
            "   - Click 'Patch now' button",
            "   - Select 'Scan and install'",
            "   - Choose instances:",
            "     * Select instances manually, or",
            "     * Use tags to select instances, or",
            "     * Select by patch group",
            "   - Configure patching:",
            "     * Patching operation: Scan and install",
            "     * Reboot option: Reboot if needed / No reboot",
            "     * Concurrency: Number or percentage",
            "     * Error threshold: Number or percentage",
            "   - Click 'Patch now'",
            "",
            "6. Reboot instances with pending reboot patches:",
            "   aws ec2 reboot-instances \\",
            "     --instance-ids <instance-id> \\",
            "     --region <region>",
            "",
            "7. Set up automated patching with maintenance windows:",
            "   # Create maintenance window (if not exists)",
            "   aws ssm create-maintenance-window \\",
            "     --name 'Weekly-Patching' \\",
            "     --schedule 'cron(0 2 ? * SUN *)' \\",
            "     --duration 4 \\",
            "     --cutoff 1 \\",
            "     --region <region>",
            "",
            "8. Troubleshoot failed patches:",
            "   # View patch execution logs",
            "   aws ssm get-command-invocation \\",
            "     --command-id <command-id> \\",
            "     --instance-id <instance-id> \\",
            "     --region <region>",
            "",
            "   # Common failure reasons:",
            "   - Insufficient disk space",
            "   - Network connectivity issues",
            "   - Package manager conflicts",
            "   - Missing dependencies",
            "",
            "9. Best practices:",
            "   - Schedule regular patching windows (weekly or monthly)",
            "   - Test patches in non-production first",
            "   - Allow automatic reboots during maintenance windows",
            "   - Monitor patch compliance with CloudWatch",
            "   - Set up SNS notifications for patch failures",
            "   - Use patch groups to organize instances",
            "   - Maintain at least 7-day approval delay for production",
            "",
            "10. Verify compliance after patching:",
            "    # Wait for patching to complete, then check status",
            "    aws ssm describe-instance-patch-states \\",
            "      --instance-ids <instance-id> \\",
            "      --query 'InstancePatchStates[0].{Missing:MissingCount,Failed:FailedCount,PendingReboot:InstalledPendingRebootCount}' \\",
            "      --region <region>",
            "",
            "Priority: CRITICAL - Unpatched systems are vulnerable to exploits",
            "Effort: Medium - Requires patching execution and potential reboots",
            "",
            "AWS Documentation:",
            "https://docs.aws.amazon.com/systems-manager/latest/userguide/patch-manager-compliance.html"
        ]
