"""Configuration loader for CIS Controls and AWS Config rule mappings."""

import os
import yaml
from typing import Dict, List, Optional
from pathlib import Path

from aws_cis_assessment.core.models import ConfigRule, CISControl, ImplementationGroup


class ConfigRuleLoader:
    """Load and parse AWS Config rule specifications for CIS Controls."""
    
    def __init__(self, config_path: Optional[str] = None):
        """Initialize with path to CIS Controls configuration files.
        
        Args:
            config_path: Path to configuration directory. If None, uses package default.
        """
        if config_path is None:
            # Use package default configuration path
            package_dir = Path(__file__).parent
            self.config_path = package_dir / "rules"
        else:
            self.config_path = Path(config_path)
        
        self._config_cache = {}
        self._rules_cache = {}
    
    def load_rules_for_ig(self, implementation_group: str) -> Dict[str, List[ConfigRule]]:
        """Load all Config rules for specified Implementation Group.
        
        Args:
            implementation_group: IG1, IG2, or IG3
            
        Returns:
            Dictionary mapping control IDs to lists of ConfigRule objects
            
        Raises:
            ValueError: If implementation group is invalid
            FileNotFoundError: If configuration file not found
        """
        if implementation_group not in [ig.value for ig in ImplementationGroup]:
            raise ValueError(f"Invalid implementation group: {implementation_group}")
        
        # Check cache first
        cache_key = f"rules_{implementation_group}"
        if cache_key in self._rules_cache:
            return self._rules_cache[cache_key]
        
        # Load configuration file
        config_file = self.config_path / f"cis_controls_{implementation_group.lower()}.yaml"
        if not config_file.exists():
            raise FileNotFoundError(f"Configuration file not found: {config_file}")
        
        with open(config_file, 'r', encoding='utf-8') as f:
            config_data = yaml.safe_load(f)
        
        # Parse configuration into ConfigRule objects
        rules_by_control = {}
        
        if 'controls' in config_data:
            for control_id, control_data in config_data['controls'].items():
                config_rules = []
                
                if 'config_rules' in control_data:
                    for rule_data in control_data['config_rules']:
                        config_rule = ConfigRule(
                            name=rule_data['name'],
                            control_id=control_id,
                            resource_types=rule_data.get('resource_types', []),
                            parameters=rule_data.get('parameters', {}),
                            implementation_group=implementation_group,
                            description=rule_data.get('description', ''),
                            remediation_guidance=rule_data.get('remediation_guidance', '')
                        )
                        config_rules.append(config_rule)
                
                if config_rules:
                    rules_by_control[control_id] = config_rules
        
        # Cache results
        self._rules_cache[cache_key] = rules_by_control
        return rules_by_control
    
    def get_rule_by_name(self, rule_name: str) -> Optional[ConfigRule]:
        """Get specific Config rule definition by name.
        
        Args:
            rule_name: Name of the AWS Config rule
            
        Returns:
            ConfigRule object if found, None otherwise
        """
        # Search through all implementation groups
        for ig in ImplementationGroup:
            rules_by_control = self.load_rules_for_ig(ig.value)
            for control_rules in rules_by_control.values():
                for rule in control_rules:
                    if rule.name == rule_name:
                        return rule
        
        return None
    
    def get_all_controls(self) -> Dict[str, CISControl]:
        """Get all CIS Controls across all Implementation Groups.
        
        Returns:
            Dictionary mapping control IDs to CISControl objects
        """
        all_controls = {}
        
        for ig in ImplementationGroup:
            rules_by_control = self.load_rules_for_ig(ig.value)
            
            # Load control metadata
            config_file = self.config_path / f"cis_controls_{ig.value.lower()}.yaml"
            with open(config_file, 'r', encoding='utf-8') as f:
                config_data = yaml.safe_load(f)
            
            if 'controls' in config_data:
                for control_id, control_data in config_data['controls'].items():
                    # Create unique key for each IG-control combination
                    unique_key = f"{ig.value}_{control_id}"
                    
                    control = CISControl(
                        control_id=control_id,
                        title=control_data.get('title', ''),
                        implementation_group=ig.value,
                        config_rules=rules_by_control.get(control_id, []),
                        weight=control_data.get('weight', 1.0)
                    )
                    all_controls[unique_key] = control
        
        return all_controls
    
    def validate_configuration(self) -> List[str]:
        """Validate configuration files and return any errors.
        
        Returns:
            List of validation error messages
        """
        errors = []
        
        for ig in ImplementationGroup:
            config_file = self.config_path / f"cis_controls_{ig.value.lower()}.yaml"
            
            if not config_file.exists():
                errors.append(f"Missing configuration file: {config_file}")
                continue
            
            try:
                with open(config_file, 'r', encoding='utf-8') as f:
                    config_data = yaml.safe_load(f)
                
                # Validate structure
                if not isinstance(config_data, dict):
                    errors.append(f"Invalid YAML structure in {config_file}")
                    continue
                
                if 'controls' not in config_data:
                    errors.append(f"Missing 'controls' section in {config_file}")
                    continue
                
                # Validate each control
                for control_id, control_data in config_data['controls'].items():
                    if not isinstance(control_data, dict):
                        errors.append(f"Invalid control data for {control_id} in {config_file}")
                        continue
                    
                    if 'title' not in control_data:
                        errors.append(f"Missing title for control {control_id} in {config_file}")
                    
                    if 'config_rules' in control_data:
                        for i, rule_data in enumerate(control_data['config_rules']):
                            if not isinstance(rule_data, dict):
                                errors.append(f"Invalid rule data at index {i} for control {control_id}")
                                continue
                            
                            if 'name' not in rule_data:
                                errors.append(f"Missing rule name at index {i} for control {control_id}")
                            
                            if 'resource_types' not in rule_data:
                                errors.append(f"Missing resource_types for rule at index {i} for control {control_id}")
            
            except yaml.YAMLError as e:
                errors.append(f"YAML parsing error in {config_file}: {e}")
            except Exception as e:
                errors.append(f"Error validating {config_file}: {e}")
        
        return errors
    
    def get_rules_count_by_ig(self) -> Dict[str, int]:
        """Get count of Config rules by Implementation Group.
        
        Returns:
            Dictionary mapping IG names to rule counts
        """
        counts = {}
        
        for ig in ImplementationGroup:
            try:
                rules_by_control = self.load_rules_for_ig(ig.value)
                total_rules = sum(len(rules) for rules in rules_by_control.values())
                counts[ig.value] = total_rules
            except (FileNotFoundError, ValueError):
                counts[ig.value] = 0
        
        return counts
    
    def get_assessment_statistics(self, implementation_groups: Optional[List[str]] = None,
                                controls: Optional[List[str]] = None,
                                regions: Optional[List[str]] = None) -> Dict[str, any]:
        """Get assessment statistics based on specified criteria.
        
        Args:
            implementation_groups: List of IGs to include (default: all)
            controls: List of specific control IDs to include
            regions: List of regions to include (for estimation)
            
        Returns:
            Dictionary containing assessment statistics
        """
        # Default to all IGs if none specified
        if implementation_groups is None:
            implementation_groups = [ig.value for ig in ImplementationGroup]
        
        # Default regions for estimation
        if regions is None:
            from aws_cis_assessment.cli.utils import get_default_regions
            regions = get_default_regions()
        
        stats = {
            'total_controls': 0,
            'total_config_rules': 0,
            'total_regions': len(regions),
            'estimated_assessments': 0,
            'by_implementation_group': {},
            'by_service': {},
            'resource_types': set()
        }
        
        # Get all controls
        all_controls = self.get_all_controls()
        
        # Filter controls based on criteria
        filtered_controls = {}
        for control_id, control in all_controls.items():
            # Filter by implementation group
            if control.implementation_group not in implementation_groups:
                continue
            
            # Filter by specific controls
            if controls and control_id not in controls:
                continue
            
            filtered_controls[control_id] = control
        
        # Calculate statistics
        stats['total_controls'] = len(filtered_controls)
        
        for control_id, control in filtered_controls.items():
            ig = control.implementation_group
            
            # Initialize IG stats if needed
            if ig not in stats['by_implementation_group']:
                stats['by_implementation_group'][ig] = {
                    'controls': 0,
                    'config_rules': 0
                }
            
            # Count controls and rules
            stats['by_implementation_group'][ig]['controls'] += 1
            stats['by_implementation_group'][ig]['config_rules'] += len(control.config_rules)
            stats['total_config_rules'] += len(control.config_rules)
            
            # Count by service and resource types
            for rule in control.config_rules:
                # Extract service from rule name (heuristic)
                service = self._extract_service_from_rule(rule.name)
                if service:
                    stats['by_service'][service] = stats['by_service'].get(service, 0) + 1
                
                # Add resource types
                stats['resource_types'].update(rule.resource_types)
        
        # Estimate total assessments (rules * regions)
        stats['estimated_assessments'] = stats['total_config_rules'] * len(regions)
        
        # Convert set to list for JSON serialization
        stats['resource_types'] = sorted(list(stats['resource_types']))
        
        return stats
    
    def _extract_service_from_rule(self, rule_name: str) -> Optional[str]:
        """Extract AWS service name from Config rule name.
        
        Args:
            rule_name: AWS Config rule name
            
        Returns:
            Service name if identifiable, None otherwise
        """
        # Common service prefixes in Config rule names
        service_prefixes = {
            'ec2-': 'EC2',
            'iam-': 'IAM',
            's3-': 'S3',
            'rds-': 'RDS',
            'vpc-': 'VPC',
            'elb-': 'ELB',
            'alb-': 'ALB',
            'api-gw-': 'API Gateway',
            'cloudtrail-': 'CloudTrail',
            'guardduty-': 'GuardDuty',
            'dynamodb-': 'DynamoDB',
            'redshift-': 'Redshift',
            'secretsmanager-': 'Secrets Manager',
            'backup-': 'Backup',
            'ecr-': 'ECR'
        }
        
        rule_lower = rule_name.lower()
        for prefix, service in service_prefixes.items():
            if rule_lower.startswith(prefix):
                return service
        
        return 'Other'