"""Main CLI entry point for AWS CIS Controls compliance assessment tool."""

import os
import sys
import json
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime

import click
from tabulate import tabulate

from aws_cis_assessment.core.assessment_engine import AssessmentEngine, AssessmentProgress
from aws_cis_assessment.core.scoring_engine import ScoringEngine
from aws_cis_assessment.config.config_loader import ConfigRuleLoader
from aws_cis_assessment.reporters.json_reporter import JSONReporter
from aws_cis_assessment.reporters.html_reporter import HTMLReporter
from aws_cis_assessment.reporters.csv_reporter import CSVReporter
from aws_cis_assessment.core.models import ImplementationGroup
from aws_cis_assessment.cli.utils import (
    get_default_regions, validate_output_format, format_duration,
    colorize_compliance_status, is_tty
)
from aws_cis_assessment.cli.examples import (
    get_all_examples, get_troubleshooting_guide, get_best_practices
)
from aws_cis_assessment import __version__


def _parse_output_formats(ctx, param, value):
    """Parse output formats, handling both multiple flags and comma-separated values."""
    if not value:
        return ['json', 'html']  # default
    
    valid_formats = ['json', 'html', 'csv']
    formats = []
    
    # Handle tuple (from multiple=True), comma-separated string, or single string
    if isinstance(value, (tuple, list)):
        for v in value:
            formats.extend([fmt.strip().lower() for fmt in v.split(',')])
    elif isinstance(value, str):
        formats = [fmt.strip().lower() for fmt in value.split(',')]
    else:
        formats = [str(value).lower()]
    
    # Validate formats
    invalid_formats = [fmt for fmt in formats if fmt not in valid_formats]
    if invalid_formats:
        raise click.BadParameter(f"Invalid format(s): {', '.join(invalid_formats)}. Valid formats: {', '.join(valid_formats)}")
    
    # Remove duplicates while preserving order
    seen = set()
    unique_formats = []
    for fmt in formats:
        if fmt not in seen:
            seen.add(fmt)
            unique_formats.append(fmt)
    
    return unique_formats


# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class ProgressDisplay:
    """Display progress updates during assessment."""
    
    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.last_update = None
    
    def update_progress(self, progress: AssessmentProgress):
        """Update progress display."""
        if not self.verbose and progress.progress_percentage == self.last_update:
            return
        
        # Clear previous line if not verbose
        if not self.verbose:
            click.echo('\r', nl=False)
        
        # Format progress message
        if progress.current_control and progress.current_region:
            status_msg = f"Assessing {progress.current_control} in {progress.current_region}"
        else:
            status_msg = "Initializing assessment..."
        
        progress_bar = self._create_progress_bar(progress.progress_percentage)
        
        if self.verbose:
            click.echo(f"[{progress_bar}] {progress.progress_percentage:.1f}% - {status_msg}")
        else:
            click.echo(f"[{progress_bar}] {progress.progress_percentage:.1f}% - {status_msg}", nl=False)
        
        self.last_update = progress.progress_percentage
        
        # Show errors if any
        if progress.errors and self.verbose:
            for error in progress.errors[-3:]:  # Show last 3 errors
                click.echo(f"  ⚠️  {error}", err=True)
    
    def _create_progress_bar(self, percentage: float, width: int = 20) -> str:
        """Create a text-based progress bar."""
        filled = int(width * percentage / 100)
        bar = '█' * filled + '░' * (width - filled)
        return bar
    
    def finish(self):
        """Finish progress display."""
        if not self.verbose:
            click.echo()  # New line after progress


@click.group()
@click.version_option(version=__version__, prog_name="aws-cis-assess")
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.option('--debug', is_flag=True, help='Enable debug logging')
@click.pass_context
def cli(ctx, verbose, debug):
    """AWS CIS Controls Compliance Assessment Tool
    
    Evaluate AWS account security posture against CIS Controls Implementation Groups
    (IG1, IG2, IG3) and generate comprehensive compliance reports.
    
    Commands:
    
      assess              Run compliance assessment
      list-controls       List available CIS Controls
      list-regions        List available AWS regions
      show-stats          Show assessment statistics
      validate-config     Validate configuration files
      validate-credentials Test AWS credentials
      help-guide          Show detailed help and examples
    
    Examples:
    
      # Run full assessment with HTML report
      aws-cis-assess assess --output-format html --output-file report.html
      
      # Assess only IG1 controls in specific regions
      aws-cis-assess assess --implementation-groups IG1 --regions us-east-1,us-west-2
      
      # Assess specific controls with detailed logging
      aws-cis-assess assess --controls 1.1,3.3,4.1 --log-level DEBUG
      
      # Generate multiple output formats in custom directory
      aws-cis-assess assess --output-format json,html,csv --output-dir ./reports/
      
      # Use custom AWS profile and configuration
      aws-cis-assess assess --aws-profile prod --config-path ./custom-config/
    """
    ctx.ensure_object(dict)
    ctx.obj['verbose'] = verbose
    
    if debug:
        logging.getLogger().setLevel(logging.DEBUG)
        logging.getLogger('aws_cis_assessment').setLevel(logging.DEBUG)
    elif verbose:
        logging.getLogger().setLevel(logging.INFO)
    else:
        logging.getLogger().setLevel(logging.WARNING)


@cli.command()
@click.option('--implementation-groups', '-ig', 
              type=click.Choice(['IG1', 'IG2', 'IG3'], case_sensitive=False),
              multiple=True,
              help='Implementation Groups to assess (can specify multiple)')
@click.option('--controls', '-ctrl',
              help='Comma-separated list of specific CIS Control IDs to assess (e.g., 1.1,3.3,4.1)')
@click.option('--exclude-controls',
              help='Comma-separated list of CIS Control IDs to exclude from assessment')
@click.option('--regions', '-r',
              help='Comma-separated list of AWS regions (default: us-east-1)')
@click.option('--exclude-regions',
              help='Comma-separated list of AWS regions to exclude from assessment')
@click.option('--aws-profile', '-p',
              help='AWS profile to use for credentials')
@click.option('--aws-access-key-id',
              help='AWS Access Key ID (alternative to profile)')
@click.option('--aws-secret-access-key',
              help='AWS Secret Access Key (alternative to profile)')
@click.option('--aws-session-token',
              help='AWS Session Token (for temporary credentials)')
@click.option('--config-path', '-c',
              type=click.Path(exists=True, file_okay=False, dir_okay=True),
              help='Path to CIS Controls configuration directory')
@click.option('--output-format', '-f',
              default='json,html',
              callback=_parse_output_formats,
              help='Output format(s) for the report (comma-separated or multiple flags: json,html,csv or -f json -f html)')
@click.option('--output-file', '-o',
              help='Output file path (extension added based on format)')
@click.option('--output-dir',
              type=click.Path(file_okay=False, dir_okay=True),
              help='Output directory for generated reports')
@click.option('--max-workers', '-w',
              type=int,
              default=4,
              help='Maximum number of parallel workers for assessment')
@click.option('--timeout',
              type=int,
              default=3600,
              help='Assessment timeout in seconds (default: 3600)')
@click.option('--enable-error-recovery/--disable-error-recovery',
              default=True,
              help='Enable/disable error recovery mechanisms')
@click.option('--enable-audit-trail/--disable-audit-trail',
              default=True,
              help='Enable/disable audit trail logging')
@click.option('--dry-run',
              is_flag=True,
              help='Validate configuration and credentials without running assessment')
@click.option('--quiet', '-q',
              is_flag=True,
              help='Suppress progress output (only show final results)')
@click.option('--log-level',
              type=click.Choice(['DEBUG', 'INFO', 'WARNING', 'ERROR'], case_sensitive=False),
              help='Set logging level (overrides --verbose and --debug)')
@click.option('--log-file',
              type=click.Path(),
              help='Write logs to specified file in addition to console')
@click.pass_context
def assess(ctx, implementation_groups, controls, exclude_controls, regions, exclude_regions,
           aws_profile, aws_access_key_id, aws_secret_access_key, aws_session_token, 
           config_path, output_format, output_file, output_dir, max_workers, timeout,
           enable_error_recovery, enable_audit_trail, dry_run, quiet, log_level, log_file):
    """Run CIS Controls compliance assessment.
    
    This command evaluates your AWS account against CIS Controls Implementation Groups
    and generates comprehensive compliance reports.
    
    Examples:
    
      # Full assessment with default settings
      aws-cis-assess assess
      
      # Assess only essential controls (IG1) in specific regions
      aws-cis-assess assess -ig IG1 -r us-east-1,us-west-2
      
      # Assess specific controls across all regions
      aws-cis-assess assess --controls 1.1,3.3,4.1
      
      # Exclude certain regions from assessment
      aws-cis-assess assess --exclude-regions us-gov-east-1,us-gov-west-1
      
      # Generate HTML report with custom output directory
      aws-cis-assess assess -f html --output-dir ./reports/
      
      # Use specific AWS profile with custom configuration and logging
      aws-cis-assess assess -p production -c ./config/ --log-level DEBUG --log-file assessment.log
    """
    verbose = ctx.obj.get('verbose', False)
    
    try:
        # Configure logging based on options
        _configure_logging(verbose, ctx.obj.get('debug', False), log_level, log_file)
        
        # Parse regions and handle exclusions
        region_list = _parse_regions(regions, exclude_regions)
        
        # Parse implementation groups
        ig_list = list(implementation_groups) if implementation_groups else None
        
        # Parse controls and exclusions
        controls_list = _parse_controls(controls)
        exclude_controls_list = _parse_controls(exclude_controls)
        
        # Validate control selections
        if controls_list and ig_list:
            click.echo("⚠️  Warning: Both --controls and --implementation-groups specified. Controls will take precedence.", err=True)
        
        # Prepare AWS credentials
        aws_credentials = _prepare_aws_credentials(
            aws_profile, aws_access_key_id, aws_secret_access_key, aws_session_token
        )
        
        # Set up output directory — default to ./reports/ if neither output_dir nor output_file specified
        if not output_dir and not output_file:
            output_dir = './reports'
        
        if output_dir:
            output_base_path = Path(output_dir)
            output_base_path.mkdir(parents=True, exist_ok=True)
            if not output_file:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                output_file = str(output_base_path / f"cis_assessment_{timestamp}")
        
        # Add default log file to reports directory if user didn't specify one
        if not log_file and output_file:
            default_log_path = Path(output_file).with_suffix('.log')
            try:
                default_log_path.parent.mkdir(parents=True, exist_ok=True)
                file_handler = logging.FileHandler(str(default_log_path))
                file_handler.setLevel(logging.DEBUG)
                file_handler.setFormatter(logging.Formatter(
                    '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
                ))
                logging.getLogger().addHandler(file_handler)
            except Exception as e:
                click.echo(f"⚠️  Warning: Could not create log file {default_log_path}: {e}", err=True)
        
        # Initialize progress display (suppress if quiet mode)
        progress_display = ProgressDisplay(verbose=verbose and not quiet)
        
        # Initialize assessment engine
        if not quiet:
            click.echo("🔧 Initializing assessment engine...")
        
        engine = AssessmentEngine(
            aws_credentials=aws_credentials,
            regions=region_list,
            config_path=config_path,
            max_workers=max_workers,
            progress_callback=progress_display.update_progress if not quiet else None,
            enable_error_recovery=enable_error_recovery,
            enable_audit_trail=enable_audit_trail,
            timeout=timeout
        )
        
        # Validate configuration
        if not quiet:
            click.echo("✅ Validating configuration...")
        validation_errors = engine.validate_configuration()
        if validation_errors:
            click.echo("❌ Configuration validation failed:", err=True)
            for error in validation_errors:
                click.echo(f"  • {error}", err=True)
            sys.exit(1)
        
        # Show assessment summary
        summary = engine.get_assessment_summary(
            implementation_groups=ig_list,
            controls=controls_list,
            exclude_controls=exclude_controls_list
        )
        if not quiet:
            _display_assessment_summary(summary, verbose)
        
        if dry_run:
            click.echo("✅ Dry run completed successfully. Configuration is valid.")
            return
        
        # Run assessment
        if not quiet:
            click.echo("🚀 Starting compliance assessment...")
            click.echo(f"   Implementation Groups: {ig_list or summary.get('implementation_groups', ['IG1', 'IG2', 'IG3'])}")
            if controls_list:
                click.echo(f"   Specific Controls: {controls_list}")
            if exclude_controls_list:
                click.echo(f"   Excluded Controls: {exclude_controls_list}")
            click.echo(f"   Regions: {summary['regions']}")
            click.echo(f"   Total Assessments: {summary['total_assessments']}")
            click.echo()
        
        assessment_result = engine.run_assessment(
            implementation_groups=ig_list,
            controls=controls_list,
            exclude_controls=exclude_controls_list
        )
        
        if not quiet:
            progress_display.finish()
        
        # Generate compliance summary
        scoring_engine = engine.get_scoring_engine()
        compliance_summary = scoring_engine.generate_compliance_summary(assessment_result)
        
        # Display results summary
        _display_results_summary(assessment_result, compliance_summary, verbose and not quiet)
        
        # Generate reports
        _generate_reports(assessment_result, compliance_summary, output_format, output_file, verbose and not quiet)
        
        # Show error summary if available
        error_summary = engine.get_error_summary()
        if error_summary and verbose and not quiet:
            _display_error_summary(error_summary)
        
        if not quiet:
            click.echo("✅ Assessment completed successfully!")
        
        # Show final summary with color coding if terminal supports it
        if is_tty() and not quiet:
            overall_pct = compliance_summary.overall_compliance_percentage
            colored_status = colorize_compliance_status(f"{overall_pct:.1f}%", overall_pct)
            click.echo(f"\n🎯 Final Result: {colored_status} overall compliance")
        
    except KeyboardInterrupt:
        click.echo("\n⚠️  Assessment interrupted by user", err=True)
        sys.exit(1)
    except Exception as e:
        click.echo(f"❌ Assessment failed: {str(e)}", err=True)
        if verbose:
            import traceback
            click.echo(traceback.format_exc(), err=True)
        sys.exit(1)


@cli.command()
@click.option('--aws-profile', '-p',
              help='AWS profile to use for credentials')
@click.option('--output-format', '-f',
              type=click.Choice(['table', 'json'], case_sensitive=False),
              default='table',
              help='Output format for the region list')
@click.pass_context
def list_regions(ctx, aws_profile, output_format):
    """List available AWS regions.
    
    This command displays all AWS regions that can be used for assessment,
    showing which regions are enabled for your account.
    
    Examples:
    
      # List regions in table format
      aws-cis-assess list-regions
      
      # List regions in JSON format
      aws-cis-assess list-regions -f json
      
      # Use specific AWS profile
      aws-cis-assess list-regions -p production
    """
    verbose = ctx.obj.get('verbose', False)
    
    try:
        from aws_cis_assessment.cli.utils import get_all_enabled_regions, get_default_regions
        
        # Get regions
        if aws_profile:
            # Use specific profile to get enabled regions
            aws_credentials = _prepare_aws_credentials(aws_profile, None, None, None)
            from aws_cis_assessment.core.aws_client_factory import AWSClientFactory
            aws_factory = AWSClientFactory(aws_credentials, None)
            enabled_regions = aws_factory.get_enabled_regions()
        else:
            enabled_regions = get_all_enabled_regions()
        
        default_regions = get_default_regions()
        
        if output_format == 'json':
            # JSON output
            regions_data = {
                'enabled_regions': enabled_regions,
                'default_regions': default_regions,
                'total_enabled': len(enabled_regions),
                'total_default': len(default_regions)
            }
            click.echo(json.dumps(regions_data, indent=2))
        else:
            # Table output
            click.echo("📍 Available AWS Regions")
            click.echo("=" * 50)
            
            table_data = []
            for region in sorted(enabled_regions):
                is_default = "✓" if region in default_regions else ""
                table_data.append([region, is_default])
            
            headers = ['Region', 'Default']
            from tabulate import tabulate
            click.echo(tabulate(table_data, headers=headers, tablefmt='grid'))
            
            click.echo(f"\nTotal enabled regions: {len(enabled_regions)}")
            click.echo(f"Default regions for assessment: {len(default_regions)}")
            
    except Exception as e:
        click.echo(f"❌ Failed to list regions: {str(e)}", err=True)
        if verbose:
            import traceback
            click.echo(traceback.format_exc(), err=True)
        sys.exit(1)


@cli.command()
@click.option('--config-path', '-c',
              type=click.Path(exists=True, file_okay=False, dir_okay=True),
              help='Path to CIS Controls configuration directory')
@click.option('--implementation-groups', '-ig', 
              type=click.Choice(['IG1', 'IG2', 'IG3'], case_sensitive=False),
              multiple=True,
              help='Implementation Groups to analyze (can specify multiple)')
@click.option('--controls',
              help='Comma-separated list of specific CIS Control IDs to analyze')
@click.option('--regions', '-r',
              help='Comma-separated list of AWS regions to analyze')
@click.option('--output-format', '-f',
              type=click.Choice(['table', 'json'], case_sensitive=False),
              default='table',
              help='Output format for the statistics')
@click.pass_context
def show_stats(ctx, config_path, implementation_groups, controls, regions, output_format):
    """Show assessment statistics and scope.
    
    This command displays detailed statistics about what would be assessed
    based on the specified criteria, without actually running the assessment.
    
    Examples:
    
      # Show statistics for all controls
      aws-cis-assess show-stats
      
      # Show statistics for specific Implementation Groups
      aws-cis-assess show-stats -ig IG1,IG2
      
      # Show statistics for specific controls
      aws-cis-assess show-stats --controls 1.1,3.3,4.1
      
      # Show statistics in JSON format
      aws-cis-assess show-stats -f json
    """
    verbose = ctx.obj.get('verbose', False)
    
    try:
        # Initialize config loader
        from aws_cis_assessment.config.config_loader import ConfigRuleLoader
        config_loader = ConfigRuleLoader(config_path)
        
        # Parse options
        ig_list = list(implementation_groups) if implementation_groups else None
        controls_list = _parse_controls(controls)
        region_list = _parse_regions(regions, None)
        
        # Get statistics
        stats = config_loader.get_assessment_statistics(
            implementation_groups=ig_list,
            controls=controls_list,
            regions=region_list
        )
        
        if output_format == 'json':
            click.echo(json.dumps(stats, indent=2))
        else:
            _display_assessment_statistics(stats, verbose)
            
    except Exception as e:
        click.echo(f"❌ Failed to show statistics: {str(e)}", err=True)
        if verbose:
            import traceback
            click.echo(traceback.format_exc(), err=True)
        sys.exit(1)


def _display_assessment_statistics(stats: Dict[str, Any], verbose: bool):
    """Display assessment statistics in table format."""
    click.echo("📊 Assessment Statistics")
    click.echo("=" * 50)
    
    # Overall statistics
    click.echo(f"Total Controls: {stats.get('total_controls', 0)}")
    click.echo(f"Total Config Rules: {stats.get('total_config_rules', 0)}")
    click.echo(f"Total Regions: {stats.get('total_regions', 0)}")
    click.echo(f"Estimated Assessments: {stats.get('estimated_assessments', 0)}")
    
    # By Implementation Group
    if 'by_implementation_group' in stats:
        click.echo("\nBy Implementation Group:")
        for ig, ig_stats in stats['by_implementation_group'].items():
            click.echo(f"  {ig}: {ig_stats.get('controls', 0)} controls, {ig_stats.get('config_rules', 0)} rules")
    
    # By service
    if 'by_service' in stats and verbose:
        click.echo("\nBy AWS Service:")
        for service, count in sorted(stats['by_service'].items()):
            click.echo(f"  {service}: {count} assessments")
    
    # Resource types
    if 'resource_types' in stats and verbose:
        click.echo(f"\nResource Types: {len(stats['resource_types'])}")
        for resource_type in sorted(stats['resource_types'])[:10]:  # Show first 10
            click.echo(f"  • {resource_type}")
        if len(stats['resource_types']) > 10:
            click.echo(f"  ... and {len(stats['resource_types']) - 10} more")


@cli.command()
@click.option('--config-path', '-c',
              type=click.Path(exists=True, file_okay=False, dir_okay=True),
              help='Path to CIS Controls configuration directory')
@click.option('--output-format', '-f',
              type=click.Choice(['table', 'json'], case_sensitive=False),
              default='table',
              help='Output format for the control list')
@click.pass_context
def list_controls(ctx, config_path, output_format):
    """List available CIS Controls and their Config rules.
    
    This command displays all available CIS Controls organized by Implementation Group,
    showing the AWS Config rules that will be evaluated for each control.
    
    Examples:
    
      # List controls in table format
      aws-cis-assess list-controls
      
      # List controls in JSON format
      aws-cis-assess list-controls -f json
      
      # Use custom configuration path
      aws-cis-assess list-controls -c ./custom-config/
    """
    verbose = ctx.obj.get('verbose', False)
    
    try:
        # Initialize config loader
        config_loader = ConfigRuleLoader(config_path)
        
        # Get all controls
        all_controls = config_loader.get_all_controls()
        
        if output_format == 'json':
            # JSON output
            controls_data = {}
            for control_id, control in all_controls.items():
                controls_data[control_id] = {
                    'title': control.title,
                    'implementation_group': control.implementation_group,
                    'weight': control.weight,
                    'config_rules': [
                        {
                            'name': rule.name,
                            'resource_types': rule.resource_types,
                            'description': rule.description
                        }
                        for rule in control.config_rules
                    ]
                }
            
            click.echo(json.dumps(controls_data, indent=2))
        else:
            # Table output
            _display_controls_table(all_controls, verbose)
            
    except Exception as e:
        click.echo(f"❌ Failed to list controls: {str(e)}", err=True)
        if verbose:
            import traceback
            click.echo(traceback.format_exc(), err=True)
        sys.exit(1)


@cli.command()
@click.option('--aws-profile', '-p',
              help='AWS profile to use for credentials')
@click.option('--aws-access-key-id',
              help='AWS Access Key ID (alternative to profile)')
@click.option('--aws-secret-access-key',
              help='AWS Secret Access Key (alternative to profile)')
@click.option('--aws-session-token',
              help='AWS Session Token (for temporary credentials)')
@click.option('--regions', '-r',
              help='Comma-separated list of AWS regions to validate')
@click.pass_context
def validate_credentials(ctx, aws_profile, aws_access_key_id, aws_secret_access_key,
                        aws_session_token, regions):
    """Validate AWS credentials and permissions.
    
    This command validates your AWS credentials and checks if you have the necessary
    permissions to run CIS Controls assessments.
    
    Examples:
    
      # Validate default credentials
      aws-cis-assess validate-credentials
      
      # Validate specific AWS profile
      aws-cis-assess validate-credentials -p production
      
      # Validate credentials for specific regions
      aws-cis-assess validate-credentials -r us-east-1,us-west-2
    """
    verbose = ctx.obj.get('verbose', False)
    
    try:
        # Parse regions
        region_list = None
        if regions:
            region_list = [r.strip() for r in regions.split(',')]
        
        # Prepare AWS credentials
        aws_credentials = _prepare_aws_credentials(
            aws_profile, aws_access_key_id, aws_secret_access_key, aws_session_token
        )
        
        # Initialize assessment engine for credential validation
        from aws_cis_assessment.core.aws_client_factory import AWSClientFactory
        
        click.echo("🔧 Validating AWS credentials...")
        aws_factory = AWSClientFactory(aws_credentials, region_list)
        
        # Validate credentials
        if aws_factory.validate_credentials():
            click.echo("✅ AWS credentials are valid")
            
            # Get account information
            account_info = aws_factory.get_account_info()
            click.echo(f"   Account ID: {account_info.get('account_id', 'Unknown')}")
            click.echo(f"   User/Role: {account_info.get('user_id', 'Unknown')}")
            click.echo(f"   Regions: {aws_factory.regions}")
            
            if verbose:
                # Show supported services
                supported_services = aws_factory.get_supported_services()
                click.echo(f"   Supported Services: {', '.join(supported_services[:10])}...")  # Show first 10
        else:
            click.echo("❌ AWS credential validation failed", err=True)
            sys.exit(1)
            
    except Exception as e:
        click.echo(f"❌ Credential validation failed: {str(e)}", err=True)
        if verbose:
            import traceback
            click.echo(traceback.format_exc(), err=True)
        sys.exit(1)


@cli.command()
@click.option('--topic', '-t',
              type=click.Choice(['examples', 'troubleshooting', 'best-practices'], case_sensitive=False),
              help='Specific help topic to display')
@click.pass_context
def help_guide(ctx, topic):
    """Show detailed help, examples, and troubleshooting guide.
    
    This command provides comprehensive help including usage examples,
    troubleshooting guidance, and best practices for using the CIS assessment tool.
    
    Examples:
    
      # Show all help topics
      aws-cis-assess help-guide
      
      # Show usage examples
      aws-cis-assess help-guide --topic examples
      
      # Show troubleshooting guide
      aws-cis-assess help-guide --topic troubleshooting
    """
    verbose = ctx.obj.get('verbose', False)
    
    if topic == 'examples' or topic is None:
        _display_usage_examples()
    
    if topic == 'troubleshooting' or topic is None:
        _display_troubleshooting_guide()
    
    if topic == 'best-practices' or topic is None:
        _display_best_practices()


def _display_usage_examples():
    """Display usage examples."""
    click.echo("📚 Usage Examples")
    click.echo("=" * 50)
    
    examples = get_all_examples()
    for example_name, example_data in examples.items():
        click.echo(f"\n🔹 {example_data['title']}")
        click.echo(f"   {example_data['description']}")
        click.echo(f"   Command: {example_data['command']}")
        click.echo(f"   {example_data['explanation']}")


def _display_troubleshooting_guide():
    """Display troubleshooting guide."""
    click.echo("\n🔧 Troubleshooting Guide")
    click.echo("=" * 50)
    
    guide = get_troubleshooting_guide()
    for category, info in guide.items():
        click.echo(f"\n❗ {info['title']}")
        click.echo("   Common Problems:")
        for problem in info['problems']:
            click.echo(f"     • {problem}")
        click.echo("   Solutions:")
        for solution in info['solutions']:
            click.echo(f"     ✓ {solution}")


def _display_best_practices():
    """Display best practices."""
    click.echo("\n💡 Best Practices")
    click.echo("=" * 50)
    
    practices = get_best_practices()
    for practice in practices:
        click.echo(f"\n🎯 {practice['title']}")
        click.echo(f"   {practice['description']}")
        click.echo(f"   Example: {practice['command']}")


@cli.command()
@click.option('--config-path', '-c',
              type=click.Path(exists=True, file_okay=False, dir_okay=True),
              help='Path to CIS Controls configuration directory')
@click.pass_context
def validate_config(ctx, config_path):
    """Validate CIS Controls configuration files.
    
    This command validates the YAML configuration files that define the mapping
    between CIS Controls and AWS Config rules.
    
    Examples:
    
      # Validate default configuration
      aws-cis-assess validate-config
      
      # Validate custom configuration
      aws-cis-assess validate-config -c ./custom-config/
    """
    verbose = ctx.obj.get('verbose', False)
    
    try:
        # Initialize config loader
        config_loader = ConfigRuleLoader(config_path)
        
        click.echo("🔧 Validating CIS Controls configuration...")
        
        # Validate configuration
        validation_errors = config_loader.validate_configuration()
        
        if validation_errors:
            click.echo("❌ Configuration validation failed:", err=True)
            for error in validation_errors:
                click.echo(f"  • {error}", err=True)
            sys.exit(1)
        else:
            click.echo("✅ Configuration is valid")
            
            # Show configuration summary
            if verbose:
                rules_count = config_loader.get_rules_count_by_ig()
                click.echo("Configuration Summary:")
                for ig, count in rules_count.items():
                    click.echo(f"  {ig}: {count} Config rules")
                    
    except Exception as e:
        click.echo(f"❌ Configuration validation failed: {str(e)}", err=True)
        if verbose:
            import traceback
            click.echo(traceback.format_exc(), err=True)
        sys.exit(1)


def _prepare_aws_credentials(aws_profile: Optional[str], 
                           aws_access_key_id: Optional[str],
                           aws_secret_access_key: Optional[str],
                           aws_session_token: Optional[str]) -> Optional[Dict[str, str]]:
    """Prepare AWS credentials dictionary from CLI options."""
    credentials = {}
    
    if aws_profile:
        credentials['profile_name'] = aws_profile
    
    if aws_access_key_id and aws_secret_access_key:
        credentials['aws_access_key_id'] = aws_access_key_id
        credentials['aws_secret_access_key'] = aws_secret_access_key
        if aws_session_token:
            credentials['aws_session_token'] = aws_session_token
    
    return credentials if credentials else None


def _parse_regions(regions: Optional[str], exclude_regions: Optional[str]) -> Optional[List[str]]:
    """Parse regions and handle exclusions."""
    region_list = None
    
    if regions:
        region_list = [r.strip() for r in regions.split(',')]
    
    if exclude_regions:
        exclude_list = [r.strip() for r in exclude_regions.split(',')]
        if region_list:
            # Remove excluded regions from specified regions
            region_list = [r for r in region_list if r not in exclude_list]
        else:
            # Get all regions and exclude specified ones
            from aws_cis_assessment.cli.utils import get_all_enabled_regions
            all_regions = get_all_enabled_regions()
            region_list = [r for r in all_regions if r not in exclude_list]
    
    return region_list


def _parse_controls(controls: Optional[str]) -> Optional[List[str]]:
    """Parse comma-separated control IDs."""
    if not controls:
        return None
    
    return [c.strip() for c in controls.split(',')]


def _configure_logging(verbose: bool, debug: bool, log_level: Optional[str], log_file: Optional[str]):
    """Configure logging based on CLI options."""
    # Determine log level
    if log_level:
        level = getattr(logging, log_level.upper())
    elif debug:
        level = logging.DEBUG
    elif verbose:
        level = logging.INFO
    else:
        level = logging.WARNING
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    
    # Clear existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    root_logger.addHandler(console_handler)
    
    # File handler if specified
    if log_file:
        try:
            file_handler = logging.FileHandler(log_file)
            file_handler.setLevel(level)
            file_handler.setFormatter(formatter)
            root_logger.addHandler(file_handler)
        except Exception as e:
            click.echo(f"⚠️  Warning: Could not create log file {log_file}: {e}", err=True)


def _display_assessment_summary(summary: Dict[str, Any], verbose: bool):
    """Display assessment summary information."""
    click.echo("📊 Assessment Summary:")
    click.echo(f"   Implementation Groups: {', '.join(summary['implementation_groups'])}")
    click.echo(f"   Total Assessments: {summary['total_assessments']}")
    click.echo(f"   Regions: {', '.join(summary['regions'])}")
    
    if verbose:
        click.echo("   Assessments by IG:")
        for ig, data in summary['assessments_by_ig'].items():
            click.echo(f"     {ig}: {data['count']} assessments")


def _display_results_summary(assessment_result, compliance_summary, verbose: bool):
    """Display assessment results summary."""
    click.echo()
    click.echo("📈 Assessment Results:")
    
    # Format duration properly
    duration_str = format_duration(assessment_result.assessment_duration)
    
    click.echo(f"   Overall Compliance: {compliance_summary.overall_compliance_percentage:.1f}%")
    click.echo(f"   IG1 Compliance: {compliance_summary.ig1_compliance_percentage:.1f}%")
    click.echo(f"   IG2 Compliance: {compliance_summary.ig2_compliance_percentage:.1f}%")
    click.echo(f"   IG3 Compliance: {compliance_summary.ig3_compliance_percentage:.1f}%")
    click.echo(f"   Total Resources: {assessment_result.total_resources_evaluated}")
    click.echo(f"   Assessment Duration: {duration_str}")
    
    if verbose and compliance_summary.top_risk_areas:
        click.echo("   Top Risk Areas:")
        for risk_area in compliance_summary.top_risk_areas[:5]:
            click.echo(f"     • {risk_area}")


def _display_controls_table(all_controls: Dict[str, Any], verbose: bool):
    """Display controls in table format."""
    # Group controls by Implementation Group
    controls_by_ig = {}
    for control_id, control in all_controls.items():
        ig = control.implementation_group
        if ig not in controls_by_ig:
            controls_by_ig[ig] = []
        controls_by_ig[ig].append(control)
    
    for ig in ['IG1', 'IG2', 'IG3']:
        if ig not in controls_by_ig:
            continue
            
        click.echo(f"\n{ig} - {_get_ig_description(ig)}")
        click.echo("=" * 80)
        
        table_data = []
        for control in sorted(controls_by_ig[ig], key=lambda c: c.control_id):
            rule_count = len(control.config_rules)
            if verbose:
                rule_names = ', '.join([rule.name for rule in control.config_rules[:3]])
                if rule_count > 3:
                    rule_names += f" (+{rule_count - 3} more)"
            else:
                rule_names = f"{rule_count} Config rules"
            
            table_data.append([
                control.control_id,
                control.title[:50] + ('...' if len(control.title) > 50 else ''),
                rule_names
            ])
        
        headers = ['Control ID', 'Title', 'Config Rules']
        click.echo(tabulate(table_data, headers=headers, tablefmt='grid'))


def _get_ig_description(ig: str) -> str:
    """Get description for Implementation Group."""
    descriptions = {
        'IG1': 'Essential Cyber Hygiene',
        'IG2': 'Enhanced Security',
        'IG3': 'Advanced Security'
    }
    return descriptions.get(ig, '')


def _generate_reports(assessment_result, compliance_summary, output_formats, output_file, verbose: bool):
    """Generate reports in specified formats."""
    click.echo()
    click.echo("📄 Generating reports...")
    
    # Default output file if not specified
    if not output_file:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = f"cis_assessment_{timestamp}"
    
    # Remove extension from output_file if present
    output_base = Path(output_file).stem
    output_dir = Path(output_file).parent
    
    # Show assessment duration
    if assessment_result.assessment_duration:
        duration = assessment_result.assessment_duration
        total_seconds = int(duration.total_seconds())
        minutes, seconds = divmod(total_seconds, 60)
        click.echo(f"   ⏱️  Assessment Duration: {minutes}m {seconds}s")
    
    for format_type in output_formats:
        try:
            if format_type.lower() == 'json':
                reporter = JSONReporter()
                output_path = output_dir / f"{output_base}.json"
            elif format_type.lower() == 'html':
                reporter = HTMLReporter()
                output_path = output_dir / f"{output_base}.html"
            elif format_type.lower() == 'csv':
                reporter = CSVReporter()
                output_path = output_dir / f"{output_base}.csv"
            else:
                click.echo(f"⚠️  Unsupported format: {format_type}", err=True)
                continue
            
            # Generate report
            report_content = reporter.generate_report(assessment_result, compliance_summary, str(output_path))
            
            click.echo(f"   ✅ {format_type.upper()} report: {output_path}")
            
        except Exception as e:
            click.echo(f"   ❌ Failed to generate {format_type.upper()} report: {str(e)}", err=True)
            if verbose:
                import traceback
                click.echo(traceback.format_exc(), err=True)
    
    # Show log file location
    log_path = output_dir / f"{output_base}.log"
    if log_path.exists():
        click.echo(f"   📋 Log file: {log_path}")


def _display_error_summary(error_summary: Dict[str, Any]):
    """Display error summary if available."""
    if not error_summary or not error_summary.get('errors'):
        return
    
    click.echo()
    click.echo("⚠️  Error Summary:")
    
    total_errors = error_summary.get('total_errors', 0)
    click.echo(f"   Total Errors: {total_errors}")
    
    if 'errors_by_category' in error_summary:
        for category, count in error_summary['errors_by_category'].items():
            click.echo(f"   {category}: {count}")
    
    # Show recent errors
    recent_errors = error_summary.get('recent_errors', [])
    if recent_errors:
        click.echo("   Recent Errors:")
        for error in recent_errors[-5:]:  # Show last 5 errors
            click.echo(f"     • {error}")


@cli.command('validate-accuracy')
@click.option('--aws-profile', '-p',
              help='AWS profile to use for credentials')
@click.option('--aws-access-key-id',
              envvar='AWS_ACCESS_KEY_ID',
              help='AWS access key ID')
@click.option('--aws-secret-access-key',
              envvar='AWS_SECRET_ACCESS_KEY',
              help='AWS secret access key')
@click.option('--aws-session-token',
              envvar='AWS_SESSION_TOKEN',
              help='AWS session token')
@click.option('--regions', '-r',
              help='Comma-separated list of AWS regions to validate')
@click.option('--config-rules',
              help='Comma-separated list of specific Config rules to validate')
@click.option('--output-file', '-o',
              type=click.Path(),
              help='Output file for validation report')
@click.option('--check-config-availability', is_flag=True,
              help='Check AWS Config service availability in regions')
@click.option('--verbose', '-v', is_flag=True, help='Enable verbose output')
@click.pass_context
def validate_accuracy(ctx, aws_profile, aws_access_key_id, aws_secret_access_key, 
                     aws_session_token, regions, config_rules, output_file, 
                     check_config_availability, verbose):
    """Validate assessment accuracy against AWS Config rule evaluations.
    
    This command compares our assessment results with AWS Config rule evaluations
    to validate accuracy. Requires AWS Config to be enabled in target regions.
    
    Examples:
        aws-cis-assess validate-accuracy
        aws-cis-assess validate-accuracy --regions us-east-1,us-west-2
        aws-cis-assess validate-accuracy --config-rules eip-attached,iam-password-policy
        aws-cis-assess validate-accuracy --check-config-availability
    """
    from aws_cis_assessment.core.accuracy_validator import AccuracyValidator
    from aws_cis_assessment.core.aws_client_factory import AWSClientFactory
    
    try:
        # Configure logging
        _configure_logging(verbose, ctx.parent.params.get('debug', False), None, None)
        
        # Prepare AWS credentials
        credentials = _prepare_aws_credentials(
            aws_profile, aws_access_key_id, aws_secret_access_key, aws_session_token
        )
        
        # Parse regions
        region_list = _parse_regions(regions, None)
        
        click.echo("🔍 Starting assessment accuracy validation...")
        
        # Create AWS client factory
        aws_factory = AWSClientFactory(credentials, region_list)
        
        # Validate credentials
        if not aws_factory.validate_credentials():
            click.echo("❌ AWS credential validation failed", err=True)
            sys.exit(1)
        
        account_info = aws_factory.get_account_info()
        click.echo(f"   Account: {account_info['account_id']}")
        click.echo(f"   Regions: {', '.join(aws_factory.regions)}")
        
        # Create accuracy validator
        validator = AccuracyValidator(aws_factory)
        
        # Check Config service availability if requested
        if check_config_availability:
            click.echo()
            click.echo("🔧 Checking AWS Config service availability...")
            
            availability = validator.check_config_service_availability()
            
            available_regions = [region for region, available in availability.items() if available]
            unavailable_regions = [region for region, available in availability.items() if not available]
            
            if available_regions:
                click.echo(f"   ✅ Config available: {', '.join(available_regions)}")
            if unavailable_regions:
                click.echo(f"   ❌ Config unavailable: {', '.join(unavailable_regions)}")
            
            if not available_regions:
                click.echo("❌ AWS Config is not available in any target regions", err=True)
                click.echo("   Enable AWS Config to use accuracy validation", err=True)
                sys.exit(1)
            
            # Update regions to only include available ones
            aws_factory.regions = available_regions
        
        # Run a sample assessment to get results for validation
        click.echo()
        click.echo("🏃 Running sample assessment for validation...")
        
        with AssessmentEngine(
            aws_credentials=credentials,
            regions=aws_factory.regions,
            max_workers=4,
            enable_resource_monitoring=False,  # Disable for validation
            enable_audit_trail=False
        ) as engine:
            
            # Run assessment for IG1 only (faster for validation)
            assessment_result = engine.run_assessment(['IG1'])
            
            click.echo(f"   Assessed {assessment_result.total_resources_evaluated} resources")
        
        # Extract compliance results for validation
        all_compliance_results = []
        for ig_score in assessment_result.ig_scores.values():
            for control_score in ig_score.control_scores.values():
                all_compliance_results.extend(control_score.findings)
        
        # Parse config rules filter
        config_rule_names = None
        if config_rules:
            config_rule_names = [rule.strip() for rule in config_rules.split(',')]
        
        # Validate accuracy
        click.echo()
        click.echo("🎯 Validating assessment accuracy...")
        
        validation_summary = validator.validate_assessment_accuracy(
            all_compliance_results, 
            config_rule_names
        )
        
        # Display results
        click.echo()
        click.echo("📊 Validation Results:")
        click.echo(f"   Total rules validated: {validation_summary.total_rules_validated}")
        click.echo(f"   Accurate rules: {validation_summary.accurate_rules}")
        click.echo(f"   Overall accuracy: {validation_summary.overall_accuracy:.1f}%")
        
        if verbose:
            click.echo()
            click.echo("📋 Individual Rule Results:")
            for result in validation_summary.validation_results:
                status = "✅" if result.is_accurate else "❌"
                click.echo(f"   {status} {result.config_rule_name}: {result.accuracy_percentage:.1f}% "
                          f"({result.matching_results}/{result.total_resources})")
                
                if result.discrepancies and verbose:
                    for discrepancy in result.discrepancies[:3]:  # Show first 3
                        if 'issue' in discrepancy:
                            click.echo(f"      • {discrepancy['resource_id']}: {discrepancy['issue']}")
                        else:
                            click.echo(f"      • {discrepancy['resource_id']}: "
                                      f"Our={discrepancy['our_status']}, "
                                      f"Config={discrepancy['config_status']}")
        
        # Generate validation report
        if output_file or verbose:
            report = validator.generate_validation_report(validation_summary)
            
            if output_file:
                with open(output_file, 'w') as f:
                    f.write(report)
                click.echo(f"   📄 Validation report saved: {output_file}")
            elif verbose:
                click.echo()
                click.echo("📄 Validation Report:")
                click.echo(report)
        
        # Exit with appropriate code
        if validation_summary.overall_accuracy >= 95.0:
            click.echo()
            click.echo("✅ Validation completed successfully! High accuracy achieved.")
        else:
            click.echo()
            click.echo("⚠️  Validation completed with accuracy concerns. Review discrepancies.")
            sys.exit(1)
        
    except Exception as e:
        click.echo(f"❌ Validation failed: {str(e)}", err=True)
        if verbose:
            import traceback
            click.echo(traceback.format_exc(), err=True)
        sys.exit(1)


def main():
    """Main entry point for the CLI."""
    cli()


if __name__ == '__main__':
    main()