"""Utility functions for the CLI module."""

import os
import sys
from typing import Dict, List, Optional, Any
from pathlib import Path

import boto3
from botocore.exceptions import ClientError, NoCredentialsError


def get_default_regions() -> List[str]:
    """Get default AWS regions for assessment.
    
    Returns:
        List of default AWS region names (us-east-1 only)
    """
    # Default to us-east-1 only for focused assessment
    return ['us-east-1']


def get_all_enabled_regions() -> List[str]:
    """Get all enabled AWS regions for the current account.
    
    Returns:
        List of all enabled AWS region names
    """
    try:
        ec2 = boto3.client('ec2', region_name='us-east-1')
        response = ec2.describe_regions()
        return [region['RegionName'] for region in response['Regions']]
    except Exception:
        # Fallback to default regions if unable to query
        return get_default_regions()


def get_enabled_regions_for_profile(profile_name: str) -> List[str]:
    """Get enabled regions for a specific AWS profile.
    
    Args:
        profile_name: Name of the AWS profile
        
    Returns:
        List of enabled region names
    """
    try:
        session = boto3.Session(profile_name=profile_name)
        ec2 = session.client('ec2', region_name='us-east-1')
        response = ec2.describe_regions()
        return [region['RegionName'] for region in response['Regions']]
    except Exception:
        return get_default_regions()


def validate_aws_profile(profile_name: str) -> bool:
    """Validate that an AWS profile exists and is accessible.
    
    Args:
        profile_name: Name of the AWS profile to validate
        
    Returns:
        True if profile is valid, False otherwise
    """
    try:
        session = boto3.Session(profile_name=profile_name)
        sts = session.client('sts')
        sts.get_caller_identity()
        return True
    except Exception:
        return False


def get_aws_config_path() -> Optional[Path]:
    """Get the path to AWS configuration directory.
    
    Returns:
        Path to AWS config directory or None if not found
    """
    aws_config_dir = Path.home() / '.aws'
    if aws_config_dir.exists():
        return aws_config_dir
    return None


def list_aws_profiles() -> List[str]:
    """List available AWS profiles.
    
    Returns:
        List of AWS profile names
    """
    profiles = []
    aws_config_path = get_aws_config_path()
    
    if aws_config_path:
        credentials_file = aws_config_path / 'credentials'
        config_file = aws_config_path / 'config'
        
        # Parse credentials file
        if credentials_file.exists():
            profiles.extend(_parse_aws_config_file(credentials_file))
        
        # Parse config file
        if config_file.exists():
            config_profiles = _parse_aws_config_file(config_file, prefix='profile ')
            profiles.extend(config_profiles)
    
    # Remove duplicates and sort
    return sorted(list(set(profiles)))


def _parse_aws_config_file(file_path: Path, prefix: str = '') -> List[str]:
    """Parse AWS configuration file to extract profile names.
    
    Args:
        file_path: Path to the configuration file
        prefix: Prefix to remove from profile names (e.g., 'profile ')
        
    Returns:
        List of profile names
    """
    profiles = []
    
    try:
        with open(file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('[') and line.endswith(']'):
                    profile_name = line[1:-1]  # Remove brackets
                    if prefix and profile_name.startswith(prefix):
                        profile_name = profile_name[len(prefix):]
                    if profile_name and profile_name != 'default':
                        profiles.append(profile_name)
    except Exception:
        pass  # Ignore parsing errors
    
    return profiles


def format_duration(duration) -> str:
    """Format a timedelta duration for display.
    
    Args:
        duration: timedelta object or None
        
    Returns:
        Formatted duration string
    """
    if duration is None:
        return "Unknown"
    
    total_seconds = int(duration.total_seconds())
    hours, remainder = divmod(total_seconds, 3600)
    minutes, seconds = divmod(remainder, 60)
    
    if hours > 0:
        return f"{hours}h {minutes}m {seconds}s"
    elif minutes > 0:
        return f"{minutes}m {seconds}s"
    else:
        return f"{seconds}s"


def format_percentage(value: float, precision: int = 1) -> str:
    """Format a percentage value for display.
    
    Args:
        value: Percentage value (0-100)
        precision: Number of decimal places
        
    Returns:
        Formatted percentage string
    """
    return f"{value:.{precision}f}%"


def format_file_size(size_bytes: int) -> str:
    """Format file size in human-readable format.
    
    Args:
        size_bytes: Size in bytes
        
    Returns:
        Formatted size string
    """
    if size_bytes == 0:
        return "0 B"
    
    size_names = ["B", "KB", "MB", "GB", "TB"]
    i = 0
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    
    return f"{size_bytes:.1f} {size_names[i]}"


def ensure_output_directory(output_path: str) -> Path:
    """Ensure output directory exists and return Path object.
    
    Args:
        output_path: Output file or directory path
        
    Returns:
        Path object with directory created
    """
    path = Path(output_path)
    
    # If it's a file path, get the directory
    if path.suffix:
        directory = path.parent
    else:
        directory = path
    
    # Create directory if it doesn't exist
    directory.mkdir(parents=True, exist_ok=True)
    
    return path


def get_terminal_width() -> int:
    """Get terminal width for formatting output.
    
    Returns:
        Terminal width in characters
    """
    try:
        return os.get_terminal_size().columns
    except OSError:
        return 80  # Default width


def truncate_string(text: str, max_length: int, suffix: str = "...") -> str:
    """Truncate string to maximum length with suffix.
    
    Args:
        text: String to truncate
        max_length: Maximum length including suffix
        suffix: Suffix to add when truncating
        
    Returns:
        Truncated string
    """
    if len(text) <= max_length:
        return text
    
    return text[:max_length - len(suffix)] + suffix


def colorize_compliance_status(status: str, percentage: Optional[float] = None) -> str:
    """Add color codes to compliance status for terminal display.
    
    Args:
        status: Compliance status string
        percentage: Optional percentage value for color coding
        
    Returns:
        Colorized status string
    """
    # ANSI color codes
    RED = '\033[91m'
    YELLOW = '\033[93m'
    GREEN = '\033[92m'
    RESET = '\033[0m'
    
    if percentage is not None:
        if percentage >= 90:
            return f"{GREEN}{status}{RESET}"
        elif percentage >= 70:
            return f"{YELLOW}{status}{RESET}"
        else:
            return f"{RED}{status}{RESET}"
    
    # Status-based coloring
    status_lower = status.lower()
    if 'compliant' in status_lower and 'non' not in status_lower:
        return f"{GREEN}{status}{RESET}"
    elif 'non_compliant' in status_lower or 'failed' in status_lower:
        return f"{RED}{status}{RESET}"
    elif 'error' in status_lower or 'warning' in status_lower:
        return f"{YELLOW}{status}{RESET}"
    
    return status


def is_tty() -> bool:
    """Check if output is going to a terminal (TTY).
    
    Returns:
        True if output is to a terminal, False otherwise
    """
    return sys.stdout.isatty()


def get_config_file_path(config_path: Optional[str], filename: str) -> Path:
    """Get full path to a configuration file.
    
    Args:
        config_path: Base configuration directory path
        filename: Configuration filename
        
    Returns:
        Full path to configuration file
    """
    if config_path:
        base_path = Path(config_path)
    else:
        # Use package default
        from aws_cis_assessment.config import config_loader
        base_path = Path(config_loader.__file__).parent / 'rules'
    
    return base_path / filename


def validate_output_format(formats: List[str]) -> List[str]:
    """Validate and normalize output format list.
    
    Args:
        formats: List of output format strings
        
    Returns:
        List of validated format strings
        
    Raises:
        ValueError: If any format is invalid
    """
    valid_formats = ['json', 'html', 'csv']
    normalized_formats = []
    
    for fmt in formats:
        fmt_lower = fmt.lower()
        if fmt_lower not in valid_formats:
            raise ValueError(f"Invalid output format: {fmt}. Valid formats: {', '.join(valid_formats)}")
        normalized_formats.append(fmt_lower)
    
    return normalized_formats


def create_progress_bar(current: int, total: int, width: int = 50, 
                       fill_char: str = '█', empty_char: str = '░') -> str:
    """Create a text-based progress bar.
    
    Args:
        current: Current progress value
        total: Total progress value
        width: Width of progress bar in characters
        fill_char: Character for filled portion
        empty_char: Character for empty portion
        
    Returns:
        Progress bar string
    """
    if total == 0:
        return empty_char * width
    
    filled_width = int(width * current / total)
    return fill_char * filled_width + empty_char * (width - filled_width)