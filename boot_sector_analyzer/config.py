"""Configuration management for boot sector analyzer."""

import configparser
import logging
from pathlib import Path
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class Config:
    """Configuration manager for boot sector analyzer."""

    def __init__(self, config_path: Optional[Path] = None, load_defaults: bool = True):
        """
        Initialize configuration manager.

        Args:
            config_path: Path to configuration file
            load_defaults: Whether to load default configuration values
        """
        self.config_path = config_path
        self.load_defaults = load_defaults
        self.config_data = {}
        self._load_config()

    def _load_config(self) -> None:
        """Load configuration from file."""
        config_paths = []

        # Add specified config path
        if self.config_path:
            config_paths.append(self.config_path)

        # Add default config locations (only if loading defaults)
        if self.load_defaults:
            config_paths.extend(
                [
                    Path.home() / ".boot_sector_analyzer" / "config.ini",
                    Path.cwd() / "config.ini",
                    Path(__file__).parent.parent / "config.ini",
                ]
            )

        # First set defaults if requested
        if self.load_defaults:
            self._set_defaults()

        # Then override with file contents if found
        for config_path in config_paths:
            if config_path.exists():
                try:
                    self._parse_config_file(config_path)
                    logger.info(f"Loaded configuration from {config_path}")
                    return
                except Exception as e:
                    logger.warning(f"Failed to load config from {config_path}: {e}")

        if self.load_defaults:
            logger.info("No configuration file found, using defaults")

    def _parse_config_file(self, config_path: Path) -> None:
        """Parse configuration file."""
        parser = configparser.ConfigParser(interpolation=None)  # Disable interpolation
        parser.optionxform = str  # Preserve case of keys
        parser.read(config_path, encoding="utf-8")

        # Convert to nested dictionary, merging with existing config
        for section_name in parser.sections():
            section = parser[section_name]
            if section_name not in self.config_data:
                self.config_data[section_name] = {}

            for key, value in section.items():
                # Try to convert to appropriate types
                self.config_data[section_name][key] = self._convert_value(value)

    def _convert_value(self, value: str) -> Any:
        """Convert string value to appropriate type."""
        # Handle empty strings explicitly - preserve them as empty strings
        if value == "":
            return ""

        # Handle special marker for None values
        if value == "__NONE__":
            return None

        # Handle type-preserved values
        if value.startswith("__BOOL__"):
            bool_str = value[8:]  # Remove __BOOL__ prefix
            return bool_str == "true"
        elif value.startswith("__INT__"):
            int_str = value[7:]  # Remove __INT__ prefix
            return int(int_str)
        elif value.startswith("__FLOAT__"):
            float_str = value[9:]  # Remove __FLOAT__ prefix
            return float(float_str)
        elif value.startswith("__STR__"):
            str_value = value[7:]  # Remove __STR__ prefix
            # If it looks like a repr string, evaluate it to get the original
            try:
                if str_value.startswith("'") and str_value.endswith("'"):
                    return eval(str_value)  # Safe because we control the format
                elif str_value.startswith('"') and str_value.endswith('"'):
                    return eval(str_value)  # Safe because we control the format
                else:
                    return str_value
            except (ValueError, SyntaxError):
                return str_value

        # Boolean values - only convert explicit boolean strings (for backward compatibility)
        if value.lower() == "true":
            return True
        elif value.lower() == "false":
            return False

        # Integer values - convert all numeric strings to integers (for backward compatibility)
        try:
            if value.isdigit() or (value.startswith("-") and value[1:].isdigit()):
                return int(value)
        except ValueError:
            pass

        # Float values - only if it has a decimal point and looks like a number (for backward compatibility)
        try:
            if "." in value and value.count(".") == 1:
                parts = value.split(".")
                if len(parts) == 2:
                    # Handle negative floats
                    first_part = parts[0]
                    if (
                        first_part.isdigit()
                        or (first_part.startswith("-") and first_part[1:].isdigit())
                    ) and parts[1].isdigit():
                        return float(value)
        except ValueError:
            pass

        # Default to string for everything else
        return value

    def _set_defaults(self) -> None:
        """Set default configuration values."""
        self.config_data = {
            "api": {
                "virustotal_api_key": None,
                "rate_limit_seconds": 15,
                "timeout_seconds": 30,
                "max_retries": 3,
            },
            "cache": {
                "enabled": True,
                "directory": str(Path.home() / ".boot_sector_analyzer" / "cache"),
                "expiry_hours": 24,
                "max_size_mb": 100,
            },
            "analysis": {
                "calculate_entropy": True,
                "extract_strings": True,
                "min_string_length": 4,
                "detect_patterns": True,
                "check_signatures": True,
            },
            "output": {
                "default_format": "human",
                "include_raw_data": False,
                "highlight_threats": True,
                "max_strings_display": 10,
            },
            "logging": {
                "level": "INFO",
                "file": None,
                "format": "%(asctime)s - %(name)s - %(levelname)s - %(message)s",
            },
        }

    def get(self, section: str, key: str, default: Any = None) -> Any:
        """
        Get configuration value.

        Args:
            section: Configuration section
            key: Configuration key
            default: Default value if not found

        Returns:
            Configuration value or default
        """
        return self.config_data.get(section, {}).get(key, default)

    def get_section(self, section: str) -> Dict[str, Any]:
        """
        Get entire configuration section.

        Args:
            section: Section name

        Returns:
            Section dictionary
        """
        return self.config_data.get(section, {})

    def set(self, section: str, key: str, value: Any) -> None:
        """
        Set configuration value.

        Args:
            section: Configuration section
            key: Configuration key
            value: Value to set
        """
        if section not in self.config_data:
            self.config_data[section] = {}

        # Store the original value and its type information
        self.config_data[section][key] = value

    def save(self, config_path: Optional[Path] = None) -> None:
        """
        Save configuration to file.

        Args:
            config_path: Path to save configuration (uses loaded path if None)
        """
        if not config_path:
            config_path = self.config_path

        if not config_path:
            config_path = Path.home() / ".boot_sector_analyzer" / "config.ini"

        # Ensure directory exists
        config_path.parent.mkdir(parents=True, exist_ok=True)

        # Create ConfigParser and populate
        parser = configparser.ConfigParser(interpolation=None)  # Disable interpolation
        parser.optionxform = str  # Preserve case of keys

        for section_name, section_data in self.config_data.items():
            parser.add_section(section_name)
            for key, value in section_data.items():
                # Convert value to string with type preservation
                if value is None:
                    str_value = "__NONE__"  # Special marker for None values
                elif isinstance(value, bool):
                    # Store booleans with type prefix to preserve them
                    str_value = f"__BOOL__{str(value).lower()}"
                elif isinstance(value, int):
                    # Store integers with type prefix to preserve them
                    str_value = f"__INT__{value}"
                elif isinstance(value, float):
                    # Store floats with type prefix to preserve them
                    str_value = f"__FLOAT__{value}"
                elif isinstance(value, str):
                    # Store strings with type prefix and quote them to preserve whitespace
                    # Use repr to handle special characters and whitespace properly
                    str_value = f"__STR__{repr(value)}"
                else:
                    str_value = str(value)

                # Filter out problematic Unicode characters (surrogates)
                try:
                    # Test if the string can be encoded to UTF-8
                    str_value.encode("utf-8")
                except UnicodeEncodeError:
                    # Replace problematic characters with safe alternatives
                    str_value = str_value.encode("utf-8", errors="replace").decode(
                        "utf-8"
                    )

                parser.set(section_name, key, str_value)

        # Write to file
        try:
            with open(config_path, "w", encoding="utf-8") as f:
                parser.write(f)
            logger.info(f"Configuration saved to {config_path}")
        except Exception as e:
            logger.error(f"Failed to save configuration to {config_path}: {e}")
            raise

    def create_sample_config(self, config_path: Path) -> None:
        """
        Create a sample configuration file.

        Args:
            config_path: Path where to create the sample config
        """
        sample_config = """# Boot Sector Analyzer Configuration File

[api]
# VirusTotal API key (get from https://www.virustotal.com/gui/my-apikey)
virustotal_api_key = your_api_key_here

# Rate limiting (seconds between requests)
rate_limit_seconds = 15

# Request timeout in seconds
timeout_seconds = 30

# Maximum number of retries for failed requests
max_retries = 3

[cache]
# Enable caching of threat intelligence results
enabled = true

# Cache directory path
directory = ~/.boot_sector_analyzer/cache

# Cache expiry time in hours
expiry_hours = 24

# Maximum cache size in MB
max_size_mb = 100

[analysis]
# Calculate entropy of boot code
calculate_entropy = true

# Extract readable strings
extract_strings = true

# Minimum string length to extract
min_string_length = 4

# Detect suspicious patterns
detect_patterns = true

# Check against known signatures
check_signatures = true

[output]
# Default output format (human or json)
default_format = human

# Include raw binary data in reports
include_raw_data = false

# Highlight detected threats
highlight_threats = true

# Maximum number of strings to display
max_strings_display = 10

[logging]
# Logging level (DEBUG, INFO, WARNING, ERROR)
level = INFO

# Log file path (leave empty for console only)
file =

# Log message format (use %% to escape % characters)
format = %%(asctime)s - %%(name)s - %%(levelname)s - %%(message)s
"""

        try:
            config_path.parent.mkdir(parents=True, exist_ok=True)
            with open(config_path, "w") as f:
                f.write(sample_config)
            logger.info(f"Sample configuration created at {config_path}")
        except Exception as e:
            logger.error(f"Failed to create sample configuration: {e}")
            raise
