"""Command line interface for boot sector analyzer."""

import argparse
import logging
import sys
from pathlib import Path
from typing import Optional

from . import __version__
from .exceptions import (
    BootSectorAnalyzerError,
    InputError,
    ParsingError,
    AnalysisError,
    NetworkError,
    ConfigurationError,
    get_exit_code
)


def setup_logging(
    level: str = "INFO", quiet: bool = False, verbose: bool = False
) -> None:
    """
    Set up logging configuration.

    Args:
        level: Logging level (DEBUG, INFO, WARNING, ERROR)
        quiet: Enable quiet mode (WARNING and above only)
        verbose: Enable verbose mode (DEBUG level)
    """
    # Clear any existing handlers to avoid conflicts
    for handler in logging.root.handlers[:]:
        logging.root.removeHandler(handler)
    
    # Determine log level
    if quiet:
        log_level = logging.WARNING
    elif verbose:
        log_level = logging.DEBUG
    else:
        log_level = getattr(logging, level.upper(), logging.INFO)

    # Configure logging format with timestamp for audit purposes
    log_format = "%(asctime)s - %(levelname)s - %(name)s:%(filename)s:%(lineno)d - %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"

    # Create handler that outputs to stderr
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(log_level)
    
    # Create formatter
    formatter = logging.Formatter(log_format, datefmt=date_format)
    handler.setFormatter(formatter)
    
    # Configure root logger
    logging.root.setLevel(log_level)
    logging.root.addHandler(handler)
    
    # Log audit message for all analysis activities (Requirement 8.6)
    logger = logging.getLogger(__name__)
    logger.info(f"Boot Sector Analyzer v{__version__} starting - logging level: {logging.getLevelName(log_level)}")


def create_parser() -> argparse.ArgumentParser:
    """Create command line argument parser."""
    parser = argparse.ArgumentParser(
        prog="boot-sector-analyzer",
        description="Comprehensive boot sector analysis tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s /dev/sda                    # Analyze first sector of /dev/sda
  %(prog)s boot_sector.img             # Analyze boot sector image file
  %(prog)s -v -f json boot.img         # Verbose output in JSON format
  %(prog)s -f html -o report.html boot.img # Generate HTML report
  %(prog)s --config config.ini boot.img # Use configuration file
        """,
    )

    # Version
    parser.add_argument(
        "--version", action="version", version=f"%(prog)s {__version__}"
    )

    # Input source
    parser.add_argument(
        "source", nargs="?", help="Boot sector source (device path or image file)"
    )

    # Output options
    parser.add_argument(
        "-f",
        "--format",
        choices=["human", "json", "html"],
        default="human",
        help="Output format (default: human)",
    )

    parser.add_argument(
        "-o", "--output", type=Path, help="Output file (default: stdout)"
    )

    # Verbosity options
    verbosity_group = parser.add_mutually_exclusive_group()
    verbosity_group.add_argument(
        "-v", "--verbose", action="store_true", help="Enable verbose output"
    )

    verbosity_group.add_argument(
        "-q",
        "--quiet",
        action="store_true",
        help="Enable quiet mode (warnings and errors only)",
    )

    # Configuration
    parser.add_argument("--config", type=Path, help="Configuration file path")

    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="INFO",
        help="Set logging level (default: INFO)",
    )

    # Analysis options
    parser.add_argument(
        "--no-internet",
        action="store_true",
        help="Disable internet-based threat intelligence",
    )

    parser.add_argument("--api-key", help="VirusTotal API key (overrides config file)")

    parser.add_argument(
        "--cache-dir",
        type=Path,
        help="Directory for caching threat intelligence results",
    )

    return parser


def load_config(config_path: Optional[Path]) -> dict:
    """
    Load configuration from file.

    Args:
        config_path: Path to configuration file

    Returns:
        Configuration dictionary
        
    Raises:
        ConfigurationError: If configuration cannot be loaded
    """
    logger = logging.getLogger(__name__)
    config = {}

    if not config_path:
        # Try default config locations
        default_locations = [
            Path.home() / ".boot_sector_analyzer" / "config.ini",
            Path.cwd() / "config.ini",
        ]

        for location in default_locations:
            if location.exists():
                config_path = location
                break

    if config_path and config_path.exists():
        try:
            import configparser

            parser = configparser.ConfigParser()
            parser.read(config_path)

            # Convert to dict
            for section_name in parser.sections():
                section = parser[section_name]
                config[section_name] = dict(section)

            logger.info(f"Loaded configuration from {config_path}")

        except Exception as e:
            error_msg = f"Failed to load configuration from {config_path}: {e}"
            logger.error(error_msg)
            # Return empty config instead of raising exception for graceful handling
            logger.warning(f"Using default configuration due to config error: {e}")
            return {}

    return config


def validate_arguments(args: argparse.Namespace) -> int:
    """
    Validate command line arguments.

    Args:
        args: Parsed arguments

    Returns:
        0 if arguments are valid, otherwise appropriate exit code
    """
    logger = logging.getLogger(__name__)
    
    # Requirement 7.2: Validate input parameters
    if not args.source:
        error_msg = "Boot sector source is required"
        logger.error(error_msg)
        print("Error: Boot sector source is required", file=sys.stderr)
        print("Use --help for usage information", file=sys.stderr)
        return get_exit_code(InputError("Missing source"))

    source_path = Path(args.source)

    # Check if source exists (for files) or is a valid device path
    if not source_path.exists():
        # Check if it might be a device path
        if not str(source_path).startswith("/dev/"):
            error_msg = f"Source not found: {args.source}"
            logger.error(error_msg)
            print(f"Error: Source not found: {args.source}", file=sys.stderr)
            print("Please provide a valid file path or device path (e.g., /dev/sda)", file=sys.stderr)
            return get_exit_code(InputError("Source not found"))
        else:
            # For device paths, we can't easily check existence without root privileges
            # Let the actual reading operation handle this
            logger.debug(f"Device path specified: {args.source}")

    # Validate output directory if specified
    if args.output:
        output_dir = args.output.parent
        try:
            if not output_dir.exists():
                try:
                    output_dir.mkdir(parents=True, exist_ok=True)
                    logger.info(f"Created output directory: {output_dir}")
                except Exception as e:
                    error_msg = f"Cannot create output directory {output_dir}: {e}"
                    logger.error(error_msg)
                    print(f"Error: {error_msg}", file=sys.stderr)
                    return get_exit_code(InputError("Output directory error"))
        except PermissionError as e:
            error_msg = f"Permission denied accessing output directory {output_dir}"
            logger.error(error_msg)
            print(f"Error: {error_msg}", file=sys.stderr)
            return get_exit_code(PermissionError("Output directory permission denied"))

    # Validate configuration file if specified
    if args.config and not args.config.exists():
        error_msg = f"Configuration file not found: {args.config}"
        logger.error(error_msg)
        print(f"Error: {error_msg}", file=sys.stderr)
        return get_exit_code(ConfigurationError("Config file not found"))

    # Validate cache directory if specified
    if args.cache_dir:
        try:
            args.cache_dir.mkdir(parents=True, exist_ok=True)
            logger.debug(f"Cache directory ready: {args.cache_dir}")
        except Exception as e:
            error_msg = f"Cannot create cache directory {args.cache_dir}: {e}"
            logger.error(error_msg)
            print(f"Error: {error_msg}", file=sys.stderr)
            return get_exit_code(InputError("Cache directory error"))

    logger.debug("Argument validation completed successfully")
    return 0


def main() -> int:
    """Main entry point for CLI."""
    parser = create_parser()

    # Show help if no arguments provided (Requirement 7.1)
    if len(sys.argv) == 1:
        parser.print_help()
        return 0

    try:
        args = parser.parse_args()
    except SystemExit as e:
        # argparse calls sys.exit on error, catch it to return proper exit code
        return e.code if e.code is not None else 1

    # Set up logging first
    try:
        setup_logging(args.log_level, args.quiet, args.verbose)
        logger = logging.getLogger(__name__)
        logger.info("Starting boot sector analysis")
    except Exception as e:
        print(f"Error setting up logging: {e}", file=sys.stderr)
        return get_exit_code(e)

    try:
        # Validate arguments (Requirement 7.2, 7.5)
        validation_result = validate_arguments(args)
        if validation_result != 0:
            return validation_result

        # Load configuration (Requirement 7.6)
        config_data = load_config(args.config)
        
        # Import main analyzer
        from .analyzer import BootSectorAnalyzer
        from .config import Config
        
        # Initialize configuration
        config = Config(args.config)
        
        # Get API key from config or command line
        api_key = args.api_key
        if not api_key:
            api_key = config.get('api', 'virustotal_api_key')
        
        # Get cache directory from config or command line
        cache_dir = args.cache_dir
        if not cache_dir:
            cache_dir_str = config.get('cache', 'directory')
            if cache_dir_str:
                cache_dir = Path(cache_dir_str)
        
        # Disable internet if requested
        if args.no_internet:
            api_key = None
        
        # Initialize main analyzer
        logger.debug("Initializing Boot Sector Analyzer")
        analyzer = BootSectorAnalyzer(
            api_key=api_key,
            cache_dir=str(cache_dir) if cache_dir else None
        )
        
        logger.info(f"Starting analysis of {args.source}")
        
        # Perform complete analysis
        analysis_result = analyzer.analyze(
            source=args.source,
            include_threat_intelligence=not args.no_internet
        )
        
        # Generate report
        output_format = args.format
        report = analyzer.generate_report(analysis_result, output_format)
        
        # Output to file or stdout
        if args.output:
            try:
                with open(args.output, 'w', encoding='utf-8') as f:
                    f.write(report)
                logger.info(f"Report written to {args.output}")
            except Exception as e:
                error_msg = f"Failed to write report to {args.output}: {e}"
                logger.error(error_msg)
                raise InputError(
                    error_msg,
                    error_code="REPORT_WRITE_ERROR",
                    details={"output_path": str(args.output), "error": str(e)}
                )
        else:
            print(report)
        
        logger.info("Analysis completed successfully")
        return 0
        
    except KeyboardInterrupt:
        logger.info("Analysis interrupted by user")
        return get_exit_code(KeyboardInterrupt())
    except (InputError, ParsingError, AnalysisError, NetworkError, ConfigurationError) as e:
        # Handle our custom exceptions with appropriate exit codes
        logger.error(f"Analysis failed: {e}")
        if args.verbose:
            import traceback
            logger.debug(traceback.format_exc())
        return get_exit_code(e)
    except Exception as e:
        # Handle unexpected exceptions
        logger.error(f"Unexpected error during analysis: {e}")
        if args.verbose:
            import traceback
            logger.debug(traceback.format_exc())
        return get_exit_code(e)


if __name__ == "__main__":
    sys.exit(main())
