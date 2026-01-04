# Boot Sector Analyzer

**Version 0.1.1** - Enhanced Hexdump Release

A comprehensive Python tool for analyzing boot sectors from disk drives or boot sector image files. The system analyzes the structure and content of boot sectors, then cross-references findings against internet resources to identify suspicious deviations or potential security threats.

## Features

- **Structure Analysis**: Parse and validate Master Boot Record (MBR) structure
- **Content Analysis**: Calculate hashes, extract strings, detect suspicious patterns
- **Security Scanning**: Check against known malware signatures and bootkit patterns
- **Threat Intelligence**: Query VirusTotal API for online threat information
- **Hexdump Display**: Manual review with formatted 17-column table and ASCII representation
- **Comprehensive Reporting**: Generate human-readable and JSON format reports
- **Command Line Interface**: Easy-to-use CLI with configuration file support

## Installation

```bash
# Clone the repository
git clone https://github.com/bootsectoranalyzer/boot-sector-analyzer.git
cd boot-sector-analyzer

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install -e .
```

## Usage

### Basic Usage

```bash
# Analyze a boot sector image file
boot-sector-analyzer boot_sector.img

# Analyze the first sector of a disk device
boot-sector-analyzer /dev/sda

# Generate JSON output
boot-sector-analyzer -f json boot_sector.img

# Verbose output
boot-sector-analyzer -v boot_sector.img
```

### Configuration

Create a configuration file to set API keys and preferences:

```bash
# Create sample configuration
mkdir -p ~/.boot_sector_analyzer
boot-sector-analyzer --create-config ~/.boot_sector_analyzer/config.ini
```

Edit the configuration file to add your VirusTotal API key:

```ini
[api]
virustotal_api_key = your_api_key_here
```

## Requirements

- Python 3.8 or higher
- Required packages listed in `requirements.txt`
- Optional: VirusTotal API key for threat intelligence

## Project Structure

```
boot_sector_analyzer/
├── __init__.py              # Package initialization
├── models.py                # Data models and structures
├── input_handler.py         # Boot sector input handling
├── structure_analyzer.py    # MBR structure analysis
├── content_analyzer.py      # Content analysis and pattern detection
├── security_scanner.py      # Security threat detection
├── internet_checker.py      # Online threat intelligence
├── report_generator.py      # Report generation
├── cli.py                   # Command line interface
└── config.py                # Configuration management
```

## Development

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=boot_sector_analyzer

# Run property-based tests
pytest -v tests/test_properties.py
```

### Code Quality

```bash
# Check code style
flake8 boot_sector_analyzer/

# Format code
black boot_sector_analyzer/
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## Security

This tool is designed for security analysis purposes. Always ensure you have proper authorization before analyzing boot sectors from systems you do not own.

## Changelog

### Version 0.1.1 (Enhanced Hexdump Release)

**New Features:**
- Enhanced hexdump functionality for manual boot sector review
- 17-column table format with offset and hex byte columns
- ASCII representation with dots for non-printable characters
- Zero-padded uppercase hexadecimal offsets (0x0000, 0x0010, etc.)
- Hexdump included in both human-readable and JSON report formats
- New HexdumpData model for structured hexdump storage

**Enhancements:**
- All reports now include dedicated hexdump section
- Raw boot sector data formatted for easy manual analysis
- Complete 512-byte boot sector coverage (32 data rows)

**Testing:**
- 5 new property-based tests for hexdump functionality validation
- Integration testing with real boot sector data
- 26 total correctness properties validated

### Version 0.1.0 (Initial Release)

**Features:**
- Complete MBR structure parsing and validation
- Boot sector content analysis with hash calculation
- Security threat detection and pattern matching
- VirusTotal API integration for threat intelligence
- Comprehensive error handling and logging
- Command line interface with configuration support
- Property-based testing for correctness validation
- Support for both human-readable and JSON output formats

**Components:**
- Input handler for files and device access
- Structure analyzer for MBR parsing
- Content analyzer for pattern detection
- Security scanner for threat identification
- Internet checker for online threat intelligence
- Report generator for structured output
- CLI with argument validation and error handling

**Testing:**
- 21 correctness properties validated through property-based testing
- Comprehensive unit test coverage
- Integration tests for end-to-end workflows
- Error handling and edge case validation