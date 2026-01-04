# Boot Sector Analyzer

**Version 0.2.0** - HTML Reports & Disassembly Release

A comprehensive Python tool for analyzing boot sectors from disk drives or boot sector image files. The system analyzes the structure and content of boot sectors, performs x86/x86-64 disassembly, and generates professional HTML reports with responsive design and interactive elements.

## Features

- **Structure Analysis**: Parse and validate Master Boot Record (MBR) structure
- **Content Analysis**: Calculate hashes, extract strings, detect suspicious patterns
- **Boot Code Disassembly**: x86/x86-64 assembly analysis with pattern recognition
- **Security Scanning**: Check against known malware signatures and bootkit patterns
- **Threat Intelligence**: Query VirusTotal API for online threat information
- **HTML Reports**: Professional, responsive reports with syntax highlighting
- **Hexdump Display**: Manual review with formatted 17-column table and MBR section highlighting
- **Multi-Format Output**: Human-readable, JSON, and HTML report formats
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

# Generate JSON output for automation
boot-sector-analyzer -f json boot_sector.img

# Generate HTML report with disassembly and responsive design
boot-sector-analyzer -f html boot_sector.img > report.html

# Verbose output with detailed logging
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
├── disassembly_engine.py    # x86/x86-64 boot code disassembly
├── security_scanner.py      # Security threat detection
├── internet_checker.py      # Online threat intelligence
├── report_generator.py      # Report generation (human, JSON)
├── html_generator.py        # HTML report generation with responsive design
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

### Version 0.2.0 (HTML Reports & Disassembly Release)

**New Features:**
- **HTML Report Generation**: Professional, self-contained HTML reports with embedded CSS
- **Responsive Design**: HTML reports adapt to desktop, tablet, and mobile screen sizes
- **Boot Code Disassembly**: Complete x86/x86-64 disassembly using Capstone engine
- **Assembly Syntax Highlighting**: Color-coded assembly instructions in HTML reports
- **Boot Pattern Recognition**: Intelligent identification of BIOS calls and boot operations
- **Interactive HTML Elements**: Table of contents with anchor navigation
- **MBR Section Highlighting**: Color-coded hexdump sections in HTML reports

**Enhanced Components:**
- HTMLGenerator class for comprehensive HTML document generation
- DisassemblyEngine class with Capstone framework integration
- Extended data models for disassembly results and HTML formatting
- Multi-format support (human, JSON, HTML) with consistent data

**Testing:**
- 12 new property-based tests for HTML and disassembly validation
- 155 total tests with complete coverage including integration testing
- Real-world validation with actual boot sector samples

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