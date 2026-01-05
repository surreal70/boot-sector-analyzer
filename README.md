# 🔍 Boot Sector Analyzer

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/Version-0.3.2-orange.svg)](VERSION)
[![Security](https://img.shields.io/badge/Security-Analysis-red.svg)](#security)
[![Tests](https://img.shields.io/badge/Tests-217%20Passing-brightgreen.svg)](#development)

**Version 0.3.2** - Enhanced Negative Result Reporting Release

A comprehensive Python tool for analyzing boot sectors from disk drives or boot sector image files. The system analyzes the structure and content of both Master Boot Records (MBRs) and Volume Boot Records (VBRs), performs x86/x86-64 disassembly, and generates professional HTML reports with responsive design and interactive elements.

## ⚠️ Important Notice

> **ATTENTION**: Please read carefully before using this tool
> 
> - **🧪 Experimental Features**: VBR analysis and advanced threat detection are still experimental. Results should be verified through additional analysis methods.
> - **🔐 Root Access Required**: For direct device analysis (e.g., `/dev/sda`), this script must be run as root to access raw disk devices. **BE EXTREMELY CAREFUL** when running as root - ensure you're analyzing the correct device to avoid data loss.
> - **📁 Image Files**: For safety, consider using disk image files instead of direct device access when possible.

## ✨ Features

- **Structure Analysis**: Parse and validate Master Boot Record (MBR) structure
- **VBR Analysis**: Detect and analyze Volume Boot Records from valid partitions
- **Content Analysis**: Calculate hashes, extract strings, detect suspicious patterns
- **Boot Code Disassembly**: x86/x86-64 assembly analysis with pattern recognition
- **Filesystem Support**: FAT12/16/32, NTFS, and exFAT VBR parsing
- **Security Scanning**: Check against known malware signatures and bootkit patterns
- **Enhanced VirusTotal Integration**: Dual analysis workflow (full MBR vs boot code) with comprehensive negative result reporting
- **Professional Clean Result Display**: Prominent display of clean results with enhanced formatting and visual indicators
- **HTML Reports**: Professional, responsive reports with syntax highlighting
- **Hexdump Display**: Manual review with formatted 17-column table and MBR section highlighting
- **Multi-Format Output**: Human-readable, JSON, and HTML report formats
- **Command Line Interface**: Easy-to-use CLI with configuration file support

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/surreal70/boot-sector-analyzer.git
cd boot-sector-analyzer

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Install the package
pip install -e .
```

## 📖 Usage

### Basic Usage

```bash
# 🔍 Analyze a boot sector image file (RECOMMENDED - safer than direct device access)
boot-sector-analyzer boot_sector.img

# ⚠️ Analyze the first sector of a disk device (REQUIRES ROOT - BE CAREFUL!)
sudo boot-sector-analyzer /dev/sda

# 📊 Generate JSON output for automation
boot-sector-analyzer -f json boot_sector.img

# 🌐 Generate HTML report with disassembly and responsive design
boot-sector-analyzer -f html boot_sector.img > report.html

# 📝 Verbose output with detailed logging
boot-sector-analyzer -v boot_sector.img

# 🚫 Analyze disk without VBR analysis (faster, MBR only)
sudo boot-sector-analyzer --no-vbr /dev/sda
```

### ⚙️ Configuration

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

## 📋 Requirements

- Python 3.8 or higher
- Required packages listed in `requirements.txt`
- Optional: VirusTotal API key for threat intelligence

## 🏗️ Project Structure

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
├── vbr_analyzer.py          # VBR analysis orchestration
├── partition_scanner.py     # Partition detection and VBR extraction
├── vbr_structure_parser.py  # Filesystem-specific VBR parsing
├── vbr_content_analyzer.py  # VBR content analysis and threat detection
├── cli.py                   # Command line interface
└── config.py                # Configuration management
```

## 🛠️ Development

### 🧪 Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=boot_sector_analyzer

# Run property-based tests
pytest -v tests/test_properties.py
```

### 📏 Code Quality

```bash
# Check code style
flake8 boot_sector_analyzer/

# Format code
black boot_sector_analyzer/
```

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## 🔒 Security

This tool is designed for security analysis purposes. Always ensure you have proper authorization before analyzing boot sectors from systems you do not own.

### ⚠️ Root Access Warnings

- **Direct Device Analysis**: Accessing raw disk devices (e.g., `/dev/sda`) requires root privileges
- **Data Safety**: Always double-check device paths before analysis to prevent accidental data access
- **Recommended Approach**: Use disk image files instead of direct device access when possible
- **Backup First**: Consider creating disk images using `dd` before direct analysis

### 🧪 Experimental Features

- **VBR Analysis**: Volume Boot Record analysis is experimental and may produce false positives
- **Threat Detection**: Advanced threat detection algorithms are still being refined
- **Verification**: Always verify results through multiple analysis methods for critical assessments

## 📝 Changelog

### Version 0.3.2 (Enhanced Negative Result Reporting Release)

**Enhanced VirusTotal Integration:**
- **Dual Analysis Workflow**: Separate reporting for full MBR (512 bytes) and boot code only (446 bytes) analyses
- **Prominent Clean Result Display**: "✅ CLEAN: 0/X detections" prominently displayed with enhanced messaging
- **Complete Scan Statistics**: Detailed breakdown of malicious, suspicious, undetected, and harmless counts for all results
- **Professional HTML Formatting**: Enhanced green status badges and expandable details for clean results
- **Cross-Format Consistency**: Reliable negative result reporting across human, JSON, and HTML formats

**Technical Enhancements:**
- **Enhanced Data Models**: Complete VirusTotal response capture with dual analysis support
- **Property-Based Testing**: 2 new correctness properties (Properties 64-65) for negative result validation
- **Robust Error Handling**: Enhanced error recovery for VirusTotal API failures
- **Performance Optimization**: Efficient processing for comprehensive negative result reporting

**Testing & Validation:**
- 217 total tests passing with comprehensive coverage
- 65 correctness properties validated (2 new for enhanced negative result reporting)
- Manual testing with empty and real boot sectors demonstrating enhanced clean result display
- Cross-format compatibility testing ensuring consistent negative result data

### Version 0.3.0 (Volume Boot Record Analysis Release)

**Major New Features:**
- **Volume Boot Record (VBR) Analysis**: Complete VBR detection, extraction, and analysis
- **Automatic Partition Detection**: Identifies valid partitions from MBR for VBR extraction
- **Filesystem-Specific Parsing**: Supports FAT12/16/32, NTFS, and exFAT VBR structures
- **VBR Boot Code Disassembly**: x86/x86-64 disassembly with filesystem-specific context
- **VBR Security Scanning**: Threat detection and malware signature checking for VBRs
- **Direct Disk Access**: VBR extraction from disk devices (not performed on image files)
- **Enhanced Reporting**: VBR analysis integrated into all output formats

**New Components:**
- VBRAnalyzer: Orchestrates complete VBR analysis workflow
- PartitionScanner: Identifies partitions and extracts VBR data
- VBRStructureParser: Filesystem-specific VBR structure parsing
- VBRContentAnalyzer: VBR content analysis and threat detection

**Testing & Validation:**
- 217 total tests passing with comprehensive coverage
- 59 correctness properties validated (13 new VBR-specific properties)
- Property-based testing for VBR functionality
- Integration testing for end-to-end VBR workflows
- Cross-format compatibility testing for VBR reports

**Technical Improvements:**
- Error-resilient VBR extraction (continues if individual partitions fail)
- Intelligent VBR analysis (only for direct disk access, not image files)
- Comprehensive VBR data models and filesystem metadata extraction
- Enhanced security analysis with VBR-specific threat detection

### Version 0.2.2 (Enhanced HTML Styling Release)

**HTML Styling Improvements:**
- **Light Background Assembly Code**: Changed from dark theme to professional light background (#f8f9fa)
- **Professional Color Scheme**: Updated syntax highlighting with blue instructions, green registers, and improved contrast
- **Fixed-Width Hexdump Columns**: Implemented consistent column widths (80px offset, 30px hex bytes, 120px ASCII)
- **Empty Boot Code Detection**: Intelligent handling of all-zero boot code regions with appropriate messaging
- **Enhanced Readability**: Improved text contrast and professional appearance for technical documentation

**Technical Enhancements:**
- Updated CSS styling for better readability and professional presentation
- Added empty boot code detection to skip unnecessary disassembly
- Fixed hexdump table layout inconsistencies
- Maintained full backward compatibility with existing functionality

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