# Changelog

All notable changes to the Boot Sector Analyzer project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] - 2026-01-04

### Added
- **Enhanced Hexdump Functionality**: Complete hexdump display for manual boot sector review
- **17-Column Table Format**: Structured hexdump with offset column and 16 hex byte columns
- **ASCII Representation**: Side-by-side ASCII view with dots for non-printable characters
- **Zero-Padded Offsets**: Uppercase hexadecimal offsets (0x0000, 0x0010, etc.)
- **Dual Format Support**: Hexdump included in both human-readable and JSON reports
- **HexdumpData Model**: New dataclass for structured hexdump storage

### Enhanced
- **Report Generation**: All reports now include dedicated hexdump section
- **JSON Export**: Hexdump data available in structured JSON format
- **Manual Review Support**: Raw boot sector data formatted for easy analysis

### Testing
- **5 New Property-Based Tests**: Comprehensive hexdump functionality validation
  - Property 22: Hexdump report inclusion
  - Property 23: Hexdump table format validation
  - Property 24: ASCII representation accuracy
  - Property 25: Offset formatting compliance
  - Property 26: Multi-format support verification
- **Integration Testing**: End-to-end testing with hexdump functionality
- **Manual Verification**: Tested with real boot sector samples

### Requirements
- **Requirements 8.1-8.7**: Complete implementation of hexdump display requirements
- **Backward Compatibility**: Fully compatible with v0.1.0 configurations
- **No New Dependencies**: Enhanced functionality using existing libraries

## [0.1.0] - 2025-01-04

### Added
- Initial release of Boot Sector Analyzer
- Complete MBR structure parsing and validation
- Boot sector content analysis with cryptographic hash calculation (MD5, SHA-256)
- Security threat detection and pattern matching
- VirusTotal API integration for online threat intelligence
- Comprehensive error handling and logging system
- Command line interface with argument validation
- Configuration file support for API keys and settings
- Support for both human-readable and JSON output formats
- Property-based testing framework with 21 correctness properties
- Comprehensive unit test coverage
- Integration tests for end-to-end workflows

### Components
- **Input Handler**: File and device boot sector reading with validation
- **Structure Analyzer**: MBR parsing, partition table analysis, boot signature validation
- **Content Analyzer**: Hash calculation, string extraction, entropy analysis, pattern detection
- **Security Scanner**: Known malware signature detection, bootkit pattern matching, threat classification
- **Internet Checker**: VirusTotal API integration with caching and rate limiting
- **Report Generator**: Structured report generation in multiple formats
- **CLI Interface**: Complete command line interface with help, validation, and error handling
- **Configuration System**: INI-based configuration with default value handling

### Testing
- 21 correctness properties validated through property-based testing using Hypothesis
- Comprehensive unit test suite covering all components
- Integration tests for complete analysis workflows
- Error handling and edge case validation
- Mock-based testing for external API interactions

### Documentation
- Complete requirements specification in German
- Comprehensive design document with architecture diagrams
- Detailed implementation plan with task breakdown
- README with installation and usage instructions
- Code documentation and inline comments

### Security Features
- Malware hash signature detection
- Bootkit pattern recognition
- MBR hijacking detection
- Partition table manipulation detection
- Encryption and obfuscation detection
- SSL certificate validation for HTTPS requests

### Performance Features
- Local caching for threat intelligence results
- API rate limiting compliance
- Graceful degradation when offline
- Efficient binary parsing using Python struct module

### Error Handling
- Comprehensive exception hierarchy
- Graceful error exit with appropriate exit codes
- Detailed error logging for debugging and audit
- User-friendly error messages with actionable guidance

## [Unreleased]

### Planned Features
- Support for additional boot sector formats (GPT, UEFI)
- Extended malware signature database
- Additional threat intelligence sources
- Web-based reporting interface
- Batch processing capabilities
- Enhanced visualization of analysis results