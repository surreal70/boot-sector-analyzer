"""Property-based tests for ReportGenerator."""

import json
from datetime import datetime
from hypothesis import given, strategies as st
from boot_sector_analyzer.report_generator import ReportGenerator
from boot_sector_analyzer.models import (
    AnalysisResult,
    StructureAnalysis,
    ContentAnalysis,
    SecurityAnalysis,
    ThreatIntelligence,
    HexdumpData,
    MBRStructure,
    PartitionEntry,
    Anomaly,
    Pattern,
    ThreatMatch,
    BootkitIndicator,
    VirusTotalResult,
    ThreatLevel,
)


# Generators for test data
@st.composite
def partition_entry_strategy(draw):
    """Generate a valid PartitionEntry."""
    return PartitionEntry(
        status=draw(st.integers(min_value=0, max_value=255)),
        start_chs=draw(st.tuples(
            st.integers(min_value=0, max_value=1023),
            st.integers(min_value=0, max_value=255),
            st.integers(min_value=1, max_value=63)
        )),
        partition_type=draw(st.integers(min_value=0, max_value=255)),
        end_chs=draw(st.tuples(
            st.integers(min_value=0, max_value=1023),
            st.integers(min_value=0, max_value=255),
            st.integers(min_value=1, max_value=63)
        )),
        start_lba=draw(st.integers(min_value=0, max_value=2**32-1)),
        size_sectors=draw(st.integers(min_value=0, max_value=2**32-1))
    )


@st.composite
def mbr_structure_strategy(draw):
    """Generate a valid MBRStructure."""
    return MBRStructure(
        bootstrap_code=draw(st.binary(min_size=446, max_size=446)),
        partition_table=draw(st.lists(partition_entry_strategy(), min_size=4, max_size=4)),
        boot_signature=draw(st.integers(min_value=0, max_value=65535)),
        disk_signature=draw(st.one_of(st.none(), st.integers(min_value=0, max_value=2**32-1)))
    )


@st.composite
def anomaly_strategy(draw):
    """Generate a valid Anomaly."""
    return Anomaly(
        type=draw(st.text(min_size=1, max_size=50)),
        description=draw(st.text(min_size=1, max_size=200)),
        severity=draw(st.sampled_from(["low", "medium", "high", "critical"])),
        location=draw(st.one_of(st.none(), st.integers(min_value=0, max_value=511)))
    )


@st.composite
def pattern_strategy(draw):
    """Generate a valid Pattern."""
    return Pattern(
        type=draw(st.text(min_size=1, max_size=50)),
        description=draw(st.text(min_size=1, max_size=200)),
        location=draw(st.integers(min_value=0, max_value=511)),
        data=draw(st.binary(min_size=1, max_size=32))
    )


@st.composite
def threat_match_strategy(draw):
    """Generate a valid ThreatMatch."""
    return ThreatMatch(
        threat_name=draw(st.text(min_size=1, max_size=100)),
        threat_type=draw(st.text(min_size=1, max_size=50)),
        confidence=draw(st.floats(min_value=0.0, max_value=1.0)),
        source=draw(st.text(min_size=1, max_size=50)),
        hash_match=draw(st.one_of(st.none(), st.text(min_size=32, max_size=64)))
    )


@st.composite
def bootkit_indicator_strategy(draw):
    """Generate a valid BootkitIndicator."""
    return BootkitIndicator(
        indicator_type=draw(st.text(min_size=1, max_size=50)),
        description=draw(st.text(min_size=1, max_size=200)),
        confidence=draw(st.floats(min_value=0.0, max_value=1.0)),
        location=draw(st.one_of(st.none(), st.integers(min_value=0, max_value=511)))
    )


@st.composite
def structure_analysis_strategy(draw):
    """Generate a valid StructureAnalysis."""
    return StructureAnalysis(
        mbr_structure=draw(mbr_structure_strategy()),
        is_valid_signature=draw(st.booleans()),
        anomalies=draw(st.lists(anomaly_strategy(), max_size=5)),
        partition_count=draw(st.integers(min_value=0, max_value=4))
    )


@st.composite
def content_analysis_strategy(draw):
    """Generate a valid ContentAnalysis."""
    return ContentAnalysis(
        hashes=draw(st.dictionaries(
            st.sampled_from(["md5", "sha256"]),
            st.text(min_size=32, max_size=64),
            min_size=1, max_size=2
        )),
        strings=draw(st.lists(st.text(min_size=1, max_size=100), max_size=10)),
        suspicious_patterns=draw(st.lists(pattern_strategy(), max_size=5)),
        entropy=draw(st.floats(min_value=0.0, max_value=8.0)),
        urls=draw(st.lists(st.text(min_size=10, max_size=100), max_size=5))
    )


@st.composite
def security_analysis_strategy(draw):
    """Generate a valid SecurityAnalysis."""
    return SecurityAnalysis(
        threat_level=draw(st.sampled_from(ThreatLevel)),
        detected_threats=draw(st.lists(threat_match_strategy(), max_size=5)),
        bootkit_indicators=draw(st.lists(bootkit_indicator_strategy(), max_size=5)),
        suspicious_patterns=draw(st.lists(pattern_strategy(), max_size=5)),
        anomalies=draw(st.lists(anomaly_strategy(), max_size=5))
    )


@st.composite
def virustotal_result_strategy(draw):
    """Generate a valid VirusTotalResult."""
    return VirusTotalResult(
        hash_value=draw(st.text(min_size=32, max_size=64)),
        detection_count=draw(st.integers(min_value=0, max_value=100)),
        total_engines=draw(st.integers(min_value=1, max_value=100)),
        scan_date=draw(st.one_of(st.none(), st.datetimes())),
        permalink=draw(st.one_of(st.none(), st.text(min_size=10, max_size=200))),
        detections=draw(st.dictionaries(st.text(), st.dictionaries(st.text(), st.text())))
    )


@st.composite
def threat_intelligence_strategy(draw):
    """Generate a valid ThreatIntelligence."""
    return ThreatIntelligence(
        virustotal_result=draw(st.one_of(st.none(), virustotal_result_strategy())),
        cached=draw(st.booleans()),
        query_timestamp=draw(st.datetimes())
    )


@st.composite
def hexdump_data_strategy(draw):
    """Generate a valid HexdumpData with proper formatting."""
    raw_data = draw(st.binary(min_size=512, max_size=512))
    
    # Use the actual ReportGenerator to create proper formatted lines
    from boot_sector_analyzer.report_generator import ReportGenerator
    generator = ReportGenerator()
    formatted_lines = generator.format_hexdump_table(raw_data)
    ascii_representation = generator.format_ascii_column(raw_data)
    
    return HexdumpData(
        raw_data=raw_data,
        formatted_lines=formatted_lines,
        ascii_representation=ascii_representation,
        total_bytes=len(raw_data)
    )


@st.composite
def analysis_result_strategy(draw):
    """Generate a valid AnalysisResult."""
    return AnalysisResult(
        source=draw(st.text(min_size=1, max_size=200)),
        timestamp=draw(st.datetimes()),
        structure_analysis=draw(structure_analysis_strategy()),
        content_analysis=draw(content_analysis_strategy()),
        security_analysis=draw(security_analysis_strategy()),
        hexdump=draw(hexdump_data_strategy()),
        threat_intelligence=draw(st.one_of(st.none(), threat_intelligence_strategy()))
    )


class TestReportGeneratorProperties:
    """Property-based tests for ReportGenerator."""

    @given(analysis_result_strategy())
    def test_report_completeness_human_format(self, analysis_result):
        """
        Property 13: Report completeness
        For any completed analysis, the Report_Generator should create a structured report 
        containing all structural findings, content analysis results, and security assessment findings.
        
        Feature: boot-sector-analyzer, Property 13: Report completeness
        Validates: Requirements 6.1, 6.2, 6.3, 6.4
        """
        generator = ReportGenerator()
        report = generator.generate_report(analysis_result, "human")
        
        # Report should be non-empty string
        assert isinstance(report, str)
        assert len(report) > 0
        
        # Report should contain key sections
        assert "BOOT SECTOR ANALYSIS REPORT" in report
        assert "STRUCTURE ANALYSIS" in report
        assert "CONTENT ANALYSIS" in report
        assert "SECURITY ANALYSIS" in report
        assert "SUMMARY" in report
        
        # Should include source and timestamp
        assert analysis_result.source in report
        
        # Should include threat level
        assert analysis_result.security_analysis.threat_level.value.upper() in report
        
        # Should include structural findings
        if analysis_result.structure_analysis.is_valid_signature:
            assert "Boot Signature Valid: Yes" in report
        else:
            assert "Boot Signature Valid: No" in report
            
        assert f"Partition Count: {analysis_result.structure_analysis.partition_count}" in report
        
        # Should include content analysis results
        for hash_type, hash_value in analysis_result.content_analysis.hashes.items():
            assert hash_type.upper() in report
            assert hash_value in report
            
        assert f"Entropy: {analysis_result.content_analysis.entropy:.2f}" in report
        
        # Should include security assessment findings
        if analysis_result.security_analysis.detected_threats:
            assert "DETECTED THREATS:" in report
            for threat in analysis_result.security_analysis.detected_threats:
                assert threat.threat_name in report

    @given(analysis_result_strategy())
    def test_report_completeness_json_format(self, analysis_result):
        """
        Property 13: Report completeness (JSON format)
        For any completed analysis, the Report_Generator should create a structured JSON report 
        containing all structural findings, content analysis results, and security assessment findings.
        
        Feature: boot-sector-analyzer, Property 13: Report completeness
        Validates: Requirements 6.1, 6.2, 6.3, 6.4
        """
        generator = ReportGenerator()
        report = generator.generate_report(analysis_result, "json")
        
        # Should be valid JSON
        report_data = json.loads(report)
        
        # Should contain all required top-level fields
        assert "source" in report_data
        assert "timestamp" in report_data
        assert "threat_level" in report_data
        assert "structure_analysis" in report_data
        assert "content_analysis" in report_data
        assert "security_analysis" in report_data
        
        # Verify source and threat level
        assert report_data["source"] == analysis_result.source
        assert report_data["threat_level"] == analysis_result.security_analysis.threat_level.value
        
        # Verify structure analysis section
        struct_section = report_data["structure_analysis"]
        assert "boot_signature_valid" in struct_section
        assert "partition_count" in struct_section
        assert "anomalies" in struct_section
        assert struct_section["boot_signature_valid"] == analysis_result.structure_analysis.is_valid_signature
        assert struct_section["partition_count"] == analysis_result.structure_analysis.partition_count
        
        # Verify content analysis section
        content_section = report_data["content_analysis"]
        assert "hashes" in content_section
        assert "entropy" in content_section
        assert "strings" in content_section
        assert "urls" in content_section
        assert "suspicious_patterns" in content_section
        assert content_section["hashes"] == analysis_result.content_analysis.hashes
        assert content_section["entropy"] == analysis_result.content_analysis.entropy
        
        # Verify security analysis section
        security_section = report_data["security_analysis"]
        assert "threat_level" in security_section
        assert "detected_threats" in security_section
        assert "bootkit_indicators" in security_section
        assert security_section["threat_level"] == analysis_result.security_analysis.threat_level.value

    @given(analysis_result_strategy(), st.sampled_from(["human", "json", "HUMAN", "JSON", "Human", "Json"]))
    def test_report_format_support(self, analysis_result, format_type):
        """
        Property 14: Report format support
        For any analysis report, the Report_Generator should support both human-readable and JSON output formats.
        
        Feature: boot-sector-analyzer, Property 14: Report format support
        Validates: Requirements 6.5
        """
        generator = ReportGenerator()
        report = generator.generate_report(analysis_result, format_type)
        
        # Should always return a non-empty string
        assert isinstance(report, str)
        assert len(report) > 0
        
        # Check format-specific characteristics
        if format_type.lower() == "json":
            # Should be valid JSON
            report_data = json.loads(report)
            assert isinstance(report_data, dict)
        else:
            # Should be human-readable format
            assert "BOOT SECTOR ANALYSIS REPORT" in report
            assert "=" * 60 in report  # Header formatting

    @given(analysis_result_strategy())
    def test_critical_finding_highlighting(self, analysis_result):
        """
        Property 15: Critical finding highlighting
        For any report containing detected threats, the Report_Generator should highlight critical findings prominently.
        
        Feature: boot-sector-analyzer, Property 15: Critical finding highlighting
        Validates: Requirements 6.6
        """
        generator = ReportGenerator()
        
        # Test human-readable format
        human_report = generator.generate_report(analysis_result, "human")
        
        # Check threat level highlighting
        threat_level = analysis_result.security_analysis.threat_level
        if threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
            assert "⚠️  CRITICAL FINDINGS DETECTED!" in human_report
            assert "malicious activity" in human_report.lower()
        elif threat_level == ThreatLevel.MEDIUM:
            assert "⚠️  Suspicious activity detected" in human_report
        else:
            assert "✅ No significant threats detected" in human_report
            
        # Check threat indicators in threat level display
        threat_indicators = {"low": "✅", "medium": "⚠️", "high": "🚨", "critical": "🔴"}
        expected_indicator = threat_indicators.get(threat_level.value, "❓")
        assert expected_indicator in human_report
        
        # If there are detected threats, they should be prominently displayed
        if analysis_result.security_analysis.detected_threats:
            assert "DETECTED THREATS:" in human_report
            for threat in analysis_result.security_analysis.detected_threats:
                # Each threat should have a warning emoji
                assert "⚠️" in human_report

    @given(analysis_result_strategy())
    def test_hexdump_report_inclusion(self, analysis_result):
        """
        Property 22: Hexdump report inclusion
        For any completed analysis, the Report_Generator should include a hexdump section 
        of the complete boot sector in the generated report.
        
        Feature: boot-sector-analyzer, Property 22: Hexdump report inclusion
        Validates: Requirements 8.1
        """
        generator = ReportGenerator()
        
        # Test human-readable format
        human_report = generator.generate_report(analysis_result, "human")
        
        # Report should include a hexdump section
        assert "HEXDUMP" in human_report
        assert "Raw boot sector data for manual review:" in human_report
        
        # Should contain hex offset formatting (0x0000 style)
        assert "0x0000" in human_report
        
        # Test JSON format
        json_report = generator.generate_report(analysis_result, "json")
        
        # JSON report should also include hexdump data
        import json
        report_data = json.loads(json_report)
        
        # Should have hexdump field
        assert "hexdump" in report_data
        hexdump_section = report_data["hexdump"]
        assert "total_bytes" in hexdump_section
        assert "formatted_lines" in hexdump_section
        assert "ascii_representation" in hexdump_section
        assert hexdump_section["total_bytes"] == analysis_result.hexdump.total_bytes

    @given(st.binary(min_size=512, max_size=512))
    def test_hexdump_table_format(self, boot_sector_data):
        """
        Property 23: Hexdump table format
        For any boot sector hexdump, the Report_Generator should format it as a 17-column table 
        with hex offset in the first column and 16 hex bytes in the remaining columns.
        
        Feature: boot-sector-analyzer, Property 23: Hexdump table format
        Validates: Requirements 8.2, 8.3
        """
        generator = ReportGenerator()
        formatted_lines = generator.format_hexdump_table(boot_sector_data)
        
        # Should have header and separator lines plus 32 data lines (512 bytes / 16 bytes per line)
        assert len(formatted_lines) >= 34  # Header + separator + 32 data lines
        
        # Check header line format
        header_line = formatted_lines[0]
        assert "Offset" in header_line
        assert "ASCII" in header_line
        # Should contain column headers for 16 hex bytes (00-0F)
        for i in range(16):
            assert f"{i:02X}" in header_line
        
        # Check data lines format (skip header and separator)
        data_lines = formatted_lines[2:]  # Skip header and separator
        for i, line in enumerate(data_lines):
            # Each line should start with hex offset
            expected_offset = f"0x{i*16:04X}"
            assert line.startswith(expected_offset)
            
            # Should contain 16 hex byte pairs
            hex_part = line.split("  ")[1]  # Get hex bytes part
            hex_bytes = hex_part.split("  ")[0]  # Remove ASCII part
            byte_pairs = hex_bytes.split(" ")
            
            # Should have exactly 16 hex byte pairs (or fewer for last line if incomplete)
            expected_pairs = min(16, len(boot_sector_data) - i * 16)
            assert len(byte_pairs) == expected_pairs
            
            # Each pair should be valid hex
            for pair in byte_pairs:
                assert len(pair) == 2
                int(pair, 16)  # Should not raise exception

    @given(st.binary(min_size=1, max_size=512))
    def test_hexdump_ascii_representation(self, data):
        """
        Property 24: Hexdump ASCII representation
        For any boot sector data, the Report_Generator should include ASCII representation 
        alongside hex values, displaying dots (.) for non-printable characters.
        
        Feature: boot-sector-analyzer, Property 24: Hexdump ASCII representation
        Validates: Requirements 8.4, 8.6
        """
        generator = ReportGenerator()
        ascii_repr = generator.format_ascii_column(data)
        
        # ASCII representation should have same length as input data
        assert len(ascii_repr) == len(data)
        
        # Check each character
        for i, byte_val in enumerate(data):
            char = ascii_repr[i]
            if 32 <= byte_val <= 126:  # Printable ASCII range
                assert char == chr(byte_val)
            else:
                assert char == '.'

    @given(st.binary(min_size=512, max_size=512))
    def test_hexdump_offset_formatting(self, boot_sector_data):
        """
        Property 25: Hexdump offset formatting
        For any hexdump offset, the Report_Generator should format it as zero-padded 
        uppercase hexadecimal (e.g., 0x0000, 0x0010).
        
        Feature: boot-sector-analyzer, Property 25: Hexdump offset formatting
        Validates: Requirements 8.5
        """
        generator = ReportGenerator()
        formatted_lines = generator.format_hexdump_table(boot_sector_data)
        
        # Skip header and separator lines
        data_lines = formatted_lines[2:]
        
        for i, line in enumerate(data_lines):
            # Extract offset from beginning of line
            offset_part = line.split("  ")[0]
            
            # Should be in format 0xXXXX
            assert offset_part.startswith("0x")
            hex_part = offset_part[2:]
            
            # Should be exactly 4 characters (zero-padded)
            assert len(hex_part) == 4
            
            # Should be valid uppercase hex (digits and A-F)
            assert all(c in "0123456789ABCDEF" for c in hex_part)
            
            # If there are any letters, they should be uppercase
            letters_in_hex = [c for c in hex_part if c.isalpha()]
            if letters_in_hex:
                assert all(c.isupper() for c in letters_in_hex)
            
            # Should match expected offset value
            expected_offset = i * 16
            actual_offset = int(hex_part, 16)
            assert actual_offset == expected_offset

    @given(analysis_result_strategy())
    def test_hexdump_format_support(self, analysis_result):
        """
        Property 26: Hexdump format support
        For any analysis report, the Report_Generator should include the hexdump 
        in both human-readable and JSON output formats.
        
        Feature: boot-sector-analyzer, Property 26: Hexdump format support
        Validates: Requirements 8.7
        """
        generator = ReportGenerator()
        
        # Test human-readable format
        human_report = generator.generate_report(analysis_result, "human")
        assert "HEXDUMP" in human_report
        
        # Should contain formatted hexdump lines
        for line in analysis_result.hexdump.formatted_lines[:5]:  # Check first few lines
            if line.strip():  # Skip empty lines
                assert line in human_report
        
        # Test JSON format
        json_report = generator.generate_report(analysis_result, "json")
        import json
        report_data = json.loads(json_report)
        
        # Should have hexdump section in JSON
        assert "hexdump" in report_data
        hexdump_data = report_data["hexdump"]
        
        # Should contain all hexdump fields
        assert "total_bytes" in hexdump_data
        assert "formatted_lines" in hexdump_data
        assert "ascii_representation" in hexdump_data
        
        # Values should match the analysis result
        assert hexdump_data["total_bytes"] == analysis_result.hexdump.total_bytes
        assert hexdump_data["formatted_lines"] == analysis_result.hexdump.formatted_lines
        assert hexdump_data["ascii_representation"] == analysis_result.hexdump.ascii_representation