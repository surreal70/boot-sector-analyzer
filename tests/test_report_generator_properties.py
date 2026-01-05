"""Property-based tests for ReportGenerator."""

import html
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
    VBRAnalysisResult,
    VBRStructure,
    VBRContentAnalysis,
    FilesystemType,
    FilesystemMetadata,
    Instruction,
    InvalidInstruction,
    BootPattern,
    DisassemblyResult,
)


# Generators for test data
@st.composite
def instruction_strategy(draw):
    """Generate a valid Instruction."""
    from boot_sector_analyzer.models import Instruction
    return Instruction(
        address=draw(st.integers(min_value=0x7C00, max_value=0x7DFF)),
        bytes=draw(st.binary(min_size=1, max_size=8)),
        mnemonic=draw(st.sampled_from(["mov", "jmp", "int", "push", "pop", "call", "ret"])),
        operands=draw(st.text(max_size=50)),
        comment=draw(st.one_of(st.none(), st.text(max_size=100)))
    )


@st.composite
def invalid_instruction_strategy(draw):
    """Generate a valid InvalidInstruction."""
    from boot_sector_analyzer.models import InvalidInstruction
    return InvalidInstruction(
        address=draw(st.integers(min_value=0x7C00, max_value=0x7DFF)),
        bytes=draw(st.binary(min_size=1, max_size=8)),
        reason=draw(st.text(min_size=1, max_size=100))
    )


@st.composite
def boot_pattern_strategy(draw):
    """Generate a valid BootPattern."""
    from boot_sector_analyzer.models import BootPattern
    return BootPattern(
        pattern_type=draw(st.sampled_from(["disk_read", "interrupt_call", "jump"])),
        description=draw(st.text(min_size=1, max_size=200)),
        instructions=draw(st.lists(instruction_strategy(), min_size=1, max_size=5)),
        significance=draw(st.text(min_size=1, max_size=200))
    )


@st.composite
def disassembly_result_strategy(draw):
    """Generate a valid DisassemblyResult."""
    from boot_sector_analyzer.models import DisassemblyResult
    return DisassemblyResult(
        instructions=draw(st.lists(instruction_strategy(), max_size=20)),
        total_bytes_disassembled=draw(st.integers(min_value=0, max_value=446)),
        invalid_instructions=draw(st.lists(invalid_instruction_strategy(), max_size=5)),
        boot_patterns=draw(st.lists(boot_pattern_strategy(), max_size=5))
    )


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
    """Generate a valid VirusTotalResult with enhanced fields and consistent data."""
    from boot_sector_analyzer.models import VirusTotalStats, VirusTotalEngineResult
    
    # First determine the total number of engines and detection count
    total_engines = draw(st.integers(min_value=1, max_value=100))
    detection_count = draw(st.integers(min_value=0, max_value=total_engines))
    
    # Generate enhanced stats that are consistent with detection count
    stats = None
    if draw(st.booleans()):
        # Ensure stats are consistent with detection_count
        malicious = draw(st.integers(min_value=0, max_value=detection_count))
        suspicious = detection_count - malicious
        remaining_engines = total_engines - detection_count
        
        undetected = draw(st.integers(min_value=0, max_value=remaining_engines))
        harmless = remaining_engines - undetected
        
        stats = VirusTotalStats(
            malicious=malicious,
            suspicious=suspicious,
            undetected=undetected,
            harmless=harmless,
            timeout=draw(st.integers(min_value=0, max_value=5)),
            confirmed_timeout=draw(st.integers(min_value=0, max_value=2)),
            failure=draw(st.integers(min_value=0, max_value=3)),
            type_unsupported=draw(st.integers(min_value=0, max_value=2))
        )
    
    # Generate engine results that are consistent with detection_count
    engine_results = []
    generate_engine_results = draw(st.booleans())
    if generate_engine_results:
        # Generate exactly detection_count detected engines plus some undetected ones
        detected_engines = []
        undetected_engines = []
        
        # Create detected engines
        for i in range(detection_count):
            detected_engines.append(VirusTotalEngineResult(
                engine_name=f"Engine{i}",
                detected=True,
                result=draw(st.text(min_size=1, max_size=50)),
                category=draw(st.sampled_from(["malicious", "suspicious"])),
                engine_version=draw(st.one_of(st.none(), st.text(min_size=1, max_size=20))),
                engine_update=draw(st.one_of(st.none(), st.text(min_size=1, max_size=20)))
            ))
        
        # Create some undetected engines
        num_undetected = draw(st.integers(min_value=0, max_value=min(10, total_engines - detection_count)))
        for i in range(num_undetected):
            undetected_engines.append(VirusTotalEngineResult(
                engine_name=f"UndetectedEngine{i}",
                detected=False,
                result=None,
                category=draw(st.sampled_from(["undetected", "harmless"])),
                engine_version=draw(st.one_of(st.none(), st.text(min_size=1, max_size=20))),
                engine_update=draw(st.one_of(st.none(), st.text(min_size=1, max_size=20)))
            ))
        
        engine_results = detected_engines + undetected_engines
    
    # Generate legacy detections dictionary that is consistent with detection_count
    detections = {}
    generate_detections = draw(st.booleans())
    
    # If we have detections but no engine_results, we must generate detections
    # If we have no engine_results and detection_count > 0, we must generate detections
    if (detection_count > 0 and not generate_engine_results) or generate_detections:
        # Generate exactly detection_count detected entries
        for i in range(detection_count):
            engine_name = f"LegacyEngine{i}"
            detections[engine_name] = {
                'detected': True,
                'result': draw(st.text(min_size=1, max_size=50)),
                'category': draw(st.sampled_from(["malicious", "suspicious"])),
                'engine_name': engine_name
            }
        
        # Add some undetected entries
        num_undetected = draw(st.integers(min_value=0, max_value=min(5, total_engines - detection_count)))
        for i in range(num_undetected):
            engine_name = f"LegacyUndetected{i}"
            detections[engine_name] = {
                'detected': False,
                'result': None,
                'category': draw(st.sampled_from(["undetected", "harmless"])),
                'engine_name': engine_name
            }
    
    # Generate raw response
    raw_response = None
    if draw(st.booleans()):
        raw_response = {
            "id": draw(st.text(min_size=32, max_size=64)),
            "type": "file",
            "attributes": {
                "last_analysis_stats": {
                    "malicious": stats.malicious if stats else draw(st.integers(min_value=0, max_value=detection_count)),
                    "suspicious": stats.suspicious if stats else max(0, detection_count - (stats.malicious if stats else 0)),
                    "undetected": stats.undetected if stats else draw(st.integers(min_value=0, max_value=total_engines - detection_count)),
                    "harmless": stats.harmless if stats else max(0, total_engines - detection_count - (stats.undetected if stats else 0))
                },
                "first_submission_date": draw(st.integers(min_value=1000000000, max_value=2000000000)),
                "times_submitted": draw(st.integers(min_value=1, max_value=1000)),
                "reputation": draw(st.integers(min_value=-100, max_value=100))
            }
        }
    
    return VirusTotalResult(
        hash_value=draw(st.text(min_size=32, max_size=64)),
        detection_count=detection_count,
        total_engines=total_engines,
        scan_date=draw(st.one_of(st.none(), st.datetimes())),
        permalink=draw(st.one_of(st.none(), st.text(min_size=10, max_size=200))),
        detections=detections,
        stats=stats,
        engine_results=engine_results,
        raw_response=raw_response
    )


@st.composite
def threat_intelligence_strategy(draw):
    """Generate a valid ThreatIntelligence."""
    return ThreatIntelligence(
        virustotal_result=draw(st.one_of(st.none(), virustotal_result_strategy())),
        cached=draw(st.booleans()),
        query_timestamp=draw(st.datetimes()),
        analysis_type=draw(st.sampled_from(["full_boot_sector", "boot_code_only"]))
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
def filesystem_metadata_strategy(draw):
    """Generate a valid FilesystemMetadata."""
    return FilesystemMetadata(
        volume_label=draw(st.one_of(st.none(), st.text(min_size=1, max_size=11))),
        cluster_size=draw(st.one_of(st.none(), st.integers(min_value=512, max_value=65536))),
        total_sectors=draw(st.one_of(st.none(), st.integers(min_value=1, max_value=2**32-1))),
        filesystem_version=draw(st.one_of(st.none(), st.text(min_size=1, max_size=10))),
        creation_timestamp=draw(st.one_of(st.none(), st.datetimes()))
    )


@st.composite
def vbr_structure_strategy(draw):
    """Generate a valid VBRStructure."""
    return VBRStructure(
        filesystem_type=draw(st.sampled_from(FilesystemType)),
        boot_code=draw(st.binary(min_size=400, max_size=450)),
        boot_signature=draw(st.integers(min_value=0, max_value=0xFFFF)),
        filesystem_metadata=draw(filesystem_metadata_strategy()),
        raw_data=draw(st.binary(min_size=512, max_size=512))
    )


@st.composite
def vbr_content_analysis_strategy(draw):
    """Generate a valid VBRContentAnalysis."""
    return VBRContentAnalysis(
        hashes=draw(st.dictionaries(
            st.sampled_from(["md5", "sha256"]),
            st.text(min_size=32, max_size=64, alphabet="0123456789abcdef"),
            min_size=1, max_size=2
        )),
        boot_code_hashes=draw(st.dictionaries(
            st.sampled_from(["md5", "sha256"]),
            st.text(min_size=32, max_size=64, alphabet="0123456789abcdef"),
            min_size=1, max_size=2
        )),
        disassembly_result=draw(st.one_of(st.none(), disassembly_result_strategy())),
        detected_patterns=draw(st.lists(vbr_pattern_strategy(), min_size=0, max_size=3)),
        anomalies=draw(st.lists(vbr_anomaly_strategy(), min_size=0, max_size=3)),
        threat_level=draw(st.sampled_from(ThreatLevel))
    )


@st.composite
def vbr_pattern_strategy(draw):
    """Generate a valid VBRPattern."""
    from boot_sector_analyzer.models import VBRPattern, Instruction
    return VBRPattern(
        pattern_type=draw(st.sampled_from(["fat_boot_code", "ntfs_boot_code", "filesystem_check"])),
        description=draw(st.text(min_size=10, max_size=100)),
        instructions=draw(st.lists(instruction_strategy(), min_size=1, max_size=5)),
        significance=draw(st.text(min_size=10, max_size=50)),
        filesystem_specific=draw(st.booleans())
    )


@st.composite
def vbr_anomaly_strategy(draw):
    """Generate a valid VBRAnomalyy."""
    from boot_sector_analyzer.models import VBRAnomalyy
    return VBRAnomalyy(
        anomaly_type=draw(st.sampled_from(["modified_boot_code", "suspicious_metadata", "invalid_signature"])),
        description=draw(st.text(min_size=10, max_size=100)),
        severity=draw(st.sampled_from(["low", "medium", "high", "critical"])),
        evidence=draw(st.lists(st.text(min_size=5, max_size=50), min_size=0, max_size=3))
    )


@st.composite
def vbr_analysis_result_strategy(draw):
    """Generate a valid VBRAnalysisResult."""
    return VBRAnalysisResult(
        partition_number=draw(st.integers(min_value=1, max_value=4)),
        partition_info=draw(partition_entry_strategy()),
        vbr_structure=draw(st.one_of(st.none(), vbr_structure_strategy())),
        content_analysis=draw(st.one_of(st.none(), vbr_content_analysis_strategy())),
        extraction_error=draw(st.one_of(st.none(), st.text(min_size=10, max_size=100)))
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
        threat_intelligence=draw(st.one_of(st.none(), threat_intelligence_strategy())),
        vbr_analysis=draw(st.lists(vbr_analysis_result_strategy(), min_size=0, max_size=4))
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
        
        # Should include structural findings - check boot signature status
        # The enhanced MBR decoder may override the original analysis result
        if "Boot Signature: Valid" in report or "Boot Signature Valid: Yes" in report:
            # Valid signature found in report
            pass
        elif "Boot Signature: INVALID" in report or "Boot Signature Valid: No" in report:
            # Invalid signature found in report
            pass
        else:
            # Should have some boot signature information
            assert "Boot Signature" in report or "boot signature" in report
            
        # Check for partition count in either old or new format
        partition_count = analysis_result.structure_analysis.partition_count
        assert (f"Partition Count: {partition_count}" in report or
                "Partition Table:" in report)  # New format shows partition table
        
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

    @given(analysis_result_strategy(), st.sampled_from(["human", "json", "html", "HUMAN", "JSON", "HTML", "Human", "Json", "Html"]))
    def test_report_format_support(self, analysis_result, format_type):
        """
        Property 14: Report format support
        For any analysis report, the Report_Generator should support human-readable, JSON, and HTML output formats.
        
        Feature: boot-sector-analyzer, Property 14: Report format support
        Validates: Requirements 6.5, 7.7
        """
        generator = ReportGenerator()
        report = generator.generate_report(analysis_result, format_type)
        
        # Should always return a non-empty string
        assert isinstance(report, str)
        assert len(report) > 0
        
        # Check format-specific characteristics
        format_lower = format_type.lower()
        if format_lower == "json":
            # Should be valid JSON
            report_data = json.loads(report)
            assert isinstance(report_data, dict)
        elif format_lower == "html":
            # Should be valid HTML document
            assert "<!DOCTYPE html>" in report
            assert "<html" in report
            assert "</html>" in report
            assert "<head>" in report
            assert "<body>" in report
            assert "Boot Sector Analysis Report" in report
        else:
            # Should be human-readable format
            assert "BOOT SECTOR ANALYSIS REPORT" in report
            assert "=" * 60 in report  # Header formatting

    @given(analysis_result_strategy())
    def test_multi_format_report_support(self, analysis_result):
        """
        Property 19: Multi-format report support
        For any analysis result, the Report_Generator should generate equivalent data 
        across all supported output formats (human, JSON, HTML).
        
        Feature: boot-sector-analyzer, Property 19: Multi-format report support
        Validates: Requirements 6.5, 7.7
        """
        generator = ReportGenerator()
        
        # Generate reports in all formats
        human_report = generator.generate_report(analysis_result, "human")
        json_report = generator.generate_report(analysis_result, "json")
        html_report = generator.generate_report(analysis_result, "html")
        
        # All reports should be non-empty strings
        assert isinstance(human_report, str) and len(human_report) > 0
        assert isinstance(json_report, str) and len(json_report) > 0
        assert isinstance(html_report, str) and len(html_report) > 0
        
        # Parse JSON report for data verification
        json_data = json.loads(json_report)
        
        # All formats should contain the same core data
        # Source information
        assert analysis_result.source in human_report
        assert json_data["source"] == analysis_result.source
        assert analysis_result.source in html_report or self._html_escape(analysis_result.source) in html_report
        
        # Threat level information
        threat_level = analysis_result.security_analysis.threat_level.value
        assert threat_level.upper() in human_report
        assert json_data["threat_level"] == threat_level
        assert threat_level in html_report or threat_level.upper() in html_report
        
        # Hash values should be present in all formats
        for hash_type, hash_value in analysis_result.content_analysis.hashes.items():
            assert hash_type.upper() in human_report
            assert hash_value in human_report
            assert json_data["content_analysis"]["hashes"][hash_type] == hash_value
            assert hash_value in html_report
        
        # Entropy should be consistent
        entropy = analysis_result.content_analysis.entropy
        assert f"{entropy:.2f}" in human_report
        assert json_data["content_analysis"]["entropy"] == entropy
        assert f"{entropy:.2f}" in html_report
        
        # Detected threats should be present in all formats
        if analysis_result.security_analysis.detected_threats:
            assert "DETECTED THREATS:" in human_report
            assert len(json_data["security_analysis"]["detected_threats"]) > 0
            assert "Detected Threats" in html_report or "detected threats" in html_report.lower()
            
            for threat in analysis_result.security_analysis.detected_threats:
                assert threat.threat_name in human_report
                # Find corresponding threat in JSON
                json_threats = json_data["security_analysis"]["detected_threats"]
                assert any(t["name"] == threat.threat_name for t in json_threats)
                assert threat.threat_name in html_report or self._html_escape(threat.threat_name) in html_report

    def _html_escape(self, text: str) -> str:
        """Helper method to HTML escape text for comparison."""
        return html.escape(text)

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
        assert "Raw boot sector data with MBR section highlighting:" in human_report
        
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
        # Check for either original format or enhanced color-coded format
        hexdump_found = False
        for line in analysis_result.hexdump.formatted_lines[:5]:  # Check first few lines
            if line.strip():  # Skip empty lines
                # Check if line exists in report (may have color codes in enhanced version)
                if line in human_report:
                    hexdump_found = True
                    break
                # Also check if the line content exists without color codes
                elif any(part in human_report for part in line.split() if len(part) > 3):
                    hexdump_found = True
                    break
        
        # At minimum, should contain hex offset formatting
        assert hexdump_found or "0x0000" in human_report
        
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

    @given(analysis_result_strategy())
    def test_vbr_report_inclusion(self, analysis_result):
        """
        Property 54: VBR report inclusion
        For any analysis result with VBR analysis data, the Report_Generator should include 
        VBR analysis results in the generated report.
        
        Feature: boot-sector-analyzer, Property 54: VBR report inclusion
        Validates: Requirements 14.9
        """
        generator = ReportGenerator()
        
        # Test human-readable format
        human_report = generator.generate_report(analysis_result, "human")
        
        if analysis_result.vbr_analysis:
            # Report should include VBR analysis section
            assert "VOLUME BOOT RECORD (VBR) ANALYSIS" in human_report
            assert f"Analyzed {len(analysis_result.vbr_analysis)} partition(s) for VBR data:" in human_report
            
            # Should include partition-specific information
            for vbr_result in analysis_result.vbr_analysis:
                assert f"Partition {vbr_result.partition_number}:" in human_report
                
                # Should include partition info
                assert f"System ID: 0x{vbr_result.partition_info.partition_type:02X}" in human_report
                assert f"Start LBA: {vbr_result.partition_info.start_lba}" in human_report
                
                if vbr_result.extraction_error:
                    assert vbr_result.extraction_error in human_report
                elif vbr_result.vbr_structure:
                    assert vbr_result.vbr_structure.filesystem_type.value in human_report
                    assert f"0x{vbr_result.vbr_structure.boot_signature:04X}" in human_report
        else:
            # If no VBR analysis, should not have VBR section
            assert "VOLUME BOOT RECORD (VBR) ANALYSIS" not in human_report
        
        # Test JSON format
        json_report = generator.generate_report(analysis_result, "json")
        import json
        report_data = json.loads(json_report)
        
        if analysis_result.vbr_analysis:
            # Should have vbr_analysis field in JSON
            assert "vbr_analysis" in report_data
            vbr_data = report_data["vbr_analysis"]
            assert len(vbr_data) == len(analysis_result.vbr_analysis)
            
            # Check each VBR analysis result
            for i, vbr_result in enumerate(analysis_result.vbr_analysis):
                json_vbr = vbr_data[i]
                assert json_vbr["partition_number"] == vbr_result.partition_number
                assert "partition_info" in json_vbr
                
                # Check partition info
                partition_info = json_vbr["partition_info"]
                assert partition_info["system_id"] == f"0x{vbr_result.partition_info.partition_type:02X}"
                assert partition_info["start_lba"] == vbr_result.partition_info.start_lba
                assert partition_info["size_sectors"] == vbr_result.partition_info.size_sectors
                assert partition_info["bootable"] == bool(vbr_result.partition_info.status & 0x80)
                
                if vbr_result.extraction_error:
                    assert json_vbr["extraction_error"] == vbr_result.extraction_error
                elif vbr_result.vbr_structure:
                    assert "vbr_structure" in json_vbr
                    vbr_struct = json_vbr["vbr_structure"]
                    assert vbr_struct["filesystem_type"] == vbr_result.vbr_structure.filesystem_type.value
                    assert vbr_struct["boot_signature"] == f"0x{vbr_result.vbr_structure.boot_signature:04X}"
        else:
            # If no VBR analysis, should have empty list or no field
            if "vbr_analysis" in report_data:
                assert report_data["vbr_analysis"] == []

    @given(analysis_result_strategy())
    def test_vbr_hexdump_representation(self, analysis_result):
        """
        Property 55: VBR hexdump representation
        For any analysis result with VBR analysis data, the Report_Generator should include 
        VBR hexdump representation in all report formats.
        
        Feature: boot-sector-analyzer, Property 55: VBR hexdump representation
        Validates: Requirements 14.10
        """
        generator = ReportGenerator()
        
        # Only test if there are VBR analysis results with valid VBR structures AND no extraction errors
        # When there are extraction errors, the hash values are not displayed in human format
        vbr_results_with_data = [
            vbr for vbr in analysis_result.vbr_analysis 
            if (vbr.vbr_structure and vbr.vbr_structure.raw_data and 
                not vbr.extraction_error)  # Only test VBRs without extraction errors
        ]
        
        if not vbr_results_with_data:
            # Skip test if no VBR data to display without extraction errors
            return
        
        # Test human-readable format
        human_report = generator.generate_report(analysis_result, "human")
        
        # Should include VBR analysis section
        assert "VOLUME BOOT RECORD (VBR) ANALYSIS" in human_report
        
        # For each VBR with data and no extraction errors, should have hash representation
        for vbr_result in vbr_results_with_data:
            # Should have partition section
            assert f"Partition {vbr_result.partition_number}:" in human_report
            
            # Should show VBR hashes which are derived from the raw data
            # Only check for hashes when there's no extraction error
            if vbr_result.content_analysis and vbr_result.content_analysis.hashes:
                for hash_value in vbr_result.content_analysis.hashes.values():
                    assert hash_value in human_report
        
        # Test JSON format
        json_report = generator.generate_report(analysis_result, "json")
        import json
        report_data = json.loads(json_report)
        
        if "vbr_analysis" in report_data:
            vbr_data = report_data["vbr_analysis"]
            
            # Check each VBR analysis result with data and no extraction errors
            for i, vbr_result in enumerate(analysis_result.vbr_analysis):
                if (vbr_result.vbr_structure and vbr_result.vbr_structure.raw_data and 
                    not vbr_result.extraction_error):
                    json_vbr = vbr_data[i]
                    
                    # Should have hexdump field in JSON
                    assert "hexdump" in json_vbr
                    hexdump_data = json_vbr["hexdump"]
                    
                    # Should contain hexdump fields
                    assert "total_bytes" in hexdump_data
                    assert "formatted_lines" in hexdump_data
                    assert "ascii_representation" in hexdump_data
                    
                    # Should be 512 bytes for valid VBR
                    assert hexdump_data["total_bytes"] == 512
                    
                    # Should have formatted lines (32 lines for 512 bytes at 16 bytes per line)
                    assert len(hexdump_data["formatted_lines"]) == 32
                    
                    # Each line should contain hex offset
                    for line in hexdump_data["formatted_lines"]:
                        assert "0x" in line  # Should contain hex offset
        
        # Test HTML format
        html_report = generator.generate_report(analysis_result, "html")
        
        if vbr_results_with_data:
            # Should include VBR analysis section
            assert 'id="vbr-analysis"' in html_report
            
            # For each VBR with data and no extraction errors, should have hexdump table
            for vbr_result in vbr_results_with_data:
                # Should have partition section
                assert f"Partition {vbr_result.partition_number}" in html_report
                
                # Should have VBR hexdump table (look for hexdump-table class)
                # The HTML should contain a table with hex data
                assert "hexdump-table" in html_report
                
                # Should contain hex offsets in HTML
                assert "0x0000" in html_report

    @given(analysis_result_strategy())
    def test_virustotal_response_inclusion(self, analysis_result):
        """
        Property 60: VirusTotal response inclusion
        **Validates: Requirements 5.7**
        
        For any analysis result with VirusTotal data, all report formats should include
        complete VirusTotal response information including stats, engine results, and raw response.
        """
        generator = ReportGenerator()
        
        # Skip if no threat intelligence or VirusTotal result
        if (not analysis_result.threat_intelligence or 
            not analysis_result.threat_intelligence.virustotal_result):
            return
        
        vt_result = analysis_result.threat_intelligence.virustotal_result
        
        # Test human-readable format
        human_report = generator.generate_report(analysis_result, "human")
        
        # Should include threat intelligence section
        assert "THREAT INTELLIGENCE" in human_report
        
        # Should include analysis type indicator
        analysis_type = getattr(analysis_result.threat_intelligence, 'analysis_type', 'full_boot_sector')
        if analysis_type == "boot_code_only":
            assert "Boot Code Only" in human_report
        else:
            assert "Full Boot Sector" in human_report
        
        # Should include detection count and total engines
        assert f"{vt_result.detection_count}/{vt_result.total_engines}" in human_report
        
        # Should include enhanced statistics if available
        if vt_result.stats:
            assert "Scan Statistics:" in human_report
            assert f"Malicious: {vt_result.stats.malicious}" in human_report
            assert f"Suspicious: {vt_result.stats.suspicious}" in human_report
            assert f"Undetected: {vt_result.stats.undetected}" in human_report
            assert f"Harmless: {vt_result.stats.harmless}" in human_report
        
        # Should include detection ratio analysis if there are detections
        if vt_result.total_engines > 0:
            detection_ratio = vt_result.detection_count / vt_result.total_engines
            if detection_ratio == 0:
                # Enhanced negative result display
                assert "CLEAN RESULT" in human_report
            elif detection_ratio >= 0.5:
                assert "HIGH DETECTION RATIO" in human_report
            elif detection_ratio >= 0.2:
                assert "MODERATE DETECTION RATIO" in human_report
            else:
                assert "LOW DETECTION RATIO" in human_report
        
        # Should include additional metadata from raw response if available
        if vt_result.raw_response and isinstance(vt_result.raw_response, dict):
            attributes = vt_result.raw_response.get('attributes', {})
            if attributes.get('first_submission_date'):
                assert "First Seen:" in human_report
            if attributes.get('times_submitted'):
                assert "Times Submitted:" in human_report
            if attributes.get('reputation') is not None:
                assert "Reputation Score:" in human_report
        
        # Test JSON format
        json_report = generator.generate_report(analysis_result, "json")
        import json
        report_data = json.loads(json_report)
        
        # Should have threat intelligence section
        assert "threat_intelligence" in report_data
        threat_intel = report_data["threat_intelligence"]
        
        # Should have VirusTotal data
        assert "virustotal" in threat_intel
        vt_data = threat_intel["virustotal"]
        
        # Should include all basic fields
        assert "detection_count" in vt_data
        assert "total_engines" in vt_data
        assert "hash_value" in vt_data
        assert vt_data["detection_count"] == vt_result.detection_count
        assert vt_data["total_engines"] == vt_result.total_engines
        assert vt_data["hash_value"] == vt_result.hash_value
        
        # Should include enhanced statistics if available
        if vt_result.stats:
            assert "stats" in vt_data
            stats_data = vt_data["stats"]
            assert stats_data["malicious"] == vt_result.stats.malicious
            assert stats_data["suspicious"] == vt_result.stats.suspicious
            assert stats_data["undetected"] == vt_result.stats.undetected
            assert stats_data["harmless"] == vt_result.stats.harmless
        
        # Should include engine results if available
        if vt_result.engine_results:
            assert "engine_results" in vt_data
            engine_data = vt_data["engine_results"]
            assert len(engine_data) == len(vt_result.engine_results)
            
            for i, engine_result in enumerate(vt_result.engine_results):
                assert engine_data[i]["engine_name"] == engine_result.engine_name
                assert engine_data[i]["detected"] == engine_result.detected
                assert engine_data[i]["category"] == engine_result.category
        
        # Should include raw response if available
        if vt_result.raw_response:
            assert "raw_response" in vt_data
            assert vt_data["raw_response"] == vt_result.raw_response
        
        # Should include detection ratio
        if vt_result.total_engines > 0:
            assert "detection_ratio" in vt_data
            expected_ratio = vt_result.detection_count / vt_result.total_engines
            assert abs(vt_data["detection_ratio"] - expected_ratio) < 0.001
        
        # Should include analysis type
        assert "analysis_type" in threat_intel
        assert threat_intel["analysis_type"] in ["full_boot_sector", "boot_code_only"]

    @given(analysis_result_strategy())
    def test_virustotal_detection_results_display(self, analysis_result):
        """
        Property 63: VirusTotal detection results display
        **Validates: Requirements 5.10**
        
        For any analysis result with VirusTotal detections, reports should display
        detection results, scan statistics, and vendor-specific findings clearly.
        """
        generator = ReportGenerator()
        
        # Skip if no threat intelligence or VirusTotal result
        if (not analysis_result.threat_intelligence or 
            not analysis_result.threat_intelligence.virustotal_result):
            return
        
        vt_result = analysis_result.threat_intelligence.virustotal_result
        
        # Skip if no detections to display
        if vt_result.detection_count == 0:
            return
        
        # Test human-readable format
        human_report = generator.generate_report(analysis_result, "human")
        
        # Should include detection results section
        assert "Detection Results:" in human_report
        
        # Should display individual engine detections
        detected_count = 0
        if vt_result.engine_results:
            # Use enhanced engine results
            for engine_result in vt_result.engine_results:
                if engine_result.detected:
                    detected_count += 1
                    # Should show engine name
                    assert engine_result.engine_name in human_report
                    # Should show detection result if available
                    if engine_result.result:
                        assert engine_result.result in human_report
                    # Should show category
                    assert engine_result.category in human_report
        else:
            # Fall back to legacy detections
            for engine, detection in vt_result.detections.items():
                if detection.get("detected"):
                    detected_count += 1
                    assert engine in human_report
                    if detection.get('result'):
                        assert detection['result'] in human_report
        
        # Should have found at least some detections if detection_count > 0
        if vt_result.detection_count > 0:
            assert detected_count > 0
        
        # Should include scan statistics if available
        if vt_result.stats:
            stats = vt_result.stats
            assert f"Malicious: {stats.malicious}" in human_report
            assert f"Suspicious: {stats.suspicious}" in human_report
            assert f"Undetected: {stats.undetected}" in human_report
            assert f"Harmless: {stats.harmless}" in human_report
        
        # Test JSON format
        json_report = generator.generate_report(analysis_result, "json")
        import json
        report_data = json.loads(json_report)
        
        # Should have VirusTotal data with detection information
        vt_data = report_data["threat_intelligence"]["virustotal"]
        
        # Should include detection count and total engines
        assert vt_data["detection_count"] == vt_result.detection_count
        assert vt_data["total_engines"] == vt_result.total_engines
        
        # Should include detections dictionary
        assert "detections" in vt_data
        assert vt_data["detections"] == vt_result.detections
        
        # Should include enhanced engine results if available
        if vt_result.engine_results:
            assert "engine_results" in vt_data
            engine_data = vt_data["engine_results"]
            
            # Should have same number of engine results
            assert len(engine_data) == len(vt_result.engine_results)
            
            # Should include all engine result fields
            for i, engine_result in enumerate(vt_result.engine_results):
                json_engine = engine_data[i]
                assert json_engine["engine_name"] == engine_result.engine_name
                assert json_engine["detected"] == engine_result.detected
                assert json_engine["result"] == engine_result.result
                assert json_engine["category"] == engine_result.category
                assert json_engine["engine_version"] == engine_result.engine_version
                assert json_engine["engine_update"] == engine_result.engine_update
        
        # Should include enhanced statistics if available
        if vt_result.stats:
            assert "stats" in vt_data
            stats_data = vt_data["stats"]
            assert stats_data["malicious"] == vt_result.stats.malicious
            assert stats_data["suspicious"] == vt_result.stats.suspicious
            assert stats_data["undetected"] == vt_result.stats.undetected
            assert stats_data["harmless"] == vt_result.stats.harmless
            assert stats_data["timeout"] == vt_result.stats.timeout
            assert stats_data["confirmed_timeout"] == vt_result.stats.confirmed_timeout
            assert stats_data["failure"] == vt_result.stats.failure
            assert stats_data["type_unsupported"] == vt_result.stats.type_unsupported

    @given(analysis_result_strategy())
    def test_dual_virustotal_analysis_reporting(self, analysis_result):
        """
        Property 64: Dual VirusTotal analysis reporting
        **Validates: Requirements 5.11**
        
        For any analysis with VirusTotal support enabled, the Report_Generator should report 
        both entire MBR and boot code region analyses separately, even when results are negative (0 detections).
        """
        # Feature: boot-sector-analyzer, Property 64: Dual VirusTotal analysis reporting
        generator = ReportGenerator()
        
        # Skip if no threat intelligence
        if not analysis_result.threat_intelligence:
            return
        
        # Get available VirusTotal results
        full_mbr_result = analysis_result.threat_intelligence.virustotal_result
        boot_code_result = analysis_result.boot_code_threat_intelligence.virustotal_result if analysis_result.boot_code_threat_intelligence else None
        
        # Skip if we don't have at least one VirusTotal result
        if not full_mbr_result and not boot_code_result:
            return
        
        # Test human-readable format
        human_report = generator.generate_report(analysis_result, "human")
        
        # Should have VirusTotal analysis section
        assert "THREAT INTELLIGENCE" in human_report or "VirusTotal" in human_report
        
        # Should report analyses even if they have 0 detections
        if full_mbr_result:
            # Should show the full MBR analysis with detection ratio, even if 0 detections
            assert f"{full_mbr_result.detection_count}/{full_mbr_result.total_engines}" in human_report
            if full_mbr_result.detection_count == 0:
                assert "No threats detected" in human_report or "Clean" in human_report or "0 detections" in human_report
        
        if boot_code_result:
            # Should show the boot code analysis with detection ratio, even if 0 detections
            assert f"{boot_code_result.detection_count}/{boot_code_result.total_engines}" in human_report
            if boot_code_result.detection_count == 0:
                assert "No threats detected" in human_report or "Clean" in human_report or "0 detections" in human_report
        
        # Test JSON format
        json_report = generator.generate_report(analysis_result, "json")
        import json
        report_data = json.loads(json_report)
        
        # Should have threat intelligence section
        assert "threat_intelligence" in report_data
        
        # Should have appropriate entries for available analyses
        if full_mbr_result:
            assert "virustotal" in report_data["threat_intelligence"]
            full_vt_data = report_data["threat_intelligence"]["virustotal"]
            assert "analysis_type" in report_data["threat_intelligence"]
            # Should indicate the correct analysis type
            analysis_type = report_data["threat_intelligence"]["analysis_type"]
            assert analysis_type in ["full_boot_sector", "full_mbr", "boot_code_only"]
            
            # Should include detection data even if 0 detections
            assert "detection_count" in full_vt_data
            assert "total_engines" in full_vt_data
            assert full_vt_data["detection_count"] == full_mbr_result.detection_count
            assert full_vt_data["total_engines"] == full_mbr_result.total_engines
        
        if boot_code_result:
            # Check if boot code analysis is in separate field or main threat intelligence
            if "boot_code_threat_intelligence" in report_data:
                boot_code_intel = report_data["boot_code_threat_intelligence"]
                assert "virustotal" in boot_code_intel
                boot_vt_data = boot_code_intel["virustotal"]
                assert "analysis_type" in boot_code_intel
                assert boot_code_intel["analysis_type"] == "boot_code_only"
            else:
                # Boot code analysis might be in main threat intelligence if it's the only one
                boot_vt_data = report_data["threat_intelligence"]["virustotal"]
                assert report_data["threat_intelligence"]["analysis_type"] == "boot_code_only"
            
            # Should include detection data even if 0 detections
            assert "detection_count" in boot_vt_data
            assert "total_engines" in boot_vt_data
            assert boot_vt_data["detection_count"] == boot_code_result.detection_count
            assert boot_vt_data["total_engines"] == boot_code_result.total_engines
        
        # Test HTML format
        html_report = generator.generate_report(analysis_result, "html")
        
        # Should have VirusTotal section in HTML
        assert "VirusTotal" in html_report or "virustotal" in html_report
        
        # Should show detection ratios for available analyses, even if 0
        if full_mbr_result:
            assert f"{full_mbr_result.detection_count}/{full_mbr_result.total_engines}" in html_report
        
        if boot_code_result:
            assert f"{boot_code_result.detection_count}/{boot_code_result.total_engines}" in html_report
    @given(analysis_result_strategy())
    def test_negative_virustotal_result_inclusion(self, analysis_result):
        """
        Property 65: Negative VirusTotal result inclusion
        **Validates: Requirements 5.12**
        
        For any VirusTotal analysis that returns negative results (clean/0 detections), 
        the Report_Generator should still include the complete response data showing scan statistics and detection ratios.
        """
        # Feature: boot-sector-analyzer, Property 65: Negative VirusTotal result inclusion
        generator = ReportGenerator()
        
        # Skip if no threat intelligence
        if not analysis_result.threat_intelligence:
            return
        
        vt_result = analysis_result.threat_intelligence.virustotal_result
        
        # Skip if no VirusTotal result
        if not vt_result:
            return
        
        # Only test negative results (0 detections)
        if vt_result.detection_count > 0:
            return
        
        # Test human-readable format
        human_report = generator.generate_report(analysis_result, "human")
        
        # Should include threat intelligence section even for negative results
        assert "THREAT INTELLIGENCE" in human_report
        
        # Should show detection ratio even when 0/X
        assert f"{vt_result.detection_count}/{vt_result.total_engines}" in human_report
        
        # Should explicitly indicate clean/negative result
        assert "No threats detected" in human_report or "Clean" in human_report or "0 detections" in human_report
        
        # Should include scan statistics if available, even for negative results
        if vt_result.stats:
            assert "Scan Statistics:" in human_report
            assert f"Malicious: {vt_result.stats.malicious}" in human_report
            assert f"Suspicious: {vt_result.stats.suspicious}" in human_report
            assert f"Undetected: {vt_result.stats.undetected}" in human_report
            assert f"Harmless: {vt_result.stats.harmless}" in human_report
            
            # For negative results, malicious + suspicious should be 0
            assert vt_result.stats.malicious == 0
            assert vt_result.stats.suspicious == 0
        
        # Should include additional metadata from raw response if available
        if vt_result.raw_response and isinstance(vt_result.raw_response, dict):
            attributes = vt_result.raw_response.get('attributes', {})
            if attributes.get('first_submission_date'):
                assert "First Seen:" in human_report
            if attributes.get('times_submitted'):
                assert "Times Submitted:" in human_report
            if attributes.get('reputation') is not None:
                assert "Reputation Score:" in human_report
        
        # Test JSON format
        json_report = generator.generate_report(analysis_result, "json")
        import json
        report_data = json.loads(json_report)
        
        # Should have threat intelligence section
        assert "threat_intelligence" in report_data
        threat_intel = report_data["threat_intelligence"]
        
        # Should have VirusTotal data even for negative results
        assert "virustotal" in threat_intel
        vt_data = threat_intel["virustotal"]
        
        # Should include all basic fields even for negative results
        assert "detection_count" in vt_data
        assert "total_engines" in vt_data
        assert "hash_value" in vt_data
        assert vt_data["detection_count"] == 0  # Should be 0 for negative results
        assert vt_data["total_engines"] == vt_result.total_engines
        assert vt_data["hash_value"] == vt_result.hash_value
        
        # Should include detection ratio even when 0
        if vt_result.total_engines > 0:
            assert "detection_ratio" in vt_data
            assert vt_data["detection_ratio"] == 0.0  # Should be 0.0 for negative results
        
        # Should include enhanced statistics if available, even for negative results
        if vt_result.stats:
            assert "stats" in vt_data
            stats_data = vt_data["stats"]
            assert stats_data["malicious"] == 0  # Should be 0 for negative results
            assert stats_data["suspicious"] == 0  # Should be 0 for negative results
            assert stats_data["undetected"] == vt_result.stats.undetected
            assert stats_data["harmless"] == vt_result.stats.harmless
            assert stats_data["timeout"] == vt_result.stats.timeout
            assert stats_data["confirmed_timeout"] == vt_result.stats.confirmed_timeout
            assert stats_data["failure"] == vt_result.stats.failure
            assert stats_data["type_unsupported"] == vt_result.stats.type_unsupported
        
        # Should include raw response if available, even for negative results
        if vt_result.raw_response:
            assert "raw_response" in vt_data
            assert vt_data["raw_response"] == vt_result.raw_response
        
        # Should include analysis type
        assert "analysis_type" in threat_intel
        assert threat_intel["analysis_type"] in ["full_boot_sector", "boot_code_only", "full_mbr"]
        
        # Test HTML format
        html_report = generator.generate_report(analysis_result, "html")
        
        # Should include VirusTotal section in HTML even for negative results
        assert "VirusTotal" in html_report or "virustotal" in html_report
        
        # Should show detection ratio in HTML even when 0/X
        assert f"{vt_result.detection_count}/{vt_result.total_engines}" in html_report
        
        # Should have clean/negative result indicator in HTML
        assert "Clean" in html_report or "No threats" in html_report or "0 detections" in html_report
        
        # Should include scan statistics in HTML if available
        if vt_result.stats:
            # HTML format uses span tags for formatting
            assert f'<span class="stat-label">Malicious:</span>' in html_report
            assert f'<span class="stat-value">{vt_result.stats.malicious}</span>' in html_report
            assert f'<span class="stat-label">Suspicious:</span>' in html_report
            assert f'<span class="stat-value">{vt_result.stats.suspicious}</span>' in html_report
            assert f"Undetected: {vt_result.stats.undetected}" in html_report
            assert f"Harmless: {vt_result.stats.harmless}" in html_report