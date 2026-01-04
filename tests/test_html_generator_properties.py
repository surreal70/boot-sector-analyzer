"""Property-based tests for HTMLGenerator."""

import re
from datetime import datetime
from html import escape as html_escape
from hypothesis import given, strategies as st
from boot_sector_analyzer import __version__
from boot_sector_analyzer.html_generator import HTMLGenerator
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
    DisassemblyResult,
    Instruction,
    InvalidInstruction,
    BootPattern,
)


# Reuse generators from existing test file
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
def instruction_strategy(draw):
    """Generate a valid Instruction."""
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
    return InvalidInstruction(
        address=draw(st.integers(min_value=0x7C00, max_value=0x7DFF)),
        bytes=draw(st.binary(min_size=1, max_size=8)),
        reason=draw(st.text(min_size=1, max_size=100))
    )


@st.composite
def boot_pattern_strategy(draw):
    """Generate a valid BootPattern."""
    return BootPattern(
        pattern_type=draw(st.sampled_from(["disk_read", "interrupt_call", "jump"])),
        description=draw(st.text(min_size=1, max_size=200)),
        instructions=draw(st.lists(instruction_strategy(), min_size=1, max_size=5)),
        significance=draw(st.text(min_size=1, max_size=200))
    )


@st.composite
def disassembly_result_strategy(draw):
    """Generate a valid DisassemblyResult."""
    return DisassemblyResult(
        instructions=draw(st.lists(instruction_strategy(), max_size=20)),
        total_bytes_disassembled=draw(st.integers(min_value=0, max_value=446)),
        invalid_instructions=draw(st.lists(invalid_instruction_strategy(), max_size=5)),
        boot_patterns=draw(st.lists(boot_pattern_strategy(), max_size=5))
    )


@st.composite
def hexdump_data_strategy(draw):
    """Generate a valid HexdumpData."""
    raw_data = draw(st.binary(min_size=512, max_size=512))
    
    # Create simple formatted lines for testing
    formatted_lines = []
    for offset in range(0, len(raw_data), 16):
        row_data = raw_data[offset:offset + 16]
        hex_bytes = ' '.join(f'{b:02X}' for b in row_data)
        ascii_repr = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in row_data)
        line = f"0x{offset:04X}  {hex_bytes:<48}  {ascii_repr}"
        formatted_lines.append(line)
    
    ascii_representation = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in raw_data)
    
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
        disassembly=draw(st.one_of(st.none(), disassembly_result_strategy())),
        threat_intelligence=draw(st.one_of(st.none(), threat_intelligence_strategy()))
    )


class TestHTMLGeneratorProperties:
    """Property-based tests for HTMLGenerator."""

    @given(analysis_result_strategy())
    def test_html_document_structure(self, analysis_result):
        """
        Property 21: HTML document structure
        For any analysis result formatted as HTML, the Report_Generator should create a complete, 
        self-contained HTML document with DOCTYPE declaration and embedded CSS styling.
        
        Feature: boot-sector-analyzer, Property 21: HTML document structure
        Validates: Requirements 6.7, 10.1, 10.2
        """
        generator = HTMLGenerator()
        html_document = generator.create_html_document(analysis_result)
        
        # Should be a non-empty string
        assert isinstance(html_document, str)
        assert len(html_document) > 0
        
        # Should have proper DOCTYPE declaration
        assert html_document.strip().startswith("<!DOCTYPE html>")
        
        # Should have complete HTML structure
        assert "<html" in html_document
        assert "<head>" in html_document
        assert "</head>" in html_document
        assert "<body>" in html_document
        assert "</body>" in html_document
        assert "</html>" in html_document
        
        # Should have proper meta tags
        assert '<meta charset="UTF-8">' in html_document
        assert '<meta name="viewport"' in html_document
        assert '<meta name="generator"' in html_document
        assert '<meta name="generated"' in html_document
        
        # Should have embedded CSS (self-contained)
        assert "<style>" in html_document
        assert "</style>" in html_document
        
        # Should not have external CSS links (self-contained requirement)
        assert '<link rel="stylesheet"' not in html_document
        
        # Should have proper title
        assert "<title>" in html_document
        assert "Boot Sector Analysis Report" in html_document
        
        # Should include source information in title
        # The source may be HTML-escaped, so check for both original and escaped versions
        source_in_title = (analysis_result.source in html_document or 
                          html_escape(analysis_result.source) in html_document)
        assert source_in_title, f"Source '{analysis_result.source}' not found in HTML title"
        
        # Should have main content sections
        assert "Structure Analysis" in html_document
        assert "Content Analysis" in html_document
        assert "Security Analysis" in html_document
        assert "Hexdump" in html_document
        assert "Summary" in html_document
        
        # Should have proper HTML structure with container
        assert 'class="container"' in html_document
        assert 'class="report-header"' in html_document
        assert 'class="report-content"' in html_document or '<main' in html_document
        
        # Should include timestamp and version metadata
        assert "Analysis Time:" in html_document
        assert "Generated:" in html_document
        assert "Analyzer Version:" in html_document

    @given(analysis_result_strategy())
    def test_html_responsive_design(self, analysis_result):
        """
        Property 25: HTML responsive design
        For any HTML report, the Report_Generator should include responsive CSS 
        to ensure proper display on different screen sizes.
        
        Feature: boot-sector-analyzer, Property 25: HTML responsive design
        Validates: Requirements 10.5
        """
        generator = HTMLGenerator()
        html_document = generator.create_html_document(analysis_result)
        
        # Should contain embedded CSS
        assert "<style>" in html_document and "</style>" in html_document
        
        # Extract CSS content
        css_start = html_document.find("<style>") + 7
        css_end = html_document.find("</style>")
        css_content = html_document[css_start:css_end]
        
        # Should have responsive media queries
        assert "@media" in css_content
        
        # Should have mobile-specific breakpoints
        mobile_breakpoints = ["768px", "480px"]
        has_mobile_query = any(breakpoint in css_content for breakpoint in mobile_breakpoints)
        assert has_mobile_query, "Should have mobile responsive breakpoints"
        
        # Should have max-width media queries for responsive design
        assert "max-width" in css_content
        
        # Should have responsive container styles
        assert "container" in css_content
        
        # Should have responsive adjustments for small screens
        # Look for common responsive patterns
        responsive_patterns = [
            "font-size",  # Font size adjustments
            "padding",    # Padding adjustments
            "columns",    # Column layout adjustments
        ]
        
        # At least some responsive patterns should be present
        responsive_found = sum(1 for pattern in responsive_patterns if pattern in css_content)
        assert responsive_found >= 2, f"Should have responsive design patterns, found {responsive_found}"
        
        # Should have print styles for better printing
        assert "@media print" in css_content or "print" in css_content

    @given(analysis_result_strategy())
    def test_html_color_coding(self, analysis_result):
        """
        Property 22: HTML color coding
        For any HTML report, the Report_Generator should use appropriate color coding for threat levels 
        and assembly syntax highlighting.
        
        Feature: boot-sector-analyzer, Property 22: HTML color coding
        Validates: Requirements 6.8, 10.3, 11.4, 11.5
        """
        generator = HTMLGenerator()
        html_document = generator.create_html_document(analysis_result)
        
        # Should have threat level badge with appropriate color coding
        threat_level = analysis_result.security_analysis.threat_level
        
        # Check for threat level badge
        assert 'class="threat-badge' in html_document
        
        # Check for appropriate threat level class
        threat_classes = {
            ThreatLevel.LOW: "threat-low",
            ThreatLevel.MEDIUM: "threat-medium",
            ThreatLevel.HIGH: "threat-high",
            ThreatLevel.CRITICAL: "threat-critical"
        }
        
        expected_class = threat_classes[threat_level]
        assert expected_class in html_document
        
        # Should have CSS color definitions for threat levels
        css_start = html_document.find("<style>") + 7
        css_end = html_document.find("</style>")
        css_content = html_document[css_start:css_end]
        
        # Check for threat level color definitions
        assert ".threat-low" in css_content
        assert ".threat-medium" in css_content
        assert ".threat-high" in css_content
        assert ".threat-critical" in css_content
        
        # Should have appropriate colors (green, yellow, red, dark red)
        color_patterns = ["#28a745", "#ffc107", "#dc3545", "#6f0000"]  # Bootstrap-like colors
        colors_found = sum(1 for color in color_patterns if color in css_content)
        assert colors_found >= 3, "Should have appropriate threat level colors"
        
        # If disassembly is present, should have assembly syntax highlighting
        if analysis_result.disassembly and analysis_result.disassembly.instructions:
            # Should have assembly syntax highlighting classes
            assert "asm-instruction" in css_content  # Blue for instructions
            assert "asm-register" in css_content     # Green for registers
            assert "asm-immediate" in css_content    # Orange for immediate values
            assert "asm-address" in css_content      # Red for addresses
            assert "asm-comment" in css_content      # Green for comments
            
            # Should have appropriate colors for assembly syntax
            # Professional blue for instructions, forest green for registers, chocolate orange for values, crimson red for addresses, muted gray for comments
            assembly_colors = ["#0066cc", "#228b22", "#d2691e", "#dc143c", "#6a737d"]
            assembly_colors_found = sum(1 for color in assembly_colors if color in css_content)
            assert assembly_colors_found >= 3, "Should have assembly syntax highlighting colors"

    @given(analysis_result_strategy())
    def test_html_interactive_elements(self, analysis_result):
        """
        Property 23: HTML interactive elements
        For any HTML report, the Report_Generator should include interactive elements 
        such as a table of contents with anchor links for navigation.
        
        Feature: boot-sector-analyzer, Property 23: HTML interactive elements
        Validates: Requirements 6.9, 10.7
        """
        generator = HTMLGenerator()
        html_document = generator.create_html_document(analysis_result)
        
        # Should have table of contents
        assert "Table of Contents" in html_document
        assert 'class="table-of-contents"' in html_document or 'class="toc' in html_document
        
        # Should have navigation links with anchors
        anchor_links = [
            "#structure-analysis",
            "#content-analysis", 
            "#security-analysis",
            "#threat-intelligence",
            "#disassembly",
            "#hexdump",
            "#summary"
        ]
        
        # Should have most anchor links present
        links_found = sum(1 for link in anchor_links if link in html_document)
        assert links_found >= 5, f"Should have anchor navigation links, found {links_found}"
        
        # Should have corresponding section IDs
        section_ids = [
            'id="structure-analysis"',
            'id="content-analysis"',
            'id="security-analysis"',
            'id="hexdump"',
            'id="summary"'
        ]
        
        # Should have most section IDs present
        ids_found = sum(1 for section_id in section_ids if section_id in html_document)
        assert ids_found >= 4, f"Should have section anchor IDs, found {ids_found}"
        
        # Should have clickable links (href attributes)
        assert 'href="#' in html_document
        
        # Should have CSS for interactive elements
        css_start = html_document.find("<style>") + 7
        css_end = html_document.find("</style>")
        css_content = html_document[css_start:css_end]
        
        # Should have hover effects for interactive elements
        assert ":hover" in css_content
        
        # Should have transition effects for smooth interactions
        assert "transition" in css_content

    @given(analysis_result_strategy())
    def test_html_monospace_formatting(self, analysis_result):
        """
        Property 24: HTML monospace formatting
        For any HTML report containing hexdump data, hash values, or assembly code, 
        the Report_Generator should format them using monospace fonts with proper alignment and indentation.
        
        Feature: boot-sector-analyzer, Property 24: HTML monospace formatting
        Validates: Requirements 10.4, 10.8, 11.8
        """
        generator = HTMLGenerator()
        html_document = generator.create_html_document(analysis_result)
        
        # Should have monospace CSS class definitions
        css_start = html_document.find("<style>") + 7
        css_end = html_document.find("</style>")
        css_content = html_document[css_start:css_end]
        
        # Should have monospace font family definitions
        monospace_fonts = ["Consolas", "Monaco", "Courier New", "monospace"]
        monospace_found = sum(1 for font in monospace_fonts if font in css_content)
        assert monospace_found >= 2, "Should have monospace font definitions"
        
        # Should have monospace classes
        monospace_classes = [".monospace", ".code-block", ".hash-value", ".assembly-code", ".hexdump-table"]
        classes_found = sum(1 for cls in monospace_classes if cls in css_content)
        assert classes_found >= 3, f"Should have monospace CSS classes, found {classes_found}"
        
        # Should use monospace classes in HTML content
        html_monospace_usage = ['class="monospace"', 'class="hash-value"', 'class="code-block"']
        usage_found = sum(1 for usage in html_monospace_usage if usage in html_document)
        assert usage_found >= 1, "Should use monospace classes in HTML content"
        
        # Hash values should be formatted with monospace
        if analysis_result.content_analysis.hashes:
            # Should have hash values in the document
            for hash_value in analysis_result.content_analysis.hashes.values():
                if hash_value in html_document:
                    # Hash should be near monospace formatting
                    hash_index = html_document.find(hash_value)
                    surrounding_text = html_document[max(0, hash_index-100):hash_index+100]
                    assert ('class="hash-value"' in surrounding_text or 
                           'class="monospace"' in surrounding_text), "Hash values should have monospace formatting"
                    break
        
        # If disassembly is present, should have monospace assembly formatting
        if analysis_result.disassembly and analysis_result.disassembly.instructions:
            assert ('class="assembly-code"' in html_document or 
                   'class="code-block"' in html_document), "Assembly code should have monospace formatting"
        
        # Hexdump should have monospace table formatting
        assert 'class="hexdump-table"' in html_document, "Hexdump should have monospace table formatting"

    @given(analysis_result_strategy())
    def test_html_mbr_section_highlighting(self, analysis_result):
        """
        Property 26: HTML MBR section highlighting
        For any HTML report containing hexdump data, the Report_Generator should use 
        background colors to highlight different MBR sections.
        
        Feature: boot-sector-analyzer, Property 26: HTML MBR section highlighting
        Validates: Requirements 10.6
        """
        generator = HTMLGenerator()
        html_document = generator.create_html_document(analysis_result)
        
        # Should have hexdump table
        assert 'class="hexdump-table"' in html_document
        
        # Should have MBR section CSS classes
        css_start = html_document.find("<style>") + 7
        css_end = html_document.find("</style>")
        css_content = html_document[css_start:css_end]
        
        mbr_section_classes = [
            ".mbr-boot-code",
            ".mbr-disk-signature", 
            ".mbr-partition-table",
            ".mbr-boot-signature"
        ]
        
        # Should have all MBR section classes defined
        classes_found = sum(1 for cls in mbr_section_classes if cls in css_content)
        assert classes_found == 4, f"Should have all MBR section classes, found {classes_found}"
        
        # Should have background color definitions for MBR sections
        background_colors = ["background-color:", "#cce5ff", "#fff2cc", "#d4edda", "#f8d7da"]
        colors_found = sum(1 for color in background_colors if color in css_content)
        assert colors_found >= 4, f"Should have MBR section background colors, found {colors_found}"
        
        # Should use MBR section classes in hexdump table
        mbr_class_usage = ['class="mbr-boot-code"', 'class="mbr-disk-signature"', 
                          'class="mbr-partition-table"', 'class="mbr-boot-signature"']
        usage_found = sum(1 for usage in mbr_class_usage if usage in html_document)
        assert usage_found >= 2, f"Should use MBR section classes in hexdump, found {usage_found}"
        
        # Should have MBR legend
        assert "MBR Section Legend" in html_document or "Legend" in html_document
        
        # Legend should explain the color coding
        legend_items = ["Boot Code", "Disk Signature", "Partition Table", "Boot Signature"]
        legend_found = sum(1 for item in legend_items if item in html_document)
        assert legend_found >= 3, f"Should have MBR section legend items, found {legend_found}"

    @given(analysis_result_strategy())
    def test_html_metadata_inclusion(self, analysis_result):
        """
        Property 27: HTML metadata inclusion
        For any HTML report, the Report_Generator should include metadata such as 
        generation timestamp and analyzer version in the HTML header.
        
        Feature: boot-sector-analyzer, Property 27: HTML metadata inclusion
        Validates: Requirements 10.9
        """
        generator = HTMLGenerator()
        html_document = generator.create_html_document(analysis_result)
        
        # Should have proper HTML head section
        assert "<head>" in html_document
        assert "</head>" in html_document
        
        # Should have generator meta tag
        assert '<meta name="generator"' in html_document
        assert "Boot Sector Analyzer" in html_document
        
        # Should have generation timestamp meta tag
        assert '<meta name="generated"' in html_document
        
        # Should include analyzer version in metadata
        version_patterns = [f"v{__version__}", "version"]
        version_found = any(pattern in html_document.lower() for pattern in version_patterns)
        assert version_found, "Should include analyzer version"
        
        # Should have proper character encoding
        assert '<meta charset="UTF-8">' in html_document
        
        # Should have viewport meta tag for responsive design
        assert '<meta name="viewport"' in html_document
        assert "width=device-width" in html_document
        
        # Should include metadata in visible content as well
        assert "Generated:" in html_document
        assert "Analyzer Version:" in html_document
        
        # Should have proper title with source information
        assert "<title>" in html_document
        assert "Boot Sector Analysis Report" in html_document
        
        # Timestamp should be properly formatted
        # Look for timestamp patterns (YYYY-MM-DD HH:MM:SS)
        timestamp_pattern = r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}'
        assert re.search(timestamp_pattern, html_document), "Should have properly formatted timestamps"
        
        # Should be self-contained (no external dependencies)
        assert "http://" not in html_document or "https://" not in html_document or html_document.count("http") <= 2  # Allow for VirusTotal links
        assert '<link rel="stylesheet"' not in html_document
        assert '<script src=' not in html_document