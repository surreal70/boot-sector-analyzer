"""Integration tests for HTML report generation workflow."""

import tempfile
from pathlib import Path
from boot_sector_analyzer.analyzer import BootSectorAnalyzer


class TestHTMLIntegration:
    """Integration tests for complete HTML workflow."""

    def test_end_to_end_html_report_generation(self):
        """
        Test complete HTML report generation workflow with sample boot sector.
        Verifies HTML structure, CSS embedding, and syntax highlighting.
        """
        # Create a sample boot sector with valid signature
        boot_sector = bytearray(512)
        # Add some recognizable x86 instructions at the beginning
        boot_sector[0:6] = [0xFA, 0x31, 0xC0, 0x8E, 0xD8, 0x8E]  # cli; xor ax,ax; mov ds,ax; mov es,ax
        # Add boot signature
        boot_sector[510:512] = [0x55, 0xAA]
        
        # Write to temporary file
        with tempfile.NamedTemporaryFile(delete=False, suffix='.img') as temp_file:
            temp_file.write(boot_sector)
            temp_file_path = temp_file.name
        
        try:
            # Initialize analyzer without internet connectivity
            analyzer = BootSectorAnalyzer(api_key=None)
            
            # Perform complete analysis
            analysis_result = analyzer.analyze(
                source=temp_file_path,
                include_threat_intelligence=False
            )
            
            # Generate HTML report
            html_report = analyzer.generate_report(analysis_result, "html")
            
            # Verify HTML document structure
            assert isinstance(html_report, str)
            assert len(html_report) > 0
            
            # Should have proper DOCTYPE declaration
            assert html_report.strip().startswith("<!DOCTYPE html>")
            
            # Should have complete HTML structure
            assert "<html" in html_report
            assert "<head>" in html_report
            assert "</head>" in html_report
            assert "<body>" in html_report
            assert "</body>" in html_report
            assert "</html>" in html_report
            
            # Should have proper meta tags
            assert '<meta charset="UTF-8">' in html_report
            assert '<meta name="viewport"' in html_report
            assert '<meta name="generator"' in html_report
            assert '<meta name="generated"' in html_report
            
            # Should have embedded CSS (self-contained)
            assert "<style>" in html_report
            assert "</style>" in html_report
            
            # Should not have external CSS links (self-contained requirement)
            assert '<link rel="stylesheet"' not in html_report
            
            # Should have proper title
            assert "<title>" in html_report
            assert "Boot Sector Analysis Report" in html_report
            
            # Should include source information
            assert temp_file_path in html_report or Path(temp_file_path).name in html_report
            
            # Should have main content sections
            assert "Structure Analysis" in html_report
            assert "Content Analysis" in html_report
            assert "Security Analysis" in html_report
            assert "Hexdump" in html_report
            assert "Summary" in html_report
            
            # Should have threat level badge
            assert 'class="threat-badge' in html_report
            assert 'threat-low' in html_report  # Should be low threat for clean boot sector
            
            # Should have table of contents with anchor links
            assert "Table of Contents" in html_report
            assert 'href="#structure-analysis"' in html_report
            assert 'href="#content-analysis"' in html_report
            assert 'href="#security-analysis"' in html_report
            assert 'href="#hexdump"' in html_report
            assert 'href="#summary"' in html_report
            
            # Should have corresponding section IDs
            assert 'id="structure-analysis"' in html_report
            assert 'id="content-analysis"' in html_report
            assert 'id="security-analysis"' in html_report
            assert 'id="hexdump"' in html_report
            assert 'id="summary"' in html_report
            
            # Should have hexdump table with MBR section highlighting
            assert 'class="hexdump-table"' in html_report
            assert "MBR Section Legend" in html_report or "Legend" in html_report
            
            # Should have disassembly section if disassembly was performed
            if analysis_result.disassembly and analysis_result.disassembly.instructions:
                assert "Boot Code Disassembly" in html_report or "Disassembly" in html_report
                assert 'class="assembly-code"' in html_report
                
                # Should have syntax highlighting for assembly
                assert 'class="asm-instruction"' in html_report
                
            # Should have hash values displayed
            for hash_type, hash_value in analysis_result.content_analysis.hashes.items():
                assert hash_value in html_report
                
            # Should have responsive design CSS
            assert "@media" in html_report
            assert "max-width" in html_report
            
        finally:
            # Clean up temporary file
            Path(temp_file_path).unlink(missing_ok=True)

    def test_html_responsive_design_elements(self):
        """
        Test HTML responsive design and interactive elements.
        """
        # Create a minimal boot sector
        boot_sector = b'\x00' * 510 + b'\x55\xAA'
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.img') as temp_file:
            temp_file.write(boot_sector)
            temp_file_path = temp_file.name
        
        try:
            analyzer = BootSectorAnalyzer(api_key=None)
            analysis_result = analyzer.analyze(temp_file_path, include_threat_intelligence=False)
            html_report = analyzer.generate_report(analysis_result, "html")
            
            # Extract CSS content
            css_start = html_report.find("<style>") + 7
            css_end = html_report.find("</style>")
            css_content = html_report[css_start:css_end]
            
            # Should have responsive media queries
            assert "@media" in css_content
            
            # Should have mobile-specific breakpoints
            mobile_breakpoints = ["768px", "480px"]
            has_mobile_query = any(breakpoint in css_content for breakpoint in mobile_breakpoints)
            assert has_mobile_query, "Should have mobile responsive breakpoints"
            
            # Should have hover effects for interactive elements
            assert ":hover" in css_content
            
            # Should have transition effects
            assert "transition" in css_content
            
            # Should have copyable hash values
            assert 'class="hash-value"' in html_report
            
        finally:
            Path(temp_file_path).unlink(missing_ok=True)

    def test_html_syntax_highlighting(self):
        """
        Test HTML assembly syntax highlighting functionality.
        """
        # Create boot sector with recognizable x86 instructions
        boot_sector = bytearray(512)
        # Add common boot sector instructions
        boot_sector[0:10] = [
            0xFA,        # cli
            0x31, 0xC0,  # xor ax, ax
            0x8E, 0xD8,  # mov ds, ax
            0x8E, 0xC0,  # mov es, ax
            0xB8, 0x00, 0x7C  # mov ax, 0x7C00
        ]
        boot_sector[510:512] = [0x55, 0xAA]
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.img') as temp_file:
            temp_file.write(boot_sector)
            temp_file_path = temp_file.name
        
        try:
            analyzer = BootSectorAnalyzer(api_key=None)
            analysis_result = analyzer.analyze(temp_file_path, include_threat_intelligence=False)
            html_report = analyzer.generate_report(analysis_result, "html")
            
            # Should have disassembly section
            if analysis_result.disassembly and analysis_result.disassembly.instructions:
                # Should have assembly syntax highlighting classes
                assert 'class="asm-instruction"' in html_report  # Blue for instructions
                assert 'class="asm-register"' in html_report     # Green for registers
                
                # Should have appropriate colors in CSS
                css_start = html_report.find("<style>") + 7
                css_end = html_report.find("</style>")
                css_content = html_report[css_start:css_end]
                
                # Check for assembly syntax highlighting colors (professional scheme)
                assembly_colors = ["#0066cc", "#228b22", "#d2691e", "#dc143c", "#6a737d"]
                colors_found = sum(1 for color in assembly_colors if color in css_content)
                assert colors_found >= 2, "Should have assembly syntax highlighting colors"
                
        finally:
            Path(temp_file_path).unlink(missing_ok=True)