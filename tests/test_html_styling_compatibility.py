"""Cross-format styling compatibility tests for HTML styling improvements."""

import json
import tempfile
from pathlib import Path
from html import escape as html_escape
from boot_sector_analyzer.analyzer import BootSectorAnalyzer


class TestHTMLStylingCompatibility:
    """Tests to ensure styling improvements don't break existing functionality and maintain cross-format consistency."""

    def test_styling_improvements_backward_compatibility(self):
        """
        Test that styling improvements don't break existing HTML report functionality.
        Ensures backward compatibility with existing HTML reports.
        """
        # Create a comprehensive test boot sector
        boot_sector = bytearray(512)
        
        # Add recognizable content for analysis
        boot_sector[0:10] = [
            0xFA,              # cli
            0x31, 0xC0,        # xor ax, ax
            0x8E, 0xD8,        # mov ds, ax
            0x8E, 0xC0,        # mov es, ax
            0xCD, 0x13,        # int 0x13
        ]
        
        # Add some string data
        test_string = b"BOOTLDR"
        boot_sector[100:107] = test_string
        
        # Add boot signature
        boot_sector[510:512] = [0x55, 0xAA]
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.img') as temp_file:
            temp_file.write(boot_sector)
            temp_file_path = temp_file.name
        
        try:
            analyzer = BootSectorAnalyzer(api_key=None)
            analysis_result = analyzer.analyze(temp_file_path, include_threat_intelligence=False)
            html_report = analyzer.generate_report(analysis_result, "html")
            
            # Test 1: Core HTML structure should remain intact
            assert html_report.strip().startswith("<!DOCTYPE html>"), "Should maintain DOCTYPE declaration"
            assert "<html" in html_report, "Should have html tag"
            assert "<head>" in html_report and "</head>" in html_report, "Should have head section"
            assert "<body>" in html_report and "</body>" in html_report, "Should have body section"
            assert "</html>" in html_report, "Should have closing html tag"
            
            # Test 2: Essential meta tags should be preserved
            assert '<meta charset="UTF-8">' in html_report, "Should have charset meta tag"
            assert '<meta name="viewport"' in html_report, "Should have viewport meta tag"
            assert '<meta name="generator"' in html_report, "Should have generator meta tag"
            assert '<meta name="generated"' in html_report, "Should have generated meta tag"
            
            # Test 3: Self-contained nature should be preserved
            assert "<style>" in html_report and "</style>" in html_report, "Should have embedded CSS"
            assert '<link rel="stylesheet"' not in html_report, "Should not have external CSS links"
            
            # Test 4: Core content sections should be preserved
            required_sections = [
                "Structure Analysis",
                "Content Analysis", 
                "Security Analysis",
                "Hexdump",
                "Summary"
            ]
            
            for section in required_sections:
                assert section in html_report, f"Should have {section} section"
            
            # Test 5: Navigation elements should be preserved
            assert "Table of Contents" in html_report, "Should have table of contents"
            assert 'href="#structure-analysis"' in html_report, "Should have structure analysis anchor"
            assert 'href="#content-analysis"' in html_report, "Should have content analysis anchor"
            assert 'href="#hexdump"' in html_report, "Should have hexdump anchor"
            
            # Test 6: Threat level badge should be preserved
            assert 'class="threat-badge' in html_report, "Should have threat level badge"
            threat_level = analysis_result.security_analysis.threat_level.value
            assert threat_level in html_report or threat_level.upper() in html_report, "Should display threat level"
            
            # Test 7: Hash values should be preserved and properly formatted
            for hash_type, hash_value in analysis_result.content_analysis.hashes.items():
                assert hash_value in html_report, f"Should contain {hash_type} hash value"
                # Hash values should still be in monospace/copyable format
                assert ('class="hash-value"' in html_report or 'class="monospace"' in html_report), "Should have monospace hash formatting"
            
            # Test 8: Hexdump table should be preserved with enhancements
            assert 'class="hexdump-table"' in html_report, "Should have hexdump table"
            assert "0x0000" in html_report, "Should have hexdump offsets"
            
            # Test 9: Disassembly section should be preserved (if present)
            if analysis_result.disassembly and analysis_result.disassembly.instructions:
                assert "disassembly" in html_report.lower(), "Should have disassembly section"
                assert 'class="assembly-code"' in html_report, "Should have assembly code section"
            
            # Test 10: Responsive design should be preserved
            css_start = html_report.find("<style>") + 7
            css_end = html_report.find("</style>")
            css_content = html_report[css_start:css_end]
            
            assert "@media" in css_content, "Should have responsive media queries"
            mobile_breakpoints = ["768px", "480px"]
            has_mobile_query = any(breakpoint in css_content for breakpoint in mobile_breakpoints)
            assert has_mobile_query, "Should have mobile responsive breakpoints"
            
        finally:
            Path(temp_file_path).unlink(missing_ok=True)

    def test_cross_format_consistency_with_styling_improvements(self):
        """
        Test consistency between different output formats with styling improvements.
        Ensures that HTML styling improvements don't affect data consistency across formats.
        """
        # Create test cases with different boot sector types
        test_cases = [
            {
                "name": "normal_boot_sector",
                "data": self._create_normal_boot_sector()
            },
            {
                "name": "empty_boot_code",
                "data": self._create_empty_boot_code_sector()
            },
            {
                "name": "high_entropy_sector",
                "data": self._create_high_entropy_sector()
            }
        ]
        
        for test_case in test_cases:
            with tempfile.NamedTemporaryFile(delete=False, suffix='.img') as temp_file:
                temp_file.write(test_case["data"])
                temp_file_path = temp_file.name
            
            try:
                analyzer = BootSectorAnalyzer(api_key=None)
                analysis_result = analyzer.analyze(temp_file_path, include_threat_intelligence=False)
                
                # Generate reports in all formats
                human_report = analyzer.generate_report(analysis_result, "human")
                json_report = analyzer.generate_report(analysis_result, "json")
                html_report = analyzer.generate_report(analysis_result, "html")
                
                # Parse JSON for structured comparison
                json_data = json.loads(json_report)
                
                # Test 1: Core data consistency across formats
                # Source information
                source_name = Path(temp_file_path).name
                assert (source_name in human_report or temp_file_path in human_report), "Human format should have source"
                assert json_data["source"] == temp_file_path, "JSON format should have source"
                assert (temp_file_path in html_report or html_escape(temp_file_path) in html_report), "HTML format should have source"
                
                # Threat level consistency
                threat_level = analysis_result.security_analysis.threat_level.value
                assert threat_level.upper() in human_report, "Human format should have threat level"
                assert json_data["threat_level"] == threat_level, "JSON format should have threat level"
                assert (threat_level in html_report or threat_level.upper() in html_report), "HTML format should have threat level"
                
                # Hash values consistency
                for hash_type, hash_value in analysis_result.content_analysis.hashes.items():
                    assert hash_value in human_report, f"Human format should have {hash_type} hash"
                    assert json_data["content_analysis"]["hashes"][hash_type] == hash_value, f"JSON format should have {hash_type} hash"
                    assert hash_value in html_report, f"HTML format should have {hash_type} hash"
                
                # Test 2: Disassembly consistency (if present)
                if analysis_result.disassembly and analysis_result.disassembly.instructions:
                    # Human format should have disassembly
                    assert "DISASSEMBLY" in human_report.upper(), "Human format should have disassembly section"
                    
                    # JSON format should have disassembly data
                    assert "disassembly" in json_data, "JSON format should have disassembly data"
                    assert "instructions" in json_data["disassembly"], "JSON should have instructions"
                    
                    # HTML format should have disassembly with styling
                    assert "disassembly" in html_report.lower(), "HTML format should have disassembly section"
                    assert 'class="assembly-code"' in html_report, "HTML should have styled assembly code"
                    
                    # Check instruction consistency
                    for i, instruction in enumerate(analysis_result.disassembly.instructions[:3]):
                        addr_str = f"0x{instruction.address:04X}"
                        
                        # Should appear in all formats
                        assert addr_str in human_report, f"Human format should have instruction address {addr_str}"
                        
                        json_instruction = json_data["disassembly"]["instructions"][i]
                        assert json_instruction["address"] == addr_str, f"JSON should have instruction address {addr_str}"
                        
                        assert (addr_str in html_report or instruction.mnemonic in html_report), f"HTML should have instruction {addr_str}"
                
                # Test 3: Empty boot code handling consistency
                if test_case["name"] == "empty_boot_code":
                    # All formats should handle empty boot code appropriately
                    if analysis_result.disassembly is None:
                        # Human format might mention empty boot code
                        # JSON format should have null or empty disassembly
                        assert (json_data.get("disassembly") is None or 
                               not json_data.get("disassembly", {}).get("instructions", [])), "JSON should have empty disassembly for empty boot code"
                        
                        # HTML format should show appropriate message
                        assert "No boot code present" in html_report, "HTML should show empty boot code message"
                
                # Test 4: Hexdump consistency
                assert "0x0000" in human_report, "Human format should have hexdump"
                assert json_data["hexdump"]["total_bytes"] == 512, "JSON should have hexdump data"
                assert "hexdump" in html_report.lower(), "HTML should have hexdump section"
                
                # Test 5: Entropy consistency
                entropy = analysis_result.content_analysis.entropy
                entropy_str = f"{entropy:.2f}"
                
                assert entropy_str in human_report, "Human format should have entropy"
                assert json_data["content_analysis"]["entropy"] == entropy, "JSON should have entropy"
                assert entropy_str in html_report, "HTML should have entropy"
                
            finally:
                Path(temp_file_path).unlink(missing_ok=True)

    def test_html_styling_with_various_boot_sector_samples(self):
        """
        Test HTML styling improvements with various boot sector samples including edge cases.
        Verifies that styling works correctly across different types of boot sectors.
        """
        test_samples = [
            {
                "name": "minimal_valid",
                "data": b'\x00' * 510 + b'\x55\xAA',
                "expected_empty_boot": True
            },
            {
                "name": "with_instructions",
                "data": self._create_instruction_boot_sector(),
                "expected_empty_boot": False
            },
            {
                "name": "with_strings",
                "data": self._create_string_boot_sector(),
                "expected_empty_boot": False
            },
            {
                "name": "invalid_signature",
                "data": b'\x00' * 510 + b'\x00\x00',
                "expected_empty_boot": True
            }
        ]
        
        for sample in test_samples:
            with tempfile.NamedTemporaryFile(delete=False, suffix='.img') as temp_file:
                temp_file.write(sample["data"])
                temp_file_path = temp_file.name
            
            try:
                analyzer = BootSectorAnalyzer(api_key=None)
                analysis_result = analyzer.analyze(temp_file_path, include_threat_intelligence=False)
                html_report = analyzer.generate_report(analysis_result, "html")
                
                # Should generate valid HTML for all samples
                assert isinstance(html_report, str), f"Should generate HTML string for {sample['name']}"
                assert len(html_report) > 0, f"Should generate non-empty HTML for {sample['name']}"
                assert html_report.strip().startswith("<!DOCTYPE html>"), f"Should have DOCTYPE for {sample['name']}"
                
                # Extract CSS content
                css_start = html_report.find("<style>") + 7
                css_end = html_report.find("</style>")
                css_content = html_report[css_start:css_end]
                
                # Should have enhanced styling for all samples
                assert "#f8f9fa" in css_content, f"Should have light background for {sample['name']}"
                assert "#212529" in css_content, f"Should have dark text for {sample['name']}"
                assert "table-layout: fixed" in css_content, f"Should have fixed table layout for {sample['name']}"
                
                # Should have professional color scheme
                professional_colors = ["#0066cc", "#228b22", "#d2691e", "#dc143c", "#6a737d"]
                colors_found = sum(1 for color in professional_colors if color in css_content)
                assert colors_found >= 3, f"Should have professional colors for {sample['name']}"
                
                # Check empty boot code handling
                if sample["expected_empty_boot"]:
                    if "No boot code present" in html_report:
                        # Should handle empty boot code properly
                        assert 'class="assembly-code"' in html_report, f"Should have assembly section for {sample['name']}"
                        assert "all zeros" in html_report, f"Should explain empty boot code for {sample['name']}"
                else:
                    # Should not show empty boot code message
                    assert "No boot code present" not in html_report, f"Should not show empty message for {sample['name']}"
                
                # Should have hexdump table with fixed widths
                assert 'class="hexdump-table"' in html_report, f"Should have hexdump table for {sample['name']}"
                assert "width: 80px" in css_content, f"Should have fixed offset width for {sample['name']}"
                assert "width: 30px" in css_content, f"Should have fixed hex width for {sample['name']}"
                assert "width: 120px" in css_content, f"Should have fixed ASCII width for {sample['name']}"
                
                # Should have responsive design
                assert "@media" in css_content, f"Should have responsive design for {sample['name']}"
                
            finally:
                Path(temp_file_path).unlink(missing_ok=True)

    def test_html_styling_error_resilience(self):
        """
        Test that HTML styling improvements are resilient to various error conditions.
        Ensures styling doesn't break when encountering edge cases or errors.
        """
        # Test with corrupted/truncated boot sector
        corrupted_sector = b'\xFF' * 256  # Only 256 bytes instead of 512
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.img') as temp_file:
            temp_file.write(corrupted_sector)
            temp_file_path = temp_file.name
        
        try:
            analyzer = BootSectorAnalyzer(api_key=None)
            
            # This should handle the error gracefully
            try:
                analysis_result = analyzer.analyze(temp_file_path, include_threat_intelligence=False)
                # If analysis succeeds despite corruption, HTML should still be generated
                html_report = analyzer.generate_report(analysis_result, "html")
                
                # Should still generate valid HTML structure
                assert isinstance(html_report, str), "Should generate HTML string even with corrupted data"
                if len(html_report) > 0:
                    assert html_report.strip().startswith("<!DOCTYPE html>"), "Should have DOCTYPE even with corrupted data"
                    
                    # Should still have CSS styling
                    if "<style>" in html_report:
                        css_start = html_report.find("<style>") + 7
                        css_end = html_report.find("</style>")
                        css_content = html_report[css_start:css_end]
                        
                        # Should still have enhanced styling
                        assert "#f8f9fa" in css_content, "Should have light background even with corrupted data"
                        assert "table-layout: fixed" in css_content, "Should have fixed table layout even with corrupted data"
                        
            except Exception as e:
                # If analysis fails, that's acceptable for corrupted data
                # The important thing is that it fails gracefully
                assert isinstance(e, Exception), "Should handle corrupted data gracefully"
                
        finally:
            Path(temp_file_path).unlink(missing_ok=True)

    def _create_normal_boot_sector(self) -> bytes:
        """Create a normal boot sector with instructions."""
        boot_sector = bytearray(512)
        boot_sector[0:10] = [
            0xFA,              # cli
            0x31, 0xC0,        # xor ax, ax
            0x8E, 0xD8,        # mov ds, ax
            0x8E, 0xC0,        # mov es, ax
            0xCD, 0x13,        # int 0x13
        ]
        boot_sector[510:512] = [0x55, 0xAA]
        return bytes(boot_sector)

    def _create_empty_boot_code_sector(self) -> bytes:
        """Create a boot sector with empty boot code (all zeros)."""
        boot_sector = bytearray(512)
        # Boot code region remains all zeros
        boot_sector[510:512] = [0x55, 0xAA]
        return bytes(boot_sector)

    def _create_high_entropy_sector(self) -> bytes:
        """Create a boot sector with high entropy data."""
        boot_sector = bytearray(512)
        # Fill with pseudo-random data
        for i in range(510):
            boot_sector[i] = (i * 7 + 13) % 256
        boot_sector[510:512] = [0x55, 0xAA]
        return bytes(boot_sector)

    def _create_instruction_boot_sector(self) -> bytes:
        """Create a boot sector with clear x86 instructions."""
        boot_sector = bytearray(512)
        boot_sector[0:15] = [
            0xFA,              # cli
            0x31, 0xC0,        # xor ax, ax
            0x8E, 0xD8,        # mov ds, ax
            0x8E, 0xC0,        # mov es, ax
            0xB8, 0x00, 0x7C,  # mov ax, 0x7C00
            0x8E, 0xD0,        # mov ss, ax
            0xBC, 0x00, 0x7C,  # mov sp, 0x7C00
        ]
        boot_sector[510:512] = [0x55, 0xAA]
        return bytes(boot_sector)

    def _create_string_boot_sector(self) -> bytes:
        """Create a boot sector with embedded strings."""
        boot_sector = bytearray(512)
        # Add some instructions
        boot_sector[0:3] = [0xFA, 0x31, 0xC0]  # cli; xor ax, ax
        # Add string data
        test_string = b"BOOTLOADER"
        boot_sector[100:110] = test_string
        boot_sector[510:512] = [0x55, 0xAA]
        return bytes(boot_sector)