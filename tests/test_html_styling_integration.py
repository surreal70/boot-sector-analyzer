"""Integration tests for HTML styling improvements workflow."""

import tempfile
from pathlib import Path
from boot_sector_analyzer.analyzer import BootSectorAnalyzer


class TestHTMLStylingIntegration:
    """Integration tests for complete HTML styling workflow."""

    def test_end_to_end_html_styling_workflow(self):
        """
        Test end-to-end HTML report generation with enhanced styling.
        Verifies light background assembly code display, fixed-width hexdump table formatting,
        and empty boot code handling in HTML output.
        """
        # Create a comprehensive test boot sector with recognizable assembly instructions
        boot_sector = bytearray(512)
        
        # Add recognizable x86 instructions at the beginning for disassembly testing
        boot_sector[0:15] = [
            0xFA,              # cli
            0x31, 0xC0,        # xor ax, ax
            0x8E, 0xD8,        # mov ds, ax
            0x8E, 0xC0,        # mov es, ax
            0xB8, 0x00, 0x7C,  # mov ax, 0x7C00
            0x8E, 0xD0,        # mov ss, ax
            0xBC, 0x00, 0x7C,  # mov sp, 0x7C00
        ]
        
        # Add some string data for content analysis
        test_string = b"BOOTLDR"
        boot_sector[100:107] = test_string
        
        # Add boot signature
        boot_sector[510:512] = [0x55, 0xAA]
        
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
            assert html_report.strip().startswith("<!DOCTYPE html>")
            
            # Extract CSS content for styling verification
            css_start = html_report.find("<style>") + 7
            css_end = html_report.find("</style>")
            css_content = html_report[css_start:css_end]
            
            # Test 1: Light background assembly code display
            assert ".assembly-code" in css_content, "Should have assembly-code CSS class"
            
            # Should use light background color (#f8f9fa) instead of dark theme
            light_background_color = "#f8f9fa"
            assert light_background_color in css_content, "Should use light background color for assembly code"
            
            # Should NOT use dark background colors
            dark_colors = ["#1e1e1e", "#000000", "#222222", "#333333"]
            for dark_color in dark_colors:
                assert dark_color not in css_content, f"Should not use dark background color {dark_color}"
            
            # Should use dark text color for contrast against light background
            dark_text_color = "#212529"
            assert dark_text_color in css_content, "Should use dark text color for contrast"
            
            # Should have professional appearance with border and padding
            assert ("border:" in css_content or "border-radius:" in css_content), "Should have border for professional appearance"
            assert "padding:" in css_content, "Should have padding for professional appearance"
            
            # Test 2: Professional color scheme for syntax highlighting
            professional_colors = {
                "#0066cc": "Professional blue for instructions",
                "#228b22": "Forest green for registers", 
                "#d2691e": "Chocolate orange for immediate values",
                "#dc143c": "Crimson red for memory addresses",
                "#6a737d": "Muted gray for comments"
            }
            
            for color, description in professional_colors.items():
                assert color in css_content, f"Should have {description} ({color})"
            
            # Instructions should have medium font weight for better readability
            instruction_section = css_content[css_content.find(".asm-instruction"):css_content.find(".asm-register")]
            assert ("font-weight: 500" in instruction_section or "font-weight: medium" in instruction_section), "Instructions should have medium font weight"
            
            # Comments should be muted and italicized
            comment_section = css_content[css_content.find(".asm-comment"):]
            assert "#6a737d" in comment_section, "Comments should use muted gray color"
            assert "font-style: italic" in comment_section, "Comments should be italicized"
            
            # Test 3: Fixed-width hexdump table formatting
            assert 'class="hexdump-table"' in html_report, "Should have hexdump table"
            
            # Should have table-layout: fixed to prevent column width variations
            assert "table-layout: fixed" in css_content, "Should use table-layout: fixed to prevent column variations"
            
            # Should have fixed offset column width (80px)
            assert ".hexdump-table .offset" in css_content
            offset_section = css_content[css_content.find(".hexdump-table .offset"):css_content.find(".hexdump-table .offset") + 200]
            assert "width: 80px" in offset_section, "Offset column should have fixed 80px width for consistency"
            
            # Should have fixed hex byte column widths (30px each)
            hex_byte_width_found = "width: 30px" in css_content
            assert hex_byte_width_found, "Hex byte columns should have fixed 30px width each for uniform spacing"
            
            # Should have fixed ASCII column width (120px)
            assert ".hexdump-table .ascii" in css_content
            ascii_section = css_content[css_content.find(".hexdump-table .ascii"):css_content.find(".hexdump-table .ascii") + 200]
            assert "width: 120px" in ascii_section, "ASCII column should have fixed 120px width for proper alignment"
            
            # Test 4: Assembly code section should have the light background styling
            if analysis_result.disassembly and analysis_result.disassembly.instructions:
                # Should have assembly code section in HTML
                assert 'class="assembly-code"' in html_report, "Should have assembly code section with light background class"
                
                # Should have syntax highlighting classes in the HTML content
                assert 'class="asm-instruction"' in html_report, "Should have instruction syntax highlighting"
                assert 'class="asm-register"' in html_report, "Should have register syntax highlighting"
                
                # Should NOT contain "No boot code present" message since we have actual instructions
                assert "No boot code present" not in html_report, "Should not show empty boot code message when instructions are present"
            
            # Test 5: Hexdump table structure verification
            table_start = html_report.find('<table class="hexdump-table">')
            table_end = html_report.find('</table>', table_start)
            assert table_start > 0 and table_end > 0, "Should have complete hexdump table"
            
            table_content = html_report[table_start:table_end]
            
            # Should have header row with proper structure
            assert "<th" in table_content, "Should have header row with th elements"
            assert 'class="offset"' in table_content, "Should have offset column header"
            assert 'class="ascii"' in table_content, "Should have ASCII column header"
            
            # Should have data rows with td elements
            assert "<td" in table_content, "Should have data rows with td elements"
            
            # Count the number of columns in header row
            header_start = table_content.find("<tr>")
            header_end = table_content.find("</tr>", header_start)
            if header_start > 0 and header_end > 0:
                header_row = table_content[header_start:header_end]
                header_columns = header_row.count("<th")
                # Should have 18 columns: 1 offset + 16 hex bytes + 1 ASCII
                assert header_columns == 18, f"Header should have 18 columns (1 offset + 16 hex + 1 ASCII), found {header_columns}"
            
            # Test 6: MBR section highlighting and partition color coding
            assert "MBR Section Legend" in html_report or "Legend" in html_report, "Should have MBR section legend"
            
            # Should have MBR section CSS classes
            mbr_section_classes = [
                ".mbr-boot-code",
                ".mbr-disk-signature", 
                ".mbr-partition-table",
                ".mbr-boot-signature"
            ]
            
            classes_found = sum(1 for cls in mbr_section_classes if cls in css_content)
            assert classes_found == 4, f"Should have all MBR section classes, found {classes_found}"
            
            # Should have individual partition color classes
            partition_classes = [".mbr-partition-1", ".mbr-partition-2", ".mbr-partition-3", ".mbr-partition-4"]
            partition_classes_found = sum(1 for cls in partition_classes if cls in css_content)
            assert partition_classes_found == 4, f"Should have all partition color classes, found {partition_classes_found}"
            
            # Test 7: Responsive design elements
            assert "@media" in css_content, "Should have responsive media queries"
            
            # Should have mobile-specific breakpoints
            mobile_breakpoints = ["768px", "480px"]
            has_mobile_query = any(breakpoint in css_content for breakpoint in mobile_breakpoints)
            assert has_mobile_query, "Should have mobile responsive breakpoints"
            
            # Test 8: Professional styling elements
            # Should have hover effects for interactive elements
            assert ":hover" in css_content, "Should have hover effects"
            
            # Should have transition effects for smooth interactions
            assert "transition" in css_content, "Should have transition effects"
            
            # Should have proper typography and spacing
            assert "font-family:" in css_content, "Should have font family definitions"
            assert "line-height:" in css_content, "Should have line height definitions"
            
        finally:
            # Clean up temporary file
            Path(temp_file_path).unlink(missing_ok=True)

    def test_empty_boot_code_html_handling(self):
        """
        Test HTML output for boot sectors with empty boot code (all zeros).
        Verifies that empty boot code is properly handled and displays appropriate message.
        """
        # Create boot sector with empty boot code (all zeros in first 446 bytes)
        boot_sector = bytearray(512)
        # Boot code region (first 446 bytes) remains all zeros
        # Add boot signature
        boot_sector[510:512] = [0x55, 0xAA]
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.img') as temp_file:
            temp_file.write(boot_sector)
            temp_file_path = temp_file.name
        
        try:
            analyzer = BootSectorAnalyzer(api_key=None)
            analysis_result = analyzer.analyze(temp_file_path, include_threat_intelligence=False)
            html_report = analyzer.generate_report(analysis_result, "html")
            
            # Should have HTML document structure
            assert isinstance(html_report, str)
            assert len(html_report) > 0
            assert html_report.strip().startswith("<!DOCTYPE html>")
            
            # Should have disassembly section
            assert 'id="disassembly"' in html_report, "Should have disassembly section"
            assert "Boot Code Disassembly" in html_report, "Should have disassembly section title"
            
            # Should display "No boot code present" message for empty boot code
            assert "No boot code present" in html_report, "Should display empty boot code message"
            assert "(all zeros)" in html_report, "Should explain that boot code is all zeros"
            
            # Should have assembly-code div with empty boot code message
            assert 'class="assembly-code"' in html_report, "Should have assembly code section"
            
            # Should NOT have actual assembly instructions
            assert 'class="asm-instruction"' not in html_report, "Should not have instruction syntax highlighting for empty boot code"
            assert 'class="asm-register"' not in html_report, "Should not have register syntax highlighting for empty boot code"
            
            # Should still have proper CSS styling for assembly code section
            css_start = html_report.find("<style>") + 7
            css_end = html_report.find("</style>")
            css_content = html_report[css_start:css_end]
            
            # Should have light background styling even for empty boot code
            assert ".assembly-code" in css_content, "Should have assembly-code CSS class"
            assert "#f8f9fa" in css_content, "Should have light background color"
            assert "#212529" in css_content, "Should have dark text color for contrast"
            
            # Should still have all other HTML styling elements
            assert 'class="hexdump-table"' in html_report, "Should have hexdump table"
            assert "table-layout: fixed" in css_content, "Should have fixed table layout"
            
        finally:
            Path(temp_file_path).unlink(missing_ok=True)

    def test_mixed_boot_code_html_styling(self):
        """
        Test HTML styling with boot sectors containing both valid instructions and invalid bytes.
        Verifies that styling works correctly with mixed content.
        """
        # Create boot sector with mixed content
        boot_sector = bytearray(512)
        
        # Add some valid x86 instructions
        boot_sector[0:6] = [
            0xFA,        # cli
            0x31, 0xC0,  # xor ax, ax
            0x8E, 0xD8,  # mov ds, ax
        ]
        
        # Add some invalid/random bytes that might not disassemble properly
        boot_sector[6:10] = [0xFF, 0xFF, 0xFF, 0xFF]
        
        # Add more valid instructions
        boot_sector[10:15] = [
            0xB8, 0x00, 0x7C,  # mov ax, 0x7C00
            0xCD, 0x13,        # int 0x13
        ]
        
        # Add boot signature
        boot_sector[510:512] = [0x55, 0xAA]
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.img') as temp_file:
            temp_file.write(boot_sector)
            temp_file_path = temp_file.name
        
        try:
            analyzer = BootSectorAnalyzer(api_key=None)
            analysis_result = analyzer.analyze(temp_file_path, include_threat_intelligence=False)
            html_report = analyzer.generate_report(analysis_result, "html")
            
            # Should have HTML document structure
            assert isinstance(html_report, str)
            assert len(html_report) > 0
            
            # Extract CSS content
            css_start = html_report.find("<style>") + 7
            css_end = html_report.find("</style>")
            css_content = html_report[css_start:css_end]
            
            # Should have disassembly section with proper styling
            assert 'id="disassembly"' in html_report, "Should have disassembly section"
            assert 'class="assembly-code"' in html_report, "Should have assembly code section"
            
            # Should NOT show empty boot code message since we have actual instructions
            assert "No boot code present" not in html_report, "Should not show empty boot code message"
            
            # Should have syntax highlighting for valid instructions
            if analysis_result.disassembly and analysis_result.disassembly.instructions:
                # Should have at least some syntax highlighting
                has_instruction_highlighting = 'class="asm-instruction"' in html_report
                has_register_highlighting = 'class="asm-register"' in html_report
                has_address_highlighting = 'class="asm-address"' in html_report
                
                # At least one type of syntax highlighting should be present
                assert (has_instruction_highlighting or has_register_highlighting or has_address_highlighting), \
                    "Should have some form of syntax highlighting for valid instructions"
            
            # Should have professional color scheme in CSS
            professional_colors = ["#0066cc", "#228b22", "#d2691e", "#dc143c", "#6a737d"]
            colors_found = sum(1 for color in professional_colors if color in css_content)
            assert colors_found >= 3, f"Should have professional color scheme, found {colors_found} colors"
            
            # Should have light background styling
            assert "#f8f9fa" in css_content, "Should have light background color"
            assert "#212529" in css_content, "Should have dark text color"
            
            # Should have fixed-width hexdump table
            assert "table-layout: fixed" in css_content, "Should have fixed table layout"
            assert "width: 80px" in css_content, "Should have fixed offset column width"
            assert "width: 30px" in css_content, "Should have fixed hex byte column width"
            assert "width: 120px" in css_content, "Should have fixed ASCII column width"
            
        finally:
            Path(temp_file_path).unlink(missing_ok=True)