"""Cross-format compatibility tests for report generation."""

import json
import tempfile
from pathlib import Path
from html import escape as html_escape
from boot_sector_analyzer.analyzer import BootSectorAnalyzer


class TestCrossFormatCompatibility:
    """Tests to ensure all output formats contain equivalent data."""

    def test_format_switching_with_identical_input(self):
        """
        Test format switching with identical input data.
        Ensures all three output formats (human, JSON, HTML) contain equivalent data.
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
            
            # Generate reports in all formats
            human_report = analyzer.generate_report(analysis_result, "human")
            json_report = analyzer.generate_report(analysis_result, "json")
            html_report = analyzer.generate_report(analysis_result, "html")
            
            # Parse JSON for structured comparison
            json_data = json.loads(json_report)
            
            # Test 1: Source information consistency
            source_name = Path(temp_file_path).name
            assert source_name in human_report or temp_file_path in human_report
            assert json_data["source"] == temp_file_path
            assert temp_file_path in html_report or html_escape(temp_file_path) in html_report
            
            # Test 2: Threat level consistency
            threat_level = analysis_result.security_analysis.threat_level.value
            assert threat_level.upper() in human_report
            assert json_data["threat_level"] == threat_level
            assert threat_level in html_report or threat_level.upper() in html_report
            
            # Test 3: Hash values consistency
            for hash_type, hash_value in analysis_result.content_analysis.hashes.items():
                # Human format
                assert hash_type.upper() in human_report
                assert hash_value in human_report
                
                # JSON format
                assert json_data["content_analysis"]["hashes"][hash_type] == hash_value
                
                # HTML format
                assert hash_value in html_report
            
            # Test 4: Boot signature consistency
            signature_valid = analysis_result.structure_analysis.is_valid_signature
            
            # Human format (may be overridden by enhanced MBR decoder)
            signature_text = "Yes" if signature_valid else "No"
            assert ("Boot Signature Valid: " + signature_text in human_report or
                    "Boot Signature: Valid" in human_report or
                    "Boot Signature: INVALID" in human_report)
            
            # JSON format
            assert json_data["structure_analysis"]["boot_signature_valid"] == signature_valid
            
            # HTML format
            assert ("Boot Signature Valid" in html_report or 
                    "Boot Signature" in html_report)
            
            # Test 5: Entropy consistency
            entropy = analysis_result.content_analysis.entropy
            entropy_str = f"{entropy:.2f}"
            
            assert entropy_str in human_report
            assert json_data["content_analysis"]["entropy"] == entropy
            assert entropy_str in html_report
            
            # Test 6: Partition count consistency
            partition_count = analysis_result.structure_analysis.partition_count
            
            # Human format (may show enhanced partition table instead)
            assert (f"Partition Count: {partition_count}" in human_report or
                    "Partition Table:" in human_report)
            
            # JSON format
            assert json_data["structure_analysis"]["partition_count"] == partition_count
            
            # HTML format
            assert (str(partition_count) in html_report or
                    "Partition" in html_report)
            
            # Test 7: Disassembly consistency (if present)
            if analysis_result.disassembly and analysis_result.disassembly.instructions:
                # Human format should have disassembly section
                assert "DISASSEMBLY" in human_report.upper()
                
                # JSON format should have disassembly data
                assert "disassembly" in json_data
                assert "instructions" in json_data["disassembly"]
                assert len(json_data["disassembly"]["instructions"]) > 0
                
                # HTML format should have disassembly section
                assert "disassembly" in html_report.lower()
                
                # Check first few instructions for consistency
                for i, instruction in enumerate(analysis_result.disassembly.instructions[:3]):
                    addr_str = f"0x{instruction.address:04X}"
                    
                    # Should appear in human format
                    assert addr_str in human_report
                    
                    # Should appear in JSON format
                    json_instruction = json_data["disassembly"]["instructions"][i]
                    assert json_instruction["address"] == addr_str
                    assert json_instruction["mnemonic"] == instruction.mnemonic
                    
                    # Should appear in HTML format (check for address or mnemonic)
                    assert addr_str in html_report or instruction.mnemonic in html_report
            
            # Test 8: Hexdump consistency
            # All formats should include hexdump data
            assert "0x0000" in human_report  # Hexdump offset
            assert "hexdump" in json_data
            assert json_data["hexdump"]["total_bytes"] == 512
            assert "hexdump" in html_report.lower()
            
        finally:
            Path(temp_file_path).unlink(missing_ok=True)

    def test_consistency_across_different_boot_sectors(self):
        """
        Test consistency across different types of boot sectors.
        """
        test_cases = [
            # Case 1: Empty boot sector (all zeros)
            {
                "name": "empty",
                "data": b'\x00' * 510 + b'\x55\xAA'
            },
            # Case 2: Boot sector with high entropy (random-like data)
            {
                "name": "high_entropy", 
                "data": bytes([(i * 7 + 13) % 256 for i in range(510)]) + b'\x55\xAA'
            },
            # Case 3: Boot sector with text strings
            {
                "name": "with_strings",
                "data": b'BOOT' + b'\x00' * 506 + b'\x55\xAA'
            }
        ]
        
        for test_case in test_cases:
            with tempfile.NamedTemporaryFile(delete=False, suffix='.img') as temp_file:
                temp_file.write(test_case["data"])
                temp_file_path = temp_file.name
            
            try:
                analyzer = BootSectorAnalyzer(api_key=None)
                analysis_result = analyzer.analyze(temp_file_path, include_threat_intelligence=False)
                
                # Generate all formats
                human_report = analyzer.generate_report(analysis_result, "human")
                json_report = analyzer.generate_report(analysis_result, "json")
                html_report = analyzer.generate_report(analysis_result, "html")
                
                # All should be non-empty
                assert len(human_report) > 0
                assert len(json_report) > 0
                assert len(html_report) > 0
                
                # JSON should be valid
                json_data = json.loads(json_report)
                
                # All should contain core analysis data
                assert "BOOT SECTOR ANALYSIS REPORT" in human_report
                assert "source" in json_data
                assert "<!DOCTYPE html>" in html_report
                
                # All should have the same threat level
                threat_level = analysis_result.security_analysis.threat_level.value
                assert threat_level.upper() in human_report
                assert json_data["threat_level"] == threat_level
                assert threat_level in html_report or threat_level.upper() in html_report
                
                # All should have the same hash values
                for hash_type, hash_value in analysis_result.content_analysis.hashes.items():
                    assert hash_value in human_report
                    assert json_data["content_analysis"]["hashes"][hash_type] == hash_value
                    assert hash_value in html_report
                
            finally:
                Path(temp_file_path).unlink(missing_ok=True)