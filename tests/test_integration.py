"""Integration tests for complete analysis workflow."""

import pytest
import tempfile
import os
from pathlib import Path
from unittest.mock import patch, MagicMock

from boot_sector_analyzer import BootSectorAnalyzer, AnalysisResult, ThreatLevel
from boot_sector_analyzer.exceptions import (
    BootSectorAnalyzerError, 
    InputError, 
    FileAccessError, 
    InvalidBootSectorError
)


class TestBootSectorAnalyzerIntegration:
    """Integration tests for the complete Boot Sector Analyzer workflow."""

    def create_sample_boot_sector(self) -> bytes:
        """Create a sample boot sector for testing."""
        # Create a minimal valid MBR structure
        boot_sector = bytearray(512)
        
        # Add some simple bootstrap code (first 446 bytes) - avoid suspicious patterns
        boot_sector[0:10] = b'\x33\xc0\x8e\xd0\x8e\xc0\x8e\xd8\xbc\x00'  # Simple boot code without suspicious patterns
        
        # Add partition table (4 entries at offset 446)
        # Entry 1: Active FAT32 partition
        boot_sector[446] = 0x80  # Active
        boot_sector[450] = 0x0C  # FAT32 LBA
        boot_sector[454:458] = (2048).to_bytes(4, 'little')  # Start LBA
        boot_sector[458:462] = (1024000).to_bytes(4, 'little')  # Size in sectors
        
        # Add boot signature (0x55AA in little-endian format)
        boot_sector[510] = 0xAA  # Low byte
        boot_sector[511] = 0x55  # High byte
        
        return bytes(boot_sector)

    def create_malicious_boot_sector(self) -> bytes:
        """Create a boot sector with suspicious patterns for testing."""
        boot_sector = bytearray(512)
        
        # Add suspicious shellcode patterns
        boot_sector[0:4] = b'\x31\xc0\x8e\xd8'  # XOR EAX, EAX; MOV DS, EAX
        boot_sector[10:14] = b'\xeb\xfe\x90\x90'  # JMP $; NOP; NOP
        boot_sector[20:24] = b'\x0f\x01\x16\x00'  # LGDT instruction
        
        # Add multiple active partitions (suspicious)
        boot_sector[446] = 0x80  # Active partition 1
        boot_sector[462] = 0x80  # Active partition 2 (suspicious)
        
        # Add boot signature (0x55AA in little-endian format)
        boot_sector[510] = 0xAA  # Low byte
        boot_sector[511] = 0x55  # High byte
        
        return bytes(boot_sector)

    def test_complete_analysis_workflow_clean_boot_sector(self):
        """Test complete analysis workflow with a clean boot sector."""
        # Create analyzer
        analyzer = BootSectorAnalyzer()
        
        # Create temporary boot sector file
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            boot_sector_data = self.create_sample_boot_sector()
            temp_file.write(boot_sector_data)
            temp_file_path = temp_file.name
        
        try:
            # Perform analysis
            result = analyzer.analyze(temp_file_path, include_threat_intelligence=False)
            
            # Verify result structure
            assert isinstance(result, AnalysisResult)
            assert result.source == temp_file_path
            assert result.timestamp is not None
            
            # Verify structure analysis
            assert result.structure_analysis is not None
            assert result.structure_analysis.is_valid_signature is True
            assert result.structure_analysis.partition_count >= 0
            
            # Verify content analysis
            assert result.content_analysis is not None
            assert 'md5' in result.content_analysis.hashes
            assert 'sha256' in result.content_analysis.hashes
            assert result.content_analysis.entropy >= 0.0
            
            # Verify security analysis
            assert result.security_analysis is not None
            assert isinstance(result.security_analysis.threat_level, ThreatLevel)
            
            # For a clean boot sector, threat level should be low
            assert result.security_analysis.threat_level in [ThreatLevel.LOW, ThreatLevel.MEDIUM]
            
        finally:
            # Clean up
            os.unlink(temp_file_path)

    def test_complete_analysis_workflow_suspicious_boot_sector(self):
        """Test complete analysis workflow with a suspicious boot sector."""
        # Create analyzer
        analyzer = BootSectorAnalyzer()
        
        # Create temporary boot sector file with suspicious content
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            boot_sector_data = self.create_malicious_boot_sector()
            temp_file.write(boot_sector_data)
            temp_file_path = temp_file.name
        
        try:
            # Perform analysis
            result = analyzer.analyze(temp_file_path, include_threat_intelligence=False)
            
            # Verify result structure
            assert isinstance(result, AnalysisResult)
            
            # Verify security analysis detected threats
            assert result.security_analysis is not None
            
            # Should detect suspicious patterns or anomalies
            has_threats = (
                len(result.security_analysis.detected_threats) > 0 or
                len(result.security_analysis.bootkit_indicators) > 0 or
                len(result.security_analysis.suspicious_patterns) > 0 or
                len(result.security_analysis.anomalies) > 0
            )
            assert has_threats, "Should detect suspicious patterns in malicious boot sector"
            
            # Threat level should be elevated
            assert result.security_analysis.threat_level in [ThreatLevel.MEDIUM, ThreatLevel.HIGH, ThreatLevel.CRITICAL]
            
        finally:
            # Clean up
            os.unlink(temp_file_path)

    @patch('boot_sector_analyzer.internet_checker.InternetChecker.query_virustotal')
    def test_complete_analysis_workflow_with_threat_intelligence(self, mock_virustotal):
        """Test complete analysis workflow with threat intelligence."""
        # Mock VirusTotal response
        from boot_sector_analyzer.models import VirusTotalResult
        from datetime import datetime
        
        mock_vt_result = VirusTotalResult(
            hash_value="test_hash",
            detection_count=2,
            total_engines=50,
            scan_date=datetime.now(),
            permalink="https://virustotal.com/test",
            detections={"Engine1": {"detected": True, "result": "Trojan.Test"}}
        )
        mock_virustotal.return_value = mock_vt_result
        
        # Create analyzer with API key
        analyzer = BootSectorAnalyzer(api_key="test_api_key")
        
        # Create temporary boot sector file
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            boot_sector_data = self.create_sample_boot_sector()
            temp_file.write(boot_sector_data)
            temp_file_path = temp_file.name
        
        try:
            # Perform analysis with threat intelligence
            result = analyzer.analyze(temp_file_path, include_threat_intelligence=True)
            
            # Verify threat intelligence was included
            assert result.threat_intelligence is not None
            assert result.threat_intelligence.virustotal_result is not None
            assert result.threat_intelligence.virustotal_result.detection_count == 2
            
            # Verify VirusTotal was called
            mock_virustotal.assert_called_once()
            
        finally:
            # Clean up
            os.unlink(temp_file_path)

    def test_report_generation_human_format(self):
        """Test report generation in human-readable format."""
        # Create analyzer
        analyzer = BootSectorAnalyzer()
        
        # Create temporary boot sector file
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            boot_sector_data = self.create_sample_boot_sector()
            temp_file.write(boot_sector_data)
            temp_file_path = temp_file.name
        
        try:
            # Perform analysis
            result = analyzer.analyze(temp_file_path, include_threat_intelligence=False)
            
            # Generate human-readable report
            report = analyzer.generate_report(result, format_type="human")
            
            # Verify report content
            assert isinstance(report, str)
            assert len(report) > 0
            assert "BOOT SECTOR ANALYSIS REPORT" in report
            assert "THREAT LEVEL:" in report
            assert "STRUCTURE ANALYSIS" in report
            assert "CONTENT ANALYSIS" in report
            assert "SECURITY ANALYSIS" in report
            
        finally:
            # Clean up
            os.unlink(temp_file_path)

    def test_report_generation_json_format(self):
        """Test report generation in JSON format."""
        import json
        
        # Create analyzer
        analyzer = BootSectorAnalyzer()
        
        # Create temporary boot sector file
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            boot_sector_data = self.create_sample_boot_sector()
            temp_file.write(boot_sector_data)
            temp_file_path = temp_file.name
        
        try:
            # Perform analysis
            result = analyzer.analyze(temp_file_path, include_threat_intelligence=False)
            
            # Generate JSON report
            report = analyzer.generate_report(result, format_type="json")
            
            # Verify report is valid JSON
            report_data = json.loads(report)
            
            # Verify JSON structure
            assert "source" in report_data
            assert "timestamp" in report_data
            assert "threat_level" in report_data
            assert "structure_analysis" in report_data
            assert "content_analysis" in report_data
            assert "security_analysis" in report_data
            
        finally:
            # Clean up
            os.unlink(temp_file_path)

    def test_error_handling_invalid_file(self):
        """Test error handling for invalid input files."""
        # Create analyzer
        analyzer = BootSectorAnalyzer()
        
        # Test with non-existent file
        with pytest.raises((BootSectorAnalyzerError, FileAccessError)) as exc_info:
            analyzer.analyze("/non/existent/file.img")
        
        # Check that it's an appropriate error with file not found message
        assert "Source not found" in str(exc_info.value)

    def test_error_handling_invalid_boot_sector_size(self):
        """Test error handling for invalid boot sector size."""
        # Create analyzer
        analyzer = BootSectorAnalyzer()
        
        # Create temporary file with wrong size
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(b"invalid_data_too_short")
            temp_file_path = temp_file.name
        
        try:
            # Should raise error for invalid size
            with pytest.raises((BootSectorAnalyzerError, InvalidBootSectorError)) as exc_info:
                analyzer.analyze(temp_file_path)
            
            # Check that it's an appropriate error with size message
            assert "512 bytes" in str(exc_info.value)
            
        finally:
            # Clean up
            os.unlink(temp_file_path)

    def test_component_status(self):
        """Test component status reporting."""
        # Create analyzer
        analyzer = BootSectorAnalyzer(api_key="test_key")
        
        # Get component status
        status = analyzer.get_component_status()
        
        # Verify status structure
        assert isinstance(status, dict)
        assert "input_handler" in status
        assert "structure_analyzer" in status
        assert "content_analyzer" in status
        assert "security_scanner" in status
        assert "internet_checker" in status
        assert "report_generator" in status
        
        # Verify internet checker status details
        assert isinstance(status["internet_checker"], dict)
        assert "initialized" in status["internet_checker"]
        assert "api_key_configured" in status["internet_checker"]
        assert status["internet_checker"]["api_key_configured"] is True

    def test_cache_management(self):
        """Test cache management functionality."""
        # Create analyzer with cache directory
        with tempfile.TemporaryDirectory() as temp_dir:
            analyzer = BootSectorAnalyzer(cache_dir=temp_dir)
            
            # Test cache clearing
            cleared_count = analyzer.clear_cache()
            assert isinstance(cleared_count, int)
            assert cleared_count >= 0

    def test_analysis_without_internet(self):
        """Test analysis workflow without internet connectivity."""
        # Create analyzer without API key
        analyzer = BootSectorAnalyzer()
        
        # Create temporary boot sector file
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            boot_sector_data = self.create_sample_boot_sector()
            temp_file.write(boot_sector_data)
            temp_file_path = temp_file.name
        
        try:
            # Perform analysis without threat intelligence
            result = analyzer.analyze(temp_file_path, include_threat_intelligence=False)
            
            # Should complete successfully without threat intelligence
            assert isinstance(result, AnalysisResult)
            assert result.threat_intelligence is None
            
        finally:
            # Clean up
            os.unlink(temp_file_path)

    def test_end_to_end_workflow_with_all_components(self):
        """Test end-to-end workflow ensuring all components work together."""
        # Create analyzer
        analyzer = BootSectorAnalyzer()
        
        # Create temporary boot sector file with various patterns
        boot_sector = bytearray(512)
        
        # Add bootstrap code with some strings
        boot_sector[0:7] = b'BOOTMGR'
        boot_sector[12:16] = b'\x31\xc0\x8e\xd8'  # Some assembly code
        
        # Add partition table
        boot_sector[446] = 0x80  # Active
        boot_sector[450] = 0x07  # NTFS
        boot_sector[454:458] = (2048).to_bytes(4, 'little')  # Start LBA
        boot_sector[458:462] = (2048000).to_bytes(4, 'little')  # Size
        
        # Add boot signature (0x55AA in little-endian format)
        boot_sector[510] = 0xAA  # Low byte
        boot_sector[511] = 0x55  # High byte
        
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(bytes(boot_sector))
            temp_file_path = temp_file.name
        
        try:
            # Perform complete analysis
            result = analyzer.analyze(temp_file_path, include_threat_intelligence=False)
            
            # Verify all analysis components produced results
            
            # Structure analysis
            assert result.structure_analysis.is_valid_signature is True
            assert result.structure_analysis.partition_count == 1
            assert len(result.structure_analysis.mbr_structure.partition_table) == 4
            
            # Content analysis
            assert len(result.content_analysis.hashes) >= 2  # MD5 and SHA-256
            assert result.content_analysis.entropy > 0
            assert len(result.content_analysis.strings) > 0  # Should find "BOOTMGR"
            
            # Security analysis
            assert result.security_analysis.threat_level is not None
            
            # Generate both report formats
            human_report = analyzer.generate_report(result, "human")
            json_report = analyzer.generate_report(result, "json")
            
            assert len(human_report) > 0
            assert len(json_report) > 0
            
            # Verify JSON is valid
            import json
            json_data = json.loads(json_report)
            assert "source" in json_data
            
        finally:
            # Clean up
            os.unlink(temp_file_path)


if __name__ == "__main__":
    pytest.main([__file__])