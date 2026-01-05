"""Integration tests for complete analysis workflow."""

import pytest
import tempfile
import os
import json
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
    @patch('boot_sector_analyzer.internet_checker.InternetChecker.query_virustotal_boot_code')
    def test_complete_analysis_workflow_with_threat_intelligence(self, mock_virustotal_boot_code, mock_virustotal):
        """Test complete analysis workflow with enhanced threat intelligence."""
        # Mock VirusTotal responses
        from boot_sector_analyzer.models import VirusTotalResult, VirusTotalStats, VirusTotalEngineResult
        from datetime import datetime
        
        # Mock full boot sector response
        mock_vt_result_full = VirusTotalResult(
            hash_value="test_hash_full",
            detection_count=1,
            total_engines=50,
            scan_date=datetime.now(),
            permalink="https://virustotal.com/test_full",
            detections={"Engine1": {"detected": True, "result": "Suspicious.File"}},
            stats=VirusTotalStats(
                malicious=1, suspicious=0, undetected=49, harmless=0,
                timeout=0, confirmed_timeout=0, failure=0, type_unsupported=0
            ),
            engine_results=[
                VirusTotalEngineResult(
                    engine_name="Engine1", detected=True, result="Suspicious.File",
                    category="malicious", engine_version="1.0", engine_update="20240101"
                )
            ],
            raw_response={"id": "test_hash_full", "type": "file", "attributes": {}}
        )
        mock_virustotal.return_value = mock_vt_result_full
        
        # Mock boot code specific response (more detections)
        mock_vt_result_boot = VirusTotalResult(
            hash_value="test_hash_boot",
            detection_count=3,
            total_engines=50,
            scan_date=datetime.now(),
            permalink="https://virustotal.com/test_boot",
            detections={
                "Engine1": {"detected": True, "result": "Trojan.Boot"},
                "Engine2": {"detected": True, "result": "Malware.Generic"}
            },
            stats=VirusTotalStats(
                malicious=2, suspicious=1, undetected=47, harmless=0,
                timeout=0, confirmed_timeout=0, failure=0, type_unsupported=0
            ),
            engine_results=[
                VirusTotalEngineResult(
                    engine_name="Engine1", detected=True, result="Trojan.Boot",
                    category="malicious", engine_version="1.0", engine_update="20240101"
                ),
                VirusTotalEngineResult(
                    engine_name="Engine2", detected=True, result="Malware.Generic",
                    category="malicious", engine_version="2.0", engine_update="20240101"
                )
            ],
            raw_response={"id": "test_hash_boot", "type": "file", "attributes": {}}
        )
        mock_virustotal_boot_code.return_value = mock_vt_result_boot
        
        # Create analyzer with API key
        analyzer = BootSectorAnalyzer(api_key="test_api_key")
        
        # Create temporary boot sector file with non-empty boot code
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            boot_sector_data = self.create_sample_boot_sector()
            temp_file.write(boot_sector_data)
            temp_file_path = temp_file.name
        
        try:
            # Perform analysis with threat intelligence
            result = analyzer.analyze(temp_file_path, include_threat_intelligence=True)
            
            # Verify full boot sector threat intelligence was included
            assert result.threat_intelligence is not None
            assert result.threat_intelligence.virustotal_result is not None
            assert result.threat_intelligence.virustotal_result.detection_count == 1
            assert result.threat_intelligence.analysis_type == "full_boot_sector"
            
            # Verify boot code specific threat intelligence was included
            assert result.boot_code_threat_intelligence is not None
            assert result.boot_code_threat_intelligence.virustotal_result is not None
            assert result.boot_code_threat_intelligence.virustotal_result.detection_count == 3
            assert result.boot_code_threat_intelligence.analysis_type == "boot_code_only"
            
            # Verify enhanced data is present
            boot_code_vt = result.boot_code_threat_intelligence.virustotal_result
            assert boot_code_vt.stats is not None
            assert boot_code_vt.stats.malicious == 2
            assert boot_code_vt.stats.suspicious == 1
            assert len(boot_code_vt.engine_results) == 2
            assert boot_code_vt.raw_response is not None
            
            # Verify both VirusTotal methods were called
            mock_virustotal.assert_called_once()
            mock_virustotal_boot_code.assert_called_once()
            
        finally:
            # Clean up
            os.unlink(temp_file_path)

    @patch('boot_sector_analyzer.internet_checker.InternetChecker.query_virustotal')
    @patch('boot_sector_analyzer.internet_checker.InternetChecker.query_virustotal_boot_code')
    def test_complete_analysis_workflow_with_clean_threat_intelligence(self, mock_virustotal_boot_code, mock_virustotal):
        """Test complete analysis workflow with clean (negative) threat intelligence results."""
        # Mock clean VirusTotal responses
        from boot_sector_analyzer.models import VirusTotalResult, VirusTotalStats, VirusTotalEngineResult
        from datetime import datetime
        
        # Mock clean full boot sector response
        mock_vt_result_full = VirusTotalResult(
            hash_value="clean_hash_full",
            detection_count=0,
            total_engines=50,
            scan_date=datetime.now(),
            permalink="https://virustotal.com/clean_full",
            detections={},
            stats=VirusTotalStats(
                malicious=0, suspicious=0, undetected=50, harmless=0,
                timeout=0, confirmed_timeout=0, failure=0, type_unsupported=0
            ),
            engine_results=[
                VirusTotalEngineResult(
                    engine_name="Avast", detected=False, result=None,
                    category="undetected", engine_version="21.1.0", engine_update="20240101"
                ),
                VirusTotalEngineResult(
                    engine_name="Kaspersky", detected=False, result=None,
                    category="undetected", engine_version="15.0.1", engine_update="20240101"
                )
            ],
            raw_response={
                "id": "clean_hash_full", "type": "file", 
                "attributes": {
                    "last_analysis_stats": {"malicious": 0, "suspicious": 0, "undetected": 50, "harmless": 0},
                    "reputation": 5
                }
            }
        )
        mock_virustotal.return_value = mock_vt_result_full
        
        # Mock clean boot code specific response
        mock_vt_result_boot = VirusTotalResult(
            hash_value="clean_hash_boot",
            detection_count=0,
            total_engines=50,
            scan_date=datetime.now(),
            permalink="https://virustotal.com/clean_boot",
            detections={},
            stats=VirusTotalStats(
                malicious=0, suspicious=0, undetected=48, harmless=2,
                timeout=0, confirmed_timeout=0, failure=0, type_unsupported=0
            ),
            engine_results=[
                VirusTotalEngineResult(
                    engine_name="Avast", detected=False, result=None,
                    category="undetected", engine_version="21.1.0", engine_update="20240101"
                ),
                VirusTotalEngineResult(
                    engine_name="McAfee", detected=False, result=None,
                    category="harmless", engine_version="6.0.6", engine_update="20240101"
                )
            ],
            raw_response={
                "id": "clean_hash_boot", "type": "file",
                "attributes": {
                    "last_analysis_stats": {"malicious": 0, "suspicious": 0, "undetected": 48, "harmless": 2},
                    "reputation": 8
                }
            }
        )
        mock_virustotal_boot_code.return_value = mock_vt_result_boot
        
        # Create analyzer with API key
        analyzer = BootSectorAnalyzer(api_key="test_api_key")
        
        # Create temporary boot sector file with non-empty boot code
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            boot_sector_data = self.create_sample_boot_sector()
            temp_file.write(boot_sector_data)
            temp_file_path = temp_file.name
        
        try:
            # Perform analysis with threat intelligence
            result = analyzer.analyze(temp_file_path, include_threat_intelligence=True)
            
            # Verify full boot sector threat intelligence was included (clean result)
            assert result.threat_intelligence is not None
            assert result.threat_intelligence.virustotal_result is not None
            assert result.threat_intelligence.virustotal_result.detection_count == 0  # Clean
            assert result.threat_intelligence.analysis_type == "full_boot_sector"
            
            # Verify boot code specific threat intelligence was included (clean result)
            assert result.boot_code_threat_intelligence is not None
            assert result.boot_code_threat_intelligence.virustotal_result is not None
            assert result.boot_code_threat_intelligence.virustotal_result.detection_count == 0  # Clean
            assert result.boot_code_threat_intelligence.analysis_type == "boot_code_only"
            
            # Verify clean stats are present
            full_vt = result.threat_intelligence.virustotal_result
            assert full_vt.stats is not None
            assert full_vt.stats.malicious == 0
            assert full_vt.stats.suspicious == 0
            assert full_vt.stats.undetected == 50
            
            boot_code_vt = result.boot_code_threat_intelligence.virustotal_result
            assert boot_code_vt.stats is not None
            assert boot_code_vt.stats.malicious == 0
            assert boot_code_vt.stats.suspicious == 0
            assert boot_code_vt.stats.undetected == 48
            assert boot_code_vt.stats.harmless == 2
            
            # Verify engine results show clean status
            assert len(full_vt.engine_results) == 2
            assert len(boot_code_vt.engine_results) == 2
            
            for engine_result in full_vt.engine_results + boot_code_vt.engine_results:
                assert engine_result.detected is False
                assert engine_result.result is None
                assert engine_result.category in ["undetected", "harmless"]
            
            # Verify both VirusTotal methods were called
            mock_virustotal.assert_called_once()
            mock_virustotal_boot_code.assert_called_once()
            
            # Test that clean results are prominently displayed in reports
            human_report = analyzer.generate_report(result, "human")
            assert "✅ CLEAN: 0/50 detections" in human_report
            assert "No threats detected" in human_report
            assert "CLEAN RESULT: 0% detection ratio" in human_report
            
            # Test JSON includes clean results
            json_report = analyzer.generate_report(result, "json")
            json_data = json.loads(json_report)
            assert json_data["threat_intelligence"]["virustotal"]["detection_count"] == 0
            assert json_data["boot_code_threat_intelligence"]["virustotal"]["detection_count"] == 0
            
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