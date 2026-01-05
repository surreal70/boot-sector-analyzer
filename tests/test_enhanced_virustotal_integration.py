"""Integration tests for enhanced VirusTotal functionality."""

import pytest
import tempfile
import os
import json
import hashlib
from datetime import datetime
from pathlib import Path
from unittest.mock import patch, MagicMock, Mock

from boot_sector_analyzer import BootSectorAnalyzer
from boot_sector_analyzer.internet_checker import InternetChecker
from boot_sector_analyzer.models import (
    VirusTotalResult, VirusTotalStats, VirusTotalEngineResult, 
    ThreatIntelligence, AnalysisResult
)


class TestEnhancedVirusTotalIntegration:
    """Integration tests for enhanced VirusTotal functionality."""

    def create_sample_boot_sector_with_code(self) -> bytes:
        """Create a sample boot sector with non-empty boot code for testing."""
        boot_sector = bytearray(512)
        
        # Add non-zero boot code (first 446 bytes) - simple but not all zeros
        boot_sector[0:10] = b'\x33\xc0\x8e\xd0\x8e\xc0\x8e\xd8\xbc\x00'  # Simple boot code
        boot_sector[10:20] = b'\x7c\xfa\xfc\xb8\x00\x07\x8e\xd8\x8e\xc0'  # More boot code
        boot_sector[20:30] = b'\xbe\x00\x7c\xbf\x00\x06\xb9\x00\x02\xf3'  # Additional instructions
        
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

    def create_empty_boot_code_sector(self) -> bytes:
        """Create a boot sector with empty (all zeros) boot code for testing."""
        boot_sector = bytearray(512)
        
        # Boot code region (first 446 bytes) remains all zeros
        
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

    def create_mock_virustotal_response(self, hash_value: str, detection_count: int = 2) -> VirusTotalResult:
        """Create a mock VirusTotal response for testing."""
        # Calculate malicious and suspicious counts based on detection_count
        malicious_count = max(0, detection_count - 1)  # Most detections are malicious
        suspicious_count = 1 if detection_count > 0 else 0  # Always 1 suspicious if any detections
        
        stats = VirusTotalStats(
            malicious=malicious_count,
            suspicious=suspicious_count,
            undetected=50 - detection_count,
            harmless=0,
            timeout=0,
            confirmed_timeout=0,
            failure=0,
            type_unsupported=0
        )
        
        engine_results = []
        detections = {}
        
        # Create engine results based on detection count
        for i in range(min(detection_count, 3)):  # Max 3 engines for simplicity
            engine_name = f"Engine{i+1}"
            if i < malicious_count:
                # Malicious detection
                result_name = "Trojan.Generic" if i == 0 else "Malware.Boot"
                engine_results.append(VirusTotalEngineResult(
                    engine_name=engine_name,
                    detected=True,
                    result=result_name,
                    category="malicious",
                    engine_version=f"{i+1}.0.0",
                    engine_update="20240101"
                ))
                detections[engine_name] = {"detected": True, "result": result_name, "category": "malicious"}
            elif i < malicious_count + suspicious_count:
                # Suspicious detection
                engine_results.append(VirusTotalEngineResult(
                    engine_name=engine_name,
                    detected=True,
                    result="Suspicious.Code",
                    category="suspicious",
                    engine_version=f"{i+1}.0.0",
                    engine_update="20240101"
                ))
                detections[engine_name] = {"detected": True, "result": "Suspicious.Code", "category": "suspicious"}
        
        # Add one undetected engine for completeness
        if len(engine_results) < 3:
            engine_name = f"Engine{len(engine_results)+1}"
            engine_results.append(VirusTotalEngineResult(
                engine_name=engine_name,
                detected=False,
                result=None,
                category="undetected",
                engine_version=f"{len(engine_results)+1}.0.0",
                engine_update="20240101"
            ))
        
        raw_response = {
            'id': hash_value,
            'type': 'file',
            'attributes': {
                'last_analysis_stats': {
                    'malicious': malicious_count,
                    'suspicious': suspicious_count,
                    'undetected': 50 - detection_count,
                    'harmless': 0,
                    'timeout': 0,
                    'confirmed-timeout': 0,
                    'failure': 0,
                    'type-unsupported': 0
                },
                'last_analysis_date': 1640995200,
                'last_analysis_results': {
                    engine_name: {'result': det['result'], 'category': det['category']}
                    for engine_name, det in detections.items()
                },
                'sha256': hash_value,
                'md5': 'mock_md5_hash',
                'sha1': 'mock_sha1_hash',
                'size': 446,  # Boot code size
                'type_description': 'data',
                'magic': 'data',
                'first_submission_date': 1640995200,
                'last_submission_date': 1640995200,
                'times_submitted': 5,
                'reputation': -10 if detection_count > 0 else 0
            }
        }
        
        return VirusTotalResult(
            hash_value=hash_value,
            detection_count=detection_count,
            total_engines=50,
            scan_date=datetime.fromtimestamp(1640995200),
            permalink=f"https://www.virustotal.com/gui/file/{hash_value}",
            detections=detections,
            stats=stats,
            engine_results=engine_results,
            raw_response=raw_response
        )

    def create_mock_clean_virustotal_response(self, hash_value: str) -> VirusTotalResult:
        """Create a mock clean (0 detections) VirusTotal response for testing negative results."""
        stats = VirusTotalStats(
            malicious=0,
            suspicious=0,
            undetected=50,
            harmless=0,
            timeout=0,
            confirmed_timeout=0,
            failure=0,
            type_unsupported=0
        )
        
        # Create some undetected engine results to show comprehensive scanning
        engine_results = [
            VirusTotalEngineResult(
                engine_name="Avast",
                detected=False,
                result=None,
                category="undetected",
                engine_version="21.1.0",
                engine_update="20240101"
            ),
            VirusTotalEngineResult(
                engine_name="Kaspersky",
                detected=False,
                result=None,
                category="undetected",
                engine_version="15.0.1",
                engine_update="20240101"
            ),
            VirusTotalEngineResult(
                engine_name="McAfee",
                detected=False,
                result=None,
                category="undetected",
                engine_version="6.0.6",
                engine_update="20240101"
            )
        ]
        
        raw_response = {
            'id': hash_value,
            'type': 'file',
            'attributes': {
                'last_analysis_stats': {
                    'malicious': 0,
                    'suspicious': 0,
                    'undetected': 50,
                    'harmless': 0,
                    'timeout': 0,
                    'confirmed-timeout': 0,
                    'failure': 0,
                    'type-unsupported': 0
                },
                'last_analysis_date': 1640995200,
                'last_analysis_results': {
                    'Avast': {'result': None, 'category': 'undetected'},
                    'Kaspersky': {'result': None, 'category': 'undetected'},
                    'McAfee': {'result': None, 'category': 'undetected'}
                },
                'sha256': hash_value,
                'md5': 'mock_md5_hash',
                'sha1': 'mock_sha1_hash',
                'size': 446 if 'boot' in hash_value else 512,
                'type_description': 'data',
                'magic': 'data',
                'first_submission_date': 1640995200,
                'last_submission_date': 1640995200,
                'times_submitted': 3,
                'reputation': 0  # Clean reputation
            }
        }
        
        return VirusTotalResult(
            hash_value=hash_value,
            detection_count=0,
            total_engines=50,
            scan_date=datetime.fromtimestamp(1640995200),
            permalink=f"https://www.virustotal.com/gui/file/{hash_value}",
            detections={},  # No detections
            stats=stats,
            engine_results=engine_results,
            raw_response=raw_response
        )

    @patch('boot_sector_analyzer.internet_checker.InternetChecker.query_virustotal')
    @patch('boot_sector_analyzer.internet_checker.InternetChecker.query_virustotal_boot_code')
    def test_end_to_end_clean_boot_sector_negative_results(self, mock_boot_code_query, mock_full_query):
        """Test end-to-end analysis with clean boot sectors that return 0 detections."""
        # Create boot sector with non-empty boot code (but clean)
        boot_sector_data = self.create_sample_boot_sector_with_code()
        boot_code_region = boot_sector_data[:446]
        
        # Calculate expected hashes
        full_sector_hash = hashlib.sha256(boot_sector_data).hexdigest()
        boot_code_hash = hashlib.sha256(boot_code_region).hexdigest()
        
        # Create mock clean VirusTotal responses for both full sector and boot code
        full_sector_vt_result = self.create_mock_clean_virustotal_response(full_sector_hash)
        boot_code_vt_result = self.create_mock_clean_virustotal_response(boot_code_hash)
        
        # Set up mocks
        mock_full_query.return_value = full_sector_vt_result
        mock_boot_code_query.return_value = boot_code_vt_result
        
        # Create analyzer with API key
        analyzer = BootSectorAnalyzer(api_key="test_api_key")
        
        # Create temporary boot sector file
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(boot_sector_data)
            temp_file_path = temp_file.name
        
        try:
            # Mock network connectivity
            with patch.object(analyzer.internet_checker, '_check_network_connectivity', return_value=True):
                # Perform analysis with threat intelligence
                result = analyzer.analyze(temp_file_path, include_threat_intelligence=True)
            
            # Verify analysis result structure
            assert isinstance(result, AnalysisResult)
            
            # Verify both full sector and boot code threat intelligence are present (even with 0 detections)
            assert result.threat_intelligence is not None
            assert result.boot_code_threat_intelligence is not None
            
            # Verify full sector analysis (clean result)
            full_sector_ti = result.threat_intelligence
            assert full_sector_ti.analysis_type == "full_boot_sector"
            assert full_sector_ti.virustotal_result is not None
            assert full_sector_ti.virustotal_result.hash_value == full_sector_hash
            assert full_sector_ti.virustotal_result.detection_count == 0  # Clean result
            assert full_sector_ti.virustotal_result.stats.malicious == 0
            assert full_sector_ti.virustotal_result.stats.suspicious == 0
            assert full_sector_ti.virustotal_result.stats.undetected == 50
            
            # Verify boot code specific analysis (clean result)
            boot_code_ti = result.boot_code_threat_intelligence
            assert boot_code_ti.analysis_type == "boot_code_only"
            assert boot_code_ti.virustotal_result is not None
            assert boot_code_ti.virustotal_result.hash_value == boot_code_hash
            assert boot_code_ti.virustotal_result.detection_count == 0  # Clean result
            assert boot_code_ti.virustotal_result.stats.malicious == 0
            assert boot_code_ti.virustotal_result.stats.suspicious == 0
            assert boot_code_ti.virustotal_result.stats.undetected == 50
            
            # Verify both VirusTotal queries were made
            assert mock_full_query.called
            assert mock_boot_code_query.called
            
        finally:
            # Clean up
            os.unlink(temp_file_path)

    @patch('boot_sector_analyzer.internet_checker.InternetChecker.query_virustotal')
    @patch('boot_sector_analyzer.internet_checker.InternetChecker.query_virustotal_boot_code')
    def test_negative_results_prominently_displayed_in_all_formats(self, mock_boot_code_query, mock_full_query):
        """Test that negative results are prominently displayed in all report formats."""
        # Create boot sector with non-empty boot code (but clean)
        boot_sector_data = self.create_sample_boot_sector_with_code()
        boot_code_region = boot_sector_data[:446]
        
        # Calculate expected hashes
        full_sector_hash = hashlib.sha256(boot_sector_data).hexdigest()
        boot_code_hash = hashlib.sha256(boot_code_region).hexdigest()
        
        # Create mock clean VirusTotal responses
        full_sector_vt_result = self.create_mock_clean_virustotal_response(full_sector_hash)
        boot_code_vt_result = self.create_mock_clean_virustotal_response(boot_code_hash)
        
        # Set up mocks
        mock_full_query.return_value = full_sector_vt_result
        mock_boot_code_query.return_value = boot_code_vt_result
        
        # Create analyzer with API key
        analyzer = BootSectorAnalyzer(api_key="test_api_key")
        
        # Create temporary boot sector file
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(boot_sector_data)
            temp_file_path = temp_file.name
        
        try:
            # Mock network connectivity
            with patch.object(analyzer.internet_checker, '_check_network_connectivity', return_value=True):
                # Perform analysis with threat intelligence
                result = analyzer.analyze(temp_file_path, include_threat_intelligence=True)
            
            # Test human-readable format prominently displays negative results
            human_report = analyzer.generate_report(result, "human")
            
            # Verify negative results are prominently displayed
            assert "✅ CLEAN: 0/50 detections" in human_report
            assert "No threats detected" in human_report
            assert "CLEAN RESULT: 0% detection ratio" in human_report
            assert "All engines report clean" in human_report
            assert "All 50 engines reported" in human_report
            
            # Verify dual analysis sections are present
            assert "FULL BOOT SECTOR VIRUSTOTAL ANALYSIS" in human_report or "VirusTotal Analysis" in human_report
            assert "BOOT CODE VIRUSTOTAL ANALYSIS" in human_report
            
            # Test JSON format includes negative results
            json_report = analyzer.generate_report(result, "json")
            json_data = json.loads(json_report)
            
            # Verify both analyses are present in JSON
            assert "threat_intelligence" in json_data
            assert "boot_code_threat_intelligence" in json_data
            
            # Verify full sector analysis data
            full_ti = json_data["threat_intelligence"]
            assert full_ti["analysis_type"] == "full_boot_sector"
            assert "virustotal" in full_ti
            full_vt = full_ti["virustotal"]
            assert full_vt["detection_count"] == 0
            assert full_vt["stats"]["malicious"] == 0
            assert full_vt["stats"]["undetected"] == 50
            
            # Verify boot code analysis data
            boot_ti = json_data["boot_code_threat_intelligence"]
            assert boot_ti["analysis_type"] == "boot_code_only"
            assert "virustotal" in boot_ti
            boot_vt = boot_ti["virustotal"]
            assert boot_vt["detection_count"] == 0
            assert boot_vt["stats"]["malicious"] == 0
            assert boot_vt["stats"]["undetected"] == 50
            
            # Test HTML format prominently displays negative results
            html_report = analyzer.generate_report(result, "html")
            
            # Verify negative results are prominently displayed in HTML
            assert "CLEAN" in html_report or "No detections" in html_report
            assert "0/50" in html_report  # Detection ratio
            assert "Full Boot Sector Analysis" in html_report or "VirusTotal Analysis" in html_report
            assert "Boot Code Analysis" in html_report or "Boot Code VirusTotal" in html_report
            
            # Verify scan statistics are included in HTML
            assert "Scan Statistics" in html_report or "stats" in html_report
            assert "Undetected: 50" in html_report or "undetected" in html_report
            
        finally:
            # Clean up
            os.unlink(temp_file_path)

    @patch('boot_sector_analyzer.internet_checker.InternetChecker.query_virustotal')
    @patch('boot_sector_analyzer.internet_checker.InternetChecker.query_virustotal_boot_code')
    def test_dual_analysis_reporting_with_negative_results(self, mock_boot_code_query, mock_full_query):
        """Test dual analysis reporting (full MBR vs boot code only) with negative results."""
        # Create boot sector with non-empty boot code
        boot_sector_data = self.create_sample_boot_sector_with_code()
        boot_code_region = boot_sector_data[:446]
        
        # Calculate expected hashes
        full_sector_hash = hashlib.sha256(boot_sector_data).hexdigest()
        boot_code_hash = hashlib.sha256(boot_code_region).hexdigest()
        
        # Create mixed results: full sector clean, boot code has 1 detection
        full_sector_vt_result = self.create_mock_clean_virustotal_response(full_sector_hash)
        boot_code_vt_result = self.create_mock_virustotal_response(boot_code_hash, detection_count=1)
        
        # Set up mocks
        mock_full_query.return_value = full_sector_vt_result
        mock_boot_code_query.return_value = boot_code_vt_result
        
        # Create analyzer with API key
        analyzer = BootSectorAnalyzer(api_key="test_api_key")
        
        # Create temporary boot sector file
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(boot_sector_data)
            temp_file_path = temp_file.name
        
        try:
            # Mock network connectivity
            with patch.object(analyzer.internet_checker, '_check_network_connectivity', return_value=True):
                # Perform analysis with threat intelligence
                result = analyzer.analyze(temp_file_path, include_threat_intelligence=True)
            
            # Verify both analyses are present and distinct
            assert result.threat_intelligence is not None
            assert result.boot_code_threat_intelligence is not None
            
            # Verify full sector analysis (clean)
            full_sector_ti = result.threat_intelligence
            assert full_sector_ti.analysis_type == "full_boot_sector"
            assert full_sector_ti.virustotal_result.detection_count == 0
            
            # Verify boot code analysis (has detection)
            boot_code_ti = result.boot_code_threat_intelligence
            assert boot_code_ti.analysis_type == "boot_code_only"
            assert boot_code_ti.virustotal_result.detection_count == 1
            
            # Test that both analyses are reported separately in human format
            human_report = analyzer.generate_report(result, "human")
            
            # Should have separate sections for each analysis
            assert "FULL BOOT SECTOR" in human_report or "VirusTotal Analysis" in human_report
            assert "BOOT CODE" in human_report
            
            # Full sector should show clean result
            full_sector_section = human_report
            assert "✅ CLEAN: 0/50 detections" in full_sector_section
            
            # Boot code should show detection
            boot_code_section = human_report
            assert "1/50" in boot_code_section  # 1 detection
            
            # Test JSON format has both analyses
            json_report = analyzer.generate_report(result, "json")
            json_data = json.loads(json_report)
            
            assert "threat_intelligence" in json_data
            assert "boot_code_threat_intelligence" in json_data
            
            # Verify different results
            assert json_data["threat_intelligence"]["virustotal"]["detection_count"] == 0
            assert json_data["boot_code_threat_intelligence"]["virustotal"]["detection_count"] == 1
            
        finally:
            # Clean up
            os.unlink(temp_file_path)

    @patch('boot_sector_analyzer.internet_checker.InternetChecker.query_virustotal')
    @patch('boot_sector_analyzer.internet_checker.InternetChecker.query_virustotal_boot_code')
    def test_scan_statistics_included_for_clean_results(self, mock_boot_code_query, mock_full_query):
        """Test that scan statistics are included even for clean results."""
        # Create boot sector with non-empty boot code
        boot_sector_data = self.create_sample_boot_sector_with_code()
        boot_code_region = boot_sector_data[:446]
        
        # Calculate expected hashes
        full_sector_hash = hashlib.sha256(boot_sector_data).hexdigest()
        boot_code_hash = hashlib.sha256(boot_code_region).hexdigest()
        
        # Create comprehensive clean responses with detailed stats
        full_sector_vt_result = self.create_mock_clean_virustotal_response(full_sector_hash)
        boot_code_vt_result = self.create_mock_clean_virustotal_response(boot_code_hash)
        
        # Add additional metadata to show comprehensive scanning
        full_sector_vt_result.raw_response['attributes'].update({
            'times_submitted': 15,
            'reputation': 5,  # Good reputation
            'first_submission_date': 1640995100,
            'last_submission_date': 1640995200
        })
        
        boot_code_vt_result.raw_response['attributes'].update({
            'times_submitted': 8,
            'reputation': 3,  # Good reputation
            'first_submission_date': 1640995150,
            'last_submission_date': 1640995200
        })
        
        # Set up mocks
        mock_full_query.return_value = full_sector_vt_result
        mock_boot_code_query.return_value = boot_code_vt_result
        
        # Create analyzer with API key
        analyzer = BootSectorAnalyzer(api_key="test_api_key")
        
        # Create temporary boot sector file
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(boot_sector_data)
            temp_file_path = temp_file.name
        
        try:
            # Mock network connectivity
            with patch.object(analyzer.internet_checker, '_check_network_connectivity', return_value=True):
                # Perform analysis with threat intelligence
                result = analyzer.analyze(temp_file_path, include_threat_intelligence=True)
            
            # Test human-readable format includes comprehensive scan statistics
            human_report = analyzer.generate_report(result, "human")
            
            # Verify scan statistics are prominently displayed for clean results
            assert "Scan Statistics:" in human_report
            assert "Malicious: 0" in human_report
            assert "Suspicious: 0" in human_report
            assert "Undetected: 50" in human_report
            assert "Harmless: 0" in human_report
            
            # Verify additional metadata is included
            assert "Times Submitted:" in human_report
            assert "Reputation Score:" in human_report
            assert "First Seen:" in human_report
            
            # Verify clean result messaging
            assert "All 50 engines reported" in human_report
            assert "CLEAN RESULT: 0% detection ratio" in human_report
            
            # Test JSON format includes complete statistics
            json_report = analyzer.generate_report(result, "json")
            json_data = json.loads(json_report)
            
            # Verify full sector stats
            full_vt = json_data["threat_intelligence"]["virustotal"]
            assert "stats" in full_vt
            stats = full_vt["stats"]
            assert stats["malicious"] == 0
            assert stats["suspicious"] == 0
            assert stats["undetected"] == 50
            assert stats["harmless"] == 0
            
            # Verify boot code stats
            boot_vt = json_data["boot_code_threat_intelligence"]["virustotal"]
            assert "stats" in boot_vt
            boot_stats = boot_vt["stats"]
            assert boot_stats["malicious"] == 0
            assert boot_stats["suspicious"] == 0
            assert boot_stats["undetected"] == 50
            
            # Verify raw response data is included
            assert "raw_response" in full_vt
            assert "raw_response" in boot_vt
            
            # Test HTML format includes scan statistics
            html_report = analyzer.generate_report(result, "html")
            
            # Verify scan statistics are displayed in HTML
            assert "Malicious: 0" in html_report or "malicious" in html_report
            assert "Undetected: 50" in html_report or "undetected" in html_report
            assert "0/50" in html_report  # Detection ratio
            
        finally:
            # Clean up
            os.unlink(temp_file_path)

    @patch('boot_sector_analyzer.internet_checker.InternetChecker.query_virustotal')
    @patch('boot_sector_analyzer.internet_checker.InternetChecker.query_virustotal_boot_code')
    def test_end_to_end_enhanced_virustotal_workflow_with_boot_code(self, mock_boot_code_query, mock_full_query):
        """Test complete enhanced VirusTotal workflow with boot code analysis."""
        # Create boot sector with non-empty boot code
        boot_sector_data = self.create_sample_boot_sector_with_code()
        boot_code_region = boot_sector_data[:446]
        
        # Calculate expected hashes
        full_sector_hash = hashlib.sha256(boot_sector_data).hexdigest()
        boot_code_hash = hashlib.sha256(boot_code_region).hexdigest()
        
        # Create mock VirusTotal responses for both full sector and boot code
        full_sector_vt_result = self.create_mock_virustotal_response(full_sector_hash, detection_count=1)
        boot_code_vt_result = self.create_mock_virustotal_response(boot_code_hash, detection_count=3)
        
        # Update boot code result to have more detections
        boot_code_vt_result.stats.malicious = 3
        boot_code_vt_result.stats.suspicious = 1
        boot_code_vt_result.stats.undetected = 46
        boot_code_vt_result.detection_count = 4  # 3 malicious + 1 suspicious
        
        # Set up mocks
        mock_full_query.return_value = full_sector_vt_result
        mock_boot_code_query.return_value = boot_code_vt_result
        
        # Create analyzer with API key
        analyzer = BootSectorAnalyzer(api_key="test_api_key")
        
        # Create temporary boot sector file
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(boot_sector_data)
            temp_file_path = temp_file.name
        
        try:
            # Mock network connectivity
            with patch.object(analyzer.internet_checker, '_check_network_connectivity', return_value=True):
                # Perform analysis with threat intelligence
                result = analyzer.analyze(temp_file_path, include_threat_intelligence=True)
            
            # Verify analysis result structure
            assert isinstance(result, AnalysisResult)
            
            # Verify both full sector and boot code threat intelligence are present
            assert result.threat_intelligence is not None
            assert result.boot_code_threat_intelligence is not None
            
            # Verify full sector analysis
            full_sector_ti = result.threat_intelligence
            assert full_sector_ti.analysis_type == "full_boot_sector"
            assert full_sector_ti.virustotal_result is not None
            assert full_sector_ti.virustotal_result.hash_value == full_sector_hash
            assert full_sector_ti.virustotal_result.detection_count == 1  # 1 detection as specified
            
            # Verify boot code specific analysis
            boot_code_ti = result.boot_code_threat_intelligence
            assert boot_code_ti.analysis_type == "boot_code_only"
            assert boot_code_ti.virustotal_result is not None
            assert boot_code_ti.virustotal_result.hash_value == boot_code_hash
            assert boot_code_ti.virustotal_result.detection_count == 4  # 4 detections as specified
            
            # Verify both VirusTotal queries were made
            assert mock_full_query.called
            assert mock_boot_code_query.called
            
        finally:
            # Clean up
            os.unlink(temp_file_path)

    @patch('boot_sector_analyzer.internet_checker.InternetChecker.query_virustotal')
    @patch('boot_sector_analyzer.internet_checker.InternetChecker.query_virustotal_boot_code')
    def test_empty_boot_code_detection_and_skipping(self, mock_boot_code_query, mock_full_query):
        """Test that empty boot code is detected and VirusTotal submission is skipped."""
        # Create boot sector with empty (all zeros) boot code
        boot_sector_data = self.create_empty_boot_code_sector()
        
        # Calculate expected hash for full sector only
        full_sector_hash = hashlib.sha256(boot_sector_data).hexdigest()
        
        # Create mock VirusTotal response for full sector only
        full_sector_vt_result = self.create_mock_virustotal_response(full_sector_hash, detection_count=0)
        full_sector_vt_result.stats.malicious = 0
        full_sector_vt_result.stats.suspicious = 0
        full_sector_vt_result.stats.undetected = 50
        full_sector_vt_result.detection_count = 0
        
        # Set up mocks: full sector succeeds, boot code returns None (empty boot code)
        mock_full_query.return_value = full_sector_vt_result
        mock_boot_code_query.return_value = None  # Empty boot code is skipped
        
        # Create analyzer with API key
        analyzer = BootSectorAnalyzer(api_key="test_api_key")
        
        # Create temporary boot sector file
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(boot_sector_data)
            temp_file_path = temp_file.name
        
        try:
            # Mock network connectivity
            with patch.object(analyzer.internet_checker, '_check_network_connectivity', return_value=True):
                # Perform analysis with threat intelligence
                result = analyzer.analyze(temp_file_path, include_threat_intelligence=True)
            
            # Verify analysis result structure
            assert isinstance(result, AnalysisResult)
            
            # Verify full sector threat intelligence is present
            assert result.threat_intelligence is not None
            assert result.threat_intelligence.analysis_type == "full_boot_sector"
            assert result.threat_intelligence.virustotal_result is not None
            assert result.threat_intelligence.virustotal_result.hash_value == full_sector_hash
            
            # Verify boot code threat intelligence is None (skipped due to empty boot code)
            assert result.boot_code_threat_intelligence is None
            
            # Verify both queries were attempted (boot code query returns None for empty boot code)
            assert mock_full_query.called
            assert mock_boot_code_query.called
            
        finally:
            # Clean up
            os.unlink(temp_file_path)

    @patch('boot_sector_analyzer.internet_checker.InternetChecker.query_virustotal')
    @patch('boot_sector_analyzer.internet_checker.InternetChecker.query_virustotal_boot_code')
    def test_complete_virustotal_response_capture_and_display(self, mock_boot_code_query, mock_full_query):
        """Test that complete VirusTotal response is captured and displayed in reports."""
        # Create boot sector with non-empty boot code
        boot_sector_data = self.create_sample_boot_sector_with_code()
        boot_code_region = boot_sector_data[:446]
        
        # Calculate expected hashes
        full_sector_hash = hashlib.sha256(boot_sector_data).hexdigest()
        boot_code_hash = hashlib.sha256(boot_code_region).hexdigest()
        
        # Create comprehensive mock VirusTotal responses
        full_sector_vt_result = self.create_mock_virustotal_response(full_sector_hash, detection_count=1)
        boot_code_vt_result = self.create_mock_virustotal_response(boot_code_hash, detection_count=5)
        
        # Update boot code result with more comprehensive data
        boot_code_vt_result.stats.malicious = 5
        boot_code_vt_result.stats.suspicious = 2
        boot_code_vt_result.stats.undetected = 40
        boot_code_vt_result.stats.harmless = 3
        boot_code_vt_result.detection_count = 7  # 5 malicious + 2 suspicious
        
        # Add more engine results for boot code
        boot_code_vt_result.engine_results = [
            VirusTotalEngineResult(
                engine_name="Avast",
                detected=True,
                result="Trojan.Boot",
                category="malicious",
                engine_version="21.1.0",
                engine_update="20240101"
            ),
            VirusTotalEngineResult(
                engine_name="Kaspersky",
                detected=True,
                result="HEUR:Trojan.Boot",
                category="malicious",
                engine_version="15.0.1",
                engine_update="20240101"
            ),
            VirusTotalEngineResult(
                engine_name="McAfee",
                detected=True,
                result="Suspicious.Code",
                category="suspicious",
                engine_version="6.0.6",
                engine_update="20240101"
            ),
            VirusTotalEngineResult(
                engine_name="Symantec",
                detected=False,
                result=None,
                category="undetected",
                engine_version="1.17.0",
                engine_update="20240101"
            )
        ]
        
        # Update raw response with comprehensive data
        boot_code_vt_result.raw_response.update({
            'id': boot_code_hash,
            'type': 'file',
            'attributes': {
                'last_analysis_stats': {
                    'malicious': 5,
                    'suspicious': 2,
                    'undetected': 40,
                    'harmless': 3,
                    'timeout': 0,
                    'confirmed-timeout': 0,
                    'failure': 0,
                    'type-unsupported': 0
                },
                'last_analysis_date': 1640995200,
                'last_analysis_results': {
                    'Avast': {'result': 'Trojan.Boot', 'category': 'malicious'},
                    'Kaspersky': {'result': 'HEUR:Trojan.Boot', 'category': 'malicious'},
                    'McAfee': {'result': 'Suspicious.Code', 'category': 'suspicious'},
                    'Symantec': {'result': None, 'category': 'undetected'}
                },
                'sha256': boot_code_hash,
                'md5': 'mock_md5_hash',
                'sha1': 'mock_sha1_hash',
                'size': 446,
                'type_description': 'data',
                'magic': 'data',
                'first_submission_date': 1640995100,
                'last_submission_date': 1640995200,
                'times_submitted': 10,
                'reputation': -15
            }
        })
        
        # Set up mocks
        mock_full_query.return_value = full_sector_vt_result
        mock_boot_code_query.return_value = boot_code_vt_result
        
        # Create analyzer with API key
        analyzer = BootSectorAnalyzer(api_key="test_api_key")
        
        # Create temporary boot sector file
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(boot_sector_data)
            temp_file_path = temp_file.name
        
        try:
            # Mock network connectivity
            with patch.object(analyzer.internet_checker, '_check_network_connectivity', return_value=True):
                # Perform analysis with threat intelligence
                result = analyzer.analyze(temp_file_path, include_threat_intelligence=True)
            
            # Verify both queries were called
            assert mock_full_query.called
            assert mock_boot_code_query.called
            
            # Verify boot code threat intelligence contains complete response data
            boot_code_ti = result.boot_code_threat_intelligence
            assert boot_code_ti is not None
            vt_result = boot_code_ti.virustotal_result
            assert vt_result is not None
            
            # Verify enhanced stats are captured
            assert vt_result.stats is not None
            assert vt_result.stats.malicious == 5
            assert vt_result.stats.suspicious == 2
            assert vt_result.stats.undetected == 40
            assert vt_result.stats.harmless == 3
            
            # Verify engine results are captured
            assert vt_result.engine_results is not None
            assert len(vt_result.engine_results) == 4
            
            # Find specific engine results
            avast_result = next((er for er in vt_result.engine_results if er.engine_name == "Avast"), None)
            assert avast_result is not None
            assert avast_result.detected is True
            assert avast_result.result == "Trojan.Boot"
            assert avast_result.category == "malicious"
            assert avast_result.engine_version == "21.1.0"
            
            # Verify raw response is captured
            assert vt_result.raw_response is not None
            assert vt_result.raw_response['id'] == boot_code_hash
            assert vt_result.raw_response['type'] == 'file'
            assert 'attributes' in vt_result.raw_response
            
            # Test report generation includes complete VirusTotal data
            human_report = analyzer.generate_report(result, "human")
            assert "VirusTotal Analysis" in human_report
            assert "DETECTION RATIO" in human_report  # Detection ratio analysis
            assert "7/50" in human_report  # 5 malicious + 2 suspicious / total
            assert "Avast: Trojan.Boot" in human_report
            assert "Kaspersky: HEUR:Trojan.Boot" in human_report
            
            # Test JSON report includes complete data
            json_report = analyzer.generate_report(result, "json")
            json_data = json.loads(json_report)
            
            assert "boot_code_threat_intelligence" in json_data
            boot_code_data = json_data["boot_code_threat_intelligence"]
            assert boot_code_data["analysis_type"] == "boot_code_only"
            assert "virustotal" in boot_code_data
            
            vt_data = boot_code_data["virustotal"]
            assert "stats" in vt_data
            assert "engine_results" in vt_data
            assert "raw_response" in vt_data
            assert vt_data["stats"]["malicious"] == 5
            assert len(vt_data["engine_results"]) == 4
            
        finally:
            # Clean up
            os.unlink(temp_file_path)

    @patch('boot_sector_analyzer.internet_checker.InternetChecker.query_virustotal')
    @patch('boot_sector_analyzer.internet_checker.InternetChecker.query_virustotal_boot_code')
    def test_virustotal_data_integration_across_all_report_formats(self, mock_boot_code_query, mock_full_query):
        """Test that VirusTotal data is consistently integrated across all report formats."""
        # Create mock analysis result with enhanced VirusTotal data
        boot_sector_data = self.create_sample_boot_sector_with_code()
        boot_code_hash = hashlib.sha256(boot_sector_data[:446]).hexdigest()
        full_sector_hash = hashlib.sha256(boot_sector_data).hexdigest()
        
        # Create mock VirusTotal results with complete data
        full_sector_vt_result = self.create_mock_virustotal_response(full_sector_hash, detection_count=1)
        boot_code_vt_result = self.create_mock_virustotal_response(boot_code_hash, detection_count=3)
        
        # Set up mocks
        mock_full_query.return_value = full_sector_vt_result
        mock_boot_code_query.return_value = boot_code_vt_result
        
        # Create analyzer with API key
        analyzer = BootSectorAnalyzer(api_key="test_api_key")
        
        # Create temporary boot sector file
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(boot_sector_data)
            temp_file_path = temp_file.name
        
        try:
            # Mock network connectivity
            with patch.object(analyzer.internet_checker, '_check_network_connectivity', return_value=True):
                # Perform analysis with threat intelligence
                result = analyzer.analyze(temp_file_path, include_threat_intelligence=True)
            
            # Verify both queries were called
            assert mock_full_query.called
            assert mock_boot_code_query.called
            
            # Verify both threat intelligence results are present
            assert result.threat_intelligence is not None
            assert result.boot_code_threat_intelligence is not None
            
            # Test human-readable format
            human_report = analyzer.generate_report(result, "human")
            assert "Boot Code VirusTotal Analysis" in human_report
            assert "DETECTION RATIO" in human_report  # Detection ratio analysis
            assert "3/50" in human_report  # 3 detections as specified
            assert "Engine1: Trojan.Generic" in human_report
            assert "Engine2: Malware.Boot" in human_report
            assert boot_code_hash in human_report
            
            # Test JSON format
            json_report = analyzer.generate_report(result, "json")
            json_data = json.loads(json_report)
            
            assert "boot_code_threat_intelligence" in json_data
            boot_code_data = json_data["boot_code_threat_intelligence"]
            assert boot_code_data["analysis_type"] == "boot_code_only"
            
            vt_data = boot_code_data["virustotal"]
            assert vt_data["hash_value"] == boot_code_hash
            assert vt_data["detection_count"] == 3
            assert vt_data["total_engines"] == 50
            assert "stats" in vt_data
            assert "engine_results" in vt_data
            assert "raw_response" in vt_data
            
            # Test HTML format
            html_report = analyzer.generate_report(result, "html")
            assert "Boot Code VirusTotal Analysis" in html_report
            assert boot_code_hash in html_report
            assert "3/50" in html_report  # Detection ratio display
            assert "detections" in html_report  # Detection label
            assert "Trojan.Generic" in html_report
            assert "Malware.Boot" in html_report
            
            # Verify HTML contains enhanced data
            assert "Engine Results" in html_report or "Detection Details" in html_report
            assert "Engine1" in html_report
            assert "Engine2" in html_report
            
        finally:
            # Clean up
            os.unlink(temp_file_path)

    @patch('boot_sector_analyzer.internet_checker.InternetChecker.query_virustotal')
    @patch('boot_sector_analyzer.internet_checker.InternetChecker.query_virustotal_boot_code')
    def test_virustotal_error_handling_in_enhanced_workflow(self, mock_boot_code_query, mock_full_query):
        """Test error handling in enhanced VirusTotal workflow."""
        # Create boot sector with non-empty boot code
        boot_sector_data = self.create_sample_boot_sector_with_code()
        full_sector_hash = hashlib.sha256(boot_sector_data).hexdigest()
        
        # Create successful full sector response
        full_sector_vt_result = self.create_mock_virustotal_response(full_sector_hash, detection_count=0)
        full_sector_vt_result.stats.malicious = 0
        full_sector_vt_result.stats.suspicious = 0
        full_sector_vt_result.stats.undetected = 50
        full_sector_vt_result.detection_count = 0
        
        # Set up mocks: full sector succeeds, boot code fails
        mock_full_query.return_value = full_sector_vt_result
        mock_boot_code_query.side_effect = Exception("API quota exceeded")
        
        # Create analyzer with API key
        analyzer = BootSectorAnalyzer(api_key="test_api_key")
        
        # Create temporary boot sector file
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file.write(boot_sector_data)
            temp_file_path = temp_file.name
        
        try:
            # Mock network connectivity
            with patch.object(analyzer.internet_checker, '_check_network_connectivity', return_value=True):
                # Perform analysis with threat intelligence
                result = analyzer.analyze(temp_file_path, include_threat_intelligence=True)
            
            # Verify analysis completed despite boot code query failure
            assert isinstance(result, AnalysisResult)
            
            # Verify full sector threat intelligence is present
            assert result.threat_intelligence is not None
            assert result.threat_intelligence.virustotal_result is not None
            assert result.threat_intelligence.virustotal_result.hash_value == full_sector_hash
            
            # Verify boot code threat intelligence is None due to API error
            assert result.boot_code_threat_intelligence is None
            
            # Verify both queries were attempted
            assert mock_full_query.called
            assert mock_boot_code_query.called
            
        finally:
            # Clean up
            os.unlink(temp_file_path)

    def test_enhanced_virustotal_caching_behavior(self):
        """Test caching behavior for enhanced VirusTotal functionality."""
        with tempfile.TemporaryDirectory() as temp_dir:
            # Create InternetChecker with custom cache directory
            checker = InternetChecker(api_key="test_api_key", cache_dir=temp_dir)
            
            # Create test boot code
            boot_code = b'\x33\xc0\x8e\xd0' + b'\x00' * 442  # Non-empty boot code
            boot_code_hash = hashlib.sha256(boot_code).hexdigest()
            
            # Create mock VirusTotal result
            vt_result = self.create_mock_virustotal_response(boot_code_hash, detection_count=2)
            
            # Cache the result
            checker._cache_result(boot_code_hash, vt_result)
            
            # Verify cache file exists
            cache_file = Path(temp_dir) / f"{boot_code_hash}.json"
            assert cache_file.exists()
            
            # Verify cached data structure includes enhanced fields
            with open(cache_file, 'r') as f:
                cache_data = json.load(f)
            
            result_data = cache_data["result"]
            assert "stats" in result_data
            assert "engine_results" in result_data
            assert "raw_response" in result_data
            
            # Verify stats data
            stats_data = result_data["stats"]
            assert stats_data["malicious"] == 1  # detection_count=2 means 1 malicious + 1 suspicious
            assert stats_data["suspicious"] == 1
            assert stats_data["undetected"] == 48
            
            # Verify engine results data
            engine_results_data = result_data["engine_results"]
            assert len(engine_results_data) == 3
            assert engine_results_data[0]["engine_name"] == "Engine1"
            assert engine_results_data[0]["detected"] is True
            assert engine_results_data[0]["result"] == "Trojan.Generic"
            
            # Verify raw response data
            raw_response_data = result_data["raw_response"]
            assert raw_response_data["id"] == boot_code_hash
            assert raw_response_data["type"] == "file"
            assert "attributes" in raw_response_data
            
            # Test cache retrieval
            retrieved_result = checker._get_cached_result(boot_code_hash)
            assert retrieved_result is not None
            assert retrieved_result.hash_value == boot_code_hash
            assert retrieved_result.detection_count == 2  # As specified in the mock
            assert retrieved_result.stats is not None
            assert retrieved_result.stats.malicious == 1  # detection_count=2 means 1 malicious + 1 suspicious
            assert len(retrieved_result.engine_results) == 3
            assert retrieved_result.raw_response is not None


if __name__ == "__main__":
    pytest.main([__file__])