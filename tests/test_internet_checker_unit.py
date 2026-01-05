"""Unit tests for InternetChecker API integration scenarios."""

import pytest
import tempfile
import json
from datetime import datetime
from pathlib import Path
from unittest.mock import Mock, patch, MagicMock
import requests
import vt
from boot_sector_analyzer.internet_checker import InternetChecker
from boot_sector_analyzer.models import VirusTotalResult, VirusTotalStats, VirusTotalEngineResult


class TestInternetCheckerUnit:
    """Unit tests for InternetChecker API integration scenarios."""

    def test_missing_api_key(self):
        """Test behavior when API key is missing."""
        checker = InternetChecker(api_key=None)
        
        result = checker.query_virustotal("a" * 64)
        assert result is None
        
        # Test boot code specific method as well
        result_boot = checker.query_virustotal_boot_code(b"test_boot_code" + b"\x00" * 440)
        assert result_boot is None

    def test_empty_api_key(self):
        """Test behavior when API key is empty string."""
        checker = InternetChecker(api_key="")
        
        result = checker.query_virustotal("a" * 64)
        assert result is None
        
        # Test boot code specific method as well
        result_boot = checker.query_virustotal_boot_code(b"test_boot_code" + b"\x00" * 440)
        assert result_boot is None

    @patch('boot_sector_analyzer.internet_checker.vt.Client')
    def test_network_failure(self, mock_vt_client):
        """Test handling of network failures."""
        checker = InternetChecker(api_key="test_key")
        
        # Mock network failure
        mock_client_instance = MagicMock()
        mock_vt_client.return_value.__enter__.return_value = mock_client_instance
        mock_client_instance.get_object.side_effect = requests.exceptions.ConnectionError("Network unreachable")
        
        result = checker.query_virustotal("a" * 64)
        
        assert result is None

    @patch('boot_sector_analyzer.internet_checker.vt.Client')
    def test_api_quota_exceeded(self, mock_vt_client):
        """Test handling of API quota exceeded."""
        checker = InternetChecker(api_key="test_key")
        
        # Mock quota exceeded error
        mock_client_instance = MagicMock()
        mock_vt_client.return_value.__enter__.return_value = mock_client_instance
        mock_client_instance.get_object.side_effect = vt.APIError("QuotaExceededError", "Quota exceeded")
        
        result = checker.query_virustotal("a" * 64)
        
        assert result is None

    @patch('boot_sector_analyzer.internet_checker.vt.Client')
    def test_api_authentication_error(self, mock_vt_client):
        """Test handling of API authentication errors."""
        checker = InternetChecker(api_key="invalid_key")
        
        # Mock authentication error
        mock_client_instance = MagicMock()
        mock_vt_client.return_value.__enter__.return_value = mock_client_instance
        mock_client_instance.get_object.side_effect = vt.APIError("AuthenticationRequiredError", "Invalid API key")
        
        result = checker.query_virustotal("a" * 64)
        
        assert result is None

    @patch('boot_sector_analyzer.internet_checker.vt.Client')
    def test_api_not_found_error(self, mock_vt_client):
        """Test handling of file not found in VirusTotal."""
        checker = InternetChecker(api_key="test_key")
        
        # Mock not found error
        mock_client_instance = MagicMock()
        mock_vt_client.return_value.__enter__.return_value = mock_client_instance
        mock_client_instance.get_object.side_effect = vt.APIError("NotFoundError", "File not found")
        
        result = checker.query_virustotal("a" * 64)
        
        assert result is None

    @patch('boot_sector_analyzer.internet_checker.vt.Client')
    def test_ssl_error_handling(self, mock_vt_client):
        """Test handling of SSL certificate errors."""
        checker = InternetChecker(api_key="test_key")
        
        # Mock SSL error
        mock_client_instance = MagicMock()
        mock_vt_client.return_value.__enter__.return_value = mock_client_instance
        mock_client_instance.get_object.side_effect = requests.exceptions.SSLError("SSL certificate verification failed")
        
        result = checker.query_virustotal("a" * 64)
        
        assert result is None

    @patch('boot_sector_analyzer.internet_checker.vt.Client')
    def test_timeout_error_handling(self, mock_vt_client):
        """Test handling of request timeout errors."""
        checker = InternetChecker(api_key="test_key")
        
        # Mock timeout error
        mock_client_instance = MagicMock()
        mock_vt_client.return_value.__enter__.return_value = mock_client_instance
        mock_client_instance.get_object.side_effect = requests.exceptions.Timeout("Request timed out")
        
        result = checker.query_virustotal("a" * 64)
        
        assert result is None

    def test_rate_limiting_enforcement(self):
        """Test that rate limiting is properly enforced."""
        import time
        
        checker = InternetChecker(api_key="test_key")
        checker.min_request_interval = 1  # 1 second for testing
        
        # Record start time
        start_time = time.time()
        
        # Make first "request"
        checker._enforce_rate_limit()
        first_request_time = time.time()
        
        # Make second "request" immediately
        checker._enforce_rate_limit()
        second_request_time = time.time()
        
        # Second request should be delayed by at least the minimum interval
        time_diff = second_request_time - first_request_time
        assert time_diff >= checker.min_request_interval

    def test_cache_directory_creation(self):
        """Test that cache directory is created if it doesn't exist."""
        import tempfile
        import os
        
        with tempfile.TemporaryDirectory() as temp_dir:
            cache_path = os.path.join(temp_dir, "nonexistent", "cache")
            
            checker = InternetChecker(cache_dir=cache_path)
            
            assert os.path.exists(cache_path)
            assert os.path.isdir(cache_path)

    def test_network_connectivity_check_success(self):
        """Test successful network connectivity check."""
        checker = InternetChecker()
        
        with patch.object(checker.session, 'get') as mock_get:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_get.return_value = mock_response
            
            result = checker._check_network_connectivity()
            
            assert result is True
            mock_get.assert_called_once()

    def test_network_connectivity_check_failure(self):
        """Test network connectivity check failure."""
        checker = InternetChecker()
        
        with patch.object(checker.session, 'get') as mock_get:
            mock_get.side_effect = requests.exceptions.ConnectionError("No network")
            
            result = checker._check_network_connectivity()
            
            assert result is False

    def test_clear_expired_cache(self):
        """Test clearing of expired cache entries."""
        import tempfile
        import json
        from datetime import datetime, timedelta
        
        with tempfile.TemporaryDirectory() as temp_dir:
            checker = InternetChecker(cache_dir=temp_dir)
            
            # Create expired cache file
            expired_file = checker.cache_dir / "expired.json"
            expired_data = {
                "cached_at": (datetime.now() - timedelta(hours=25)).isoformat(),
                "result": {"test": "data"}
            }
            with open(expired_file, "w") as f:
                json.dump(expired_data, f)
            
            # Create valid cache file
            valid_file = checker.cache_dir / "valid.json"
            valid_data = {
                "cached_at": datetime.now().isoformat(),
                "result": {"test": "data"}
            }
            with open(valid_file, "w") as f:
                json.dump(valid_data, f)
            
            # Clear expired cache
            cleared_count = checker.clear_expired_cache()
            
            assert cleared_count == 1
            assert not expired_file.exists()
            assert valid_file.exists()

    def test_corrupted_cache_handling(self):
        """Test handling of corrupted cache files."""
        import tempfile
        
        with tempfile.TemporaryDirectory() as temp_dir:
            checker = InternetChecker(cache_dir=temp_dir)
            
            # Create corrupted cache file with proper hash filename
            test_hash = "a" * 64
            corrupted_file = checker.cache_dir / f"{test_hash}.json"
            with open(corrupted_file, "w") as f:
                f.write("invalid json content")
            
            # Try to get cached result
            result = checker._get_cached_result(test_hash)
            
            assert result is None
            # Corrupted file should be removed
            assert not corrupted_file.exists()

    @patch('boot_sector_analyzer.internet_checker.vt.Client')
    def test_backward_compatibility_with_existing_virustotal_integration(self, mock_vt_client):
        """Test that enhanced VirusTotal functionality maintains backward compatibility."""
        checker = InternetChecker(api_key="test_key")
        
        # Mock VirusTotal response with enhanced data
        mock_client_instance = MagicMock()
        mock_vt_client.return_value.__enter__.return_value = mock_client_instance
        
        mock_file_obj = Mock()
        mock_file_obj.last_analysis_stats = {"malicious": 2, "suspicious": 1, "undetected": 47}
        mock_file_obj.last_analysis_date = 1640995200
        mock_file_obj.last_analysis_results = {
            "Engine1": Mock(result="Trojan.Test", category="malicious", engine_version="1.0", engine_update="20240101"),
            "Engine2": Mock(result="Suspicious.Code", category="suspicious", engine_version="2.0", engine_update="20240101")
        }
        # Add enhanced attributes
        mock_file_obj.id = "test_hash"
        mock_file_obj.type = "file"
        mock_file_obj.md5 = "mock_md5"
        mock_file_obj.sha1 = "mock_sha1"
        mock_file_obj.size = 512
        mock_file_obj.type_description = "data"
        mock_file_obj.magic = "data"
        mock_file_obj.first_submission_date = 1640995100
        mock_file_obj.last_submission_date = 1640995200
        mock_file_obj.times_submitted = 5
        mock_file_obj.reputation = -5
        
        mock_client_instance.get_object.return_value = mock_file_obj
        
        # Mock network connectivity
        with patch.object(checker, '_check_network_connectivity', return_value=True):
            result = checker.query_virustotal("test_hash")
        
        # Verify backward compatibility - basic fields still work
        assert result is not None
        assert result.hash_value == "test_hash"
        assert result.detection_count == 3  # malicious + suspicious
        assert result.total_engines == 50
        assert result.permalink == "https://www.virustotal.com/gui/file/test_hash"
        assert "Engine1" in result.detections
        assert result.detections["Engine1"]["result"] == "Trojan.Test"
        
        # Verify enhanced fields are also populated
        assert result.stats is not None
        assert result.stats.malicious == 2
        assert result.stats.suspicious == 1
        assert result.stats.undetected == 47
        
        assert result.engine_results is not None
        assert len(result.engine_results) == 2
        
        assert result.raw_response is not None
        assert result.raw_response["id"] == "test_hash"
        assert result.raw_response["type"] == "file"

    @patch('boot_sector_analyzer.internet_checker.vt.Client')
    def test_enhanced_virustotal_properties_validation(self, mock_vt_client):
        """Test that all enhanced VirusTotal properties pass validation."""
        checker = InternetChecker(api_key="test_key")
        
        # Create comprehensive mock response
        mock_client_instance = MagicMock()
        mock_vt_client.return_value.__enter__.return_value = mock_client_instance
        
        mock_file_obj = Mock()
        mock_file_obj.last_analysis_stats = {
            "malicious": 5, "suspicious": 2, "undetected": 40, "harmless": 3,
            "timeout": 0, "confirmed-timeout": 0, "failure": 0, "type-unsupported": 0
        }
        mock_file_obj.last_analysis_date = 1640995200
        mock_file_obj.last_analysis_results = {
            "Avast": Mock(result="Trojan.Boot", category="malicious", engine_version="21.1.0", engine_update="20240101"),
            "Kaspersky": Mock(result="HEUR:Trojan.Boot", category="malicious", engine_version="15.0.1", engine_update="20240101"),
            "McAfee": Mock(result="Suspicious.Code", category="suspicious", engine_version="6.0.6", engine_update="20240101"),
            "Symantec": Mock(result="Clean", category="undetected", engine_version="1.17.0", engine_update="20240101")
        }
        # Enhanced attributes
        mock_file_obj.id = "enhanced_test_hash"
        mock_file_obj.type = "file"
        mock_file_obj.md5 = "enhanced_md5_hash"
        mock_file_obj.sha1 = "enhanced_sha1_hash"
        mock_file_obj.size = 446
        mock_file_obj.type_description = "data"
        mock_file_obj.magic = "data"
        mock_file_obj.first_submission_date = 1640995100
        mock_file_obj.last_submission_date = 1640995200
        mock_file_obj.times_submitted = 15
        mock_file_obj.reputation = -20
        
        mock_client_instance.get_object.return_value = mock_file_obj
        
        # Mock network connectivity
        with patch.object(checker, '_check_network_connectivity', return_value=True):
            result = checker.query_virustotal("enhanced_test_hash")
        
        # Validate all enhanced properties are correctly populated
        assert result is not None
        
        # Basic properties
        assert result.hash_value == "enhanced_test_hash"
        assert result.detection_count == 7  # 5 malicious + 2 suspicious
        assert result.total_engines == 50
        
        # Enhanced stats validation
        assert result.stats is not None
        assert result.stats.malicious == 5
        assert result.stats.suspicious == 2
        assert result.stats.undetected == 40
        assert result.stats.harmless == 3
        assert result.stats.timeout == 0
        assert result.stats.confirmed_timeout == 0
        assert result.stats.failure == 0
        assert result.stats.type_unsupported == 0
        
        # Engine results validation
        assert result.engine_results is not None
        assert len(result.engine_results) == 4
        
        # Find and validate specific engine results
        avast_result = next((er for er in result.engine_results if er.engine_name == "Avast"), None)
        assert avast_result is not None
        assert avast_result.detected is True
        assert avast_result.result == "Trojan.Boot"
        assert avast_result.category == "malicious"
        assert avast_result.engine_version == "21.1.0"
        assert avast_result.engine_update == "20240101"
        
        symantec_result = next((er for er in result.engine_results if er.engine_name == "Symantec"), None)
        assert symantec_result is not None
        assert symantec_result.detected is False
        assert symantec_result.result is None
        assert symantec_result.category == "undetected"
        
        # Raw response validation
        assert result.raw_response is not None
        assert result.raw_response["id"] == "enhanced_test_hash"
        assert result.raw_response["type"] == "file"
        assert "attributes" in result.raw_response
        
        attributes = result.raw_response["attributes"]
        assert attributes["sha256"] == "enhanced_test_hash"
        assert attributes["md5"] == "enhanced_md5_hash"
        assert attributes["size"] == 446
        assert attributes["times_submitted"] == 15
        assert attributes["reputation"] == -20

    def test_empty_boot_code_detection(self):
        """Test detection of empty boot code for VirusTotal skipping."""
        checker = InternetChecker(api_key="test_key")
        
        # Test with all-zero boot code
        empty_boot_code = bytes(446)  # All zeros
        assert checker.should_skip_virustotal(empty_boot_code) is True
        
        # Test with non-empty boot code
        non_empty_boot_code = b'\x33\xc0\x8e\xd0' + bytes(442)  # Some non-zero bytes
        assert checker.should_skip_virustotal(non_empty_boot_code) is False
        
        # Test with empty input
        assert checker.should_skip_virustotal(b'') is True
        
        # Test with partial boot code
        partial_boot_code = bytes(200)  # Less than 446 bytes, all zeros
        assert checker.should_skip_virustotal(partial_boot_code) is True

    @patch('boot_sector_analyzer.internet_checker.vt.Client')
    def test_negative_virustotal_result_handling(self, mock_vt_client):
        """Test handling and display of negative (clean) VirusTotal results."""
        checker = InternetChecker(api_key="test_key")
        
        # Create comprehensive mock response for clean file
        mock_client_instance = MagicMock()
        mock_vt_client.return_value.__enter__.return_value = mock_client_instance
        
        # Create proper mock result objects for engines
        avast_result = Mock()
        avast_result.result = None  # Clean result has no result value
        avast_result.category = "undetected"
        avast_result.engine_version = "21.1.0"
        avast_result.engine_update = "20240101"
        
        kaspersky_result = Mock()
        kaspersky_result.result = None  # Clean result has no result value
        kaspersky_result.category = "undetected"
        kaspersky_result.engine_version = "15.0.1"
        kaspersky_result.engine_update = "20240101"
        
        mcafee_result = Mock()
        mcafee_result.result = None  # Clean result has no result value
        mcafee_result.category = "undetected"
        mcafee_result.engine_version = "6.0.6"
        mcafee_result.engine_update = "20240101"
        
        mock_file_obj = Mock()
        mock_file_obj.last_analysis_stats = {
            "malicious": 0, "suspicious": 0, "undetected": 50, "harmless": 0,
            "timeout": 0, "confirmed-timeout": 0, "failure": 0, "type-unsupported": 0
        }
        mock_file_obj.last_analysis_date = 1640995200
        mock_file_obj.last_analysis_results = {
            "Avast": avast_result,
            "Kaspersky": kaspersky_result,
            "McAfee": mcafee_result
        }
        # Enhanced attributes for clean file
        mock_file_obj.id = "clean_test_hash"
        mock_file_obj.type = "file"
        mock_file_obj.md5 = "clean_md5_hash"
        mock_file_obj.sha1 = "clean_sha1_hash"
        mock_file_obj.size = 446
        mock_file_obj.type_description = "data"
        mock_file_obj.magic = "data"
        mock_file_obj.first_submission_date = 1640995100
        mock_file_obj.last_submission_date = 1640995200
        mock_file_obj.times_submitted = 5
        mock_file_obj.reputation = 10  # Good reputation for clean file
        
        mock_client_instance.get_object.return_value = mock_file_obj
        
        # Mock network connectivity and disable caching for this test
        with patch.object(checker, '_check_network_connectivity', return_value=True), \
             patch.object(checker, '_cache_result'), \
             patch.object(checker, '_get_cached_result', return_value=None):
            result = checker.query_virustotal("clean_test_hash")
        
        # Verify clean result is properly structured
        assert result is not None
        assert result.hash_value == "clean_test_hash"
        assert result.detection_count == 0  # Clean result
        assert result.total_engines == 50
        
        # Verify clean stats are captured
        assert result.stats is not None
        assert result.stats.malicious == 0
        assert result.stats.suspicious == 0
        assert result.stats.undetected == 50
        assert result.stats.harmless == 0
        
        # For clean results, engine_results will be empty since result.result is None
        # This is the current behavior of the InternetChecker
        assert result.engine_results is not None
        assert len(result.engine_results) == 0  # Clean results don't populate engine_results
        
        # Verify detections is empty for clean result
        assert result.detections == {}
        
        # Verify raw response contains clean data
        assert result.raw_response is not None
        assert result.raw_response["id"] == "clean_test_hash"
        attributes = result.raw_response["attributes"]
        assert attributes["reputation"] == 10  # Good reputation
        assert attributes["last_analysis_stats"]["malicious"] == 0
        assert attributes["last_analysis_stats"]["undetected"] == 50

    @patch('boot_sector_analyzer.internet_checker.vt.Client')
    def test_clean_boot_code_virustotal_response(self, mock_vt_client):
        """Test VirusTotal response for clean boot code analysis."""
        checker = InternetChecker(api_key="test_key")
        
        # Create proper mock result objects for engines
        avast_result = Mock()
        avast_result.result = None  # Clean result has no result value
        avast_result.category = "undetected"
        avast_result.engine_version = "21.1.0"
        avast_result.engine_update = "20240101"
        
        kaspersky_result = Mock()
        kaspersky_result.result = None  # Clean result has no result value
        kaspersky_result.category = "undetected"
        kaspersky_result.engine_version = "15.0.1"
        kaspersky_result.engine_update = "20240101"
        
        mcafee_result = Mock()
        mcafee_result.result = None  # Clean result has no result value
        mcafee_result.category = "harmless"
        mcafee_result.engine_version = "6.0.6"
        mcafee_result.engine_update = "20240101"
        
        symantec_result = Mock()
        symantec_result.result = None  # Clean result has no result value
        symantec_result.category = "harmless"
        symantec_result.engine_version = "1.17.0"
        symantec_result.engine_update = "20240101"
        
        # Create mock response for clean boot code
        mock_client_instance = MagicMock()
        mock_vt_client.return_value.__enter__.return_value = mock_client_instance
        
        mock_file_obj = Mock()
        mock_file_obj.last_analysis_stats = {
            "malicious": 0, "suspicious": 0, "undetected": 48, "harmless": 2,
            "timeout": 0, "confirmed-timeout": 0, "failure": 0, "type-unsupported": 0
        }
        mock_file_obj.last_analysis_date = 1640995200
        mock_file_obj.last_analysis_results = {
            "Avast": avast_result,
            "Kaspersky": kaspersky_result,
            "McAfee": mcafee_result,
            "Symantec": symantec_result
        }
        mock_file_obj.id = "clean_boot_code_hash"
        mock_file_obj.type = "file"
        mock_file_obj.md5 = "clean_boot_md5"
        mock_file_obj.sha1 = "clean_boot_sha1"
        mock_file_obj.size = 446  # Boot code size
        mock_file_obj.type_description = "data"
        mock_file_obj.magic = "data"
        mock_file_obj.first_submission_date = 1640995100
        mock_file_obj.last_submission_date = 1640995200
        mock_file_obj.times_submitted = 3
        mock_file_obj.reputation = 5  # Good reputation
        
        mock_client_instance.get_object.return_value = mock_file_obj
        
        # Test boot code specific query
        boot_code = b'\x33\xc0\x8e\xd0' + bytes(442)  # Non-empty but clean boot code
        
        # Mock network connectivity and disable caching for this test
        with patch.object(checker, '_check_network_connectivity', return_value=True), \
             patch.object(checker, '_cache_result'), \
             patch.object(checker, '_get_cached_result', return_value=None):
            result = checker.query_virustotal_boot_code(boot_code)
        
        # Verify clean boot code result
        assert result is not None
        assert result.detection_count == 0  # Clean result
        assert result.stats.malicious == 0
        assert result.stats.suspicious == 0
        assert result.stats.undetected == 48
        assert result.stats.harmless == 2
        
        # For clean results, engine_results will be empty since result.result is None
        # This is the current behavior of the InternetChecker
        assert len(result.engine_results) == 0  # Clean results don't populate engine_results
        
        # Verify detections is empty for clean result
        assert result.detections == {}
        
        # Verify raw response contains clean data
        assert result.raw_response is not None
        attributes = result.raw_response["attributes"]
        assert attributes["reputation"] == 5
        assert attributes["last_analysis_stats"]["malicious"] == 0
        assert attributes["last_analysis_stats"]["undetected"] == 48
        assert attributes["last_analysis_stats"]["harmless"] == 2

    def test_negative_result_caching(self):
        """Test that negative (clean) results are properly cached."""
        with tempfile.TemporaryDirectory() as temp_dir:
            checker = InternetChecker(api_key="test_api_key", cache_dir=temp_dir)
            
            # Create clean VirusTotal result
            clean_hash = "clean_file_hash_" + "a" * 40
            clean_result = VirusTotalResult(
                hash_value=clean_hash,
                detection_count=0,
                total_engines=50,
                scan_date=datetime.now(),
                permalink=f"https://www.virustotal.com/gui/file/{clean_hash}",
                detections={},
                stats=VirusTotalStats(
                    malicious=0, suspicious=0, undetected=50, harmless=0,
                    timeout=0, confirmed_timeout=0, failure=0, type_unsupported=0
                ),
                engine_results=[],
                raw_response={
                    'id': clean_hash,
                    'type': 'file',
                    'attributes': {
                        'last_analysis_stats': {
                            'malicious': 0, 'suspicious': 0, 'undetected': 50, 'harmless': 0,
                            'timeout': 0, 'confirmed-timeout': 0, 'failure': 0, 'type-unsupported': 0
                        },
                        'reputation': 8  # Good reputation
                    }
                }
            )
            
            # Cache the clean result
            checker._cache_result(clean_hash, clean_result)
            
            # Verify cache file exists
            cache_file = Path(temp_dir) / f"{clean_hash}.json"
            assert cache_file.exists()
            
            # Verify cached clean data structure
            with open(cache_file, 'r') as f:
                cache_data = json.load(f)
            
            result_data = cache_data["result"]
            assert result_data["detection_count"] == 0
            assert result_data["stats"]["malicious"] == 0
            assert result_data["stats"]["undetected"] == 50
            assert result_data["raw_response"]["attributes"]["reputation"] == 8
            
            # Test cache retrieval of clean result
            retrieved_result = checker._get_cached_result(clean_hash)
            assert retrieved_result is not None
            assert retrieved_result.hash_value == clean_hash
            assert retrieved_result.detection_count == 0
            assert retrieved_result.stats.malicious == 0
            assert retrieved_result.stats.undetected == 50