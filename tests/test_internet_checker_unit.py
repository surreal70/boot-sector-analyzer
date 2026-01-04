"""Unit tests for InternetChecker API integration scenarios."""

import pytest
from unittest.mock import Mock, patch, MagicMock
import requests
import vt
from boot_sector_analyzer.internet_checker import InternetChecker
from boot_sector_analyzer.models import VirusTotalResult


class TestInternetCheckerUnit:
    """Unit tests for InternetChecker API integration scenarios."""

    def test_missing_api_key(self):
        """Test behavior when API key is missing."""
        checker = InternetChecker(api_key=None)
        
        result = checker.query_virustotal("a" * 64)
        
        assert result is None

    def test_empty_api_key(self):
        """Test behavior when API key is empty string."""
        checker = InternetChecker(api_key="")
        
        result = checker.query_virustotal("a" * 64)
        
        assert result is None

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