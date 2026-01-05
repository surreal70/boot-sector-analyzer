"""Property-based tests for InternetChecker."""

import json
import pytest
from datetime import datetime
from hypothesis import given, strategies as st, assume, settings
from hypothesis import HealthCheck
from unittest.mock import Mock, patch, MagicMock
import requests
import ssl
from boot_sector_analyzer.internet_checker import InternetChecker


class TestInternetCheckerProperties:
    """Property-based tests for InternetChecker functionality."""

    @given(st.text(min_size=1, max_size=50, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd'), min_codepoint=32, max_codepoint=126)))
    def test_ssl_certificate_validation_property(self, url_path):
        """
        Property 12: SSL certificate validation
        For any HTTPS URL, SSL certificates should be validated to ensure secure connections.
        **Validates: Requirements 5.6**
        """
        # Feature: boot-sector-analyzer, Property 12: SSL certificate validation
        # Create a valid HTTPS URL
        safe_path = url_path.replace(' ', '_').replace('/', '_')
        test_url = f"https://example.com/{safe_path}"
        
        checker = InternetChecker()
        
        # Mock the session to simulate SSL validation
        with patch.object(checker.session, 'get') as mock_get:
            # Test case 1: Valid SSL certificate
            mock_response = Mock()
            mock_response.status_code = 200
            mock_get.return_value = mock_response
            
            result = checker._validate_ssl_certificate(test_url)
            
            # Should call get with verify=True for SSL validation
            mock_get.assert_called_with(test_url, timeout=10, verify=True)
            assert result is True
            
            # Test case 2: SSL certificate validation failure
            mock_get.side_effect = requests.exceptions.SSLError("Certificate verification failed")
            
            result = checker._validate_ssl_certificate(test_url)
            assert result is False

    @given(st.booleans())
    def test_network_connectivity_handling_property(self, network_available):
        """
        Property: Network connectivity handling
        For any network state, the system should handle connectivity issues gracefully.
        **Validates: Requirements 5.3**
        """
        # Feature: boot-sector-analyzer, Property: Network connectivity handling
        checker = InternetChecker()
        
        with patch.object(checker.session, 'get') as mock_get:
            if network_available:
                # Simulate successful network connection
                mock_response = Mock()
                mock_response.status_code = 200
                mock_get.return_value = mock_response
                
                result = checker._check_network_connectivity()
                assert result is True
            else:
                # Simulate network failure
                mock_get.side_effect = requests.exceptions.ConnectionError("Network unreachable")
                
                result = checker._check_network_connectivity()
                assert result is False

    @given(st.text(min_size=1, max_size=20, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd'))))
    def test_ssl_context_configuration_property(self, api_key):
        """
        Property: SSL context configuration
        For any InternetChecker instance, SSL context should be properly configured.
        **Validates: Requirements 5.6**
        """
        # Feature: boot-sector-analyzer, Property: SSL context configuration
        
        checker = InternetChecker(api_key=api_key)
        
        # Verify SSL context is properly configured
        assert checker.ssl_context is not None
        assert checker.ssl_context.check_hostname is True
        assert checker.ssl_context.verify_mode == ssl.CERT_REQUIRED
        
        # Verify session has SSL verification enabled
        assert checker.session.verify is True

    @settings(deadline=None)
    @given(st.text(min_size=64, max_size=64, alphabet='0123456789abcdef'))
    def test_virustotal_ssl_validation_property(self, file_hash):
        """
        Property: VirusTotal API SSL validation
        For any VirusTotal API call, SSL certificates should be validated.
        **Validates: Requirements 5.6**
        """
        # Feature: boot-sector-analyzer, Property: VirusTotal API SSL validation
        checker = InternetChecker(api_key="test_api_key")
        
        # Mock vt.Client to simulate SSL validation
        with patch('boot_sector_analyzer.internet_checker.vt.Client') as mock_vt_client:
            # Test SSL error handling
            mock_client_instance = MagicMock()
            mock_vt_client.return_value.__enter__.return_value = mock_client_instance
            mock_client_instance.get_object.side_effect = requests.exceptions.SSLError("SSL verification failed")
            
            result = checker.query_virustotal(file_hash)
            
            # Should return None when SSL validation fails
            assert result is None

    @given(st.text(min_size=64, max_size=64, alphabet='0123456789abcdef'))
    def test_threat_intelligence_caching_property(self, file_hash):
        """
        Property 11: Threat intelligence caching
        For any threat intelligence query result, the Internet_Checker should cache the result 
        and reuse it for subsequent identical queries.
        **Validates: Requirements 5.4**
        """
        # Feature: boot-sector-analyzer, Property 11: Threat intelligence caching
        import tempfile
        import shutil
        
        # Create temporary cache directory
        with tempfile.TemporaryDirectory() as temp_dir:
            checker = InternetChecker(api_key="test_key", cache_dir=temp_dir)
            
            # Create a mock VirusTotalResult
            from boot_sector_analyzer.models import VirusTotalResult
            from datetime import datetime
            
            mock_result = VirusTotalResult(
                hash_value=file_hash,
                detection_count=5,
                total_engines=50,
                scan_date=datetime.now(),
                permalink=f"https://www.virustotal.com/gui/file/{file_hash}",
                detections={"engine1": {"detected": True, "result": "Malware"}}
            )
            
            # Cache the result
            checker._cache_result(file_hash, mock_result)
            
            # Verify result is cached
            cached_result = checker._get_cached_result(file_hash)
            assert cached_result is not None
            assert cached_result.hash_value == file_hash
            assert cached_result.detection_count == 5
            assert cached_result.total_engines == 50
            
            # Test that subsequent queries use cache
            with patch('boot_sector_analyzer.internet_checker.vt.Client') as mock_vt:
                # This should not be called since we have cached result
                result = checker.query_virustotal(file_hash)
                
                # Should return cached result without calling API
                mock_vt.assert_not_called()
                assert result is not None
                assert result.hash_value == file_hash

    @given(st.text(min_size=64, max_size=64, alphabet='0123456789abcdef'))
    def test_negative_caching_property(self, file_hash):
        """
        Property: Negative result caching
        For any hash not found in VirusTotal, the system should cache the negative result
        to avoid repeated queries.
        **Validates: Requirements 5.4**
        """
        # Feature: boot-sector-analyzer, Property: Negative result caching
        import tempfile
        
        with tempfile.TemporaryDirectory() as temp_dir:
            checker = InternetChecker(api_key="test_key", cache_dir=temp_dir)
            
            # Cache negative result
            checker._cache_negative_result(file_hash)
            
            # Verify negative result is cached
            assert checker._check_negative_cache(file_hash) is True
            
            # Test that subsequent queries use negative cache
            with patch('boot_sector_analyzer.internet_checker.vt.Client') as mock_vt:
                result = checker.query_virustotal(file_hash)
                
                # Should return None without calling API due to negative cache
                mock_vt.assert_not_called()
                assert result is None

    @given(st.integers(min_value=1, max_value=100))
    def test_cache_expiration_property(self, hours_offset):
        """
        Property: Cache expiration
        For any cached result older than 24 hours, the cache should be considered expired.
        **Validates: Requirements 5.4**
        """
        # Feature: boot-sector-analyzer, Property: Cache expiration
        import tempfile
        from datetime import timedelta
        
        with tempfile.TemporaryDirectory() as temp_dir:
            checker = InternetChecker(cache_dir=temp_dir)
            file_hash = "a" * 64  # Valid hash format
            
            # Create expired cache entry
            cache_file = checker.cache_dir / f"{file_hash}.json"
            expired_time = datetime.now() - timedelta(hours=25)  # Older than 24 hours
            
            cache_data = {
                "cached_at": expired_time.isoformat(),
                "result": {
                    "hash_value": file_hash,
                    "detection_count": 0,
                    "total_engines": 0,
                    "scan_date": None,
                    "permalink": None,
                    "detections": {}
                }
            }
            
            with open(cache_file, "w") as f:
                json.dump(cache_data, f)
            
            # Verify expired cache is not returned
            cached_result = checker._get_cached_result(file_hash)
            assert cached_result is None
            
            # Verify expired cache file is removed
            assert not cache_file.exists()

    @given(st.binary(min_size=446, max_size=512))
    def test_boot_code_specific_virustotal_analysis_property(self, boot_code):
        """
        Property 61: Boot code specific VirusTotal analysis
        For any boot sector with non-empty boot code, the Internet_Checker should submit only 
        the boot code region (first 446 bytes) to VirusTotal for targeted malware analysis.
        **Validates: Requirements 5.8**
        """
        # Feature: boot-sector-analyzer, Property 61: Boot code specific VirusTotal analysis
        import tempfile
        import hashlib
        
        # Ensure boot code is not all zeros (non-empty)
        assume(not all(byte == 0 for byte in boot_code[:446]))
        
        with tempfile.TemporaryDirectory() as temp_dir:
            checker = InternetChecker(api_key="test_api_key", cache_dir=temp_dir)
            
            # Calculate expected hash of boot code region (first 446 bytes)
            boot_code_region = boot_code[:446]
            expected_hash = hashlib.sha256(boot_code_region).hexdigest()
            
            with patch('boot_sector_analyzer.internet_checker.vt.Client') as mock_vt_client:
                # Mock successful VirusTotal response
                mock_client_instance = MagicMock()
                mock_vt_client.return_value.__enter__.return_value = mock_client_instance
                
                # Mock file object with analysis results
                mock_file_obj = Mock()
                mock_file_obj.last_analysis_stats = {"malicious": 2, "suspicious": 1, "clean": 47}
                mock_file_obj.last_analysis_date = 1640995200  # Mock timestamp
                mock_file_obj.last_analysis_results = {
                    "engine1": Mock(result="Malware.Generic", category="malicious"),
                    "engine2": Mock(result="Clean", category="clean")
                }
                mock_client_instance.get_object.return_value = mock_file_obj
                
                # Mock network connectivity
                with patch.object(checker, '_check_network_connectivity', return_value=True):
                    result = checker.query_virustotal_boot_code(boot_code)
                
                # Verify that VirusTotal was queried with the boot code hash
                mock_client_instance.get_object.assert_called_once_with(f"/files/{expected_hash}")
                
                # Verify result contains boot code hash, not full boot sector hash
                assert result is not None
                assert result.hash_value == expected_hash
                assert result.detection_count == 3  # malicious + suspicious
                assert result.total_engines == 50  # sum of all stats
                assert result.permalink == f"https://www.virustotal.com/gui/file/{expected_hash}"

    @given(st.integers(min_value=446, max_value=512))
    def test_empty_boot_code_virustotal_handling_property(self, boot_sector_size):
        """
        Property 62: Empty boot code VirusTotal handling
        For any boot sector where the boot code region contains only zero bytes, 
        the Internet_Checker should skip VirusTotal submission and report this condition appropriately.
        **Validates: Requirements 5.9**
        """
        # Feature: boot-sector-analyzer, Property 62: Empty boot code VirusTotal handling
        import tempfile
        
        # Create boot sector with all-zero boot code region (first 446 bytes)
        boot_code = bytes(446)  # All zeros for boot code region
        if boot_sector_size > 446:
            # Add some non-zero data after boot code region (partition table, etc.)
            remaining_bytes = boot_sector_size - 446
            if remaining_bytes >= 2:
                # Add boot signature and padding
                boot_code += bytes([0x55, 0xAA]) + bytes(remaining_bytes - 2)
            else:
                # Just add padding
                boot_code += bytes(remaining_bytes)
        
        with tempfile.TemporaryDirectory() as temp_dir:
            checker = InternetChecker(api_key="test_api_key", cache_dir=temp_dir)
            
            # Verify should_skip_virustotal returns True for empty boot code
            assert checker.should_skip_virustotal(boot_code) is True
            
            with patch('boot_sector_analyzer.internet_checker.vt.Client') as mock_vt_client:
                # Mock network connectivity
                with patch.object(checker, '_check_network_connectivity', return_value=True):
                    result = checker.query_virustotal_boot_code(boot_code)
                
                # Verify that VirusTotal API was NOT called for empty boot code
                mock_vt_client.assert_not_called()
                
                # Verify result is None (skipped)
                assert result is None