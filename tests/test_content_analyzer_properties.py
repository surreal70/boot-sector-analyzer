"""Property-based tests for ContentAnalyzer."""

import hashlib
import re
from hypothesis import given, strategies as st
import pytest

from boot_sector_analyzer.content_analyzer import ContentAnalyzer


class TestContentAnalyzerProperties:
    """Property-based tests for ContentAnalyzer class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.analyzer = ContentAnalyzer()

    @given(boot_code=st.binary(min_size=1, max_size=1024))
    def test_hash_calculation_accuracy(self, boot_code):
        """
        Property 5: Hash calculation accuracy
        For any boot code, the Content_Analyzer should calculate correct MD5 and SHA-256 cryptographic hashes
        **Validates: Requirements 3.1**
        **Feature: boot-sector-analyzer, Property 5: Hash calculation accuracy**
        """
        # Calculate hashes using ContentAnalyzer
        result_hashes = self.analyzer.calculate_hashes(boot_code)
        
        # Verify both hash types are present
        assert "md5" in result_hashes
        assert "sha256" in result_hashes
        
        # Calculate expected hashes directly
        expected_md5 = hashlib.md5(boot_code).hexdigest()
        expected_sha256 = hashlib.sha256(boot_code).hexdigest()
        
        # Verify hash accuracy
        assert result_hashes["md5"] == expected_md5
        assert result_hashes["sha256"] == expected_sha256
        
        # Verify hash format (hex strings)
        assert len(result_hashes["md5"]) == 32
        assert len(result_hashes["sha256"]) == 64
        assert all(c in "0123456789abcdef" for c in result_hashes["md5"])
        assert all(c in "0123456789abcdef" for c in result_hashes["sha256"])

    @given(
        strings=st.lists(
            st.text(
                alphabet=st.characters(min_codepoint=32, max_codepoint=126),
                min_size=4,
                max_size=20
            ),
            min_size=0,
            max_size=5
        ),
        urls=st.lists(
            st.sampled_from([
                "http://example.com",
                "https://malware.test",
                "ftp://files.example.org",
                "https://suspicious-site.net/payload"
            ]),
            min_size=0,
            max_size=3
        ),
        patterns=st.lists(
            st.sampled_from([
                b"\xeb\xfe",  # Infinite loop
                b"\x90\x90\x90\x90",  # NOP sled
                b"\x31\xc0",  # XOR EAX, EAX
                b"\xcc\xcc\xcc\xcc"  # INT3 debug breaks
            ]),
            min_size=0,
            max_size=3
        )
    )
    def test_pattern_and_string_detection(self, strings, urls, patterns):
        """
        Property 6: Pattern and string detection
        For any boot code containing embedded strings, URLs, or suspicious instruction patterns, 
        the Content_Analyzer should successfully identify and extract them
        **Validates: Requirements 3.2, 3.3, 3.6**
        **Feature: boot-sector-analyzer, Property 6: Pattern and string detection**
        """
        # Build boot code with embedded strings, URLs, and patterns
        boot_code = b""
        
        # Add some random padding
        boot_code += b"\x00" * 10
        
        # Embed strings
        for string in strings:
            boot_code += string.encode('ascii', errors='ignore')
            boot_code += b"\x00"  # Null terminator
        
        # Embed URLs
        for url in urls:
            boot_code += url.encode('ascii')
            boot_code += b"\x00"
        
        # Embed suspicious patterns
        for pattern in patterns:
            boot_code += pattern
            boot_code += b"\x00"
        
        # Add more padding
        boot_code += b"\x00" * 10
        
        # Test string extraction
        extracted_strings = self.analyzer.extract_strings(boot_code)
        
        # Verify all embedded strings are found
        for expected_string in strings:
            if len(expected_string) >= 4:  # Only strings >= 4 chars are extracted
                assert any(expected_string in extracted for extracted in extracted_strings), \
                    f"String '{expected_string}' not found in extracted strings: {extracted_strings}"
        
        # Verify all embedded URLs are found
        for expected_url in urls:
            assert any(expected_url in extracted for extracted in extracted_strings), \
                f"URL '{expected_url}' not found in extracted strings: {extracted_strings}"
        
        # Test suspicious pattern detection
        detected_patterns = self.analyzer.detect_suspicious_patterns(boot_code)
        
        # Verify suspicious patterns are detected
        for expected_pattern in patterns:
            pattern_found = any(
                expected_pattern in pattern.data or pattern.data in expected_pattern
                for pattern in detected_patterns
            )
            assert pattern_found, \
                f"Pattern {expected_pattern.hex()} not detected in patterns: {[p.data.hex() for p in detected_patterns]}"

    @given(partition_type=st.integers(min_value=0, max_value=255))
    def test_partition_type_validation(self, partition_type):
        """
        Property 7: Partition type validation
        For any partition entry, the Content_Analyzer should validate the partition type code against known valid types
        **Validates: Requirements 3.4**
        **Feature: boot-sector-analyzer, Property 7: Partition type validation**
        """
        # Test partition type validation
        is_valid = self.analyzer.validate_partition_type(partition_type)
        
        # Define known valid partition types (subset of what's in the implementation)
        known_valid_types = {
            0x00, 0x01, 0x04, 0x05, 0x06, 0x07, 0x0B, 0x0C, 0x0E, 0x0F,
            0x11, 0x14, 0x16, 0x17, 0x1B, 0x1C, 0x1E, 0x42, 0x82, 0x83,
            0x84, 0x85, 0x86, 0x87, 0x88, 0x8E, 0xA0, 0xA5, 0xA6, 0xA7,
            0xA8, 0xA9, 0xAB, 0xAF, 0xB7, 0xB8, 0xBE, 0xBF, 0xC1, 0xC4,
            0xC6, 0xC7, 0xDA, 0xDB, 0xDE, 0xDF, 0xE1, 0xE3, 0xE4, 0xEB,
            0xEE, 0xEF, 0xF0, 0xF1, 0xF4, 0xF2, 0xFB, 0xFC, 0xFD, 0xFE, 0xFF
        }
        
        # Verify that known valid types return True
        if partition_type in known_valid_types:
            assert is_valid, f"Known valid partition type 0x{partition_type:02X} should be validated as True"
        
        # Verify that the result is always a boolean
        assert isinstance(is_valid, bool), f"validate_partition_type should return a boolean, got {type(is_valid)}"