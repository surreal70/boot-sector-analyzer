"""Property-based tests for SecurityScanner functionality."""

import pytest
from hypothesis import given, strategies as st, assume
from boot_sector_analyzer.security_scanner import SecurityScanner
from boot_sector_analyzer.models import ThreatLevel, ThreatMatch, BootkitIndicator, MBRStructure, PartitionEntry


class TestSecurityScannerProperties:
    """Property-based tests for SecurityScanner."""

    def setup_method(self):
        """Set up test fixtures."""
        self.scanner = SecurityScanner()

    @given(
        md5_hash=st.text(min_size=32, max_size=32, alphabet="0123456789abcdef"),
        sha256_hash=st.text(min_size=64, max_size=64, alphabet="0123456789abcdef"),
    )
    def test_property_8_security_threat_detection(self, md5_hash, sha256_hash):
        """
        Property 8: Security threat detection
        For any boot sector with known malware signatures or bootkit patterns,
        the Security_Scanner should detect and classify the threat level appropriately.
        **Validates: Requirements 4.1, 4.2, 4.3**
        **Feature: boot-sector-analyzer, Property 8: Security threat detection**
        """
        # Test hash-based threat detection
        hashes = {"md5": md5_hash, "sha256": sha256_hash}
        
        # Check known signatures
        threat_matches = self.scanner.check_known_signatures(hashes)
        
        # Property: If hash matches known malware, should return threat match
        if md5_hash in self.scanner.known_malware_hashes["md5"]:
            assert len(threat_matches) >= 1
            assert all(isinstance(match, ThreatMatch) for match in threat_matches)
            assert all(match.confidence > 0 for match in threat_matches)
            assert all(match.threat_type == "malware" for match in threat_matches)
        
        if sha256_hash in self.scanner.known_malware_hashes["sha256"]:
            assert len(threat_matches) >= 1
            assert all(isinstance(match, ThreatMatch) for match in threat_matches)

    @given(boot_code=st.binary(min_size=10, max_size=446))
    def test_property_8_bootkit_pattern_detection(self, boot_code):
        """
        Property 8: Bootkit pattern detection
        For any boot code containing bootkit signatures, the Security_Scanner
        should detect bootkit indicators with appropriate confidence levels.
        **Validates: Requirements 4.1, 4.2, 4.3**
        **Feature: boot-sector-analyzer, Property 8: Security threat detection**
        """
        # Test bootkit pattern detection
        bootkit_indicators = self.scanner.detect_bootkit_patterns(boot_code)
        
        # Property: All indicators should be valid BootkitIndicator objects
        assert all(isinstance(indicator, BootkitIndicator) for indicator in bootkit_indicators)
        
        # Property: All indicators should have valid confidence levels
        assert all(0.0 <= indicator.confidence <= 1.0 for indicator in bootkit_indicators)
        
        # Property: All indicators should have valid types
        valid_types = {
            "signature_match", "privilege_escalation", "interrupt_hooking",
            "syscall_hooking", "memory_manipulation", "anti_debugging"
        }
        assert all(indicator.indicator_type in valid_types for indicator in bootkit_indicators)
        
        # Property: If known bootkit signature is present, should be detected
        for signature, description in self.scanner.bootkit_signatures:
            if signature in boot_code:
                matching_indicators = [
                    ind for ind in bootkit_indicators 
                    if ind.description == description
                ]
                assert len(matching_indicators) >= 1

    @given(
        threat_count=st.integers(min_value=0, max_value=5),
        bootkit_count=st.integers(min_value=0, max_value=10),
        pattern_count=st.integers(min_value=0, max_value=10),
        anomaly_count=st.integers(min_value=0, max_value=10),
    )
    def test_property_8_threat_level_assessment(
        self, threat_count, bootkit_count, pattern_count, anomaly_count
    ):
        """
        Property 8: Threat level assessment
        For any combination of threats, the Security_Scanner should classify
        the threat level appropriately based on the severity of findings.
        **Validates: Requirements 4.1, 4.2, 4.3**
        **Feature: boot-sector-analyzer, Property 8: Security threat detection**
        """
        # Create mock findings
        threat_matches = [
            ThreatMatch(
                threat_name=f"Test.Threat.{i}",
                threat_type="malware",
                confidence=1.0,
                source="test",
            )
            for i in range(threat_count)
        ]
        
        bootkit_indicators = [
            BootkitIndicator(
                indicator_type="test_indicator",
                description=f"Test indicator {i}",
                confidence=0.8,
            )
            for i in range(bootkit_count)
        ]
        
        # Mock patterns and anomalies as simple objects with required attributes
        class MockPattern:
            def __init__(self, pattern_type):
                self.type = pattern_type
        
        class MockAnomaly:
            def __init__(self, severity):
                self.severity = severity
        
        suspicious_patterns = [MockPattern("test_pattern") for _ in range(pattern_count)]
        anomalies = [MockAnomaly("medium") for _ in range(anomaly_count)]
        
        # Assess threat level
        threat_level = self.scanner.assess_threat_level(
            threat_matches, bootkit_indicators, suspicious_patterns, anomalies
        )
        
        # Property: Should return valid ThreatLevel
        assert isinstance(threat_level, ThreatLevel)
        
        # Property: Known malware should result in CRITICAL threat level
        if threat_matches:
            assert threat_level == ThreatLevel.CRITICAL
        
        # Property: No threats should result in LOW threat level
        if (threat_count == 0 and bootkit_count == 0 and 
            pattern_count == 0 and anomaly_count == 0):
            assert threat_level == ThreatLevel.LOW

    @given(boot_code=st.binary(min_size=50, max_size=446))
    def test_property_8_comprehensive_threat_detection(self, boot_code):
        """
        Property 8: Comprehensive threat detection
        For any boot code, the Security_Scanner should perform all detection
        methods without errors and return consistent results.
        **Validates: Requirements 4.1, 4.2, 4.3**
        **Feature: boot-sector-analyzer, Property 8: Security threat detection**
        """
        # Test that all detection methods work without errors
        hashes = {"md5": "a" * 32, "sha256": "b" * 64}
        
        # Should not raise exceptions
        threat_matches = self.scanner.check_known_signatures(hashes)
        bootkit_indicators = self.scanner.detect_bootkit_patterns(boot_code)
        
        # Property: Results should be lists
        assert isinstance(threat_matches, list)
        assert isinstance(bootkit_indicators, list)
        
        # Property: All elements should be of correct type
        assert all(isinstance(match, ThreatMatch) for match in threat_matches)
        assert all(isinstance(indicator, BootkitIndicator) for indicator in bootkit_indicators)
        
        # Property: Confidence values should be in valid range
        assert all(0.0 <= indicator.confidence <= 1.0 for indicator in bootkit_indicators)
        assert all(0.0 <= match.confidence <= 1.0 for match in threat_matches)

    @given(
        active_partition_count=st.integers(min_value=0, max_value=4),
        partition_types=st.lists(
            st.integers(min_value=0, max_value=255), 
            min_size=4, max_size=4
        ),
        start_lbas=st.lists(
            st.integers(min_value=0, max_value=1000000), 
            min_size=4, max_size=4
        ),
        sizes=st.lists(
            st.integers(min_value=0, max_value=100000), 
            min_size=4, max_size=4
        ),
        boot_code=st.binary(min_size=10, max_size=446)
    )
    def test_property_9_mbr_hijacking_detection(
        self, active_partition_count, partition_types, start_lbas, sizes, boot_code
    ):
        """
        Property 9: MBR hijacking detection
        For any boot sector with signs of partition table manipulation or rootkit indicators,
        the Security_Scanner should flag potential MBR hijacking.
        **Validates: Requirements 4.4, 4.5**
        **Feature: boot-sector-analyzer, Property 9: MBR hijacking detection**
        """
        # Create partition entries
        partitions = []
        for i in range(4):
            status = 0x80 if i < active_partition_count else 0x00
            partitions.append(
                PartitionEntry(
                    status=status,
                    start_chs=(0, 0, 1),
                    partition_type=partition_types[i],
                    end_chs=(0, 0, 1),
                    start_lba=start_lbas[i],
                    size_sectors=sizes[i]
                )
            )
        
        # Create MBR structure
        mbr_structure = MBRStructure(
            bootstrap_code=boot_code,
            partition_table=partitions,
            boot_signature=0x55AA
        )
        
        # Test MBR hijacking detection
        hijacking_indicators = self.scanner.detect_mbr_hijacking(mbr_structure, boot_code)
        
        # Property: Should return list of BootkitIndicator objects
        assert isinstance(hijacking_indicators, list)
        assert all(isinstance(indicator, BootkitIndicator) for indicator in hijacking_indicators)
        
        # Property: All indicators should have valid confidence levels
        assert all(0.0 <= indicator.confidence <= 1.0 for indicator in hijacking_indicators)
        
        # Property: Multiple active partitions should be detected
        if active_partition_count > 1:
            multiple_active_indicators = [
                ind for ind in hijacking_indicators 
                if ind.indicator_type == "partition_manipulation"
            ]
            assert len(multiple_active_indicators) >= 1
        
        # Property: Valid indicator types
        valid_types = {
            "partition_manipulation", "partition_overlap", "suspicious_partition_type", 
            "hidden_partition"
        }
        assert all(indicator.indicator_type in valid_types for indicator in hijacking_indicators)

    @given(boot_code=st.binary(min_size=20, max_size=446))
    def test_property_9_rootkit_indicator_detection(self, boot_code):
        """
        Property 9: Rootkit indicator detection
        For any boot code with rootkit indicators, the Security_Scanner
        should detect and classify rootkit patterns appropriately.
        **Validates: Requirements 4.4, 4.5**
        **Feature: boot-sector-analyzer, Property 9: MBR hijacking detection**
        """
        # Test rootkit indicator detection
        rootkit_indicators = self.scanner.detect_rootkit_indicators(boot_code)
        
        # Property: Should return list of BootkitIndicator objects
        assert isinstance(rootkit_indicators, list)
        assert all(isinstance(indicator, BootkitIndicator) for indicator in rootkit_indicators)
        
        # Property: All indicators should have valid confidence levels
        assert all(0.0 <= indicator.confidence <= 1.0 for indicator in rootkit_indicators)
        
        # Property: Valid indicator types
        valid_types = {
            "syscall_hooking", "memory_manipulation", "anti_debugging"
        }
        assert all(indicator.indicator_type in valid_types for indicator in rootkit_indicators)
        
        # Property: If specific rootkit patterns are present, they should be detected
        if b"\x0f\x22\xc0" in boot_code:  # MOV CR0, EAX
            memory_indicators = [
                ind for ind in rootkit_indicators 
                if ind.indicator_type == "memory_manipulation"
            ]
            assert len(memory_indicators) >= 1

    @given(
        boot_code=st.binary(min_size=20, max_size=446),
        entropy=st.floats(min_value=0.0, max_value=8.0, allow_nan=False, allow_infinity=False)
    )
    def test_property_10_encryption_obfuscation_detection(self, boot_code, entropy):
        """
        Property 10: Encryption and obfuscation detection
        For any boot sector with encrypted or obfuscated content, the Security_Scanner
        should detect signs of encryption or obfuscation.
        **Validates: Requirements 4.6**
        **Feature: boot-sector-analyzer, Property 10: Encryption and obfuscation detection**
        """
        # Test encryption/obfuscation detection
        obfuscation_indicators = self.scanner.detect_encryption_obfuscation(boot_code, entropy)
        
        # Property: Should return list of BootkitIndicator objects
        assert isinstance(obfuscation_indicators, list)
        assert all(isinstance(indicator, BootkitIndicator) for indicator in obfuscation_indicators)
        
        # Property: All indicators should have valid confidence levels
        assert all(0.0 <= indicator.confidence <= 1.0 for indicator in obfuscation_indicators)
        
        # Property: Valid indicator types
        valid_types = {
            "high_entropy", "medium_entropy", "packer_signature", 
            "xor_obfuscation", "self_modifying_code"
        }
        assert all(indicator.indicator_type in valid_types for indicator in obfuscation_indicators)
        
        # Property: High entropy should be detected
        if entropy > 7.5:
            high_entropy_indicators = [
                ind for ind in obfuscation_indicators 
                if ind.indicator_type == "high_entropy"
            ]
            assert len(high_entropy_indicators) >= 1
        
        # Property: Medium-high entropy should be detected
        if 6.5 < entropy <= 7.5:
            medium_entropy_indicators = [
                ind for ind in obfuscation_indicators 
                if ind.indicator_type == "medium_entropy"
            ]
            assert len(medium_entropy_indicators) >= 1
        
        # Property: Known packer signatures should be detected
        if b"UPX!" in boot_code:
            packer_indicators = [
                ind for ind in obfuscation_indicators 
                if ind.indicator_type == "packer_signature" and "UPX" in ind.description
            ]
            assert len(packer_indicators) >= 1

    @given(boot_code=st.binary(min_size=50, max_size=446))
    def test_property_10_comprehensive_obfuscation_detection(self, boot_code):
        """
        Property 10: Comprehensive obfuscation detection
        For any boot code, the Security_Scanner should analyze all obfuscation
        indicators without errors and return consistent results.
        **Validates: Requirements 4.6**
        **Feature: boot-sector-analyzer, Property 10: Encryption and obfuscation detection**
        """
        # Test with various entropy values
        for entropy in [1.0, 4.0, 6.8, 7.8]:
            obfuscation_indicators = self.scanner.detect_encryption_obfuscation(boot_code, entropy)
            
            # Property: Should not raise exceptions
            assert isinstance(obfuscation_indicators, list)
            assert all(isinstance(indicator, BootkitIndicator) for indicator in obfuscation_indicators)
            
            # Property: Confidence values should be valid
            assert all(0.0 <= indicator.confidence <= 1.0 for indicator in obfuscation_indicators)
        
        # Property: XOR patterns should be counted correctly
        xor_count = (boot_code.count(b"\x30") + boot_code.count(b"\x31") + 
                    boot_code.count(b"\x80\xf0"))
        
        obfuscation_indicators = self.scanner.detect_encryption_obfuscation(boot_code, 5.0)
        
        if xor_count > 5:
            xor_indicators = [
                ind for ind in obfuscation_indicators 
                if ind.indicator_type == "xor_obfuscation"
            ]
            assert len(xor_indicators) >= 1