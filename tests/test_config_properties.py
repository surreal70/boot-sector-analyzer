"""Property-based tests for configuration file support."""

import tempfile
import configparser
from pathlib import Path
from hypothesis import given, strategies as st
import pytest

from boot_sector_analyzer.config import Config


class TestConfigurationProperties:
    """Property-based tests for configuration file support."""
    
    @given(
        api_key=st.text(min_size=1, max_size=100, alphabet=st.characters(min_codepoint=32, max_codepoint=126, blacklist_characters='%\n\r\t')),
        rate_limit=st.integers(min_value=1, max_value=300),
        timeout=st.integers(min_value=1, max_value=120),
        cache_enabled=st.booleans(),
        cache_expiry=st.integers(min_value=1, max_value=168),
        log_level=st.sampled_from(['DEBUG', 'INFO', 'WARNING', 'ERROR'])
    )
    def test_configuration_file_round_trip(self, api_key, rate_limit, timeout, 
                                         cache_enabled, cache_expiry, log_level):
        """
        **Feature: boot-sector-analyzer, Property 18: Configuration file support**
        **Validates: Requirements 7.6**
        
        For any valid configuration values, saving and loading the configuration
        should preserve all settings correctly.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / 'test_config.ini'
            
            # Create initial config
            config = Config()
            
            # Set test values
            config.set('api', 'virustotal_api_key', api_key)
            config.set('api', 'rate_limit_seconds', rate_limit)
            config.set('api', 'timeout_seconds', timeout)
            config.set('cache', 'enabled', cache_enabled)
            config.set('cache', 'expiry_hours', cache_expiry)
            config.set('logging', 'level', log_level)
            
            # Save configuration
            config.save(config_path)
            
            # Load configuration from file
            loaded_config = Config(config_path)
            
            # Verify all values are preserved
            assert loaded_config.get('api', 'virustotal_api_key') == api_key
            assert loaded_config.get('api', 'rate_limit_seconds') == rate_limit
            assert loaded_config.get('api', 'timeout_seconds') == timeout
            assert loaded_config.get('cache', 'enabled') == cache_enabled
            assert loaded_config.get('cache', 'expiry_hours') == cache_expiry
            assert loaded_config.get('logging', 'level') == log_level
    
    @given(
        section_name=st.text(min_size=1, max_size=50, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd'), blacklist_characters='%[]')),
        key_name=st.text(min_size=1, max_size=50, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd'), blacklist_characters='%[]')),
        value=st.one_of(
            st.text(min_size=0, max_size=100, alphabet=st.characters(min_codepoint=32, max_codepoint=126, blacklist_characters='%\n\r\t')),
            st.integers(min_value=-1000, max_value=1000),
            st.floats(allow_nan=False, allow_infinity=False, min_value=-1000.0, max_value=1000.0),
            st.booleans()
        )
    )
    def test_arbitrary_config_values(self, section_name, key_name, value):
        """
        **Feature: boot-sector-analyzer, Property 18: Configuration file support**
        **Validates: Requirements 7.6**
        
        For any valid section name, key name, and value, the configuration system
        should be able to store and retrieve the value correctly.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / 'test_config.ini'
            
            # Create config and set value (without defaults to avoid interference)
            config = Config(load_defaults=False)
            config.set(section_name, key_name, value)
            
            # Save and reload
            config.save(config_path)
            loaded_config = Config(config_path, load_defaults=False)
            
            # Verify value is preserved
            retrieved_value = loaded_config.get(section_name, key_name)
            assert retrieved_value == value
    
    @given(
        config_sections=st.dictionaries(
            keys=st.text(min_size=1, max_size=20, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd'), blacklist_characters='%[]')),
            values=st.dictionaries(
                keys=st.text(min_size=1, max_size=20, alphabet=st.characters(whitelist_categories=('Lu', 'Ll', 'Nd'), blacklist_characters='%[]')),
                values=st.one_of(
                    st.text(max_size=50, alphabet=st.characters(min_codepoint=32, max_codepoint=126, blacklist_characters='%\n\r\t')), 
                    st.integers(min_value=-1000, max_value=1000), 
                    st.booleans()
                ),
                min_size=1,
                max_size=5
            ),
            min_size=1,
            max_size=5
        )
    )
    def test_complex_configuration_structure(self, config_sections):
        """
        **Feature: boot-sector-analyzer, Property 18: Configuration file support**
        **Validates: Requirements 7.6**
        
        For any complex configuration structure with multiple sections and keys,
        the configuration system should preserve the entire structure correctly.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / 'test_config.ini'
            
            # Create config with complex structure (without defaults to avoid interference)
            config = Config(load_defaults=False)
            
            # Set all values from the generated structure
            for section_name, section_data in config_sections.items():
                for key_name, value in section_data.items():
                    config.set(section_name, key_name, value)
            
            # Save and reload
            config.save(config_path)
            loaded_config = Config(config_path, load_defaults=False)
            
            # Verify entire structure is preserved
            for section_name, section_data in config_sections.items():
                loaded_section = loaded_config.get_section(section_name)
                assert len(loaded_section) == len(section_data)
                
                for key_name, expected_value in section_data.items():
                    actual_value = loaded_config.get(section_name, key_name)
                    assert actual_value == expected_value
    
    def test_config_file_creation_and_parsing(self):
        """
        Test that configuration files are created with proper format and can be parsed.
        """
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / 'test_config.ini'
            
            # Create sample config
            config = Config()
            config.create_sample_config(config_path)
            
            # Verify file was created
            assert config_path.exists()
            
            # Verify it can be parsed by ConfigParser
            parser = configparser.ConfigParser()
            parser.read(config_path)
            
            # Verify expected sections exist
            expected_sections = ['api', 'cache', 'analysis', 'output', 'logging']
            for section in expected_sections:
                assert section in parser.sections()
            
            # Verify it can be loaded by our Config class
            loaded_config = Config(config_path)
            
            # Verify some expected default values
            assert loaded_config.get('cache', 'enabled') is True
            assert loaded_config.get('analysis', 'calculate_entropy') is True
            assert loaded_config.get('output', 'default_format') == 'human'