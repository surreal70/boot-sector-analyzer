"""Custom exceptions for boot sector analyzer."""

import logging
from typing import Optional, Any


class BootSectorAnalyzerError(Exception):
    """Base exception for boot sector analyzer."""
    
    def __init__(self, message: str, error_code: Optional[str] = None, details: Optional[dict] = None):
        """
        Initialize base exception.
        
        Args:
            message: Human-readable error message
            error_code: Machine-readable error code
            details: Additional error details
        """
        super().__init__(message)
        self.message = message
        self.error_code = error_code or self.__class__.__name__
        self.details = details or {}
        
        # Log the error when it's created
        logger = logging.getLogger(__name__)
        logger.error(f"{self.error_code}: {message}", extra={"error_details": self.details})


class InputError(BootSectorAnalyzerError):
    """Errors related to input handling."""
    pass


class InvalidBootSectorError(InputError):
    """Boot sector data is invalid or corrupted."""
    pass


class FileAccessError(InputError):
    """Cannot access the specified file or device."""
    pass


class BSAPermissionError(InputError):
    """Insufficient permissions to access file or device."""
    pass


class ParsingError(BootSectorAnalyzerError):
    """Errors during boot sector parsing."""
    pass


class MBRParsingError(ParsingError):
    """Errors parsing MBR structure."""
    pass


class PartitionTableError(ParsingError):
    """Errors in partition table structure."""
    pass


class AnalysisError(BootSectorAnalyzerError):
    """Errors during analysis operations."""
    pass


class ContentAnalysisError(AnalysisError):
    """Errors during content analysis."""
    pass


class SecurityAnalysisError(AnalysisError):
    """Errors during security analysis."""
    pass


class NetworkError(BootSectorAnalyzerError):
    """Network-related errors."""
    pass


class APIError(NetworkError):
    """API communication errors."""
    pass


class VirusTotalError(APIError):
    """VirusTotal API specific errors."""
    pass


class CacheError(BootSectorAnalyzerError):
    """Cache-related errors."""
    pass


class ConfigurationError(BootSectorAnalyzerError):
    """Configuration-related errors."""
    pass


class ReportGenerationError(BootSectorAnalyzerError):
    """Report generation errors."""
    pass


# Exit codes for different error types
EXIT_CODES = {
    "success": 0,
    "general_error": 1,
    "input_error": 2,
    "parsing_error": 3,
    "analysis_error": 4,
    "network_error": 5,
    "configuration_error": 6,
    "permission_error": 7,
    "file_not_found": 8,
    "interrupted": 130,  # SIGINT
}


def get_exit_code(error: Exception) -> int:
    """
    Get appropriate exit code for an exception.
    
    Args:
        error: Exception to get exit code for
        
    Returns:
        Appropriate exit code
    """
    if isinstance(error, KeyboardInterrupt):
        return EXIT_CODES["interrupted"]
    elif isinstance(error, FileNotFoundError):
        return EXIT_CODES["file_not_found"]
    elif isinstance(error, (PermissionError, BSAPermissionError)):
        return EXIT_CODES["permission_error"]
    elif isinstance(error, InputError):
        return EXIT_CODES["input_error"]
    elif isinstance(error, ParsingError):
        return EXIT_CODES["parsing_error"]
    elif isinstance(error, AnalysisError):
        return EXIT_CODES["analysis_error"]
    elif isinstance(error, NetworkError):
        return EXIT_CODES["network_error"]
    elif isinstance(error, ConfigurationError):
        return EXIT_CODES["configuration_error"]
    else:
        return EXIT_CODES["general_error"]