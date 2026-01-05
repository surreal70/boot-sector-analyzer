"""Main Boot Sector Analyzer orchestrator class."""

import logging
from datetime import datetime
from pathlib import Path
from typing import Optional, Union

from .models import AnalysisResult, ThreatIntelligence, HexdumpData
from .input_handler import InputHandler
from .structure_analyzer import StructureAnalyzer
from .content_analyzer import ContentAnalyzer
from .security_scanner import SecurityScanner
from .internet_checker import InternetChecker
from .report_generator import ReportGenerator
from .vbr_analyzer import VBRAnalyzer
from .exceptions import (
    BootSectorAnalyzerError,
    InputError,
    ParsingError,
    ContentAnalysisError,
    SecurityAnalysisError,
    AnalysisError
)

logger = logging.getLogger(__name__)


class BootSectorAnalyzer:
    """Main orchestrator class that coordinates all analysis components."""

    def __init__(self, api_key: Optional[str] = None, cache_dir: Optional[str] = None):
        """
        Initialize the Boot Sector Analyzer.

        Args:
            api_key: VirusTotal API key for threat intelligence
            cache_dir: Directory for caching threat intelligence results
        """
        logger.info("Initializing Boot Sector Analyzer")
        
        # Initialize all components
        self.input_handler = InputHandler()
        self.structure_analyzer = StructureAnalyzer()
        self.content_analyzer = ContentAnalyzer()
        self.security_scanner = SecurityScanner()
        self.internet_checker = InternetChecker(api_key=api_key, cache_dir=cache_dir)
        self.report_generator = ReportGenerator()
        self.vbr_analyzer = VBRAnalyzer()
        
        logger.debug("All components initialized successfully")

    def analyze(self, source: Union[str, Path], include_threat_intelligence: bool = True) -> AnalysisResult:
        """
        Perform complete boot sector analysis.

        Args:
            source: Path to boot sector device or image file
            include_threat_intelligence: Whether to query online threat intelligence

        Returns:
            Complete analysis results

        Raises:
            BootSectorAnalyzerError: If analysis fails at any stage
        """
        logger.info(f"Starting boot sector analysis of: {source}")
        
        try:
            # Step 1: Read boot sector data
            logger.debug("Step 1: Reading boot sector data")
            boot_sector_data = self._read_boot_sector(source)
            
            # Step 2: Analyze structure
            logger.debug("Step 2: Analyzing boot sector structure")
            structure_analysis = self._analyze_structure(boot_sector_data)
            
            # Step 3: Analyze content
            logger.debug("Step 3: Analyzing boot sector content")
            content_analysis = self._analyze_content(boot_sector_data)
            
            # Step 4: Perform security scanning
            logger.debug("Step 4: Performing security analysis")
            security_analysis = self._perform_security_analysis(boot_sector_data, content_analysis.hashes)
            
            # Step 5: Query threat intelligence (optional)
            threat_intelligence = None
            boot_code_threat_intelligence = None
            if include_threat_intelligence:
                logger.debug("Step 5: Querying threat intelligence")
                threat_intelligence, boot_code_threat_intelligence = self._query_threat_intelligence(
                    content_analysis.hashes, boot_sector_data
                )
            else:
                logger.debug("Step 5: Skipping threat intelligence (disabled)")
            
            # Step 6: Analyze Volume Boot Records (VBRs)
            logger.debug("Step 6: Analyzing Volume Boot Records")
            if logger.isEnabledFor(logging.INFO):
                logger.info("Performing VBR analysis on valid partitions")
            vbr_analysis_results = self._analyze_vbrs(source, structure_analysis.mbr_structure)
            
            # Step 7: Generate hexdump data
            logger.debug("Step 7: Generating hexdump data")
            hexdump_data = self._generate_hexdump(boot_sector_data)
            
            # Step 8: Compile results
            logger.debug("Step 8: Compiling analysis results")
            result = AnalysisResult(
                source=str(source),
                timestamp=datetime.now(),
                structure_analysis=structure_analysis,
                content_analysis=content_analysis,
                security_analysis=security_analysis,
                hexdump=hexdump_data,
                disassembly=content_analysis.disassembly_result,
                threat_intelligence=threat_intelligence,
                boot_code_threat_intelligence=boot_code_threat_intelligence,
                vbr_analysis=vbr_analysis_results
            )
            
            logger.info(f"Analysis completed successfully - Threat Level: {security_analysis.threat_level.value}")
            return result
            
        except (InputError, ParsingError, ContentAnalysisError, SecurityAnalysisError) as e:
            # Re-raise our custom exceptions without wrapping to preserve exit codes
            logger.error(f"Analysis failed for {source}: {e}")
            raise e
        except Exception as e:
            # Handle unexpected errors
            error_msg = f"Unexpected error during analysis of {source}: {e}"
            logger.error(error_msg, exc_info=True)
            raise BootSectorAnalyzerError(
                error_msg,
                error_code="UNEXPECTED_ANALYSIS_ERROR",
                details={
                    "source": str(source),
                    "exception_type": type(e).__name__,
                    "error": str(e)
                }
            ) from e

    def generate_report(self, result: AnalysisResult, format_type: str = "human") -> str:
        """
        Generate analysis report.

        Args:
            result: Analysis results to report on
            format_type: "human" for human-readable, "json" for JSON format

        Returns:
            Formatted report string

        Raises:
            BootSectorAnalyzerError: If report generation fails
        """
        logger.debug(f"Generating {format_type} report")
        
        try:
            report = self.report_generator.generate_report(result, format_type)
            logger.debug(f"Report generated successfully ({len(report)} characters)")
            return report
            
        except Exception as e:
            error_msg = f"Failed to generate {format_type} report: {e}"
            logger.error(error_msg, exc_info=True)
            raise BootSectorAnalyzerError(
                error_msg,
                error_code="REPORT_GENERATION_ERROR",
                details={
                    "format_type": format_type,
                    "exception_type": type(e).__name__,
                    "error": str(e)
                }
            ) from e

    def _read_boot_sector(self, source: Union[str, Path]) -> bytes:
        """
        Read boot sector data from source.

        Args:
            source: Path to boot sector device or image file

        Returns:
            512 bytes of boot sector data

        Raises:
            InputError: If reading fails
        """
        try:
            logger.debug(f"Reading boot sector from: {source}")
            boot_sector_data = self.input_handler.read_boot_sector(source)
            
            # Validate the data
            if not self.input_handler.validate_boot_sector(boot_sector_data):
                logger.warning("Boot sector validation failed, continuing with analysis")
            
            logger.debug(f"Successfully read {len(boot_sector_data)} bytes")
            return boot_sector_data
            
        except Exception as e:
            error_msg = f"Failed to read boot sector from {source}: {e}"
            logger.error(error_msg)
            # Re-raise InputError or wrap other exceptions
            if isinstance(e, InputError):
                raise
            else:
                raise InputError(
                    error_msg,
                    error_code="READ_ERROR",
                    details={"source": str(source), "exception_type": type(e).__name__, "error": str(e)}
                ) from e

    def _analyze_structure(self, boot_sector_data: bytes):
        """
        Analyze boot sector structure.

        Args:
            boot_sector_data: Boot sector data to analyze

        Returns:
            Structure analysis results

        Raises:
            ParsingError: If structure analysis fails
        """
        try:
            logger.debug("Parsing MBR structure")
            mbr_structure = self.structure_analyzer.parse_mbr(boot_sector_data)
            
            logger.debug("Performing structure analysis")
            structure_analysis = self.structure_analyzer.analyze_structure(mbr_structure)
            
            logger.debug(f"Structure analysis completed: {structure_analysis.partition_count} partitions, "
                        f"{len(structure_analysis.anomalies)} anomalies")
            return structure_analysis
            
        except Exception as e:
            error_msg = f"Structure analysis failed: {e}"
            logger.error(error_msg)
            # Re-raise ParsingError or wrap other exceptions
            if isinstance(e, ParsingError):
                raise
            else:
                raise ParsingError(
                    error_msg,
                    error_code="STRUCTURE_ANALYSIS_ERROR",
                    details={"exception_type": type(e).__name__, "error": str(e)}
                ) from e

    def _analyze_content(self, boot_sector_data: bytes):
        """
        Analyze boot sector content.

        Args:
            boot_sector_data: Boot sector data to analyze

        Returns:
            Content analysis results

        Raises:
            ContentAnalysisError: If content analysis fails
        """
        try:
            logger.debug("Performing content analysis")
            content_analysis = self.content_analyzer.analyze_content(boot_sector_data)
            
            logger.debug(f"Content analysis completed: {len(content_analysis.strings)} strings, "
                        f"{len(content_analysis.urls)} URLs, entropy={content_analysis.entropy:.2f}")
            return content_analysis
            
        except Exception as e:
            error_msg = f"Content analysis failed: {e}"
            logger.error(error_msg)
            # Re-raise ContentAnalysisError or wrap other exceptions
            if isinstance(e, ContentAnalysisError):
                raise
            else:
                raise ContentAnalysisError(
                    error_msg,
                    error_code="CONTENT_ANALYSIS_ERROR",
                    details={"exception_type": type(e).__name__, "error": str(e)}
                ) from e

    def _perform_security_analysis(self, boot_sector_data: bytes, hashes: dict):
        """
        Perform security analysis.

        Args:
            boot_sector_data: Boot sector data to analyze
            hashes: Calculated hashes of the boot sector

        Returns:
            Security analysis results

        Raises:
            SecurityAnalysisError: If security analysis fails
        """
        try:
            logger.debug("Performing security analysis")
            security_analysis = self.security_scanner.scan_for_threats(boot_sector_data, hashes)
            
            logger.debug(f"Security analysis completed: threat_level={security_analysis.threat_level.value}, "
                        f"{len(security_analysis.detected_threats)} threats, "
                        f"{len(security_analysis.bootkit_indicators)} indicators")
            return security_analysis
            
        except Exception as e:
            error_msg = f"Security analysis failed: {e}"
            logger.error(error_msg)
            # Re-raise SecurityAnalysisError or wrap other exceptions
            if isinstance(e, SecurityAnalysisError):
                raise
            else:
                raise SecurityAnalysisError(
                    error_msg,
                    error_code="SECURITY_ANALYSIS_ERROR",
                    details={"exception_type": type(e).__name__, "error": str(e)}
                ) from e

    def _query_threat_intelligence(self, hashes: dict, boot_sector_data: bytes) -> tuple[Optional[ThreatIntelligence], Optional[ThreatIntelligence]]:
        """
        Query threat intelligence sources for both full boot sector and boot code.

        Args:
            hashes: Calculated hashes to query
            boot_sector_data: Full boot sector data for boot code analysis

        Returns:
            Tuple of (full_sector_threat_intelligence, boot_code_threat_intelligence)

        Note:
            This method does not raise exceptions - it logs errors and returns None
            to allow analysis to continue even if threat intelligence fails
        """
        try:
            logger.debug("Querying threat intelligence")
            
            # Query VirusTotal with SHA-256 hash (preferred) for full boot sector
            sha256_hash = hashes.get("sha256")
            if not sha256_hash:
                logger.warning("No SHA-256 hash available for threat intelligence query")
                return None, None
            
            # Query full boot sector
            virustotal_result = self.internet_checker.query_virustotal(sha256_hash)
            
            # Create full sector threat intelligence result
            full_sector_ti = None
            if virustotal_result:
                full_sector_ti = ThreatIntelligence(
                    virustotal_result=virustotal_result,
                    cached=False,  # InternetChecker handles caching internally
                    query_timestamp=datetime.now(),
                    analysis_type="full_boot_sector"
                )
                logger.debug(f"Full boot sector threat intelligence: "
                           f"{virustotal_result.detection_count}/{virustotal_result.total_engines} detections")
            else:
                logger.debug("No full boot sector threat intelligence results available")
            
            # Query boot code specific analysis
            boot_code_ti = None
            try:
                boot_code_result = self.internet_checker.query_virustotal_boot_code(boot_sector_data)
                if boot_code_result:
                    boot_code_ti = ThreatIntelligence(
                        virustotal_result=boot_code_result,
                        cached=False,  # InternetChecker handles caching internally
                        query_timestamp=datetime.now(),
                        analysis_type="boot_code_only"
                    )
                    logger.debug(f"Boot code threat intelligence: "
                               f"{boot_code_result.detection_count}/{boot_code_result.total_engines} detections")
                else:
                    logger.debug("No boot code threat intelligence results available (empty boot code or not found)")
            except Exception as e:
                logger.warning(f"Boot code threat intelligence query failed: {e}")
                logger.debug("Continuing with full boot sector analysis only")
            
            return full_sector_ti, boot_code_ti
            
        except Exception as e:
            # Don't fail the entire analysis if threat intelligence fails
            logger.warning(f"Threat intelligence query failed: {e}")
            logger.debug("Continuing analysis without threat intelligence")
            return None, None

    def _analyze_vbrs(self, source: Union[str, Path], mbr_structure) -> list:
        """
        Analyze Volume Boot Records from valid partitions.

        Args:
            source: Path to boot sector device or image file
            mbr_structure: Parsed MBR structure containing partition table

        Returns:
            List of VBR analysis results

        Note:
            This method does not raise exceptions - it logs errors and returns
            partial results to allow analysis to continue even if VBR analysis fails
        """
        try:
            logger.debug("Starting VBR analysis")
            
            # Perform VBR analysis using the VBR analyzer
            vbr_results = self.vbr_analyzer.analyze_vbrs(str(source), mbr_structure)
            
            if vbr_results:
                successful_analyses = sum(1 for result in vbr_results if result.vbr_structure is not None)
                logger.info(f"VBR analysis completed: {successful_analyses}/{len(vbr_results)} partitions analyzed successfully")
                
                # Log details for verbose mode
                for result in vbr_results:
                    if result.vbr_structure is not None:
                        logger.debug(f"Partition {result.partition_number}: VBR analysis successful")
                    else:
                        logger.debug(f"Partition {result.partition_number}: VBR analysis failed - {result.extraction_error}")
            else:
                logger.info("No VBR analysis results (no valid partitions, disabled, or image file)")
            
            return vbr_results
            
        except Exception as e:
            # Don't fail the entire analysis if VBR analysis fails
            logger.warning(f"VBR analysis failed: {e}")
            logger.debug("Continuing analysis without VBR results")
            return []

    def _generate_hexdump(self, boot_sector_data: bytes) -> HexdumpData:
        """
        Generate hexdump data for the boot sector.

        Args:
            boot_sector_data: 512-byte boot sector data

        Returns:
            HexdumpData containing formatted hexdump information
        """
        try:
            logger.debug("Generating hexdump data")
            
            # Generate formatted hexdump lines (without colors for backward compatibility)
            formatted_lines = self.report_generator.format_hexdump_table(boot_sector_data, use_colors=False)
            
            # Generate ASCII representation
            ascii_representation = self.report_generator.format_ascii_column(boot_sector_data)
            
            hexdump_data = HexdumpData(
                raw_data=boot_sector_data,
                formatted_lines=formatted_lines,
                ascii_representation=ascii_representation,
                total_bytes=len(boot_sector_data)
            )
            
            logger.debug(f"Hexdump data generated: {len(formatted_lines)} lines, {len(boot_sector_data)} bytes")
            return hexdump_data
            
        except Exception as e:
            error_msg = f"Failed to generate hexdump data: {e}"
            logger.error(error_msg)
            # Create minimal hexdump data on error
            return HexdumpData(
                raw_data=boot_sector_data,
                formatted_lines=[f"Error generating hexdump: {e}"],
                ascii_representation="",
                total_bytes=len(boot_sector_data)
            )

    def clear_cache(self) -> int:
        """
        Clear expired threat intelligence cache.

        Returns:
            Number of cache entries cleared
        """
        logger.debug("Clearing expired threat intelligence cache")
        
        try:
            cleared_count = self.internet_checker.clear_expired_cache()
            logger.info(f"Cleared {cleared_count} expired cache entries")
            return cleared_count
            
        except Exception as e:
            logger.warning(f"Failed to clear cache: {e}")
            return 0

    def get_component_status(self) -> dict:
        """
        Get status information about all components.

        Returns:
            Dictionary with component status information
        """
        status = {
            "input_handler": "initialized",
            "structure_analyzer": "initialized",
            "content_analyzer": "initialized",
            "security_scanner": "initialized",
            "internet_checker": {
                "initialized": True,
                "api_key_configured": bool(self.internet_checker.api_key),
                "cache_directory": str(self.internet_checker.cache_dir)
            },
            "report_generator": "initialized",
            "vbr_analyzer": "initialized"
        }
        
        logger.debug(f"Component status: {status}")
        return status