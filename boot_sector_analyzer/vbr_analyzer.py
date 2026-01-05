"""VBR analyzer orchestrator for coordinating Volume Boot Record analysis."""

import logging
import os
from typing import List, Optional

from .models import (
    MBRStructure,
    VBRAnalysisResult,
    VBRData,
    ValidPartition
)
from .partition_scanner import PartitionScanner
from .vbr_structure_parser import VBRStructureParser
from .vbr_content_analyzer import VBRContentAnalyzer


class VBRAnalyzer:
    """Orchestrator class for coordinating complete VBR analysis workflow."""

    def __init__(self, partition_scanner: PartitionScanner = None,
                 vbr_structure_parser: VBRStructureParser = None,
                 vbr_content_analyzer: VBRContentAnalyzer = None):
        """
        Initialize VBR analysis components.
        
        Args:
            partition_scanner: Scanner for partition detection and VBR extraction
            vbr_structure_parser: Parser for VBR structure analysis
            vbr_content_analyzer: Analyzer for VBR content analysis
        """
        self.logger = logging.getLogger(__name__)
        
        # Initialize components with defaults if not provided
        self.partition_scanner = partition_scanner or PartitionScanner()
        self.vbr_structure_parser = vbr_structure_parser or VBRStructureParser()
        self.vbr_content_analyzer = vbr_content_analyzer or VBRContentAnalyzer()
        
        # Configuration options for CLI control
        self.disable_vbr_analysis = False  # --no-vbr option
        self.force_vbr_analysis = False    # --force-vbr option

    def analyze_vbrs(self, source: str, mbr_structure: MBRStructure) -> List[VBRAnalysisResult]:
        """
        Analyze VBRs from all valid partitions.
        
        Args:
            source: Source path (device or image file)
            mbr_structure: Parsed MBR structure containing partition table
            
        Returns:
            List of VBR analysis results for each valid partition
        """
        self.logger.info(f"Starting VBR analysis for source: {source}")
        
        # Check if VBR analysis is disabled
        if self.disable_vbr_analysis:
            self.logger.info("VBR analysis disabled by configuration")
            return []
        
        # Check if VBR extraction should be performed
        if not self.should_extract_vbrs(source):
            if self.force_vbr_analysis:
                self.logger.warning("Forcing VBR analysis for image file - this may fail")
            else:
                self.logger.info("VBR extraction skipped for image file analysis")
                return []
        
        # Identify valid partitions from MBR
        valid_partitions = self.partition_scanner.identify_valid_partitions(mbr_structure)
        
        if not valid_partitions:
            self.logger.info("No valid partitions found for VBR extraction")
            return []
        
        # Extract VBR data from all valid partitions
        vbr_data_list = self.extract_partition_vbrs(source, valid_partitions)
        
        # Analyze each extracted VBR
        analysis_results = []
        for vbr_data in vbr_data_list:
            analysis_result = self._analyze_single_vbr(vbr_data, valid_partitions)
            analysis_results.append(analysis_result)
        
        self.logger.info(f"Completed VBR analysis for {len(analysis_results)} partitions")
        return analysis_results

    def should_extract_vbrs(self, source: str) -> bool:
        """
        Determine if VBR extraction should be performed (only for direct disk access).
        
        Args:
            source: Source path to analyze
            
        Returns:
            True if VBR extraction should be performed, False for image files
        """
        # If VBR analysis is forced, always return True
        if self.force_vbr_analysis:
            self.logger.debug(f"VBR analysis forced for source: {source}")
            return True
        
        # Check if source is a device path (starts with /dev/ on Unix systems)
        # or is a block device
        if source.startswith('/dev/'):
            return True
        
        # Check if source is a block device or character device
        try:
            if os.path.exists(source):
                stat_result = os.stat(source)
                # Check if it's a block device or character device
                import stat
                if stat.S_ISBLK(stat_result.st_mode) or stat.S_ISCHR(stat_result.st_mode):
                    return True
        except (OSError, IOError):
            # If we can't stat the file, assume it's a regular file
            pass
        
        # For regular files (image files), skip VBR extraction
        self.logger.debug(f"Source {source} appears to be an image file, skipping VBR extraction")
        return False

    def extract_partition_vbrs(self, source: str, partitions: List[ValidPartition]) -> List[VBRData]:
        """
        Extract VBR data from all valid partitions.
        
        Args:
            source: Device path for VBR extraction
            partitions: List of valid partitions to extract VBRs from
            
        Returns:
            List of VBR data (successful and failed extractions)
        """
        vbr_data_list = []
        
        for partition in partitions:
            self.logger.debug(
                f"Extracting VBR from partition {partition.partition_number} "
                f"at offset {partition.start_byte_offset}"
            )
            
            try:
                # Validate partition access before extraction
                if not self.partition_scanner.validate_partition_access(source, partition.partition_entry):
                    error_msg = f"Partition {partition.partition_number} is not accessible"
                    self.logger.warning(error_msg)
                    vbr_data = VBRData(
                        partition_number=partition.partition_number,
                        raw_vbr=b'',
                        extraction_successful=False,
                        error_message=error_msg
                    )
                    vbr_data_list.append(vbr_data)
                    continue
                
                # Extract VBR data
                raw_vbr = self.partition_scanner.extract_vbr_data(source, partition.partition_entry)
                
                if raw_vbr is not None:
                    vbr_data = VBRData(
                        partition_number=partition.partition_number,
                        raw_vbr=raw_vbr,
                        extraction_successful=True,
                        error_message=None
                    )
                    self.logger.debug(f"Successfully extracted VBR from partition {partition.partition_number}")
                else:
                    error_msg = f"VBR extraction failed for partition {partition.partition_number}"
                    self.logger.error(error_msg)
                    vbr_data = VBRData(
                        partition_number=partition.partition_number,
                        raw_vbr=b'',
                        extraction_successful=False,
                        error_message=error_msg
                    )
                
                vbr_data_list.append(vbr_data)
                
            except Exception as e:
                error_msg = f"Unexpected error extracting VBR from partition {partition.partition_number}: {e}"
                self.logger.error(error_msg)
                vbr_data = VBRData(
                    partition_number=partition.partition_number,
                    raw_vbr=b'',
                    extraction_successful=False,
                    error_message=error_msg
                )
                vbr_data_list.append(vbr_data)
        
        successful_extractions = sum(1 for vbr in vbr_data_list if vbr.extraction_successful)
        self.logger.info(
            f"VBR extraction completed: {successful_extractions}/{len(vbr_data_list)} successful"
        )
        
        return vbr_data_list

    def _analyze_single_vbr(self, vbr_data: VBRData, valid_partitions: List[ValidPartition]) -> VBRAnalysisResult:
        """
        Analyze a single VBR data structure.
        
        Args:
            vbr_data: VBR data to analyze
            valid_partitions: List of valid partitions for context
            
        Returns:
            Complete VBR analysis result
        """
        # Find the corresponding partition entry
        partition_entry = None
        for partition in valid_partitions:
            if partition.partition_number == vbr_data.partition_number:
                partition_entry = partition.partition_entry
                break
        
        # If extraction failed, return analysis result with error
        if not vbr_data.extraction_successful:
            return VBRAnalysisResult(
                partition_number=vbr_data.partition_number,
                partition_info=partition_entry,
                vbr_structure=None,
                content_analysis=None,
                extraction_error=vbr_data.error_message
            )
        
        try:
            # Parse VBR structure
            vbr_structure = self.vbr_structure_parser.parse_vbr_structure(
                vbr_data.raw_vbr,
                partition_entry.partition_type if partition_entry else 0
            )
            
            # Perform content analysis
            content_analysis = self.vbr_content_analyzer.analyze_vbr_content(vbr_structure)
            
            return VBRAnalysisResult(
                partition_number=vbr_data.partition_number,
                partition_info=partition_entry,
                vbr_structure=vbr_structure,
                content_analysis=content_analysis,
                extraction_error=None
            )
            
        except Exception as e:
            error_msg = f"VBR analysis failed for partition {vbr_data.partition_number}: {e}"
            self.logger.error(error_msg)
            
            return VBRAnalysisResult(
                partition_number=vbr_data.partition_number,
                partition_info=partition_entry,
                vbr_structure=None,
                content_analysis=None,
                extraction_error=error_msg
            )