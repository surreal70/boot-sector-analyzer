"""Boot sector structure analysis."""

import logging
import struct
from typing import List

from .models import MBRStructure, PartitionEntry, Anomaly, StructureAnalysis
from .exceptions import (
    ParsingError,
    MBRParsingError,
    PartitionTableError,
    InvalidBootSectorError
)

logger = logging.getLogger(__name__)


class StructureAnalyzer:
    """Analyzes boot sector structure and validates MBR format."""

    def parse_mbr(self, boot_sector: bytes) -> MBRStructure:
        """
        Parse Master Boot Record structure.

        Args:
            boot_sector: 512 bytes of boot sector data

        Returns:
            Parsed MBR structure
            
        Raises:
            MBRParsingError: If MBR structure cannot be parsed
            InvalidBootSectorError: If boot sector data is invalid
        """
        logger.debug("Starting MBR parsing")
        
        if not isinstance(boot_sector, bytes):
            error_msg = f"Boot sector must be bytes, got {type(boot_sector)}"
            logger.error(error_msg)
            raise InvalidBootSectorError(
                error_msg,
                error_code="INVALID_DATA_TYPE",
                details={"data_type": str(type(boot_sector))}
            )
        
        if len(boot_sector) != 512:
            error_msg = f"Boot sector must be exactly 512 bytes, got {len(boot_sector)}"
            logger.error(error_msg)
            raise InvalidBootSectorError(
                error_msg,
                error_code="INVALID_SIZE",
                details={"expected_size": 512, "actual_size": len(boot_sector)}
            )

        try:
            # Extract bootstrap code (first 446 bytes)
            bootstrap_code = boot_sector[:446]
            logger.debug(f"Extracted bootstrap code: {len(bootstrap_code)} bytes")

            # Parse partition table (4 entries, 16 bytes each)
            partition_table = []
            for i in range(4):
                try:
                    offset = 446 + (i * 16)
                    entry_data = boot_sector[offset : offset + 16]
                    partition_entry = self._parse_partition_entry(entry_data, i)
                    partition_table.append(partition_entry)
                    logger.debug(f"Parsed partition entry {i}: type=0x{partition_entry.partition_type:02X}, size={partition_entry.size_sectors}")
                except Exception as e:
                    error_msg = f"Failed to parse partition entry {i}: {e}"
                    logger.error(error_msg)
                    raise PartitionTableError(
                        error_msg,
                        error_code="PARTITION_ENTRY_ERROR",
                        details={"partition_index": i, "offset": offset, "error": str(e)}
                    )

            # Extract boot signature (last 2 bytes)
            try:
                boot_signature = struct.unpack("<H", boot_sector[510:512])[0]
                logger.debug(f"Boot signature: 0x{boot_signature:04X}")
            except struct.error as e:
                error_msg = f"Failed to parse boot signature: {e}"
                logger.error(error_msg)
                raise MBRParsingError(
                    error_msg,
                    error_code="BOOT_SIGNATURE_ERROR",
                    details={"error": str(e)}
                )

            # Extract optional disk signature (4 bytes at offset 440)
            disk_signature = None
            try:
                if len(boot_sector) >= 444:
                    disk_signature = struct.unpack("<I", boot_sector[440:444])[0]
                    logger.debug(f"Disk signature: 0x{disk_signature:08X}")
            except struct.error as e:
                logger.warning(f"Failed to parse disk signature: {e}")
                # Don't raise exception for optional field

            mbr_structure = MBRStructure(
                bootstrap_code=bootstrap_code,
                partition_table=partition_table,
                boot_signature=boot_signature,
                disk_signature=disk_signature,
            )
            
            logger.info("MBR parsing completed successfully")
            return mbr_structure
            
        except (MBRParsingError, PartitionTableError, InvalidBootSectorError):
            # Re-raise our custom exceptions
            raise
        except Exception as e:
            error_msg = f"Unexpected error parsing MBR: {e}"
            logger.error(error_msg, exc_info=True)
            raise MBRParsingError(
                error_msg,
                error_code="UNEXPECTED_PARSING_ERROR",
                details={"exception_type": type(e).__name__, "error": str(e)}
            )

    def _parse_partition_entry(self, entry_data: bytes, index: int = -1) -> PartitionEntry:
        """
        Parse a single 16-byte partition table entry.
        
        Args:
            entry_data: 16 bytes of partition entry data
            index: Partition index for error reporting
            
        Returns:
            Parsed partition entry
            
        Raises:
            PartitionTableError: If partition entry cannot be parsed
        """
        if len(entry_data) != 16:
            error_msg = f"Partition entry must be exactly 16 bytes, got {len(entry_data)}"
            logger.error(error_msg)
            raise PartitionTableError(
                error_msg,
                error_code="INVALID_ENTRY_SIZE",
                details={"partition_index": index, "expected_size": 16, "actual_size": len(entry_data)}
            )

        try:
            # Unpack partition entry structure
            values = struct.unpack("<BBBBBBBBII", entry_data)

            status = values[0]
            start_head = values[1]
            start_sector_cylinder = values[2]
            start_cylinder = values[3]
            partition_type = values[4]
            end_head = values[5]
            end_sector_cylinder = values[6]
            end_cylinder = values[7]
            start_lba = values[8]
            size_sectors = values[9]

            # Parse CHS values
            start_sector = start_sector_cylinder & 0x3F
            start_cylinder = ((start_sector_cylinder & 0xC0) << 2) | start_cylinder
            start_chs = (start_cylinder, start_head, start_sector)

            end_sector = end_sector_cylinder & 0x3F
            end_cylinder = ((end_sector_cylinder & 0xC0) << 2) | end_cylinder
            end_chs = (end_cylinder, end_head, end_sector)

            return PartitionEntry(
                status=status,
                start_chs=start_chs,
                partition_type=partition_type,
                end_chs=end_chs,
                start_lba=start_lba,
                size_sectors=size_sectors,
            )
            
        except struct.error as e:
            error_msg = f"Failed to unpack partition entry data: {e}"
            logger.error(error_msg)
            raise PartitionTableError(
                error_msg,
                error_code="STRUCT_UNPACK_ERROR",
                details={"partition_index": index, "error": str(e)}
            )
        except Exception as e:
            error_msg = f"Unexpected error parsing partition entry: {e}"
            logger.error(error_msg, exc_info=True)
            raise PartitionTableError(
                error_msg,
                error_code="UNEXPECTED_ENTRY_ERROR",
                details={"partition_index": index, "exception_type": type(e).__name__, "error": str(e)}
            )

    def validate_boot_signature(self, boot_sector: bytes) -> bool:
        """
        Check for valid boot signature (0x55AA).

        Args:
            boot_sector: 512 bytes of boot sector data

        Returns:
            True if boot signature is valid
            
        Raises:
            InvalidBootSectorError: If boot sector data is invalid
        """
        logger.debug("Validating boot signature")
        
        if not isinstance(boot_sector, bytes):
            error_msg = f"Boot sector must be bytes, got {type(boot_sector)}"
            logger.error(error_msg)
            raise InvalidBootSectorError(
                error_msg,
                error_code="INVALID_DATA_TYPE",
                details={"data_type": str(type(boot_sector))}
            )
        
        if len(boot_sector) < 512:
            logger.warning(f"Boot sector too short for signature validation: {len(boot_sector)} bytes")
            return False

        try:
            signature = struct.unpack("<H", boot_sector[510:512])[0]
            is_valid = signature == 0x55AA

            if is_valid:
                logger.debug("Valid boot signature found (0x55AA)")
            else:
                logger.warning(f"Invalid boot signature: 0x{signature:04X} (expected 0x55AA)")

            return is_valid
            
        except struct.error as e:
            error_msg = f"Failed to parse boot signature: {e}"
            logger.error(error_msg)
            raise MBRParsingError(
                error_msg,
                error_code="SIGNATURE_PARSE_ERROR",
                details={"error": str(e)}
            )
        except Exception as e:
            error_msg = f"Unexpected error validating boot signature: {e}"
            logger.error(error_msg, exc_info=True)
            raise MBRParsingError(
                error_msg,
                error_code="UNEXPECTED_SIGNATURE_ERROR",
                details={"exception_type": type(e).__name__, "error": str(e)}
            )

    def parse_partition_table(self, boot_sector: bytes) -> List[PartitionEntry]:
        """
        Extract and validate partition table entries.

        Args:
            boot_sector: 512 bytes of boot sector data

        Returns:
            List of partition entries
            
        Raises:
            MBRParsingError: If partition table cannot be parsed
        """
        logger.debug("Parsing partition table")
        
        try:
            mbr = self.parse_mbr(boot_sector)
            logger.info(f"Successfully parsed {len(mbr.partition_table)} partition entries")
            return mbr.partition_table
        except Exception as e:
            error_msg = f"Failed to parse partition table: {e}"
            logger.error(error_msg)
            # Re-raise if it's already our custom exception
            if isinstance(e, (MBRParsingError, PartitionTableError, InvalidBootSectorError)):
                raise
            else:
                raise MBRParsingError(
                    error_msg,
                    error_code="PARTITION_TABLE_ERROR",
                    details={"exception_type": type(e).__name__, "error": str(e)}
                )

    def analyze_structure(self, mbr: MBRStructure) -> StructureAnalysis:
        """
        Perform complete structure analysis of MBR.
        
        Args:
            mbr: Parsed MBR structure
            
        Returns:
            Complete structure analysis results
            
        Raises:
            ParsingError: If analysis cannot be completed
        """
        logger.debug("Starting structure analysis")
        
        try:
            # Validate boot signature
            is_valid_signature = mbr.boot_signature == 0x55AA
            
            # Count active partitions
            partition_count = sum(1 for p in mbr.partition_table if p.size_sectors > 0)
            
            # Detect anomalies
            anomalies = self.detect_anomalies(mbr)
            
            logger.info(f"Structure analysis completed: {partition_count} partitions, {len(anomalies)} anomalies")
            
            return StructureAnalysis(
                mbr_structure=mbr,
                is_valid_signature=is_valid_signature,
                anomalies=anomalies,
                partition_count=partition_count
            )
            
        except Exception as e:
            error_msg = f"Failed to analyze MBR structure: {e}"
            logger.error(error_msg, exc_info=True)
            raise ParsingError(
                error_msg,
                error_code="STRUCTURE_ANALYSIS_ERROR",
                details={"exception_type": type(e).__name__, "error": str(e)}
            )

    def detect_anomalies(self, mbr: MBRStructure) -> List[Anomaly]:
        """
        Identify structural anomalies in the MBR.

        Args:
            mbr: Parsed MBR structure

        Returns:
            List of detected anomalies
            
        Raises:
            ParsingError: If anomaly detection fails
        """
        logger.debug("Starting anomaly detection")
        anomalies = []

        try:
            # Check boot signature
            if mbr.boot_signature != 0x55AA:
                anomaly = Anomaly(
                    type="invalid_boot_signature",
                    description=f"Invalid boot signature: 0x{mbr.boot_signature:04X} (expected 0x55AA)",
                    severity="high",
                    location=510,
                )
                anomalies.append(anomaly)
                logger.warning(f"Boot signature anomaly detected: {anomaly.description}")

            # Check for overlapping partitions
            active_partitions = [p for p in mbr.partition_table if p.size_sectors > 0]
            for i, partition1 in enumerate(active_partitions):
                for j, partition2 in enumerate(active_partitions[i + 1:], i + 1):
                    if self._partitions_overlap(partition1, partition2):
                        anomaly = Anomaly(
                            type="overlapping_partitions",
                            description=f"Partitions overlap: LBA {partition1.start_lba}-{partition1.start_lba + partition1.size_sectors} and {partition2.start_lba}-{partition2.start_lba + partition2.size_sectors}",
                            severity="critical",
                        )
                        anomalies.append(anomaly)
                        logger.error(f"Partition overlap detected: {anomaly.description}")

            # Check for invalid partition types
            for i, partition in enumerate(mbr.partition_table):
                if partition.size_sectors > 0 and partition.partition_type == 0:
                    anomaly = Anomaly(
                        type="invalid_partition_type",
                        description=f"Partition {i} has size but type 0 (empty)",
                        severity="medium",
                        location=446 + (i * 16) + 4,
                    )
                    anomalies.append(anomaly)
                    logger.warning(f"Invalid partition type detected: {anomaly.description}")

            # Check for multiple active partitions (potential MBR hijacking)
            active_boot_partitions = [p for p in mbr.partition_table if p.status == 0x80]
            if len(active_boot_partitions) > 1:
                anomaly = Anomaly(
                    type="multiple_active_partitions",
                    description=f"Multiple active partitions detected ({len(active_boot_partitions)})",
                    severity="high",
                )
                anomalies.append(anomaly)
                logger.warning(f"Multiple active partitions: {anomaly.description}")

            # Check for suspicious partition status values
            for i, partition in enumerate(mbr.partition_table):
                if partition.status not in [0x00, 0x80] and partition.size_sectors > 0:
                    anomaly = Anomaly(
                        type="suspicious_partition_status",
                        description=f"Partition {i} has suspicious status: 0x{partition.status:02X}",
                        severity="medium",
                        location=446 + (i * 16),
                    )
                    anomalies.append(anomaly)
                    logger.warning(f"Suspicious partition status: {anomaly.description}")

            logger.info(f"Anomaly detection completed: {len(anomalies)} anomalies found")
            return anomalies
            
        except Exception as e:
            error_msg = f"Failed to detect anomalies: {e}"
            logger.error(error_msg, exc_info=True)
            raise ParsingError(
                error_msg,
                error_code="ANOMALY_DETECTION_ERROR",
                details={"exception_type": type(e).__name__, "error": str(e)}
            )

    def _partitions_overlap(self, p1: PartitionEntry, p2: PartitionEntry) -> bool:
        """
        Check if two partitions overlap in LBA space.
        
        Args:
            p1: First partition entry
            p2: Second partition entry
            
        Returns:
            True if partitions overlap, False otherwise
        """
        try:
            p1_end = p1.start_lba + p1.size_sectors
            p2_end = p2.start_lba + p2.size_sectors

            overlap = not (p1_end <= p2.start_lba or p2_end <= p1.start_lba)
            
            if overlap:
                logger.debug(f"Partition overlap detected: P1({p1.start_lba}-{p1_end}) vs P2({p2.start_lba}-{p2_end})")
            
            return overlap
            
        except Exception as e:
            logger.warning(f"Error checking partition overlap: {e}")
            return False
