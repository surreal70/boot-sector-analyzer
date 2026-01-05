"""Partition scanner for VBR detection and extraction."""

import logging
import os
from typing import List, Optional

from .models import (
    MBRStructure,
    PartitionEntry,
    ValidPartition,
    VBRData
)


class PartitionScanner:
    """Scanner for identifying valid partitions and extracting VBR data."""

    def __init__(self):
        """Initialize the partition scanner."""
        self.logger = logging.getLogger(__name__)

    def identify_valid_partitions(self, mbr_structure: MBRStructure) -> List[ValidPartition]:
        """
        Identify valid, non-empty partitions from MBR analysis.
        
        Args:
            mbr_structure: Parsed MBR structure containing partition table
            
        Returns:
            List of valid partitions suitable for VBR extraction
        """
        valid_partitions = []
        
        for i, partition in enumerate(mbr_structure.partition_table, 1):
            if self._is_valid_partition(partition):
                start_offset = self.calculate_partition_offset(partition)
                valid_partition = ValidPartition(
                    partition_entry=partition,
                    partition_number=i,
                    start_byte_offset=start_offset,
                    is_accessible=True  # Will be validated during extraction
                )
                valid_partitions.append(valid_partition)
                self.logger.debug(
                    f"Found valid partition {i}: type=0x{partition.partition_type:02X}, "
                    f"start_lba={partition.start_lba}, size={partition.size_sectors} sectors"
                )
        
        self.logger.info(f"Identified {len(valid_partitions)} valid partitions for VBR extraction")
        return valid_partitions

    def calculate_partition_offset(self, partition: PartitionEntry) -> int:
        """
        Calculate byte offset for partition's first sector.
        
        Args:
            partition: Partition entry from MBR
            
        Returns:
            Byte offset where the partition's VBR is located
        """
        # Convert LBA to byte offset (LBA * 512 bytes per sector)
        return partition.start_lba * 512

    def validate_partition_access(self, device_path: str, partition: PartitionEntry) -> bool:
        """
        Validate that partition can be accessed for VBR extraction.
        
        Args:
            device_path: Path to the disk device
            partition: Partition entry to validate
            
        Returns:
            True if partition is accessible, False otherwise
        """
        try:
            # Check if device exists and is readable
            if not os.path.exists(device_path):
                self.logger.warning(f"Device path does not exist: {device_path}")
                return False
            
            # Check if we can open the device for reading
            with open(device_path, 'rb') as device:
                # Try to seek to the partition start
                offset = self.calculate_partition_offset(partition)
                device.seek(offset)
                
                # Try to read a small amount to verify accessibility
                test_data = device.read(512)
                if len(test_data) != 512:
                    self.logger.warning(
                        f"Could not read full sector at offset {offset} "
                        f"(got {len(test_data)} bytes)"
                    )
                    return False
                
                return True
                
        except (OSError, IOError, PermissionError) as e:
            self.logger.warning(f"Cannot access partition at {device_path}: {e}")
            return False

    def extract_vbr_data(self, device_path: str, partition: PartitionEntry) -> Optional[bytes]:
        """
        Extract 512 bytes from partition's first sector.
        
        Args:
            device_path: Path to the disk device
            partition: Partition entry containing start LBA
            
        Returns:
            512-byte VBR data if successful, None if extraction failed
        """
        try:
            offset = self.calculate_partition_offset(partition)
            
            with open(device_path, 'rb') as device:
                device.seek(offset)
                vbr_data = device.read(512)
                
                if len(vbr_data) != 512:
                    self.logger.error(
                        f"VBR extraction failed: expected 512 bytes, got {len(vbr_data)} bytes "
                        f"at offset {offset}"
                    )
                    return None
                
                self.logger.debug(f"Successfully extracted VBR from offset {offset}")
                return vbr_data
                
        except (OSError, IOError, PermissionError) as e:
            self.logger.error(f"VBR extraction failed for offset {offset}: {e}")
            return None

    def _is_valid_partition(self, partition: PartitionEntry) -> bool:
        """
        Check if a partition entry is valid and non-empty.
        
        Args:
            partition: Partition entry to validate
            
        Returns:
            True if partition is valid and non-empty
        """
        # Check if partition is empty (all fields zero)
        if (partition.partition_type == 0 and 
            partition.start_lba == 0 and 
            partition.size_sectors == 0):
            return False
        
        # Check for reasonable partition type (not 0x00)
        if partition.partition_type == 0:
            return False
        
        # Check for reasonable start LBA (not 0, as that would be MBR)
        if partition.start_lba == 0:
            return False
        
        # Check for reasonable size
        if partition.size_sectors == 0:
            return False
        
        return True