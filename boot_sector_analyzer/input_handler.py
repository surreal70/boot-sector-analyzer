"""Input handling for boot sector data."""

import logging
import os
from pathlib import Path
from typing import Union

from .exceptions import (
    InputError,
    InvalidBootSectorError,
    FileAccessError,
    BSAPermissionError
)

logger = logging.getLogger(__name__)


class InputHandler:
    """Handles reading boot sector data from various sources."""

    BOOT_SECTOR_SIZE = 512

    def read_boot_sector(self, source: Union[str, Path]) -> bytes:
        """
        Read 512 bytes from device or file.

        Args:
            source: Path to device or image file

        Returns:
            512 bytes of boot sector data

        Raises:
            FileAccessError: If source file/device doesn't exist
            BSAPermissionError: If insufficient permissions to read source
            InvalidBootSectorError: If data is not exactly 512 bytes
            InputError: For other input-related errors
        """
        source_path = Path(source)
        
        logger.info(f"Attempting to read boot sector from: {source}")
        
        # Validate source path
        if not source_path.exists() and not str(source_path).startswith('/dev/'):
            error_msg = f"Source not found: {source}"
            logger.error(error_msg)
            raise FileAccessError(
                error_msg,
                error_code="FILE_NOT_FOUND",
                details={"source": str(source), "resolved_path": str(source_path)}
            )

        try:
            # Check if we have read permissions
            if source_path.exists() and not os.access(source_path, os.R_OK):
                error_msg = f"No read permission for: {source}"
                logger.error(error_msg)
                raise BSAPermissionError(
                    error_msg,
                    error_code="READ_PERMISSION_DENIED",
                    details={"source": str(source), "uid": os.getuid(), "gid": os.getgid()}
                )

            with open(source_path, "rb") as f:
                logger.debug(f"Opened file/device: {source}")
                data = f.read(self.BOOT_SECTOR_SIZE)

            # Validate boot sector size
            if len(data) == 0:
                error_msg = f"No data read from source: {source}"
                logger.error(error_msg)
                raise InvalidBootSectorError(
                    error_msg,
                    error_code="EMPTY_SOURCE",
                    details={"source": str(source), "bytes_read": 0}
                )
            
            if len(data) != self.BOOT_SECTOR_SIZE:
                error_msg = (
                    f"Boot sector must be exactly {self.BOOT_SECTOR_SIZE} bytes, "
                    f"got {len(data)} bytes from {source}"
                )
                logger.error(error_msg)
                raise InvalidBootSectorError(
                    error_msg,
                    error_code="INVALID_SIZE",
                    details={
                        "source": str(source),
                        "expected_size": self.BOOT_SECTOR_SIZE,
                        "actual_size": len(data)
                    }
                )

            logger.info(f"Successfully read {len(data)} bytes from {source}")
            logger.debug(f"Boot sector data preview: {data[:16].hex()}")
            return data

        except FileNotFoundError as e:
            error_msg = f"Source not found: {source}"
            logger.error(f"{error_msg} - {e}")
            raise FileAccessError(
                error_msg,
                error_code="FILE_NOT_FOUND",
                details={"source": str(source), "system_error": str(e)}
            )
        except PermissionError as e:
            error_msg = f"Permission denied reading: {source}"
            logger.error(f"{error_msg} - {e}")
            raise BSAPermissionError(
                error_msg,
                error_code="PERMISSION_DENIED",
                details={"source": str(source), "system_error": str(e)}
            )
        except (InvalidBootSectorError, FileAccessError, BSAPermissionError) as e:
            # Re-raise our specific exceptions without wrapping
            raise e
        except OSError as e:
            error_msg = f"OS error reading {source}: {e}"
            logger.error(error_msg)
            raise InputError(
                error_msg,
                error_code="OS_ERROR",
                details={"source": str(source), "errno": e.errno, "system_error": str(e)}
            )
        except IOError as e:
            error_msg = f"I/O error reading {source}: {e}"
            logger.error(error_msg)
            raise InputError(
                error_msg,
                error_code="IO_ERROR",
                details={"source": str(source), "system_error": str(e)}
            )
        except Exception as e:
            error_msg = f"Unexpected error reading {source}: {e}"
            logger.error(error_msg, exc_info=True)
            raise InputError(
                error_msg,
                error_code="UNEXPECTED_ERROR",
                details={"source": str(source), "exception_type": type(e).__name__, "system_error": str(e)}
            )

    def validate_boot_sector(self, data: bytes) -> bool:
        """
        Validate boot sector size and basic structure.

        Args:
            data: Boot sector data to validate

        Returns:
            True if data appears to be a valid boot sector
            
        Raises:
            InvalidBootSectorError: If data is fundamentally invalid
        """
        logger.debug("Validating boot sector data")
        
        if not isinstance(data, bytes):
            error_msg = f"Boot sector data must be bytes, got {type(data)}"
            logger.error(error_msg)
            raise InvalidBootSectorError(
                error_msg,
                error_code="INVALID_DATA_TYPE",
                details={"data_type": str(type(data))}
            )
        
        if len(data) != self.BOOT_SECTOR_SIZE:
            error_msg = f"Invalid boot sector size: {len(data)} bytes (expected {self.BOOT_SECTOR_SIZE})"
            logger.warning(error_msg)
            # Don't raise exception here, just log warning and return False
            return False

        # Check for boot signature at the end
        if len(data) >= 2:
            signature = int.from_bytes(data[-2:], byteorder="little")
            if signature == 0x55AA:
                logger.debug("Valid boot signature found (0x55AA)")
                return True
            else:
                logger.warning(f"Invalid boot signature: 0x{signature:04X} (expected 0x55AA)")
                # Still consider it valid for analysis even without signature
                return True

        logger.debug("Boot sector validation completed")
        return True
