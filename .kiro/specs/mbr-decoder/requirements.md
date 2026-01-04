# Requirements Document

## Introduction

The MBR Decoder is a system that interprets and analyzes the 512-byte Master Boot Record (MBR) structure found at the beginning of storage devices. The MBR contains critical information including the partition table, boot code, and disk signature that enables operating systems to understand disk layout and boot processes.

## Glossary

- **MBR**: Master Boot Record - the 512-byte structure at sector 0 of a storage device
- **Partition_Table**: The 64-byte section containing up to 4 partition entries
- **Boot_Code**: The executable code section (first 446 bytes) responsible for initial boot process
- **Boot_Signature**: The 2-byte signature (0x55AA) that validates the MBR
- **Partition_Entry**: A 16-byte structure describing a single partition
- **CHS**: Cylinder-Head-Sector addressing scheme
- **LBA**: Logical Block Addressing scheme
- **System_ID**: The partition type identifier (1 byte)
- **Decoder**: The system that parses and interprets MBR data
- **Validator**: Component that verifies MBR structure integrity

## Requirements

### Requirement 1: Parse MBR Structure

**User Story:** As a system administrator, I want to parse the complete 512-byte MBR structure, so that I can understand the disk layout and partition configuration.

#### Acceptance Criteria

1. WHEN a 512-byte MBR is provided, THE Decoder SHALL extract the boot code from bytes 0-445
2. WHEN a 512-byte MBR is provided, THE Decoder SHALL extract the disk signature from bytes 440-443
3. WHEN a 512-byte MBR is provided, THE Decoder SHALL extract the partition table from bytes 446-509
4. WHEN a 512-byte MBR is provided, THE Decoder SHALL extract the boot signature from bytes 510-511
5. WHEN the boot signature is not 0x55AA, THE Decoder SHALL report an invalid MBR

### Requirement 2: Interpret Partition Table Entries

**User Story:** As a developer, I want to decode individual partition entries, so that I can understand partition boundaries and types.

#### Acceptance Criteria

1. WHEN a partition entry is provided, THE Decoder SHALL extract the bootable flag from byte 0
2. WHEN a partition entry is provided, THE Decoder SHALL extract the starting CHS address from bytes 1-3
3. WHEN a partition entry is provided, THE Decoder SHALL extract the system ID from byte 4
4. WHEN a partition entry is provided, THE Decoder SHALL extract the ending CHS address from bytes 5-7
5. WHEN a partition entry is provided, THE Decoder SHALL extract the starting LBA from bytes 8-11
6. WHEN a partition entry is provided, THE Decoder SHALL extract the partition size from bytes 12-15

### Requirement 3: Validate MBR Integrity

**User Story:** As a forensic analyst, I want to validate MBR structure integrity, so that I can detect corruption or tampering.

#### Acceptance Criteria

1. WHEN validating an MBR, THE Validator SHALL verify the boot signature equals 0x55AA
2. WHEN validating an MBR, THE Validator SHALL check that at most one partition is marked as bootable
3. WHEN validating partition entries, THE Validator SHALL verify that partition boundaries do not overlap
4. WHEN validating partition entries, THE Validator SHALL verify that LBA values are consistent with partition sizes
5. WHEN validation fails, THE Validator SHALL provide specific error descriptions

### Requirement 4: Convert Between Addressing Schemes

**User Story:** As a disk utility developer, I want to convert between CHS and LBA addressing, so that I can work with both legacy and modern disk access methods.

#### Acceptance Criteria

1. WHEN converting CHS to LBA, THE Decoder SHALL use the formula: LBA = (C × heads + H) × sectors + S - 1
2. WHEN converting LBA to CHS, THE Decoder SHALL compute cylinder, head, and sector values
3. WHEN CHS values exceed disk geometry limits, THE Decoder SHALL report the limitation
4. WHEN LBA values are provided, THE Decoder SHALL validate they are within 32-bit range for MBR
5. WHEN conversion is impossible due to geometry constraints, THE Decoder SHALL provide alternative representations

### Requirement 5: Identify Partition Types

**User Story:** As a system analyst, I want to identify partition types from system IDs, so that I can understand what filesystems and operating systems are present.

#### Acceptance Criteria

1. WHEN a system ID is provided, THE Decoder SHALL return the corresponding partition type name
2. WHEN a system ID is unknown, THE Decoder SHALL return a generic description with the hex value
3. WHEN multiple operating systems use the same ID, THE Decoder SHALL list all possibilities
4. THE Decoder SHALL support all standard partition type identifiers from 0x00 to 0xFF
5. THE Decoder SHALL provide descriptions for common partition types (FAT, NTFS, Linux, etc.)

### Requirement 6: Generate Human-Readable Reports

**User Story:** As a technical support specialist, I want to generate readable reports of MBR contents, so that I can communicate disk layout information clearly.

#### Acceptance Criteria

1. WHEN generating a report, THE Decoder SHALL display partition table in tabular format
2. WHEN generating a report, THE Decoder SHALL show both CHS and LBA addressing for each partition
3. WHEN generating a report, THE Decoder SHALL display partition sizes in human-readable units
4. WHEN generating a report, THE Decoder SHALL highlight any validation warnings or errors
5. WHEN generating a report, THE Decoder SHALL include disk signature and boot code information

### Requirement 7: Handle Edge Cases and Legacy Formats

**User Story:** As a data recovery specialist, I want to handle various MBR edge cases and legacy formats, so that I can work with older or unusual disk configurations.

#### Acceptance Criteria

1. WHEN encountering empty partition entries, THE Decoder SHALL skip them gracefully
2. WHEN encountering extended partition types (0x05, 0x0F), THE Decoder SHALL identify them as containers
3. WHEN CHS addressing shows 1023/254/63, THE Decoder SHALL recognize this as LBA-only indication
4. WHEN disk signature is zero, THE Decoder SHALL note this as potentially uninitialized
5. WHEN boot code section contains non-standard patterns, THE Decoder SHALL still process the partition table

### Requirement 8: Provide Programming Interface

**User Story:** As a software developer, I want a clean programming interface for MBR operations, so that I can integrate MBR parsing into larger applications.

#### Acceptance Criteria

1. THE Decoder SHALL provide a function to parse raw 512-byte MBR data
2. THE Decoder SHALL provide structured data types for MBR components
3. THE Decoder SHALL provide error handling with specific error codes
4. THE Decoder SHALL provide functions for individual component extraction
5. THE Decoder SHALL provide validation functions that return detailed results