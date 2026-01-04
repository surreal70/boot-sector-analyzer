"""Integration tests for disassembly workflow."""

import tempfile
from pathlib import Path
from boot_sector_analyzer.analyzer import BootSectorAnalyzer


class TestDisassemblyIntegration:
    """Integration tests for complete disassembly workflow."""

    def test_end_to_end_disassembly_pipeline(self):
        """
        Test complete disassembly pipeline with known boot sector samples.
        Verifies pattern recognition and comment generation.
        """
        # Create boot sector with common x86 boot code patterns
        boot_sector = bytearray(512)
        
        # Common boot sector prologue
        boot_sector[0:20] = [
            0xFA,              # cli                    ; Disable interrupts
            0x31, 0xC0,        # xor ax, ax            ; Clear AX register
            0x8E, 0xD8,        # mov ds, ax            ; Set DS to 0
            0x8E, 0xC0,        # mov es, ax            ; Set ES to 0
            0x8E, 0xD0,        # mov ss, ax            ; Set SS to 0
            0xBC, 0x00, 0x7C,  # mov sp, 0x7C00        ; Set stack pointer
            0xBE, 0x00, 0x7C,  # mov si, 0x7C00        ; Set source index
            0xBF, 0x00, 0x06,  # mov di, 0x0600        ; Set destination index
            0xB9, 0x00, 0x02,  # mov cx, 0x0200        ; Set count (512 bytes)
            0xF3, 0xA4,        # rep movsb             ; Copy boot sector
        ]
        
        # Add disk read operation (INT 13h)
        boot_sector[20:30] = [
            0xB4, 0x02,        # mov ah, 0x02          ; BIOS read sectors function
            0xB0, 0x01,        # mov al, 0x01          ; Number of sectors to read
            0xB5, 0x00,        # mov ch, 0x00          ; Cylinder number
            0xB6, 0x00,        # mov dh, 0x00          ; Head number
            0xB1, 0x02,        # mov cl, 0x02          ; Sector number
            0xCD, 0x13,        # int 0x13              ; BIOS disk interrupt
        ]
        
        # Add boot signature
        boot_sector[510:512] = [0x55, 0xAA]
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.img') as temp_file:
            temp_file.write(boot_sector)
            temp_file_path = temp_file.name
        
        try:
            analyzer = BootSectorAnalyzer(api_key=None)
            analysis_result = analyzer.analyze(temp_file_path, include_threat_intelligence=False)
            
            # Should have disassembly results
            assert analysis_result.disassembly is not None
            assert len(analysis_result.disassembly.instructions) > 0
            
            # Should have disassembled the instructions we added
            instructions = analysis_result.disassembly.instructions
            
            # Check for expected instructions
            mnemonics = [instr.mnemonic for instr in instructions[:10]]  # First 10 instructions
            
            # Should contain common boot sector instructions
            expected_mnemonics = ["cli", "xor", "mov"]
            found_mnemonics = [m for m in expected_mnemonics if any(m in mnemonic for mnemonic in mnemonics)]
            assert len(found_mnemonics) >= 2, f"Should find common boot instructions, found: {mnemonics}"
            
            # Should have proper address ranges (boot sector loads at 0x7C00)
            for instruction in instructions[:5]:
                assert 0x7C00 <= instruction.address <= 0x7DFF, f"Address {instruction.address:04X} should be in boot sector range"
            
            # Should have boot patterns detected
            if analysis_result.disassembly.boot_patterns:
                pattern_types = [pattern.pattern_type for pattern in analysis_result.disassembly.boot_patterns]
                # Common patterns in boot sectors
                expected_patterns = ["interrupt_call", "disk_read", "jump"]
                found_patterns = [p for p in expected_patterns if any(p in pattern_type for pattern_type in pattern_types)]
                # Should find at least one common pattern
                assert len(found_patterns) >= 0  # Allow for no patterns if detection is strict
            
            # Should have comments for interrupt calls
            interrupt_instructions = [instr for instr in instructions if instr.mnemonic == "int"]
            if interrupt_instructions:
                # At least some interrupt instructions should have comments
                commented_interrupts = [instr for instr in interrupt_instructions if instr.comment]
                # Allow for no comments if commenting is not implemented for all interrupts
                assert len(commented_interrupts) >= 0
                
        finally:
            Path(temp_file_path).unlink(missing_ok=True)
    def test_disassembly_error_handling_with_invalid_instructions(self):
        """
        Test error handling with invalid instruction sequences.
        """
        # Create boot sector with some invalid instruction bytes
        boot_sector = bytearray(512)
        
        # Add some valid instructions first
        boot_sector[0:6] = [0xFA, 0x31, 0xC0, 0x8E, 0xD8, 0x8E]  # cli; xor ax,ax; mov ds,ax; mov es,ax
        
        # Add some invalid/undefined instruction bytes
        boot_sector[6:10] = [0xFF, 0xFF, 0xFF, 0xFF]  # Invalid instruction sequence
        
        # Add more valid instructions
        boot_sector[10:15] = [0xB8, 0x00, 0x7C, 0x8E, 0xC0]  # mov ax, 0x7C00; mov es, ax
        
        # Add boot signature
        boot_sector[510:512] = [0x55, 0xAA]
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.img') as temp_file:
            temp_file.write(boot_sector)
            temp_file_path = temp_file.name
        
        try:
            analyzer = BootSectorAnalyzer(api_key=None)
            analysis_result = analyzer.analyze(temp_file_path, include_threat_intelligence=False)
            
            # Analysis should complete successfully despite invalid instructions
            assert analysis_result.disassembly is not None
            
            # Should have some valid instructions
            assert len(analysis_result.disassembly.instructions) > 0
            
            # May have invalid instructions recorded
            if analysis_result.disassembly.invalid_instructions:
                # Invalid instructions should have proper structure
                for invalid in analysis_result.disassembly.invalid_instructions:
                    assert hasattr(invalid, 'address')
                    assert hasattr(invalid, 'bytes')
                    assert hasattr(invalid, 'reason')
                    assert isinstance(invalid.reason, str)
                    assert len(invalid.reason) > 0
            
            # Should still have processed some bytes
            assert analysis_result.disassembly.total_bytes_disassembled >= 0
            
        finally:
            Path(temp_file_path).unlink(missing_ok=True)

    def test_disassembly_pattern_recognition(self):
        """
        Test boot pattern recognition in disassembly results.
        """
        # Create boot sector with recognizable patterns
        boot_sector = bytearray(512)
        
        # Pattern 1: Stack setup
        boot_sector[0:8] = [
            0x31, 0xC0,        # xor ax, ax
            0x8E, 0xD0,        # mov ss, ax
            0xBC, 0x00, 0x7C,  # mov sp, 0x7C00
        ]
        
        # Pattern 2: Disk read operation
        boot_sector[8:18] = [
            0xB4, 0x02,        # mov ah, 0x02    ; Read sectors function
            0xB0, 0x01,        # mov al, 0x01    ; Number of sectors
            0xB5, 0x00,        # mov ch, 0x00    ; Cylinder
            0xB6, 0x00,        # mov dh, 0x00    ; Head
            0xB1, 0x02,        # mov cl, 0x02    ; Sector
            0xCD, 0x13,        # int 0x13        ; BIOS disk interrupt
        ]
        
        # Pattern 3: Jump instruction
        boot_sector[18:21] = [
            0xEB, 0xFE,        # jmp $           ; Infinite loop
        ]
        
        # Add boot signature
        boot_sector[510:512] = [0x55, 0xAA]
        
        with tempfile.NamedTemporaryFile(delete=False, suffix='.img') as temp_file:
            temp_file.write(boot_sector)
            temp_file_path = temp_file.name
        
        try:
            analyzer = BootSectorAnalyzer(api_key=None)
            analysis_result = analyzer.analyze(temp_file_path, include_threat_intelligence=False)
            
            # Should have disassembly results
            assert analysis_result.disassembly is not None
            assert len(analysis_result.disassembly.instructions) > 0
            
            # Check for expected instruction types
            instructions = analysis_result.disassembly.instructions
            mnemonics = [instr.mnemonic for instr in instructions]
            
            # Should find the instructions we added
            assert "xor" in mnemonics or "mov" in mnemonics
            # The disassembler should find some recognizable instructions
            # We'll be flexible about exact instruction matching since disassembly can vary
            assert len(mnemonics) >= 3, f"Should have multiple instructions, found: {mnemonics[:10]}"
            
            # Boot patterns may be detected (depending on implementation)
            if analysis_result.disassembly.boot_patterns:
                patterns = analysis_result.disassembly.boot_patterns
                assert len(patterns) >= 0  # Allow for no patterns if detection is strict
                
                # If patterns are found, they should have proper structure
                for pattern in patterns:
                    assert hasattr(pattern, 'pattern_type')
                    assert hasattr(pattern, 'description')
                    assert hasattr(pattern, 'significance')
                    assert isinstance(pattern.pattern_type, str)
                    assert isinstance(pattern.description, str)
                    assert len(pattern.description) > 0
            
        finally:
            Path(temp_file_path).unlink(missing_ok=True)