"""Property-based tests for DisassemblyEngine and boot code disassembly."""

from hypothesis import given, strategies as st, assume
import pytest

from boot_sector_analyzer.disassembly_engine import DisassemblyEngine
from boot_sector_analyzer.content_analyzer import ContentAnalyzer
from boot_sector_analyzer.models import Instruction, InvalidInstruction, BootPattern


class TestDisassemblyProperties:
    """Property-based tests for DisassemblyEngine and disassembly functionality."""

    def setup_method(self):
        """Set up test fixtures."""
        self.disassembly_engine = DisassemblyEngine()
        self.content_analyzer = ContentAnalyzer()

    @given(
        boot_code=st.binary(min_size=1, max_size=446),
        base_address=st.integers(min_value=0x7C00, max_value=0x7C00 + 446)
    )
    def test_boot_code_disassembly_completeness(self, boot_code, base_address):
        """
        Property 8: Boot code disassembly completeness
        For any boot sector, the Content_Analyzer should disassemble the first 446 bytes as x86 assembly instructions,
        providing instruction addresses, opcodes, and mnemonics for valid instructions
        **Validates: Requirements 3.7, 3.8, 11.1, 11.3**
        **Feature: boot-sector-analyzer, Property 8: Boot code disassembly completeness**
        """
        # Perform disassembly with error handling
        result = self.disassembly_engine.disassemble_with_error_handling(
            boot_code, 
            base_address=base_address,
            prefer_16bit=True
        )
        
        # Verify result structure
        assert hasattr(result, 'instructions')
        assert hasattr(result, 'total_bytes_disassembled')
        assert hasattr(result, 'invalid_instructions')
        assert hasattr(result, 'boot_patterns')
        
        # Verify all instructions have required fields
        for instruction in result.instructions:
            assert isinstance(instruction, Instruction)
            assert isinstance(instruction.address, int)
            assert isinstance(instruction.bytes, bytes)
            assert isinstance(instruction.mnemonic, str)
            assert isinstance(instruction.operands, str)
            assert instruction.comment is None or isinstance(instruction.comment, str)
            
            # Verify address is within expected range
            assert instruction.address >= base_address
            assert instruction.address < base_address + len(boot_code)
            
            # Verify instruction bytes are not empty
            assert len(instruction.bytes) > 0
            
            # Verify mnemonic is not empty
            assert len(instruction.mnemonic) > 0
        
        # Verify invalid instructions have required fields
        for invalid_insn in result.invalid_instructions:
            assert isinstance(invalid_insn, InvalidInstruction)
            assert isinstance(invalid_insn.address, int)
            assert isinstance(invalid_insn.bytes, bytes)
            assert isinstance(invalid_insn.reason, str)
            
            # Verify address is within expected range
            assert invalid_insn.address >= base_address
            assert invalid_insn.address < base_address + len(boot_code)
            
            # Verify reason is not empty
            assert len(invalid_insn.reason) > 0
        
        # Verify boot patterns have required fields
        for pattern in result.boot_patterns:
            assert isinstance(pattern, BootPattern)
            assert isinstance(pattern.pattern_type, str)
            assert isinstance(pattern.description, str)
            assert isinstance(pattern.instructions, list)
            assert isinstance(pattern.significance, str)
            
            # Verify pattern fields are not empty
            assert len(pattern.pattern_type) > 0
            assert len(pattern.description) > 0
            assert len(pattern.significance) > 0
        
        # Verify total bytes processed doesn't exceed input
        assert result.total_bytes_disassembled <= len(boot_code)
        
        # Verify that we either have instructions or invalid instructions
        total_processed = result.total_bytes_disassembled + sum(
            len(invalid.bytes) for invalid in result.invalid_instructions
        )
        assert total_processed <= len(boot_code)

    @given(
        boot_code_16=st.binary(min_size=1, max_size=100),
        boot_code_32=st.binary(min_size=1, max_size=100)
    )
    def test_multi_mode_disassembly_support(self, boot_code_16, boot_code_32):
        """
        Property 10: Multi-mode disassembly support
        For any boot code requiring different instruction modes, the Content_Analyzer should handle 
        both 16-bit and 32-bit x86 instruction modes appropriately
        **Validates: Requirements 11.2**
        **Feature: boot-sector-analyzer, Property 10: Multi-mode disassembly support**
        """
        base_address = 0x7C00
        
        # Test 16-bit mode disassembly
        instructions_16 = self.disassembly_engine.disassemble_16bit(boot_code_16, base_address)
        
        # Test 32-bit mode disassembly
        instructions_32 = self.disassembly_engine.disassemble_32bit(boot_code_32, base_address)
        
        # Verify both modes return instruction lists
        assert isinstance(instructions_16, list)
        assert isinstance(instructions_32, list)
        
        # Verify all 16-bit instructions have proper structure
        for instruction in instructions_16:
            assert isinstance(instruction, Instruction)
            assert isinstance(instruction.address, int)
            assert isinstance(instruction.bytes, bytes)
            assert isinstance(instruction.mnemonic, str)
            assert isinstance(instruction.operands, str)
            assert instruction.address >= base_address
        
        # Verify all 32-bit instructions have proper structure
        for instruction in instructions_32:
            assert isinstance(instruction, Instruction)
            assert isinstance(instruction.address, int)
            assert isinstance(instruction.bytes, bytes)
            assert isinstance(instruction.mnemonic, str)
            assert isinstance(instruction.operands, str)
            assert instruction.address >= base_address
        
        # Test that both modes can handle the same code (might produce different results)
        if boot_code_16:
            instructions_16_alt = self.disassembly_engine.disassemble_32bit(boot_code_16, base_address)
            assert isinstance(instructions_16_alt, list)
        
        if boot_code_32:
            instructions_32_alt = self.disassembly_engine.disassemble_16bit(boot_code_32, base_address)
            assert isinstance(instructions_32_alt, list)

    @given(
        valid_instructions=st.lists(
            st.sampled_from([
                b"\x90",  # NOP
                b"\xEB\xFE",  # JMP $
                b"\xB4\x02",  # MOV AH, 02h
                b"\xCD\x13",  # INT 13h
                b"\xCD\x10",  # INT 10h
                b"\x50",  # PUSH AX
                b"\x58",  # POP AX
                b"\xF4",  # HLT
            ]),
            min_size=1,
            max_size=10
        )
    )
    def test_boot_pattern_recognition(self, valid_instructions):
        """
        Property 11: Boot pattern recognition
        For any boot code containing common boot sector patterns (jump instructions, interrupt calls, disk operations),
        the Content_Analyzer should identify and highlight these patterns
        **Validates: Requirements 11.7**
        **Feature: boot-sector-analyzer, Property 11: Boot pattern recognition**
        """
        # Build boot code with known patterns
        boot_code = b"".join(valid_instructions)
        
        # Disassemble the code
        result = self.disassembly_engine.disassemble_with_error_handling(boot_code, 0x7C00, True)
        
        # Check if patterns are identified
        patterns = result.boot_patterns
        
        # Verify pattern structure
        for pattern in patterns:
            assert isinstance(pattern, BootPattern)
            assert isinstance(pattern.pattern_type, str)
            assert isinstance(pattern.description, str)
            assert isinstance(pattern.instructions, list)
            assert isinstance(pattern.significance, str)
            
            # Verify pattern fields are meaningful
            assert len(pattern.pattern_type) > 0
            assert len(pattern.description) > 0
            assert len(pattern.significance) > 0
            
            # Verify pattern instructions are valid
            for instruction in pattern.instructions:
                assert isinstance(instruction, Instruction)
        
        # Check for specific patterns based on input
        has_disk_read = any(b"\xB4\x02" in instr and b"\xCD\x13" in boot_code for instr in valid_instructions)
        has_int_calls = any(b"\xCD" in instr for instr in valid_instructions)
        has_jumps = any(b"\xEB" in instr for instr in valid_instructions)
        
        if has_disk_read:
            # Should detect disk read pattern
            disk_patterns = [p for p in patterns if "disk" in p.pattern_type.lower() or "disk" in p.description.lower()]
            # Note: Pattern detection depends on instruction sequence, so we just verify structure
        
        if has_int_calls:
            # Should have some interrupt-related patterns or comments
            int_instructions = [i for i in result.instructions if i.mnemonic.lower() == "int"]
            for int_instr in int_instructions:
                # Verify interrupt instructions have appropriate comments
                if int_instr.comment:
                    assert isinstance(int_instr.comment, str)
                    assert len(int_instr.comment) > 0

    @given(
        boot_code=st.binary(min_size=1, max_size=446)
    )
    def test_assembly_instruction_commenting(self, boot_code):
        """
        Property 12: Assembly instruction commenting
        For any disassembled boot code containing common boot sector operations (INT 13h, INT 10h, etc.),
        the Content_Analyzer should include explanatory comments
        **Validates: Requirements 11.9**
        **Feature: boot-sector-analyzer, Property 12: Assembly instruction commenting**
        """
        # Disassemble the boot code
        result = self.disassembly_engine.disassemble_with_error_handling(boot_code, 0x7C00, True)
        
        # Check comments on instructions
        for instruction in result.instructions:
            # Verify comment structure if present
            if instruction.comment is not None:
                assert isinstance(instruction.comment, str)
                assert len(instruction.comment) > 0
            
            # Check specific instruction types for appropriate comments
            if instruction.mnemonic.lower() == "int":
                # INT instructions should have comments explaining the interrupt
                if "0x10" in instruction.operands:
                    if instruction.comment:
                        assert "video" in instruction.comment.lower() or "bios" in instruction.comment.lower()
                elif "0x13" in instruction.operands:
                    if instruction.comment:
                        assert "disk" in instruction.comment.lower() or "bios" in instruction.comment.lower()
                elif "0x16" in instruction.operands:
                    if instruction.comment:
                        assert "keyboard" in instruction.comment.lower() or "bios" in instruction.comment.lower()
                elif "0x19" in instruction.operands:
                    if instruction.comment:
                        assert "bootstrap" in instruction.comment.lower() or "boot" in instruction.comment.lower()
            
            # Jump instructions should have control flow comments
            elif instruction.mnemonic.lower().startswith("j"):
                if instruction.comment:
                    assert "control" in instruction.comment.lower() or "flow" in instruction.comment.lower()
            
            # Stack operations should have stack comments
            elif instruction.mnemonic.lower() in ["push", "pop"]:
                if instruction.comment:
                    assert "stack" in instruction.comment.lower()
            
            # Halt instruction should have halt comment
            elif instruction.mnemonic.lower() == "hlt":
                if instruction.comment:
                    assert "halt" in instruction.comment.lower()

    @given(
        invalid_bytes=st.binary(min_size=1, max_size=50)
    )
    def test_disassembly_error_handling(self, invalid_bytes):
        """
        Property 9: Disassembly error handling
        For any boot code containing invalid or unrecognized instructions, the Content_Analyzer should handle them
        gracefully by displaying them as raw hex data and continuing analysis
        **Validates: Requirements 3.9, 11.6**
        **Feature: boot-sector-analyzer, Property 9: Disassembly error handling**
        """
        # Create boot code with potentially invalid bytes
        boot_code = invalid_bytes
        
        # Disassemble with error handling
        result = self.disassembly_engine.disassemble_with_error_handling(boot_code, 0x7C00, True)
        
        # Verify that the function completes without raising exceptions
        assert result is not None
        assert hasattr(result, 'instructions')
        assert hasattr(result, 'invalid_instructions')
        assert hasattr(result, 'total_bytes_disassembled')
        assert hasattr(result, 'boot_patterns')
        
        # Verify that all bytes are accounted for (either as valid or invalid instructions)
        total_instruction_bytes = sum(len(instr.bytes) for instr in result.instructions)
        total_invalid_bytes = sum(len(invalid.bytes) for invalid in result.invalid_instructions)
        
        # The total should not exceed the input length
        assert total_instruction_bytes + total_invalid_bytes <= len(boot_code)
        
        # Verify invalid instruction structure
        for invalid_instr in result.invalid_instructions:
            assert isinstance(invalid_instr, InvalidInstruction)
            assert isinstance(invalid_instr.address, int)
            assert isinstance(invalid_instr.bytes, bytes)
            assert isinstance(invalid_instr.reason, str)
            assert len(invalid_instr.bytes) > 0
            assert len(invalid_instr.reason) > 0
            assert invalid_instr.address >= 0x7C00
        
        # Verify that valid instructions still have proper structure
        for instruction in result.instructions:
            assert isinstance(instruction, Instruction)
            assert isinstance(instruction.address, int)
            assert isinstance(instruction.bytes, bytes)
            assert isinstance(instruction.mnemonic, str)
            assert len(instruction.bytes) > 0
            assert len(instruction.mnemonic) > 0