"""Disassembly engine for boot sector code analysis."""

import logging
from typing import List, Optional, Tuple
import capstone

from .models import (
    Instruction,
    InvalidInstruction,
    BootPattern,
    DisassemblyResult
)


class DisassemblyEngine:
    """Engine for disassembling x86/x86-64 boot sector code."""

    def __init__(self):
        """Initialize Capstone disassembly engine for x86 architecture."""
        self.logger = logging.getLogger(__name__)
        
        # Initialize Capstone engines for different modes
        try:
            self.cs_16 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_16)
            self.cs_32 = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
            
            # Enable detailed instruction information
            self.cs_16.detail = True
            self.cs_32.detail = True
            
            self.logger.debug("Capstone disassembly engines initialized successfully")
        except Exception as e:
            self.logger.error(f"Failed to initialize Capstone engines: {e}")
            raise

    def disassemble_16bit(self, code: bytes, base_address: int = 0x7C00) -> List[Instruction]:
        """
        Disassemble 16-bit x86 code (typical for boot sectors).
        
        Args:
            code: Raw bytes to disassemble
            base_address: Base memory address (default 0x7C00 for boot sectors)
            
        Returns:
            List of disassembled instructions
        """
        instructions = []
        
        try:
            for insn in self.cs_16.disasm(code, base_address):
                instruction = Instruction(
                    address=insn.address,
                    bytes=bytes(insn.bytes),  # Convert bytearray to bytes
                    mnemonic=insn.mnemonic,
                    operands=insn.op_str,
                    comment=self.add_comments(insn)
                )
                instructions.append(instruction)
                
        except Exception as e:
            self.logger.warning(f"Error during 16-bit disassembly: {e}")
            
        return instructions

    def disassemble_32bit(self, code: bytes, base_address: int = 0x7C00) -> List[Instruction]:
        """
        Disassemble 32-bit x86 code.
        
        Args:
            code: Raw bytes to disassemble
            base_address: Base memory address (default 0x7C00 for boot sectors)
            
        Returns:
            List of disassembled instructions
        """
        instructions = []
        
        try:
            for insn in self.cs_32.disasm(code, base_address):
                instruction = Instruction(
                    address=insn.address,
                    bytes=bytes(insn.bytes),  # Convert bytearray to bytes
                    mnemonic=insn.mnemonic,
                    operands=insn.op_str,
                    comment=self.add_comments(insn)
                )
                instructions.append(instruction)
                
        except Exception as e:
            self.logger.warning(f"Error during 32-bit disassembly: {e}")
            
        return instructions

    def format_instruction(self, instruction: Instruction) -> str:
        """
        Format instruction with address, bytes, and mnemonic for display.
        
        Args:
            instruction: Instruction to format
            
        Returns:
            Formatted instruction string
        """
        # Format address as hex
        addr_str = f"0x{instruction.address:04X}"
        
        # Format bytes as hex string
        bytes_str = " ".join(f"{b:02X}" for b in instruction.bytes)
        bytes_str = f"{bytes_str:<12}"  # Left-align with padding
        
        # Format mnemonic and operands
        if instruction.operands:
            asm_str = f"{instruction.mnemonic} {instruction.operands}"
        else:
            asm_str = instruction.mnemonic
            
        # Add comment if present
        if instruction.comment:
            asm_str += f"  ; {instruction.comment}"
            
        return f"{addr_str}: {bytes_str} {asm_str}"

    def add_comments(self, insn) -> Optional[str]:
        """
        Add explanatory comments for common boot sector operations.
        
        Args:
            insn: Capstone instruction object
            
        Returns:
            Comment string or None
        """
        mnemonic = insn.mnemonic.lower()
        
        # INT instruction comments
        if mnemonic == "int":
            if insn.op_str == "0x10":
                return "BIOS video services"
            elif insn.op_str == "0x13":
                return "BIOS disk services"
            elif insn.op_str == "0x16":
                return "BIOS keyboard services"
            elif insn.op_str == "0x19":
                return "Bootstrap loader"
            elif insn.op_str == "0x1a":
                return "BIOS time services"
            else:
                return f"BIOS interrupt {insn.op_str}"
        
        # Jump instruction comments
        elif mnemonic in ["jmp", "je", "jne", "jz", "jnz", "jc", "jnc", "js", "jns"]:
            return "Control flow"
            
        # Disk operation related instructions
        elif mnemonic in ["mov"] and "dl" in insn.op_str.lower():
            return "Drive number setup"
        elif mnemonic in ["mov"] and ("ah" in insn.op_str.lower() or "al" in insn.op_str.lower()):
            return "Function/parameter setup"
            
        # Stack operations
        elif mnemonic in ["push", "pop"]:
            return "Stack operation"
            
        # Halt instruction
        elif mnemonic == "hlt":
            return "Halt processor"
            
        # CLI/STI instructions
        elif mnemonic == "cli":
            return "Disable interrupts"
        elif mnemonic == "sti":
            return "Enable interrupts"
            
        return None

    def identify_boot_patterns(self, instructions: List[Instruction]) -> List[BootPattern]:
        """
        Identify common boot sector patterns and operations.
        
        Args:
            instructions: List of disassembled instructions
            
        Returns:
            List of identified boot patterns
        """
        patterns = []
        
        # Look for disk read patterns (INT 13h with AH=02h)
        disk_read_pattern = self._find_disk_read_pattern(instructions)
        if disk_read_pattern:
            patterns.append(disk_read_pattern)
            
        # Look for jump patterns
        jump_patterns = self._find_jump_patterns(instructions)
        patterns.extend(jump_patterns)
        
        # Look for interrupt call patterns
        interrupt_patterns = self._find_interrupt_patterns(instructions)
        patterns.extend(interrupt_patterns)
        
        return patterns

    def _find_disk_read_pattern(self, instructions: List[Instruction]) -> Optional[BootPattern]:
        """Find disk read operations (INT 13h with AH=02h)."""
        pattern_instructions = []
        
        for i, insn in enumerate(instructions):
            # Look for MOV AH, 02h followed by INT 13h
            if (insn.mnemonic.lower() == "mov" and 
                "ah" in insn.operands.lower() and 
                ("0x2" in insn.operands or "2" in insn.operands)):
                
                # Check if followed by INT 13h within next few instructions
                for j in range(i + 1, min(i + 5, len(instructions))):
                    next_insn = instructions[j]
                    if (next_insn.mnemonic.lower() == "int" and 
                        "0x13" in next_insn.operands):
                        
                        pattern_instructions = instructions[i:j+1]
                        return BootPattern(
                            pattern_type="disk_read",
                            description="BIOS disk read operation",
                            instructions=pattern_instructions,
                            significance="Reads sectors from disk using BIOS INT 13h function 02h"
                        )
        
        return None

    def _find_jump_patterns(self, instructions: List[Instruction]) -> List[BootPattern]:
        """Find significant jump patterns."""
        patterns = []
        
        for insn in instructions:
            if insn.mnemonic.lower().startswith("j"):
                # Check for far jumps (potential boot handoff)
                if ":" in insn.operands:
                    patterns.append(BootPattern(
                        pattern_type="far_jump",
                        description="Far jump to loaded code",
                        instructions=[insn],
                        significance="Transfers control to loaded boot code"
                    ))
                # Check for infinite loops (error handling)
                elif insn.operands == f"0x{insn.address:x}":
                    patterns.append(BootPattern(
                        pattern_type="infinite_loop",
                        description="Infinite loop (error condition)",
                        instructions=[insn],
                        significance="Halts execution, typically indicates error"
                    ))
        
        return patterns

    def _find_interrupt_patterns(self, instructions: List[Instruction]) -> List[BootPattern]:
        """Find significant interrupt call patterns."""
        patterns = []
        
        for insn in instructions:
            if insn.mnemonic.lower() == "int":
                if "0x19" in insn.operands:
                    patterns.append(BootPattern(
                        pattern_type="bootstrap_call",
                        description="Bootstrap loader call",
                        instructions=[insn],
                        significance="Calls BIOS bootstrap loader (boot failure recovery)"
                    ))
                elif "0x18" in insn.operands:
                    patterns.append(BootPattern(
                        pattern_type="rom_basic",
                        description="ROM BASIC call",
                        instructions=[insn],
                        significance="Calls ROM BASIC (no bootable device found)"
                    ))
        
        return patterns

    def disassemble_with_error_handling(self, code: bytes, base_address: int = 0x7C00, 
                                      prefer_16bit: bool = True) -> DisassemblyResult:
        """
        Disassemble code with comprehensive error handling.
        
        Args:
            code: Raw bytes to disassemble
            base_address: Base memory address
            prefer_16bit: Whether to prefer 16-bit mode for boot sectors
            
        Returns:
            Complete disassembly result with error handling
        """
        instructions = []
        invalid_instructions = []
        total_bytes_disassembled = 0
        
        # Process bytes sequentially to handle mixed valid/invalid instructions
        i = 0
        while i < len(code):
            remaining_code = code[i:]
            current_address = base_address + i
            
            # Try to disassemble one instruction at current position
            found_instruction = False
            
            try:
                cs_engine = self.cs_16 if prefer_16bit else self.cs_32
                
                for insn in cs_engine.disasm(remaining_code, current_address, count=1):
                    instruction = Instruction(
                        address=insn.address,
                        bytes=bytes(insn.bytes),
                        mnemonic=insn.mnemonic,
                        operands=insn.op_str,
                        comment=self.add_comments(insn)
                    )
                    instructions.append(instruction)
                    total_bytes_disassembled += len(insn.bytes)
                    i += len(insn.bytes)
                    found_instruction = True
                    break
                    
            except Exception as e:
                self.logger.debug(f"Disassembly error at offset {i}: {e}")
            
            # If no valid instruction found, treat current byte(s) as invalid
            if not found_instruction:
                # Try to group consecutive invalid bytes (up to 4 bytes)
                invalid_start = i
                invalid_end = min(i + 4, len(code))
                
                # Check if any of the next few bytes might start a valid instruction
                for j in range(i + 1, min(i + 4, len(code))):
                    try:
                        test_code = code[j:]
                        test_address = base_address + j
                        cs_engine = self.cs_16 if prefer_16bit else self.cs_32
                        
                        for test_insn in cs_engine.disasm(test_code, test_address, count=1):
                            # Found a valid instruction starting at position j
                            invalid_end = j
                            break
                        else:
                            continue
                        break
                    except:
                        continue
                
                # Add invalid bytes
                invalid_bytes = code[invalid_start:invalid_end]
                invalid_instructions.append(InvalidInstruction(
                    address=base_address + invalid_start,
                    bytes=invalid_bytes,
                    reason="Invalid or unrecognized instruction bytes"
                ))
                
                i = invalid_end
        
        # Identify boot patterns
        boot_patterns = self.identify_boot_patterns(instructions)
        
        return DisassemblyResult(
            instructions=instructions,
            total_bytes_disassembled=total_bytes_disassembled,
            invalid_instructions=invalid_instructions,
            boot_patterns=boot_patterns
        )

    def _handle_invalid_bytes(self, bytes_data: bytes, start_address: int, 
                            invalid_instructions: List[InvalidInstruction]) -> None:
        """Handle bytes that couldn't be disassembled."""
        # Try to disassemble individual bytes or small chunks to find valid instructions
        i = 0
        while i < len(bytes_data):
            # Try to disassemble from current position
            remaining_bytes = bytes_data[i:]
            current_address = start_address + i
            
            # Try to find a valid instruction starting at this position
            found_valid = False
            try:
                # Try 16-bit mode first
                for insn in self.cs_16.disasm(remaining_bytes, current_address, count=1):
                    # Found a valid instruction, but it wasn't caught in main disassembly
                    # This shouldn't happen normally, so treat as invalid
                    break
            except:
                pass
            
            if not found_valid:
                # Treat as invalid byte(s)
                # Group consecutive invalid bytes up to 4 bytes for readability
                chunk_size = min(4, len(bytes_data) - i)
                chunk = bytes_data[i:i + chunk_size]
                
                invalid_instructions.append(InvalidInstruction(
                    address=current_address,
                    bytes=chunk,
                    reason="Invalid or unrecognized instruction bytes"
                ))
                
                i += chunk_size
            else:
                i += 1

    def __del__(self):
        """Clean up Capstone engines."""
        try:
            if hasattr(self, 'cs_16'):
                self.cs_16.close()
            if hasattr(self, 'cs_32'):
                self.cs_32.close()
        except:
            pass  # Ignore cleanup errors