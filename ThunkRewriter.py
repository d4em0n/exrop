"""Kernel thunk rewriting for retpoline-mitigated binaries.

Linux kernels with retpoline replace:
  ret       -> jmp __x86_return_thunk       (semantically = ret)
  jmp reg   -> jmp __x86_indirect_thunk_REG (semantically = jmp reg)
  call reg  -> call __x86_indirect_thunk_REG (semantically = call reg)

This module detects thunk symbols from ELF and rewrites gadget opcodes
so Triton can analyze them normally.
"""

import re

# Register encoding order matching x86 ModRM
_THUNK_REG_ORDER = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi',
                    'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15']

def _build_jmp_opcodes():
    """Build jmp reg opcodes: rax-rdi = ff e0..e7, r8-r15 = 41 ff e0..e7"""
    d = {}
    for i, reg in enumerate(_THUNK_REG_ORDER):
        if i < 8:
            d[reg] = bytes([0xff, 0xe0 + i])
        else:
            d[reg] = bytes([0x41, 0xff, 0xe0 + (i - 8)])
    return d

def _build_call_opcodes():
    """Build call reg opcodes: rax-rdi = ff d0..d7, r8-r15 = 41 ff d0..d7"""
    d = {}
    for i, reg in enumerate(_THUNK_REG_ORDER):
        if i < 8:
            d[reg] = bytes([0xff, 0xd0 + i])
        else:
            d[reg] = bytes([0x41, 0xff, 0xd0 + (i - 8)])
    return d

INDIRECT_THUNK_JMP = _build_jmp_opcodes()
INDIRECT_THUNK_CALL = _build_call_opcodes()

# Pattern to match jmp/call to absolute address as last instruction
_LAST_INS_RE = re.compile(r';\s*(jmp|call)\s+(0x[0-9a-fA-F]+)$')
# Same but for single-instruction gadgets (no semicolon prefix)
_SINGLE_INS_RE = re.compile(r'^(jmp|call)\s+(0x[0-9a-fA-F]+)$')

# Patterns to filter out useless gadgets in kernel mode
# ret N — return with stack adjustment, rarely useful and complicates chain layout
_RET_N_RE = re.compile(r'ret\s+0x[0-9a-fA-F]+$')
# jmp/call qword ptr [rip + N] — PC-relative indirect jump to fixed address
_JMP_RIP_RE = re.compile(r'(jmp|call)\s+qword\s+ptr\s+\[rip\s*[+-]\s*0x[0-9a-fA-F]+\]$')


class ThunkConfig:
    """Configuration for kernel thunk rewriting.

    Attributes:
        return_thunks: set of addresses where jmp X = ret
        indirect_thunks: dict {addr: reg_name} where jmp X = jmp reg
        text_range: (start, end) tuple for .text section bounds, or None
    """

    def __init__(self, return_thunks=None, indirect_thunks=None, text_range=None):
        self.return_thunks = set(return_thunks or [])
        # indirect_thunks: {int_addr: reg_name}
        self.indirect_thunks = {}
        if indirect_thunks:
            for k, v in indirect_thunks.items():
                self.indirect_thunks[int(k) if isinstance(k, str) else k] = v
        self.text_range = text_range

    @classmethod
    def from_elf(cls, binary_path):
        """Auto-detect thunks and .text range from ELF symbols."""
        from elftools.elf.elffile import ELFFile

        return_thunks = set()
        indirect_thunks = {}
        text_range = None

        with open(binary_path, 'rb') as f:
            elf = ELFFile(f)

            # Get .text section range
            text_sec = elf.get_section_by_name('.text')
            if text_sec:
                start = text_sec['sh_addr']
                size = text_sec['sh_size']
                text_range = (start, start + size)

            # Find thunk symbols in .symtab
            symtab = elf.get_section_by_name('.symtab')
            if symtab is None:
                raise ValueError("No .symtab found in {}. Kernel vmlinux must not be stripped.".format(binary_path))

            thunk_prefix = '__x86_indirect_thunk_'
            for sym in symtab.iter_symbols():
                name = sym.name
                # Skip metadata symbols
                if name.startswith('__kstrtab_') or name.startswith('__ksymtab_'):
                    continue
                addr = sym['st_value']
                if addr == 0:
                    continue
                if name == '__x86_return_thunk':
                    return_thunks.add(addr)
                elif name.startswith(thunk_prefix):
                    reg = name[len(thunk_prefix):]
                    if reg in _THUNK_REG_ORDER:
                        indirect_thunks[addr] = reg

        config = cls(return_thunks=return_thunks, indirect_thunks=indirect_thunks,
                     text_range=text_range)
        return config

    def summary(self):
        """Print summary of detected thunks."""
        print("Thunk config:")
        print("  Return thunks: {} addresses".format(len(self.return_thunks)))
        for addr in sorted(self.return_thunks):
            print("    0x{:x}".format(addr))
        print("  Indirect thunks: {} registers".format(len(self.indirect_thunks)))
        for addr in sorted(self.indirect_thunks):
            print("    0x{:x} -> jmp {}".format(addr, self.indirect_thunks[addr]))
        if self.text_range:
            start, end = self.text_range
            print("  .text range: 0x{:x} - 0x{:x} ({:.1f} MB)".format(
                start, end, (end - start) / (1024 * 1024)))


def rewrite_gadgets(gadgets_dict, thunk_config):
    """Rewrite thunk jumps in gadgets to equivalent simple instructions.

    Args:
        gadgets_dict: {addr: (insstr, opcode)} from parseRopGadget
        thunk_config: ThunkConfig instance

    Returns:
        Filtered dict with thunk jumps rewritten and non-thunk jumps removed.
    """
    result = {}
    for addr, (insstr, opcode) in gadgets_dict.items():
        rewritten = _rewrite_one(insstr, opcode, thunk_config)
        if rewritten is not None:
            result[addr] = rewritten
    return result


def _rewrite_one(insstr, opcode, config):
    """Rewrite a single gadget. Returns (new_insstr, new_opcode) or None to filter."""
    # Filter out useless endings before thunk analysis
    last_ins = insstr.rsplit(';', 1)[-1].strip()
    if _RET_N_RE.match(last_ins):
        return None
    if _JMP_RIP_RE.match(last_ins):
        return None

    # Try to match last instruction as jmp/call to absolute address
    match = _LAST_INS_RE.search(insstr)
    if match is None:
        match = _SINGLE_INS_RE.match(insstr.strip())
    if match is None:
        # No jmp/call to absolute address — keep as-is (normal ret, jmp reg, etc.)
        return (insstr, opcode)

    mnemonic = match.group(1)  # 'jmp' or 'call'
    target = int(match.group(2), 16)

    # call __x86_return_thunk → useless (push + ret = nop), filter out
    if mnemonic == 'call' and target in config.return_thunks:
        return None

    if target in config.return_thunks:
        # jmp __x86_return_thunk → ret
        new_opcode = _replace_tail(opcode, b'\xc3')
        if new_opcode is None:
            return None
        new_insstr = insstr[:match.start()] + '; ret' if match.start() > 0 else 'ret'
        return (new_insstr.lstrip('; '), new_opcode)

    if target in config.indirect_thunks:
        reg = config.indirect_thunks[target]
        if mnemonic == 'jmp':
            replacement = INDIRECT_THUNK_JMP[reg]
            new_suffix = 'jmp {}'.format(reg)
        else:  # call
            replacement = INDIRECT_THUNK_CALL[reg]
            new_suffix = 'call {}'.format(reg)
        new_opcode = _replace_tail(opcode, replacement)
        if new_opcode is None:
            return None
        new_insstr = insstr[:match.start()] + '; ' + new_suffix if match.start() > 0 else new_suffix
        return (new_insstr.lstrip('; '), new_opcode)

    # Unknown target — not a thunk, filter out
    return None


def _replace_tail(opcode, replacement):
    """Replace the trailing jmp/call instruction bytes with replacement + NOP padding.

    The thunk jmp is either:
      e9 XX XX XX XX  (5-byte near jmp)
      e8 XX XX XX XX  (5-byte near call)
      eb XX           (2-byte short jmp)

    Returns new opcode bytes, or None if tail format not recognized.
    """
    opcode = bytearray(opcode)

    # Try 5-byte near jmp/call first
    for tail_len in (5, 2):
        if len(opcode) < tail_len:
            continue
        marker = opcode[-tail_len]
        if tail_len == 5 and marker in (0xe9, 0xe8):
            # Replace last 5 bytes
            pad_len = 5 - len(replacement)
            opcode[-5:] = replacement + b'\x90' * pad_len
            return bytes(opcode)
        elif tail_len == 2 and marker == 0xeb:
            # Short jmp: replace last 2 bytes
            pad_len = 2 - len(replacement)
            if pad_len < 0:
                # Replacement longer than short jmp — can't fit
                return None
            opcode[-2:] = replacement + b'\x90' * pad_len
            return bytes(opcode)

    return None
