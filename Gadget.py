import re
from triton import *

STACK = 0x7fffff00
MAX_FILL_STACK = 128

# Base addresses for symbolized memory regions per register.
# Each register gets a region where we place symbolic variables
# so that memory loads like mov rdx,[rdi+8] produce symbolic results (e.g. RDI1).
REG_MEM_BASES = {
    'rax': 0x100000, 'rbx': 0x200000, 'rcx': 0x300000, 'rdx': 0x400000,
    'rsi': 0x500000, 'rdi': 0x600000, 'rbp': 0x700000,
    'r8':  0x800000, 'r9':  0x900000, 'r10': 0xa00000, 'r11': 0xb00000,
    'r12': 0xc00000, 'r13': 0xd00000, 'r14': 0xe00000, 'r15': 0xf00000,
}
MAX_MEM_SLOTS = 32  # 32 slots * 8 bytes = 256 bytes per register

def initialize():
    ctx = TritonContext()
    ctx.setArchitecture(ARCH.X86_64)
    ctx.setMode(MODE.ALIGNED_MEMORY, True)
    ctx.setAstRepresentationMode(AST_REPRESENTATION.PYTHON)
    return ctx

def symbolizeReg(ctx, regname):
    tmp = ctx.symbolizeRegister(getattr(ctx.registers,regname))
    tmp.setAlias(regname)

def getTritonReg(ctx, regname):
    return getattr(ctx.registers, regname)

TYPE_RETURN = 0
TYPE_JMP_REG = 1
TYPE_JMP_MEM = 2
TYPE_CALL_REG = 3
TYPE_CALL_MEM = 4
TYPE_UNKNOWN = 5

GP_REGS = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp",
           "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]

# Suffix dict for early-exit composition (set by ChainBuilder before Pool fork)
_suffix_dict = None

# Precompiled regex for _substitute_ast_str — single-pass handles both
# STACK aliases and register names simultaneously (avoids double-substitution).
_STACK_ALIAS_RE = re.compile(r'STACK(\d+)')
_COMPOSE_SUB_RE = re.compile(
    r'\b(STACK\d+|' + '|'.join(sorted(GP_REGS, key=len, reverse=True)) + r')\b')
# Memory-region variable pattern (e.g. RDI5, RAX3, R150) for detecting when
# suffix AST strings reference a register's memory region that was overwritten
# by the prefix — in which case suffix composition is invalid.
_MEM_REGION_RE = re.compile(
    r'\b(' + '|'.join(sorted((r.upper() for r in GP_REGS), key=len, reverse=True)) + r')\d+\b')

def _substitute_ast_str(ast_str, prefix_reg_values, stack_map):
    """Substitute prefix Triton state into a suffix AST string.

    Single-pass regex: replaces STACK aliases with actual memory values
    and register names with prefix output values simultaneously.
    """
    def _replace(m):
        token = m.group(1)
        if token.startswith('STACK'):
            idx = int(token[5:])
            return stack_map.get(idx, token)
        return prefix_reg_values.get(token, token)
    return _COMPOSE_SUB_RE.sub(_replace, ast_str)

# Segment registers — not symbolized by Triton, so their concrete values
# (default 0) are unreliable.  Gadgets reading these should not be treated
# as defining a GP register to a known constant.
_SEGMENT_REGS = frozenset(["es", "cs", "ss", "ds", "fs", "gs"])

# Detect memory-writing instructions where the memory operand is the
# destination (first operand):  add byte ptr [rcx + 0x415d5be8], cl
# Excludes source-only reads:  add eax, dword ptr [rcx]
_MEM_DEST_RE = re.compile(
    r'(?:add|sub|or|xor|and|mov|adc|sbb|inc|dec|not|neg)\s+'
    r'\w+\s+ptr\s+\[([^\]]+)\]')
_CONST_OFFSET_RE = re.compile(r'[+-]\s*(?:0x)?([0-9a-fA-F]+)')

# Gadget endings that are never useful for ROP/JOP chaining:
#  - jmp/call to a constant address (not controllable)
#  - ret with non-zero immediate (pops extra bytes, breaks chain layout)
_SKIP_GADGET_RE = re.compile(
    r'(?:jmp|call)\s+0x[0-9a-fA-F]+$|'
    r'ret\s+(?:0x[0-9a-fA-F]+|[1-9]\d*)$'
)

def _compute_side_effect_score(insstr):
    """Score indicating danger from side-effect memory writes.

    Scans each instruction in the gadget for memory-destination operands
    with large constant offsets (> 0x1000).  A high offset like 0x415d5be8
    almost certainly hits unmapped memory and causes a crash.

    Returns: max offset magnitude found, or 0 if clean.
    """
    max_offset = 0
    for inst in insstr.split(';'):
        m = _MEM_DEST_RE.search(inst.strip())
        if not m:
            continue
        for cm in _CONST_OFFSET_RE.finditer(m.group(1)):
            val = int(cm.group(1), 16)
            if val > 0x1000:
                max_offset = max(max_offset, val)
    return max_offset

# Precompiled mapping: every x86-64 register variant -> 64-bit base name.
# Used by _extract_used_regs to quickly identify which GP registers a gadget
# references, enabling lazy symbolization.
_REG_VARIANT_MAP = {}
_REG_VARIANTS = {
    'rax': ['al', 'ah', 'ax', 'eax', 'rax'],
    'rbx': ['bl', 'bh', 'bx', 'ebx', 'rbx'],
    'rcx': ['cl', 'ch', 'cx', 'ecx', 'rcx'],
    'rdx': ['dl', 'dh', 'dx', 'edx', 'rdx'],
    'rdi': ['dil', 'di', 'edi', 'rdi'],
    'rsi': ['sil', 'si', 'esi', 'rsi'],
    'rbp': ['bp', 'ebp', 'rbp'],
    'r8':  ['r8b', 'r8w', 'r8d', 'r8'],
    'r9':  ['r9b', 'r9w', 'r9d', 'r9'],
    'r10': ['r10b', 'r10w', 'r10d', 'r10'],
    'r11': ['r11b', 'r11w', 'r11d', 'r11'],
    'r12': ['r12b', 'r12w', 'r12d', 'r12'],
    'r13': ['r13b', 'r13w', 'r13d', 'r13'],
    'r14': ['r14b', 'r14w', 'r14d', 'r14'],
    'r15': ['r15b', 'r15w', 'r15d', 'r15'],
}
for _base, _variants in _REG_VARIANTS.items():
    for _v in _variants:
        _REG_VARIANT_MAP[_v] = _base

# Match register-like tokens: word boundaries around register names.
# Sorted longest-first so r10 matches before r1.
_REG_TOKEN_RE = re.compile(
    r'\b(' + '|'.join(sorted(_REG_VARIANT_MAP.keys(), key=len, reverse=True)) + r')\b'
)

# Instructions with implicit GP register usage not visible in disassembly text.
_IMPLICIT_REGS = {
    'leave': {'rbp'},
    'mul': {'rax', 'rdx'}, 'imul': {'rax', 'rdx'},
    'div': {'rax', 'rdx'}, 'idiv': {'rax', 'rdx'},
    'cdq': {'rax', 'rdx'}, 'cqo': {'rax', 'rdx'},
    'cwd': {'rax', 'rdx'}, 'cbw': {'rax'},
    'cwde': {'rax'}, 'cdqe': {'rax'},
    'stosb': {'rax', 'rdi'}, 'stosw': {'rax', 'rdi'},
    'stosd': {'rax', 'rdi'}, 'stosq': {'rax', 'rdi'},
    'lodsb': {'rax', 'rsi'}, 'lodsw': {'rax', 'rsi'},
    'lodsd': {'rax', 'rsi'}, 'lodsq': {'rax', 'rsi'},
    'movsb': {'rsi', 'rdi'}, 'movsw': {'rsi', 'rdi'},
    'movsd': {'rsi', 'rdi'}, 'movsq': {'rsi', 'rdi'},
    'scasb': {'rax', 'rdi'}, 'scasw': {'rax', 'rdi'},
    'scasd': {'rax', 'rdi'}, 'scasq': {'rax', 'rdi'},
    'cmpsb': {'rsi', 'rdi'}, 'cmpsw': {'rsi', 'rdi'},
    'cmpsd': {'rsi', 'rdi'}, 'cmpsq': {'rsi', 'rdi'},
    'xlatb': {'rax', 'rbx'},
    'cpuid': {'rax', 'rbx', 'rcx', 'rdx'},
    'syscall': {'rax', 'rdi', 'rsi', 'rdx', 'r10', 'r8', 'r9'},
}

def _extract_used_regs(insstr):
    """Extract the set of 64-bit GP register base names referenced in an instruction string."""
    result = {_REG_VARIANT_MAP[m] for m in _REG_TOKEN_RE.findall(insstr)}
    for inst in insstr.split(';'):
        parts = inst.strip().split()
        if not parts:
            continue
        mnemonic = parts[0]
        if mnemonic in ('rep', 'repe', 'repz', 'repne', 'repnz'):
            result.add('rcx')
            if len(parts) > 1:
                mnemonic = parts[1]
        implicit = _IMPLICIT_REGS.get(mnemonic)
        if implicit:
            result.update(implicit)
    return result

def _extract_reg_offset(ast_str):
    """Extract (register_name, offset) from a simplified Triton pivot AST string.

    Examples:
        "rdi"                                      -> ("rdi", 0)
        "((0x20 + rdi) & 0xffffffffffffffff)"      -> ("rdi", 0x20)
        "((rdi + 0x20) & 0xffffffffffffffff)"      -> ("rdi", 0x20)
        "((rdi - 0x8) & 0xffffffffffffffff)"       -> ("rdi", -8)
    """
    s = ast_str.strip()
    if s in GP_REGS:
        return s, 0

    # Strip outer ((...) & 0xffffffffffffffff) mask
    m = re.match(r'^\(\((.+)\) & 0xffffffffffffffff\)$', s)
    inner = m.group(1).strip() if m else s.strip('()')

    if inner in GP_REGS:
        return inner, 0

    # Try: "const + reg" or "reg + const"
    for reg in GP_REGS:
        m = re.match(r'^(0x[0-9a-fA-F]+|\d+)\s*\+\s*' + re.escape(reg) + r'$', inner)
        if m:
            return reg, int(m.group(1), 0)
        m = re.match(r'^' + re.escape(reg) + r'\s*\+\s*(0x[0-9a-fA-F]+|\d+)$', inner)
        if m:
            return reg, int(m.group(1), 0)
        m = re.match(r'^' + re.escape(reg) + r'\s*-\s*(0x[0-9a-fA-F]+|\d+)$', inner)
        if m:
            return reg, -int(m.group(1), 0)

    return None, 0

def _parse_mem_region_var(ast_str):
    """Parse a memory region variable like 'RDI2' -> ('rdi', 0x10).

    Returns (src_reg, byte_offset) if the string is exactly a memory
    region alias ({REG_UPPER}{DIGIT}), otherwise (None, 0).
    """
    s = ast_str.strip()
    for reg in GP_REGS:
        prefix = reg.upper()
        if s.startswith(prefix) and s[len(prefix):].isdigit():
            return reg, int(s[len(prefix):]) * 8
    return None, 0

def regx86_64(reg):
    regs = {
        'rax': ['al', 'ah', 'ax', 'eax', 'rax'],
        'rbx': ['bl', 'bh', 'bx', 'ebx', 'rbx'],
        'rcx': ['cl', 'ch', 'cx', 'ecx', 'rcx'],
        'rdx': ['dl', 'dh', 'dx', 'edx', 'rdx'],
        'rdi': ['dil', 'di', 'edi', 'rdi'],
        'rsi': ['sil', 'si', 'esi', 'rsi'],
        'rbp': ['bp', 'ebp', 'rbp'],
        'r8': ['r8b', 'r8w', 'r8d', 'r8'],
        'r9': ['r9b', 'r9w', 'r9d', 'r9'],
        'r10': ['r10b', 'r10w', 'r10d', 'r10'],
        'r11': ['r11b', 'r11w', 'r11d', 'r11'],
        'r12': ['r12b', 'r12w', 'r12d', 'r12'],
        'r13': ['r13b', 'r13w', 'r13d', 'r13'],
        'r14': ['r14b', 'r14w', 'r14d', 'r14'],
        'r15': ['r15b', 'r15w', 'r15d', 'r15'],
    }
    if reg in regs:
        return reg
    for r in regs:
        if reg in regs[r]:
            return r
    return False

class Gadget(object):
    def __init__(self, addr):
        self.addr = addr
        self.written_regs = set() # registers written by this gadget
        self.read_regs = set() # registers read by this gadget
        self.popped_regs = set() # registers set via `pop reg`
        self.depends_regs = set() # registers this gadget depends on (e.g. `mov rax, rbx; ret` depends on rbx)
        self.defined_regs = dict() # registers defined to a constant (e.g. `xor rax, rax; ret`)
        self.regAst = dict()
        self.regAst_str = dict() # string representations (survive pickle)
        self.diff_sp = 0 # stack pointer delta before ret
        self.is_analyzed = False
        self.is_asted = False
        self.insstr = ""
        self.insns = b""
        self.is_memory_write = 0
        self.is_memory_read = 0 # not pop
        self.memory_write_ast = []
        self.end_type = TYPE_UNKNOWN
        self.end_ast = None
        self.end_ast_str = None # string representation (survives pickle)
        self.end_gadget = 0 # return gadget to fix no-return gadgets
        self.end_reg_used = set() # register used in end_ast
        self.pivot = 0
        self.pivot_ast = None
        self.pivot_indirect = 0   # 1 if rsp loaded from memory at symbolic addr
        self.pivot_mem_ast = None  # AST of the memory address for indirect pivot
        self.pivot_src_reg = None  # source register name for pivot ('rdi', 'rsi', etc.)
        self.pivot_offset = 0     # offset from src_reg
        self.pivot_stack_slot = None  # int: STACK slot number if RSP comes from stack
        self.stack_reg_writes = {}    # {slot: (reg, offset)} GP reg values pushed to stack
        self.is_syscall = False
        self.side_effect_score = 0  # max large-offset memory write (0 = clean)

    def __repr__(self):
        append_com = ""
        if self.end_gadget:
            append_com = ": next -> (0x{:08x}) # {}".format(self.end_gadget.addr, self.end_gadget)
        return self.insstr + append_com

    def __str__(self):
        append_com = ""
        if self.end_gadget:
            append_com = ": next -> (0x{:08x}) # {}".format(self.end_gadget.addr, self.end_gadget)
        return self.insstr + append_com

    def loadFromString(self, str_ins, opcodes):
        self.insstr = str_ins
        self.insns = opcodes

    def __copy__(self):
        # Shallow copy that preserves AST references (unlike pickle which strips them)
        new = Gadget.__new__(Gadget)
        new.__dict__.update(self.__dict__)
        return new

    def __getstate__(self):
        # AstNode objects can't be pickled, so strip them and mark for re-analysis
        newd = self.__dict__.copy()
        newd['regAst'] = dict()
        newd['memory_write_ast'] = []
        newd['end_ast'] = None
        newd['pivot_ast'] = None
        newd['pivot_mem_ast'] = None
        newd['is_asted'] = False
        return newd

    def _compose_from_suffix(self, ctx, astCtxt, suffix, sp, regs, used_regs):
        """Compose this gadget from prefix Triton state + suffix's analyzed fields.

        Returns True if composition succeeded, False if suffix can't be reused
        (e.g., prefix overwrites a register whose memory region the suffix reads).
        """

        # Build stack_map: read actual Triton memory at suffix's stack positions.
        # Handles pushes (prefix wrote register values onto stack) and pops
        # (suffix reads higher original STACK slots) correctly.
        max_stack_idx = -1
        all_suffix_strs = list(suffix.regAst_str.values())
        if suffix.end_ast_str:
            all_suffix_strs.append(suffix.end_ast_str)
        for s in all_suffix_strs:
            for m in _STACK_ALIAS_RE.finditer(s):
                idx = int(m.group(1))
                if idx > max_stack_idx:
                    max_stack_idx = idx
        stack_map = {}
        for i in range(max_stack_idx + 1):
            addr = (sp + i * 8) & 0xFFFFFFFFFFFFFFFF
            mem_ast = ctx.getMemoryAst(MemoryAccess(addr, CPUSIZE.QWORD))
            stack_map[i] = str(astCtxt.unroll(mem_ast))

        # Read prefix register values from Triton
        prefix_reg_values = {}
        for reg in regs:
            if reg in used_regs:
                sym = ctx.getSymbolicRegister(getTritonReg(ctx, reg))
                prefix_reg_values[reg] = str(astCtxt.unroll(sym.getAst()))
            else:
                prefix_reg_values[reg] = reg

        # Check: reject if suffix AST strings reference memory region variables
        # (e.g. RDI5) for registers overwritten by the prefix.  The suffix was
        # analyzed with original register values, so its memory slots are wrong
        # when the prefix changes the base register (double-dereference case:
        # e.g. "mov rdi,[rdi+0x18]; mov rax,[rdi+0x28]" — suffix has rax=RDI5
        # but it should be [[rdi+0x18]+0x28]).
        overwritten_upper = {reg.upper() for reg, val in prefix_reg_values.items()
                             if val != reg}
        if overwritten_upper:
            for s in all_suffix_strs:
                for m in _MEM_REGION_RE.finditer(s):
                    if m.group(1) in overwritten_upper:
                        return False

        # regAst_str: substitute into suffix ASTs
        self.regAst_str = {}
        for reg, ast_str in suffix.regAst_str.items():
            self.regAst_str[reg] = _substitute_ast_str(ast_str, prefix_reg_values, stack_map)
        # Prefix-written regs not overwritten by suffix
        for reg in self.written_regs:
            if reg not in suffix.written_regs and reg not in self.regAst_str:
                self.regAst_str[reg] = prefix_reg_values.get(reg, reg)

        # defined_regs from regAst_str
        self.defined_regs = {}
        for reg, ast_str in self.regAst_str.items():
            if ast_str in GP_REGS:
                self.defined_regs[reg] = ast_str
            else:
                try:
                    self.defined_regs[reg] = int(ast_str, 0)
                except (ValueError, TypeError):
                    pass

        # Merge prefix + suffix tracked fields
        self.written_regs |= suffix.written_regs
        self.popped_regs |= suffix.popped_regs
        self.read_regs |= suffix.read_regs
        defregs = {r for r, v in self.defined_regs.items() if isinstance(v, int)}
        self.depends_regs = self.read_regs - defregs
        self.diff_sp = (sp - STACK) + suffix.diff_sp
        self.is_memory_write += suffix.is_memory_write
        self.is_memory_read = max(self.is_memory_read, suffix.is_memory_read)
        self.is_syscall = self.is_syscall or suffix.is_syscall

        # End fields (substitute register names in end_ast_str)
        self.end_type = suffix.end_type
        self.end_ast = None
        self.end_ast_str = (_substitute_ast_str(suffix.end_ast_str, prefix_reg_values, stack_map)
                            if suffix.end_ast_str else None)
        self.end_reg_used = set(suffix.end_reg_used)

        # Pivot detection from Triton state.
        # If prefix made rsp symbolic (e.g. pop rsp loaded a pushed value),
        # detect pivot directly from Triton rather than copying suffix's fields.
        self.pivot = 0
        self.pivot_ast = None
        self.pivot_indirect = 0
        self.pivot_mem_ast = None
        self.pivot_src_reg = None
        self.pivot_offset = 0
        self.pivot_stack_slot = None
        self.stack_reg_writes = {}
        if ctx.isRegisterSymbolized(ctx.registers.rsp):
            rsp_ast = ctx.getSymbolicRegister(ctx.registers.rsp).getAst()
            # Adjust for suffix's stack consumption. diff_sp excludes ret's pop,
            # so: post_gadget_rsp = prefix_rsp + diff_sp + 8.
            # Regular code: pivot_ast = post_rsp - 8 = prefix_rsp + diff_sp.
            adj = suffix.diff_sp
            if adj != 0:
                adjusted = astCtxt.bvadd(rsp_ast, astCtxt.bv(adj, 64))
            else:
                adjusted = rsp_ast
            self.pivot_ast = ctx.simplify(adjusted, True)
            if self.pivot_ast:
                pivot_str = str(self.pivot_ast)
                childs = astCtxt.search(self.pivot_ast, AST_NODE.VARIABLE)
                for c in childs:
                    alias = c.getSymbolicVariable().getAlias()
                    for reg in regs:
                        rpfx = reg.upper()
                        if alias.startswith(rpfx) and alias[len(rpfx):].isdigit():
                            slot = int(alias[len(rpfx):])
                            if pivot_str.strip() == alias:
                                self.pivot_indirect = 1
                                self.pivot_src_reg = reg
                                self.pivot_offset = slot * 8
                            break
                    if self.pivot_indirect:
                        break
                if not self.pivot_indirect:
                    self.pivot_src_reg, self.pivot_offset = _extract_reg_offset(pivot_str)
                    if self.pivot_offset == STACK:
                        self.pivot_src_reg = None
                        self.pivot_offset = 0
                if self.pivot_src_reg is not None:
                    self.pivot = 1
                else:
                    m = re.match(r'^STACK(\d+)$', pivot_str.strip())
                    if m:
                        self.pivot = 1
                        self.pivot_stack_slot = int(m.group(1))
                    else:
                        self.pivot_ast = None
        elif suffix.pivot and suffix.pivot_src_reg:
            # Suffix itself is a pivot (rsp not symbolic from prefix) —
            # transform suffix's pivot source through prefix register state.
            # E.g., prefix "mov rdi, rsi" + suffix pivot from rdi → composed pivot from rsi.
            mapped = prefix_reg_values.get(suffix.pivot_src_reg, suffix.pivot_src_reg)
            new_reg, new_off = _extract_reg_offset(mapped)
            if new_reg is not None:
                self.pivot = 1
                self.pivot_indirect = suffix.pivot_indirect
                self.pivot_src_reg = new_reg
                self.pivot_offset = suffix.pivot_offset + new_off
            else:
                # Check if prefix loaded from a memory region variable
                # (e.g. prefix "mov rdx, [rdi+0x10]" → rdx='RDI2').
                # A direct suffix pivot from rdx becomes indirect pivot from rdi.
                mem_reg, mem_off = _parse_mem_region_var(mapped)
                if mem_reg is not None:
                    self.pivot = 1
                    self.pivot_indirect = 1
                    self.pivot_src_reg = mem_reg
                    self.pivot_offset = mem_off + suffix.pivot_offset

        # Scan stack below STACK for GP register values pushed by the prefix.
        # Use composed SP (prefix sp + suffix consumption) as the effective base.
        self.stack_reg_writes = {}
        compose_sp = STACK + self.diff_sp  # net SP before dispatch
        effective_sp = compose_sp
        if self.end_type in (TYPE_CALL_REG, TYPE_CALL_MEM):
            effective_sp = compose_sp - 8
        if effective_sp < STACK:
            n_slots = (STACK - effective_sp) // 8
            if n_slots <= 16:
                for slot in range(n_slots):
                    addr = effective_sp + slot * 8
                    mem_ast = ctx.getMemoryAst(MemoryAccess(addr, CPUSIZE.QWORD))
                    mem_str = str(astCtxt.unroll(mem_ast))
                    reg, off = _extract_reg_offset(mem_str)
                    if reg and reg in regs:
                        self.stack_reg_writes[slot] = (reg, off)

        self.memory_write_ast = []
        self.regAst = {}
        self.side_effect_score = _compute_side_effect_score(self.insstr)
        self.is_analyzed = True
        self.is_asted = False
        return True

    def buildAst(self):
        # Re-analyze the gadget to rebuild AST nodes (safe alternative to eval)
        self.written_regs = set()
        self.read_regs = set()
        self.popped_regs = set()
        self.depends_regs = set()
        self.defined_regs = dict()
        self.regAst = dict()
        self.is_memory_write = 0
        self.is_memory_read = 0
        self.memory_write_ast = []
        self.end_type = TYPE_UNKNOWN
        self.end_ast = None
        self.end_reg_used = set()
        self.pivot = 0
        self.pivot_ast = None
        self.pivot_indirect = 0
        self.pivot_mem_ast = None
        self.pivot_src_reg = None
        self.pivot_offset = 0
        self.pivot_stack_slot = None
        self.stack_reg_writes = {}
        self.is_syscall = False
        self.is_analyzed = False
        self.is_asted = False
        self.analyzeGadget()


    def analyzeGadget(self, debug=False):
        # Skip gadgets with unusable endings before creating TritonContext
        last_insn = self.insstr.rsplit(';', 1)[-1].strip()
        if _SKIP_GADGET_RE.search(last_insn):
            self.end_type = TYPE_UNKNOWN
            self.is_analyzed = True
            return

        BSIZE = 8
        ctx = initialize()
        astCtxt = ctx.getAstContext()
        regs = ["rax", "rbx", "rcx", "rdx", "rsi", "rbp", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
        syscalls = ["syscall"]

        used_regs = _extract_used_regs(self.insstr)
        for reg in regs:
            base = REG_MEM_BASES[reg]
            ctx.setConcreteRegisterValue(getTritonReg(ctx, reg), base)
            if reg in used_regs:
                symbolizeReg(ctx, reg)
                for i in range(MAX_MEM_SLOTS):
                    sym = ctx.symbolizeMemory(MemoryAccess(base + i * BSIZE, CPUSIZE.QWORD))
                    sym.setAlias("{}{}".format(reg.upper(), i))

        ctx.setConcreteRegisterValue(ctx.registers.rsp, STACK)

        n_insns = self.insstr.count(';') + 1
        stack_slots = min(MAX_FILL_STACK, max(16, n_insns * 3))
        for i in range(stack_slots):
            tmpb = ctx.symbolizeMemory(MemoryAccess(STACK+(i*8), CPUSIZE.QWORD))
            tmpb.setAlias("STACK{}".format(i))

        sp = STACK
        instructions = self.insns
        pc = 0
        _seg_tainted = set()  # GP regs tainted by segment register reads
        insstr_parts = self.insstr.split(' ; ')
        insn_idx = 0

        while True:
            inst = Instruction()
            inst.setOpcode(instructions[pc:pc+16])
            inst.setAddress(pc)
            ctx.processing(inst)
            insn_idx += 1

            written = inst.getWrittenRegisters()
            red = inst.getReadRegisters()
            pop = False
            tmp_red = set()
            for wrt in written:
                regname = regx86_64(wrt[0].getName())
                if regname:
                    self.written_regs.add(regname)
                    newsp = ctx.getConcreteRegisterValue(ctx.registers.rsp)
                    if (newsp - sp) == 8:
                        pop = True
                        self.popped_regs.add(regname)

            has_tainted_read = False
            for r in red:
                rname = r[0].getName()
                regname = regx86_64(rname)
                if regname:
                    tmp_red.add(regname)
                    self.read_regs.add(regname)
                    if regname in _seg_tainted:
                        has_tainted_read = True
                elif rname in _SEGMENT_REGS:
                    has_tainted_read = True
            if has_tainted_read:
                for wrt in written:
                    gp = regx86_64(wrt[0].getName())
                    if gp:
                        _seg_tainted.add(gp)

            if inst.isControlFlow(): # check if end of gadget
                type_end = 0
                sp_after = ctx.getConcreteRegisterValue(ctx.registers.rsp)
                if (sp - sp_after) == BSIZE and len(tmp_red) > 0:
                    if inst.isMemoryRead():
                        type_end = TYPE_CALL_MEM
                        self.end_ast = ctx.simplify(inst.getLoadAccess()[0][0].getLeaAst(), True)
                    else:
                        type_end = TYPE_CALL_REG
                        self.end_ast = ctx.simplify(ctx.getSymbolicRegister(ctx.registers.rip).getAst(), True)
                elif sp == sp_after and len(tmp_red) > 0:
                    if inst.isMemoryRead():
                        type_end = TYPE_JMP_MEM
                        self.end_ast = ctx.simplify(inst.getLoadAccess()[0][0].getLeaAst(), True)
                    else:
                        type_end = TYPE_JMP_REG
                        self.end_ast = ctx.simplify(ctx.getSymbolicRegister(ctx.registers.rip).getAst(), True)
                elif sp_after - sp == BSIZE:
                    type_end = TYPE_RETURN
                else:
                    type_end = TYPE_UNKNOWN
                self.end_type = type_end
                self.end_reg_used = tmp_red
                break

            elif inst.getDisassembly() in syscalls:
                self.is_syscall = True

            if not pop and inst.isMemoryRead():
                self.is_memory_read = 1

            if inst.isMemoryWrite() and 'mov' in inst.getDisassembly():
                for store_access in inst.getStoreAccess():
                    addr_ast = ctx.simplify(store_access[0].getLeaAst(), True)
                    val_ast = ctx.simplify(store_access[1], True)
                    self.memory_write_ast.append((addr_ast, val_ast))
                    self.is_memory_write += 1

            pc = ctx.getConcreteRegisterValue(ctx.registers.rip)
            sp = ctx.getConcreteRegisterValue(ctx.registers.rsp)
            if pc >= len(instructions):
                break

            # Check suffix dict for early exit
            if _suffix_dict is not None and insn_idx < len(insstr_parts):
                remaining = ' ; '.join(insstr_parts[insn_idx:])
                suffix = _suffix_dict.get(remaining)
                if suffix is not None and suffix.is_analyzed and suffix.diff_sp >= 0:
                    if suffix.end_type == TYPE_UNKNOWN:
                        self.end_type = TYPE_UNKNOWN
                        self.is_analyzed = True
                        return
                    if self._compose_from_suffix(ctx, astCtxt, suffix, sp, regs, used_regs):
                        return
                    # Suffix can't be reused (prefix overwrites a register whose
                    # memory region the suffix reads) — continue Triton analysis

        if ctx.isRegisterSymbolized(ctx.registers.rsp):
            rsp_ast = ctx.getSymbolicRegister(ctx.registers.rsp).getAst()
            self.pivot_ast = ctx.simplify(astCtxt.bvsub(rsp_ast, astCtxt.bv(8, 64)), True)
            if self.pivot_ast:
                pivot_str = str(self.pivot_ast)
                # Check if rsp comes from a register's memory region (indirect pivot)
                childs = astCtxt.search(self.pivot_ast, AST_NODE.VARIABLE)
                for c in childs:
                    alias = c.getSymbolicVariable().getAlias()
                    for reg in regs:
                        prefix = reg.upper()
                        if alias.startswith(prefix) and alias[len(prefix):].isdigit():
                            slot = int(alias[len(prefix):])
                            # Validate: AST must be exactly the variable (e.g. "RDI0"),
                            # not a partial operation like OR/SUB/truncation around it.
                            if pivot_str.strip() == alias:
                                self.pivot_indirect = 1
                                self.pivot_src_reg = reg
                                self.pivot_offset = slot * 8
                            break
                    if self.pivot_indirect:
                        break
                if not self.pivot_indirect:
                    self.pivot_src_reg, self.pivot_offset = _extract_reg_offset(pivot_str)
                    # Reject if offset matches concrete STACK base — means
                    # old rsp leaked into the AST (e.g. "add rsp, rdi")
                    if self.pivot_offset == STACK:
                        self.pivot_src_reg = None
                        self.pivot_offset = 0
                # Only mark as pivot if we found a valid source register
                if self.pivot_src_reg is not None:
                    self.pivot = 1
                else:
                    # Check for STACK_N pivot (e.g., pop rsp ; ret)
                    m = re.match(r'^STACK(\d+)$', pivot_str.strip())
                    if m:
                        self.pivot = 1
                        self.pivot_stack_slot = int(m.group(1))
                    else:
                        self.pivot_ast = None

        _regs_upper = {r.upper() for r in regs}
        for reg in self.written_regs:
            raw_ast = ctx.getSymbolicRegister(getTritonReg(ctx, reg)).getAst()
            unrolled = astCtxt.unroll(raw_ast)
            # Skip registers tainted by segment register reads — their
            # concrete value (Triton default 0) is not reliable.
            if reg in _seg_tainted:
                self.regAst[reg] = unrolled
                continue
            simplified = str(unrolled)
            if simplified in regs:
                self.regAst[reg] = unrolled
                self.defined_regs[reg] = simplified
                continue
            try:
                h = int(simplified, 16)
                self.regAst[reg] = unrolled
                self.defined_regs[reg] = h
                continue
            except ValueError:
                pass
            # Check if it's a known variable alias (STACK_N or REG_N like RDI0).
            # These are already resolved — Z3 can't simplify further.
            _alias = simplified.rstrip('0123456789')
            if _alias == 'STACK' or _alias in _regs_upper:
                self.regAst[reg] = unrolled
                continue
            # Complex expression — fall back to Z3 for constant folding
            # (e.g. xor eax,eax -> 0x0, lea rdx,[rdi+0x20] -> rdi + 0x20)
            z3_ast = ctx.simplify(raw_ast, True)
            self.regAst[reg] = z3_ast
            simplified = str(z3_ast)
            if simplified in regs:
                self.defined_regs[reg] = simplified
            else:
                try:
                    self.defined_regs[reg] = int(simplified, 16)
                except ValueError:
                    pass

        defregs = set(filter(lambda i: isinstance(self.defined_regs[i],int),
                              self.defined_regs.keys()))
        self.depends_regs = self.read_regs - defregs

        # Store string representations (survive pickle, used by JOP search)
        self.regAst_str = {r: str(v) for r, v in self.regAst.items()}
        self.end_ast_str = str(self.end_ast) if self.end_ast else None

        self.diff_sp = sp - STACK

        # Scan stack below STACK for GP register values pushed by the gadget.
        # For call endings, account for the return address push (sp - 8).
        # Limit scan to 16 slots to avoid runaway on leave/mov rsp instructions.
        self.stack_reg_writes = {}
        effective_sp = sp
        if self.end_type in (TYPE_CALL_REG, TYPE_CALL_MEM):
            effective_sp = sp - 8
        if effective_sp < STACK:
            n_slots = (STACK - effective_sp) // 8
            if n_slots <= 16:
                for slot in range(n_slots):
                    addr = effective_sp + slot * 8
                    mem_ast = ctx.getMemoryAst(MemoryAccess(addr, CPUSIZE.QWORD))
                    mem_str = str(astCtxt.unroll(mem_ast))
                    reg, off = _extract_reg_offset(mem_str)
                    if reg and reg in regs:
                        self.stack_reg_writes[slot] = (reg, off)

        self.side_effect_score = _compute_side_effect_score(self.insstr)
        self.is_analyzed = True
        self.is_asted = True
