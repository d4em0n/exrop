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
        self.is_syscall = False
        self.is_analyzed = False
        self.is_asted = False
        self.analyzeGadget()


    def analyzeGadget(self, debug=False):
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

        while True:
            inst = Instruction()
            inst.setOpcode(instructions[pc:pc+16])
            inst.setAddress(pc)
            ctx.processing(inst)

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
                    self.pivot_ast = None

        for reg in self.written_regs:
            self.regAst[reg] = ctx.simplify(ctx.getSymbolicRegister(getTritonReg(ctx, reg)).getAst(), True)
            # Skip registers tainted by segment register reads — their
            # concrete value (Triton default 0) is not reliable.
            if reg in _seg_tainted:
                continue
            simplified = str(self.regAst[reg])
            if simplified in regs:
                self.defined_regs[reg] = simplified
                continue
            try:
                h = int(simplified, 16)
                self.defined_regs[reg] = h
            except ValueError:
                continue

        defregs = set(filter(lambda i: isinstance(self.defined_regs[i],int),
                              self.defined_regs.keys()))
        self.depends_regs = self.read_regs - defregs

        # Store string representations (survive pickle, used by JOP search)
        self.regAst_str = {r: str(v) for r, v in self.regAst.items()}
        self.end_ast_str = str(self.end_ast) if self.end_ast else None

        self.diff_sp = sp - STACK
        self.side_effect_score = _compute_side_effect_score(self.insstr)
        self.is_analyzed = True
        self.is_asted = True
