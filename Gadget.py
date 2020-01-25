from triton import *
import code

STACK = 0x7fffff00
MAX_FILL_STACK = 128

def initialize():
    ctx = TritonContext()
    ctx.setArchitecture(ARCH.X86_64)
    ctx.setMode(MODE.ALIGNED_MEMORY, True)
    ctx.setAstRepresentationMode(AST_REPRESENTATION.PYTHON)
    return ctx

def symbolizeReg(ctx, regname):
    tmp = ctx.symbolizeRegister(getattr(ctx.registers,regname))
    tmp.setAlias(regname)
    return ctx.getSymbolicRegister(getTritonReg(ctx, regname)).getAst()

def getTritonReg(ctx, regname):
    return getattr(ctx.registers, regname)

TYPE_RETURN = 0
TYPE_JMP_REG = 1
TYPE_JMP_MEM = 2
TYPE_CALL_REG = 3
TYPE_CALL_MEM = 4
TYPE_UNKNOWN = 5

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
        self.written_regs = set() # register yang telah tertulis
        self.read_regs = set() # register yang telah terbaca
        self.popped_regs = set() # register dari hasil `pop reg`
        self.depends_regs = set() # `mov rax, rbx; ret` gadget ini akan bergantung pada rbx
        self.defined_regs = dict() # register yang telah terdefinisi konstanta `xor rax, rax; ret`
        self.regAst = dict()
        self.diff_sp = 0 # jarak rsp ke rbp sesaaat sebelum ret
        self.is_analyzed = False
        self.insstr = ""
        self.insns = b""
        self.is_memory_write = 0
        self.is_memory_read = 0 # not pop
        self.memory_write_ast = []
        self.end_type = TYPE_RETURN # default ret
        self.end_ast = None
        self.end_gadget = 0 # return gadget to fix no-return gadgets
        self.end_reg_used = set() # register used in end_ast
        self.pivot = 0
        self.pivot_ast = None

    def __repr__(self):
        append_com = ""
        if self.end_gadget:
            append_com = ": next -> (0x{:08x}) # {}".format(self.end_gadget.addr, self.end_gadget)
        return self.insstr + append_com
#        return "addr : {}\nwritten : {}\nread : {}\npopped : {}\ndepends : {}\ndiff_sp: {}".format(self.addr, self.written_regs, self.read_regs, self.popped_regs, self.depends_regs, self.diff_sp)

    def __str__(self):
        append_com = ""
        if self.end_gadget:
            append_com = ": next -> (0x{:08x}) # {}".format(self.end_gadget.addr, self.end_gadget)
        return self.insstr + append_com
#        return "addr : {}\nwritten : {}\nread : {}\npopped : {}\ndepends : {}\ndiff_sp: {}\n".format(self.addr, self.written_regs, self.read_regs, self.popped_regs, self.depends_regs, self.diff_sp)

    def loadFromString(self, str_ins, opcodes):
        self.insstr = str_ins
        self.insns = opcodes

    def buildAst(self):
        ctx = initialize()
        astCtxt = ctx.getAstContext()
        regs = ["rax", "rbx", "rcx", "rdx", "rsi", "rbp", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "eflags"]

        for reg in regs:
            symbolizeReg(ctx, reg)
        ctx.setConcreteRegisterValue(ctx.registers.rsp, STACK)

        for i in range(MAX_FILL_STACK):
            tmpb = ctx.symbolizeMemory(MemoryAccess(STACK+(i*8), CPUSIZE.QWORD))
            tmpb.setAlias("STACK{}".format(i))

        self.regAst = dict()
        self.memory_write_ast = []
        BSIZE = 8

        sp = STACK
        instructions = self.insns
        pc = 0

        while True:
            inst = Instruction()
            inst.setOpcode(instructions[pc:pc+16])
            inst.setAddress(pc)
            ctx.processing(inst)

            if inst.isControlFlow(): # check if end of gadget
                type_end = self.end_type
                if type_end == TYPE_CALL_MEM or type_end == TYPE_JMP_MEM:
                    self.end_ast = inst.getLoadAccess()[0][0].getLeaAst()
                elif type_end == TYPE_CALL_REG or type_end == TYPE_JMP_REG:
                    self.end_ast = ctx.getSymbolicRegister(ctx.registers.rip).getAst()
#                code.interact(local=locals())
                break
            pc = ctx.getConcreteRegisterValue(ctx.registers.rip)
            sp = ctx.getConcreteRegisterValue(ctx.registers.rsp)
            if inst.isMemoryWrite():
                for store_access in inst.getStoreAccess():
                    addr_ast = store_access[0].getLeaAst()
                    val_ast = store_access[1]
                    self.memory_write_ast.append((addr_ast, val_ast))

        if ctx.isRegisterSymbolized(ctx.registers.rsp):
            self.pivot_ast = ctx.getSymbolicRegister(ctx.registers.rsp).getAst() - 8
            if self.pivot_ast:
                self.pivot = 1

        for reg in self.written_regs:
            self.regAst[reg] = ctx.getSymbolicRegister(getTritonReg(ctx, reg)).getAst()

    def analyzeGadget(self, debug=False):
        BSIZE = 8
        ctx = initialize()
        astCtxt = ctx.getAstContext()
        regs = ["rax", "rbx", "rcx", "rdx", "rsi", "rbp", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "eflags"]

        reglist = dict()
        for reg in regs:
            reglist[reg] = symbolizeReg(ctx, reg)
        ctx.setConcreteRegisterValue(ctx.registers.rsp, STACK)

        for i in range(MAX_FILL_STACK):
            tmpb = ctx.symbolizeMemory(MemoryAccess(STACK+(i*8), CPUSIZE.QWORD))
            tmpb.setAlias("STACK{}".format(i))

        sp = STACK
        instructions = self.insns
        pc = 0

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

            for r in red:
                regname = regx86_64(r[0].getName())
                if regname:
                    tmp_red.add(regname)
                    self.read_regs.add(regname)

            if inst.isControlFlow(): # check if end of gadget
                type_end = 0
                sp_after = ctx.getConcreteRegisterValue(ctx.registers.rsp)
                if (sp - sp_after) == BSIZE and len(tmp_red) > 0:
                    if inst.isMemoryRead():
                        type_end = TYPE_CALL_MEM
                        self.end_ast = inst.getLoadAccess()[0][0].getLeaAst()
                    else:
                        type_end = TYPE_CALL_REG
                        self.end_ast = ctx.getSymbolicRegister(ctx.registers.rip).getAst()
                elif sp == sp_after and len(tmp_red) > 0:
                    if inst.isMemoryRead() and not inst.isBranch():
                        type_end = TYPE_JMP_MEM
                        self.end_ast = inst.getLoadAccess()[0][0].getLeaAst()
                    else:
                        type_end = TYPE_JMP_REG
                        self.end_ast = ctx.getSymbolicRegister(ctx.registers.rip).getAst()
                elif sp_after - sp == BSIZE:
                    type_end = TYPE_RETURN
                else:
                    type_end = TYPE_UNKNOWN
                self.end_type = type_end
                self.end_reg_used = tmp_red
#                code.interact(local=locals())
                break

            if not pop and inst.isMemoryRead():
                self.is_memory_read = 1

            if inst.isMemoryWrite() and 'mov' in inst.getDisassembly():
                for store_access in inst.getStoreAccess():
                    addr_ast = store_access[0].getLeaAst()
                    val_ast = store_access[1]
                    self.memory_write_ast.append((addr_ast, val_ast))
                    self.is_memory_write += 1

            pc = ctx.getConcreteRegisterValue(ctx.registers.rip)
            sp = ctx.getConcreteRegisterValue(ctx.registers.rsp)

        if ctx.isRegisterSymbolized(ctx.registers.rsp):
            self.pivot_ast = ctx.getSymbolicRegister(ctx.registers.rsp).getAst() - 8
            if self.pivot_ast:
                self.pivot = 1

        for reg in self.written_regs:
            self.regAst[reg] = ctx.getSymbolicRegister(getTritonReg(ctx, reg)).getAst()
            simplified = ctx.simplify(self.regAst[reg], True)
            if str(simplified) in regs:
                self.defined_regs[reg] = str(simplified)
                continue
            childs = simplified.getChildren()
            if not childs and len(childs) != 2:
                continue
            try:
                childs[1].getInteger()
            except TypeError:
                continue
            self.defined_regs[reg] = childs[0].getInteger()
        defregs = set(filter(lambda i: isinstance(self.defined_regs[i],int),
                              self.defined_regs.keys()))
        self.depends_regs = set.difference(self.read_regs, defregs)
        if isinstance(self.end_ast, str): # can't handle symbolic end gadget right now:
            self.depends_regs.add(self.end_ast)

        self.diff_sp = sp - STACK
        self.is_analyzed = True
        if debug:
            print("DEBUG")
            code.interact(local=locals())

