from triton import *
from keystone import *
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

def asm_per_ins(codes, addr=0):
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    insns = dict()
    for code in codes:
        if not code:
            continue
        insns[addr] = bytes(ks.asm(code)[0])
        addr += len(insns[addr])
    return insns

def asm_ins(code):
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    insns = bytes(ks.asm(code)[0])
    return insns

TYPE_RETURN = 0
TYPE_JMP_REG = 1
TYPE_JMP_MEM = 2
TYPE_CALL_REG = 3
TYPE_CALL_MEM = 4
TYPE_UNKNOWN = 5

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
        self.insstr = dict()
        self.insns = dict()
        self.is_memory_write = 0
        self.is_memory_read = 0 # not pop
        self.memory_write_ast = []
        self.end_type = TYPE_RETURN # default ret
        self.end_ast = None
        self.end_gadget = 0 # return gadget to fix no-return gadgets
        self.end_reg_used = set() # register used in end_ast

    def __repr__(self):
        append_com = ""
        if self.end_gadget:
            append_com = ": next -> (0x{:08x}) # {}".format(self.end_gadget.addr, self.end_gadget)
        return "; ".join(self.insstr.values()) + append_com
#        return "addr : {}\nwritten : {}\nread : {}\npopped : {}\ndepends : {}\ndiff_sp: {}".format(self.addr, self.written_regs, self.read_regs, self.popped_regs, self.depends_regs, self.diff_sp)

    def __str__(self):
        append_com = ""
        if self.end_gadget:
            append_com = ": next -> (0x{:08x}) # {}".format(self.end_gadget.addr, self.end_gadget)
        return "; ".join(self.insstr.values()) + append_com
#        return "addr : {}\nwritten : {}\nread : {}\npopped : {}\ndepends : {}\ndiff_sp: {}\n".format(self.addr, self.written_regs, self.read_regs, self.popped_regs, self.depends_regs, self.diff_sp)

    def loadFromString(self, instructions):
        addr = self.addr
        for ins in instructions.split(";"):
            self.insstr[addr] = ins.strip()
            self.insns[addr] = asm_ins(ins)
            addr += len(self.insns[addr])

    def buildAst(self):
        ctx = initialize()
        astCtxt = ctx.getAstContext()
        regs = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]

        for reg in regs:
            symbolizeReg(ctx, reg)
        ctx.setConcreteRegisterValue(ctx.registers.rsp, STACK)
        ctx.setConcreteRegisterValue(ctx.registers.rbp, STACK+8*64)

        for i in range(MAX_FILL_STACK):
            tmpb = ctx.symbolizeMemory(MemoryAccess(STACK+(i*8), CPUSIZE.QWORD))
            tmpb.setAlias("STACK{}".format(i))

        sp = STACK
        instructions = self.insns
        pc = self.addr
        self.regAst = dict()
        self.memory_write_ast = []
        BSIZE = 8
        while True:
            inst = Instruction()
            inst.setOpcode(instructions[pc])
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

        for reg in self.written_regs:
            self.regAst[reg] = ctx.getSymbolicRegister(getTritonReg(ctx, reg)).getAst()

    def analyzeGadget(self, debug=False):
        BSIZE = 8
        ctx = initialize()
        astCtxt = ctx.getAstContext()
        regs = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]

        reglist = dict()
        for reg in regs:
            reglist[reg] = symbolizeReg(ctx, reg)
        ctx.setConcreteRegisterValue(ctx.registers.rsp, STACK)
        ctx.setConcreteRegisterValue(ctx.registers.rbp, STACK+8*64)

        for i in range(MAX_FILL_STACK):
            tmpb = ctx.symbolizeMemory(MemoryAccess(STACK+(i*8), CPUSIZE.QWORD))
            tmpb.setAlias("STACK{}".format(i))

        sp = STACK
        instructions = self.insns
        pc = self.addr

        while True:
            inst = Instruction()
            inst.setOpcode(instructions[pc])
            inst.setAddress(pc)
            ctx.processing(inst)


            written = inst.getWrittenRegisters()
            red = inst.getReadRegisters()
            pop = False
            tmp_red = set()
            for wrt in written:
                regname = wrt[0].getName()
                if regname in regs:
                    self.written_regs.add(regname)
                    newsp = ctx.getConcreteRegisterValue(ctx.registers.rsp)
                    if (newsp - sp) == 8:
                        pop = True
                        self.popped_regs.add(regname)

            for r in red:
                regname = r[0].getName()
                if regname in regs:
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

            if inst.isMemoryWrite() and 'mov' in self.insstr[pc]:
                for store_access in inst.getStoreAccess():
                    addr_ast = store_access[0].getLeaAst()
                    val_ast = store_access[1]
                    self.memory_write_ast.append((addr_ast, val_ast))
                    self.is_memory_write += 1

            pc = ctx.getConcreteRegisterValue(ctx.registers.rip)
            sp = ctx.getConcreteRegisterValue(ctx.registers.rsp)

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

