#!/usr/bin/env python3

from keystone import *
import time
from triton import *
from itertools import combinations
import code
from pprint import pprint
import sys
from Solver import solveWriteGadgets


STACK = 0x7fffff00
MAX_FILL_STACK = 128

class ropGadget(object):
    def __init__(self, addr):
        self.addr = addr
        self.insns = []
        self.insstr = []
        self.written_regs = set() # register yang telah tertulis
        self.read_regs = set() # register yang telah terbaca
        self.popped_regs = set() # register dari hasil `pop reg`
        self.depends_regs = set() # `mov rax, rbx; ret` gadget ini akan bergantung pada rbx
        self.defined_regs = dict() # register yang telah terdefinisi konstanta `xor rax, rax; ret`
        self.regAst = dict()
        self.diff_sp = 0 # jarak rsp ke rbp sesaaat sebelum ret

    def __repr__(self):
        return "; ".join(self.insstr)
#        return "addr : {}\nwritten : {}\nread : {}\npopped : {}\ndepends : {}\ndiff_sp: {}".format(self.addr, self.written_regs, self.read_regs, self.popped_regs, self.depends_regs, self.diff_sp)

    def __str__(self):
        return "; ".join(self.insstr)
#        return "addr : {}\nwritten : {}\nread : {}\npopped : {}\ndepends : {}\ndiff_sp: {}\n".format(self.addr, self.written_regs, self.read_regs, self.popped_regs, self.depends_regs, self.diff_sp)

def asm_per_ins(codes, addr=0):
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    insns = dict()
    for code in codes:
        if not code:
            continue
        insns[addr] = bytes(ks.asm(code)[0])
        addr += len(insns[addr])
    return insns

def initialize():
    ctx = TritonContext()
    ctx.setArchitecture(ARCH.X86_64)
    ctx.setMode(MODE.ALIGNED_MEMORY, True)
    ctx.setAstRepresentationMode(AST_REPRESENTATION.PYTHON)
    return ctx

def symbolizeReg(ctx, regname):
    tmp = ctx.symbolizeRegister(getattr(ctx.registers,regname))
    tmp.setAlias(regname)

def findCandidatesGadgets(gadgets, regs_write, not_write_regs=set()):
    candidates_pop = []
    candidates_write = []
    candidates_depends = []
    candidates_defined = []
    depends_regs = set()
    for i in range(len(regs_write), 0, -1):
        reg_combs = combinations(regs_write, i)
        for comb in reg_combs:
            reg_comb = set(comb)
            for gadget in list(gadgets):
                if set.intersection(not_write_regs, gadget.written_regs):
                    continue

                if reg_comb.issubset(set(gadget.defined_regs.keys())):
                    candidates_defined.append(gadget)
                    gadgets.remove(gadget)
                    depends_regs.update(gadget.depends_regs)
                    continue

                if reg_comb.issubset(gadget.popped_regs):
                    candidates_pop.append(gadget)
                    gadgets.remove(gadget)
                    depends_regs.update(gadget.depends_regs)
                    continue

                if reg_comb.issubset(gadget.written_regs):
                    candidates_write.append(gadget)
                    gadgets.remove(gadget)
                    depends_regs.update(gadget.depends_regs)

    if depends_regs:
        candidates_depends = findCandidatesGadgets(gadgets, depends_regs, not_write_regs)
    candidates = candidates_defined + candidates_pop + candidates_write + candidates_depends
    return candidates

def analyzeGadget(instructions, ep, debug=False):
    ctx = initialize()
    astCtxt = ctx.getAstContext()
    regs = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12"]

    for reg in regs:
        symbolizeReg(ctx, reg)
    ctx.setConcreteRegisterValue(ctx.registers.rsp, STACK)
    ctx.setConcreteRegisterValue(ctx.registers.rbp, STACK+8*64)

    for i in range(MAX_FILL_STACK):
        tmpb = ctx.symbolizeMemory(MemoryAccess(STACK+(i*8), CPUSIZE.QWORD))
        tmpb.setAlias("STACK{}".format(i))
    pc = ep
    sp = STACK
    gadget = ropGadget(ep)
    gadget.insns = instructions
    gadget.is_memory_write = 0
    gadget.memory_write_ast = []
    while instructions[pc] != b"\xc3":
        inst = Instruction()
        inst.setOpcode(instructions[pc])
        inst.setAddress(pc)
        ctx.processing(inst)

        written = inst.getWrittenRegisters()
        red = inst.getReadRegisters()
        if debug:
            print("DEBUG")
            code.interact(local=locals())

        for wrt in written:
            regname = wrt[0].getName()
            if regname in regs:
                gadget.written_regs.add(regname)
                newsp = ctx.getConcreteRegisterValue(ctx.registers.rsp)
                if (newsp - sp) == 8:
                    gadget.popped_regs.add(regname)

        for r in red:
            regname = r[0].getName()
            if regname in regs:
                gadget.read_regs.add(regname)

        if inst.isMemoryWrite():
            for store_access in inst.getStoreAccess():
                code.interact(local=locals())
                addr_ast = store_access[0].getLeaAst()
                val_ast = store_access[1]
                gadget.memory_write_ast.append((addr_ast, val_ast))
                gadget.is_memory_write += 1

        pc = ctx.getConcreteRegisterValue(ctx.registers.rip)
        sp = ctx.getConcreteRegisterValue(ctx.registers.rsp)

    for reg in gadget.written_regs:
        gadget.regAst[reg] = ctx.getSymbolicRegister(getTritonReg(ctx, reg)).getAst()
        simpl = ctx.simplify(gadget.regAst[reg], True).getChildren()
        if not simpl:
            continue
        try:
            assert(len(simpl) == 2)
        except:
            code.interact(local=locals())
        try:
            simpl[1].getInteger()
        except TypeError:
            continue
        gadget.defined_regs[reg] = simpl[0].getInteger()
    defregs = set(gadget.defined_regs.keys())
    gadget.depends_regs = set.difference(gadget.read_regs, defregs)

    gadget.diff_sp = sp - STACK
    if debug:
        print("DEBUG")
        code.interact(local=locals())
    return gadget

def getTritonReg(ctx, regname):
    return getattr(ctx.registers, regname)

def solveGadgets(gadgets, solves, add_info=set(), notFirst=False):
    regs = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12"]
    final_solved = []
    solved_reg = dict()
    candidates = findCandidatesGadgets(gadgets, solves.keys())
    spi = 0
    written_regs = set()
    refind_solves = dict()
    ctx = initialize()
    solved = {}
    reglist = []
    written_regs_by_gadget = []
    for gadget in candidates:

        tmp_solved = dict()
        tmp_written_regs = set()
        intersect = False
        for reg,val in list(solves.items())[:]:
            if reg not in gadget.written_regs:
                continue
            regAst = gadget.regAst[reg]
            if reg in gadget.defined_regs and gadget.defined_regs[reg] == val:
                solved[reg] = []
                tmp_solved[reg] = []
                solved_reg[reg] = val
                del solves[reg]
                continue

            hasil = ctx.getModel(regAst == val).values()

            refind_dict = {}
            for v in hasil:
                alias = v.getVariable().getAlias()
                if 'STACK' not in alias:
                    if alias in regs and alias not in refind_dict:
                        refind_dict[alias] = v.getValue()
                    else:
                        hasil = False
                        break

            if refind_dict:
                if notFirst:
                    hasil,kk = solveGadgets(candidates[:], refind_dict, written_regs.copy(), False)
                else:
                    hasil,kk = solveGadgets(candidates[:], refind_dict, {}, True)
                tmp_written_regs.update(kk)

            if hasil:
                tmp_solved[reg] = hasil
                solved_reg[reg] = val
                del solves[reg]

        if not tmp_solved:
            continue
        tmp_written_regs.update(gadget.written_regs)
        if set.intersection(tmp_written_regs, set(list(solved.keys()))):
            intersect = True
        solved.update(tmp_solved)
        written_regs.update(tmp_written_regs)
        if intersect:
            for i in range(len(written_regs_by_gadget)-1, -1, -1):
                if set.intersection(set(tmp_solved.keys()), written_regs_by_gadget[i]):
                    final_solved.insert(i+1, (gadget, tmp_solved.values()))
                    written_regs_by_gadget.insert(i+1, tmp_written_regs)
                    break
                elif i == 0:
                    final_solved.insert(0, (gadget, tmp_solved.values()))
                    written_regs_by_gadget.insert(0, tmp_written_regs)
        else:
            final_solved.append((gadget, tmp_solved.values()))
            written_regs_by_gadget.append(tmp_written_regs)
        if not solves:
            written_regs.update(add_info)
            return final_solved, written_regs

    print("nothing more! {}".format(solves.keys()))
    return [],[]

def build_chain(raw_chain):
    chains = []
    comments = []
    for gadget, info in  raw_chain:
        len_gadget = gadget.diff_sp//8
        chain = [0]*(1 + len_gadget)
        comment = [""]*(1 + len_gadget)
        chain[0] = gadget.addr
        comment[0] = gadget.insstr
        chain_chain = None
        for l1 in info:
            l1 = list(l1)
            if l1 and isinstance(l1[0], tuple):
                chain_chain, com_com = build_chain(l1)
                continue
            for chain_item in l1:
                alias = chain_item.getVariable().getAlias()
                idxchain = int(alias.replace("STACK", "")) + 1
                chain[idxchain] = chain_item.getValue()

        if chain_chain:
            chain_chain.extend(chain)
            chain = chain_chain
            com_com.extend(comment)
            comment = com_com

        chains.extend(chain)
        comments.extend(comment)
    return chains, comments

def buildSampleGadgets(raw_gadgets):
    gadgets = set()
    lenraw = len(raw_gadgets)
    print("Analyzing {} gadgets..\n".format(lenraw))
    t = time.mktime(time.gmtime())
    for addr, ins in raw_gadgets.items():
        gadget = analyzeGadget(asm_per_ins(ins, addr),addr)
        gadget.insstr = ins
        gadgets.add(gadget)
    print("Analyzing done in {}s".format(time.mktime(time.gmtime()) - t))
    return gadgets

def parseRopGadget(filename):
    with open(filename) as fp:
        sample_gadgets = dict()
        datas = fp.read().strip().split("\n")
        for data in datas:
            addr,insns = data.split(" : ")
            insns = insns.split(" ; ")
            addr = int(addr, 16)
            sample_gadgets[addr] = insns
        return sample_gadgets

sample_gadgets1 = {
    0x0000: "xor rsi, rdi; ret".split(";"),
    0x1000: "pop rdi; ret;".split(";"),
    0x0f00: "pop rbx; pop rax; add rsp, 16; ret".split("; "),
    0x0c00: "mov r12, rax; add r12, 5; ret".split("; "),
    0x2000: "pop rsi; add rsp, 8; pop rdi; ret".split(";"),
    0x3000: "add rbx, 5; pop r15; pop rdx; ret".split(";"),
    0x4000: "add rsp, 8; ret".split(";"),
}

sample_gadgets1_find = {'rdi': 0x41414242, 'rsi': 0xffffffff, 'rdx': 0xccbbddee, 'r12': 0xdeadbeef, 'rbx': 0x43434343}

sample_gadgets2 = {
    0x1000: 'pop rsi; ret'.split(";"),
    0x2000: 'mov rbx, rsi; ret'.split(";"),
    0x3000: 'mov rax, rcx; ret'.split(";"),
    0x4000: 'mov rcx, rbx; add rcx, 100; ret'.split(";"),
    0x5000: 'mov rdx, rsi; ret'.split(";"),
    0x6000: 'mov rdi, rax; ret'.split(";"),
}
sample_gadgets2_find = {
    'rax': 0x12345678,
    'rbx': 0x87654321,
    'rcx': 0x22222222,
    'rdx': 0x7fffffff,
    'rsi': 0x41414141,
    'rdi': 0x42424242
}

sample_gadgets3 = {
        0x1000: 'pop rsi; ret'.split(';'),
        0x2000: 'xchg rax, rsi; ret'.split(';')
}
sample_gadgets3_find = {'rax': 0x12345678, 'rsi': 0x41414141}

sample_gadgets4 = {
    0x1000: 'inc rsi; ret'.split(';'),
    0x2000: 'xor rsi, rsi; ret'.split(';')
}

sample_gadgets4_find = {
    'rsi': 0x5
}


sample_gadgets5_find = {
    'rax':  0x12345678, 'rsi':  0x41414141
}
sample_gadgets5 = {
    0x1000: 'xor rsi, rsi; ret'.split(';'),
    0x2000: 'inc rsi; ret'.split(';'),
    0x3000: 'add rsi, rsi; ret'.split(';'),
    0x4000: 'mov rax, rsi; ret'.split(';'),
}
sample_gadgets6_find = {'rax': 0xb, 'rbx': 0x55554444}
sample_gadgets6 = {
        0x5455: 'mov rax, rbx; ret'.split(';'),
        0x5555: 'xor rax, rbx; ret'.split(';'),
        0x5655: 'pop rbx; ret'.split(';'),
        }

sample_gadgets7 = {
    0x1000: ['pop rdx', 'mov eax, ebp', 'pop rbx', 'pop rbp', 'pop r12', 'pop r13', 'ret'],
    0x2000: ['pop rsi', 'add rsp, 0x18', 'pop rbx', 'pop rbp', 'ret'],
    0x3000: ['pop rdi', 'ret'],
}

sample_gadgets8 = {
    0x1000: "mov qword ptr [rdx+0x10], r10 ; mov eax, 1 ; ret".split(";"),
    0x2000: "pop r10; pop rdx; ret".split(";")
}

def test_analyze():
    find_write = {0x41414141:0x42424242}
    gadgets = buildSampleGadgets(sample_gadgets8)
    hasil = solveWriteGadgets(gadgets, find_write)
    print(hasil)
#    analyzeGadget(asm_per_ins("xor rax, rax; add rax, 5; mov rbx, 10; add rbx, 5; add rsi, 5; inc rdi; sub rsi, rdi; ret".split(";"), addr),addr, True)

def tests():
    print("Loading list simple gadgets")
    find = sample_gadgets1_find
    raw_gadgets = sample_gadgets7
#    for addr,inst in raw_gadgets.items():
#        print("0x{:08x} : {}".format(addr, inst))
    print("")
    gadgets = buildSampleGadgets(parseRopGadget(sys.argv[1]))
#    gadgets = buildSampleGadgets(raw_gadgets)
    print("Find registers: ")
    for reg,val in find.items():
        print("{} = 0x{:016x}".format(reg, val))
    print("")
    raw_chain,kk = solveGadgets(gadgets, find)
    print("Solving gadgets.. DONE")
    ropchain, comments = build_chain(raw_chain)
    for i in range(len(ropchain)):
        print("$RSP+0x{:04x} : 0x{:016x} # {}".format(i*8, ropchain[i], comments[i]))
#    emulate(sample4_ins, entry_point, {})

test_analyze()
#tests()
