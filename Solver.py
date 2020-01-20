import code
from RopChain import RopChain
from Gadget import Gadget
from itertools import combinations
from triton import *

def initialize():
    ctx = TritonContext()
    ctx.setArchitecture(ARCH.X86_64)
    ctx.setMode(MODE.ALIGNED_MEMORY, True)
    ctx.setAstRepresentationMode(AST_REPRESENTATION.PYTHON)
    return ctx

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

class ChainBuilder(object):
    def __init__(self, gadgets=list()):
        self.gadgets = gadgets
        self.regs = dict()
        self.raw_chain = None

    def solve_chain(self):
        self.raw_chain,_ = solveGadgets(self.gadgets.copy(), self.regs)

    def set_regs(self, regs):
        self.regs = regs

    def build_chain(self):
        rop_chain = RopChain()
        self.build_chain_recurse(self.raw_chain, rop_chain)
        return rop_chain

    def add_gadget_string(self, addr, gadget_string):
        gadget = Gadget(addr)
        gadget.loadFromString(gadget_string)
        self.add_gadget(gadget)

    def add_gadget(self, gadget):
        self.gadgets.append(gadget)

    def load_list_gadget_string(self, gadgets_dict):
        for addr,gadget_string in gadgets_dict.items():
            self.add_gadget_string(addr, gadget_string)

    def analyzeAll(self):
        for gadget in self.gadgets:
            gadget.analyzeGadget()

    def build_chain_recurse(self, raw_chain, rop_chain):
        for gadget, info in raw_chain:
            len_gadget = gadget.diff_sp//8
            chain = [0]*(len_gadget)
            chain_chain = None
            for l1 in info:
                l1 = list(l1)
                if l1 and isinstance(l1[0], tuple):
                    self.build_chain_recurse(l1, rop_chain)
                    continue
                for chain_item in l1:
                    alias = chain_item.getVariable().getAlias()
                    idxchain = int(alias.replace("STACK", ""))
                    chain[idxchain] = chain_item.getValue()

            rop_chain.add(gadget, chain)
