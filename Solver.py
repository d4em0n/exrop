import code
import pickle
from RopChain import RopChain
from Gadget import *
from itertools import combinations
from triton import *

def initialize():
    ctx = TritonContext()
    ctx.setArchitecture(ARCH.X86_64)
    ctx.setMode(MODE.ALIGNED_MEMORY, True)
    ctx.setAstRepresentationMode(AST_REPRESENTATION.PYTHON)
    return ctx

def findCandidatesWriteGadgets(gadgets, avoid_char=None):
    candidates = {}
    for gadget in list(gadgets):
        badchar = False
        if avoid_char:
            for char in avoid_char:
                addrb = gadget.addr.to_bytes(8, 'little')
                if char in addrb:
                    badchar = True
                    break
        if badchar:
            continue
        if gadget.is_memory_write:
            isw = gadget.is_memory_write
            if not isw in candidates:
                candidates[isw] = [gadget]
                continue
            candidates[isw].append(gadget)
    return candidates

def findForRet(gadgets, min_diff_sp=0, not_write_regs=set(), avoid_char=None):
    for gadget in list(gadgets):
        badchar = False
        if avoid_char:
            for char in avoid_char:
                addrb = gadget.addr.to_bytes(8, 'little')
                if char in addrb:
                    badchar = True
                    break
        if badchar:
            continue
        if set.intersection(not_write_regs, gadget.written_regs):
            continue
        if not gadget.is_memory_write and not gadget.is_memory_write and gadget.end_type == TYPE_RETURN and gadget.diff_sp == min_diff_sp:
            return gadget
    code.interact(local=locals())
    print("KK")

def findCandidatesGadgets(gadgets, regs_write, not_write_regs=set(), avoid_char=None):
    candidates_pop = []
    candidates_write = []
    candidates_depends = []
    candidates_defined = []
    candidates_ret = [] # always
    depends_regs = set()
    for i in range(len(regs_write), 0, -1):
        reg_combs = combinations(regs_write, i)
        for comb in reg_combs:
            reg_comb = set(comb)
            for gadget in list(gadgets):
                if set.intersection(not_write_regs, gadget.written_regs) or gadget.is_memory_read:
                    continue

                if gadget.end_type == TYPE_UNKNOWN:
                    gadgets.remove(gadget)
                    continue

                badchar = False
                if avoid_char:
                    for char in avoid_char:
                        addrb = gadget.addr.to_bytes(8, 'little')
                        if char in addrb:
                            badchar = True
                            break
                if badchar:
                    continue
                if gadget.diff_sp == 0 and gadget.end_type == TYPE_RETURN:
                    candidates_ret.append(gadget)
                    gadgets.remove(gadget)
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
    candidates = candidates_defined + candidates_pop + candidates_write + candidates_depends + candidates_ret # ordered by useful gadgets
    return candidates

def extract_byte(bv, pos):
    return (bv >> pos*8) & 0xff

def filter_byte(astctxt, bv, bc, bsize):
    nbv = []
    for i in range(bsize):
        nbv.append(astctxt.lnot(astctxt.equal(astctxt.extract(i*8+7, i*8, bv),astctxt.bv(bc, 8))))
    return nbv

def solveGadgets(gadgets, solves, add_info=set(), notFirst=False, avoid_char=None):
    regs = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
    final_solved = []
    solved_reg = dict()
    candidates = findCandidatesGadgets(gadgets, solves.keys(), avoid_char=avoid_char)
    spi = 0
    written_regs = set()
    refind_solves = dict()
    ctx = initialize()
    astCtxt = ctx.getAstContext()
    solved = {}
    reglist = []
    written_regs_by_gadget = []
    for gadget in candidates:
        tmp_solved = dict()
        tmp_written_regs = set()
        intersect = False
        if gadget.end_type != TYPE_RETURN and not gadget.end_gadget:
            next_gadget = None
#            print("handling no return gadget")
            diff = 0
            if gadget.end_type == TYPE_JMP_REG:
                next_gadget = findForRet(candidates[:], 0, set(list(solved.keys())), avoid_char=avoid_char)
            elif gadget.end_type == TYPE_CALL_REG:
                next_gadget = findForRet(candidates[:], 8, set(list(solved.keys())), avoid_char=avoid_char)
                diff = 8
            if not next_gadget:
                print("NOTFOUND")
                continue
            gadget.end_gadget = next_gadget
            gadget.diff_sp += next_gadget.diff_sp - diff
            solves['rip'] = next_gadget.addr

        if not gadget.regAst:
            gadget.buildAst()
        for reg,val in list(solves.items())[:]:
            if reg != 'rip' and reg not in gadget.written_regs:
                continue

            if reg == 'rip':
                regAst = gadget.end_ast
            else:
                regAst = gadget.regAst[reg]
            if reg in gadget.defined_regs and gadget.defined_regs[reg] == val:
                tmp_solved[reg] = []
                solved_reg[reg] = val
                del solves[reg]
                continue

            refind_dict = {}
            if isinstance(val, str): # probably registers
                if reg in gadget.defined_regs and isinstance(gadget.defined_regs[reg], str):
                    refind_dict[gadget.defined_regs[reg]] = val
                    hasil = []
                else:
                    continue
            else:
                if avoid_char:
                    simpl = ctx.simplify(regAst, True)
                    childs = simpl.getChildren()
                    if not childs:
                        childs = [simpl]
                    filterbyte = []
                    lval = len(val.to_bytes(8, 'little').rstrip(b"\x00"))
                    hasil = False
                    for child in childs:
                        for char in avoid_char:
                            fb = filter_byte(astCtxt, child, char, lval)
                            filterbyte.extend(fb)
                    if filterbyte:
                        filterbyte.append(regAst == val)
                        filterbyte = astCtxt.land(filterbyte)
                        hasil = ctx.getModel(filterbyte).values()
                    if not hasil: # try to find again
                        hasil = ctx.getModel(regAst == val).values()

                else:
                    hasil = ctx.getModel(regAst == val).values()

            for v in hasil:
                alias = v.getVariable().getAlias()
                if 'STACK' not in alias:
                    if alias in regs and alias not in refind_dict:
                        refind_dict[alias] = v.getValue()
                    else:
                        hasil = False
                        break
                elif avoid_char: # check if stack is popped contain avoid char
                    for char in avoid_char:
                        if char in val.to_bytes(8, 'little'):
                            hasil = False
                            refind_dict = False
                            break
            if refind_dict:
                if notFirst:
                    hasil,kk = solveGadgets(candidates[:], refind_dict, written_regs.copy(), False, avoid_char)
                else:
                    hasil,kk = solveGadgets(candidates[:], refind_dict, {}, True, avoid_char)
                tmp_written_regs.update(kk)

            if hasil:
                tmp_solved[reg] = hasil
                solved_reg[reg] = val
                del solves[reg]

        solves.pop('rip', None) # clear end gadget ast
        if not tmp_solved:
            continue

        tmp_written_regs.update(gadget.written_regs)
        if set.intersection(tmp_written_regs, set(list(solved.keys()))):
            intersect = True
        solved.update(tmp_solved)
        written_regs.update(tmp_written_regs)
        if intersect and len(written_regs_by_gadget) > 0:
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
    print(solves)
    return [],[]

def solveWriteGadgets(gadgets, solves, avoid_char=None):
    regs = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
    final_solved = []
    candidates = findCandidatesWriteGadgets(gadgets, avoid_char=avoid_char)
    ctx = initialize()
    gwr = list(candidates.keys())
    gwr.sort()
    for w in gwr:
        for gadget in candidates[w]:
            if not gadget.memory_write_ast:
                gadget.buildAst()
            for addr,val in list(solves.items())[:]:
                tmp_solved = dict()
                mem_ast = gadget.memory_write_ast[0]
                if mem_ast[1].getBitvectorSize() != 64:
                    break
                addrhasil = ctx.getModel(mem_ast[0] == addr).values()
                valhasil = ctx.getModel(mem_ast[1] == val).values()
                if not addrhasil or not valhasil:
                    break
                hasil = list(addrhasil) + list(valhasil)
                refind_dict = {}
#                code.interact(local=locals())
                for v in hasil:
                    alias = v.getVariable().getAlias()
                    if 'STACK' not in alias:
                        if alias in regs and alias not in refind_dict:
                            refind_dict[alias] = v.getValue()
                        else:
                            hasil = False
                            break
                if hasil and refind_dict:
                    hasil,_ = solveGadgets(gadgets[:], refind_dict)
                if hasil:
                    tmp_solved[addr] = hasil
                    del solves[addr]
                    final_solved.append((gadget, tmp_solved.values()))
                    if not solves:
                        return final_solved

class ChainBuilder(object):
    def __init__(self, gadgets=list()):
        self.gadgets = gadgets
        self.regs = dict()
        self.raw_chain = None

    def solve_chain(self, avoid_char):
        self.raw_chain,_ = solveGadgets(self.gadgets.copy(), self.regs, avoid_char=avoid_char)

    def set_regs(self, regs):
        self.regs = regs

    def set_writes(self, writes):
        self.writes = writes

    def solve_chain_write(self):
        self.raw_chain = solveWriteGadgets(self.gadgets.copy(), self.writes)

    def build_chain(self, next_call=None):
        rop_chain = RopChain()
        self.build_chain_recurse(self.raw_chain, rop_chain)
        if next_call:
            last_gadget = rop_chain.chains[-1]
            last_gadget[1].append(next_call)
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

    def save_analyzed_gadgets(self):
        gadgets = self.gadgets[:]
        for gadget in gadgets:
            gadget.regAst = None # AstNode can't be cached
            gadget.memory_write_ast = None # AstNode can't be cached
        saved = pickle.dumps(gadgets)
        return saved

    def load_analyzed_gadgets(self, pickled_data):
        self.gadgets = pickle.loads(pickled_data)
