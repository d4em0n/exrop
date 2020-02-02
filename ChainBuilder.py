from Solver import *
from Gadget import *
from RopChain import *
import copy

class ChainBuilder(object):
    def __init__(self, gadgets=list()):
        self.gadgets = gadgets
        self.regs = dict()
        self.raw_chain = None

    def solve_chain(self, avoid_char):
        self.raw_chain = solveGadgets(self.gadgets.copy(), self.regs, avoid_char=avoid_char)

    def set_regs(self, regs):
        self.regs = regs

    def set_writes(self, writes):
        self.writes = writes

    def solve_chain_write(self, avoid_char=None):
        self.raw_chain = solveWriteGadgets(self.gadgets.copy(), self.writes, avoid_char=avoid_char)

    def solve_pivot(self, addr, avoid_char):
        self.raw_chain = solvePivot(self.gadgets.copy(), addr, avoid_char)

    def build_chain(self, next_call=None):
        if next_call:
            self.raw_chain.set_next_call(next_call)
        return self.raw_chain

    def add_gadget_string(self, addr, gadget_string, gadget_opcode):
        gadget = Gadget(addr)
        gadget.loadFromString(gadget_string, gadget_opcode)
        self.add_gadget(gadget)

    def add_gadget(self, gadget):
        self.gadgets.append(gadget)

    def load_list_gadget_string(self, gadgets_dict):
        for addr,info in gadgets_dict.items():
            self.add_gadget_string(addr, info[0], info[1])

    def analyzeAll(self):
        for gadget in self.gadgets:
            gadget.analyzeGadget()

    def save_analyzed_gadgets(self):
        gadgets = []
        for old_gadget in self.gadgets:
            # save state
            oldRegAst = old_gadget.regAst
            oldMemASt = old_gadget.memory_write_ast
            oldEndAst = old_gadget.end_ast
            oldPivotAst = old_gadget.pivot_ast


            old_gadget.regAst = None
            old_gadget.memory_write_ast = None
            old_gadget.end_ast = None
            old_gadget.pivot_ast = None

            # ast node can't pickle, convert all to string
            gadget = copy.deepcopy(old_gadget)
            newRegAst = dict()
            for reg,val in oldRegAst.items():
                newRegAst[reg] = str(val)
            gadget.regAst = newRegAst

            newMemAst = []
            for addr,val in oldMemASt:
                newMemAst.append((str(addr), str(val)))
            gadget.memory_write_ast = newMemAst

            if gadget.end_ast:
                gadget.end_ast = str(oldEndAst)

            if gadget.pivot_ast:
                gadget.pivot_ast = str(oldPivotAst)

            gadget.is_asted = False
            gadgets.append(gadget)

            # reload state
            old_gadget.regAst = oldRegAst
            old_gadget.memory_write_ast = oldMemASt
            old_gadget.end_ast = oldEndAst
            old_gadget.pivot_ast = oldPivotAst

        saved = pickle.dumps(gadgets)
        return saved

    def load_analyzed_gadgets(self, pickled_data):
        self.gadgets = pickle.loads(pickled_data)
