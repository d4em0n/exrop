from Solver import *
from Gadget import *
from RopChain import *

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
            gadget.end_ast = None # AstNode can't be cached
        saved = pickle.dumps(gadgets)
        return saved

    def load_analyzed_gadgets(self, pickled_data):
        self.gadgets = pickle.loads(pickled_data)
