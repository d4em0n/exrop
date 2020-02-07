from Solver import *
from Gadget import *
from RopChain import *
from multiprocessing import Pool

def analyzeGadget(gadget):
    gadget.analyzeGadget()
    return gadget

class ChainBuilder(object):
    def __init__(self, gadgets=list()):
        self.gadgets = gadgets
        self.regs = dict()
        self.raw_chain = None

    def solve_chain(self, avoid_char=None):
        self.raw_chain = solveGadgets(self.gadgets.copy(), self.regs, avoid_char=avoid_char)

    def set_regs(self, regs):
        self.regs = regs

    def get_syscall_addr(self, not_write_regs=set(), avoid_char=None):
        return findSyscall(self.gadgets.copy(), not_write_regs, avoid_char=avoid_char)

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

    def analyzeAll(self, num_process=1):
        if num_process != 1:
            p = Pool(num_process)
            self.gadgets = p.map(analyzeGadget, self.gadgets)
        else:
            for gadget in self.gadgets:
                gadget.analyzeGadget()

    def save_analyzed_gadgets(self):
        saved = pickle.dumps(self.gadgets)
        return saved

    def load_analyzed_gadgets(self, pickled_data):
        self.gadgets = pickle.loads(pickled_data)
