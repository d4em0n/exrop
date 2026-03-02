import os
import sys
import pickle
from Solver import *
from Gadget import *
from RopChain import *
from multiprocessing import Pool

def analyzeGadget(gadget):
    gadget.analyzeGadget()
    return gadget

class ChainBuilder(object):
    def __init__(self, gadgets=None):
        self.gadgets = gadgets if gadgets is not None else []
        self.regs = dict()
        self.raw_chain = None
        self.clean_only = False

    def _get_gadgets(self):
        if self.clean_only:
            return [g for g in self.gadgets if g.side_effect_score == 0]
        return self.gadgets.copy()

    def solve_chain(self, avoid_char=None):
        self.raw_chain = solveGadgets(self._get_gadgets(), self.regs, avoid_char=avoid_char)

    def set_regs(self, regs):
        self.regs = regs

    def get_syscall_addr(self, not_write_regs=None, avoid_char=None):
        return findSyscall(self._get_gadgets(), not_write_regs, avoid_char=avoid_char)

    def set_writes(self, writes):
        self.writes = writes

    def solve_chain_write(self, avoid_char=None):
        self.raw_chain = solveWriteGadgets(self._get_gadgets(), self.writes, avoid_char=avoid_char)

    def solve_pivot(self, addr, avoid_char):
        self.raw_chain = solvePivot(self._get_gadgets(), addr, avoid_char)

    def solve_pivot_reg(self, src_reg, avoid_char=None, used_dispatch=None):
        return solvePivotForReg(self._get_gadgets(), src_reg, avoid_char, used_dispatch=used_dispatch)

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

    def _progress(self, done, total):
        if total < 50:
            return
        pct = done * 100 // total
        bar = '#' * (pct // 5) + '-' * (20 - pct // 5)
        sys.stderr.write(f'\r  analyzing gadgets [{bar}] {done}/{total} ({pct}%)')
        sys.stderr.flush()

    def _clear_progress(self, total):
        if total >= 50:
            sys.stderr.write('\r' + ' ' * 60 + '\r')
            sys.stderr.flush()

    def analyzeAll(self, num_process=None):
        total = len(self.gadgets)
        if num_process is None:
            num_process = os.cpu_count() or 1
        if num_process > 1 and total > 1:
            p = Pool(num_process)
            results = []
            for i, gadget in enumerate(p.imap_unordered(analyzeGadget, self.gadgets), 1):
                results.append(gadget)
                if i % 100 == 0 or i == total:
                    self._progress(i, total)
            p.close()
            p.join()
            # Preserve original order by address
            by_addr = {g.addr: g for g in results}
            self.gadgets = [by_addr[g.addr] for g in self.gadgets]
        else:
            for i, gadget in enumerate(self.gadgets):
                gadget.analyzeGadget()
                if (i % 100 == 0 or i == total - 1):
                    self._progress(i + 1, total)
        self._clear_progress(total)
        self.gadgets.sort(key=lambda g: len(g.insns))

    def save_analyzed_gadgets(self):
        saved = pickle.dumps(self.gadgets)
        return saved

    def load_analyzed_gadgets(self, pickled_data):
        self.gadgets = pickle.loads(pickled_data)
        self.gadgets.sort(key=lambda g: len(g.insns))
