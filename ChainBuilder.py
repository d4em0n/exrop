import os
import sys
import pickle
from Solver import *
from Gadget import *
from RopChain import *
from multiprocessing import Pool
import Gadget as _gadget_mod

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

    def find_stack_shift(self, shift_bytes, avoid_char=None):
        return findStackShift(self._get_gadgets(), shift_bytes, avoid_char)

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

        if num_process <= 1 or total <= 1:
            # Single process: sort short-to-long, build dict incrementally
            self.gadgets.sort(key=lambda g: len(g.insns))
            _gadget_mod._suffix_dict = {}
            for i, gadget in enumerate(self.gadgets):
                gadget.analyzeGadget()
                if gadget.is_analyzed:
                    _gadget_mod._suffix_dict[gadget.insstr] = gadget
                if i % 100 == 0 or i == total - 1:
                    self._progress(i + 1, total)
            _gadget_mod._suffix_dict = None
        else:
            # Group gadgets by instruction count, analyze in rounds
            # shortest first.  Each round forks a Pool that inherits the
            # suffix dict (COW) containing ALL previously analyzed gadgets,
            # giving 100% suffix coverage at every depth.
            from collections import defaultdict
            by_len = defaultdict(list)
            for g in self.gadgets:
                by_len[len(g.insstr.split(' ; '))].append(g)

            _gadget_mod._suffix_dict = {}
            done = 0
            by_addr = {}

            for n_insns in sorted(by_len):
                group = by_len[n_insns]

                if n_insns == 1 or not _gadget_mod._suffix_dict:
                    # First round: no suffix dict needed
                    _gadget_mod._suffix_dict = {}

                p = Pool(num_process)
                for gadget in p.imap_unordered(analyzeGadget, group):
                    by_addr[gadget.addr] = gadget
                    if gadget.is_analyzed:
                        _gadget_mod._suffix_dict[gadget.insstr] = gadget
                    done += 1
                    if done % 100 == 0 or done == total:
                        self._progress(done, total)
                p.close()
                p.join()

            _gadget_mod._suffix_dict = None
            self._clear_progress(total)
            self.gadgets = [by_addr[g.addr] for g in self.gadgets]

        self.gadgets.sort(key=lambda g: len(g.insns))

    def save_analyzed_gadgets(self):
        saved = pickle.dumps(self.gadgets)
        return saved

    def load_analyzed_gadgets(self, pickled_data):
        self.gadgets = pickle.loads(pickled_data)
        self.gadgets.sort(key=lambda g: len(g.insns))
