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

def _analyze_chunk(chunk):
    """Analyze a chunk of gadgets, accumulating into worker's suffix dict.

    Workers inherit the base suffix dict via fork COW, then accumulate
    analyzed extensions so later chunks benefit from earlier ones.
    """
    import Gadget as _mod
    for gadget in chunk:
        gadget.analyzeGadget()
        if gadget.is_analyzed:
            _mod._suffix_dict[gadget.insstr] = gadget
    return chunk


def _build_suffix_index(gadgets):
    """Partition gadgets into bases (no suffix in gadget set) and extensions."""
    by_insstr = {}
    for g in gadgets:
        by_insstr[g.insstr] = g

    bases = []
    extensions = []
    for g in gadgets:
        parts = g.insstr.split(' ; ')
        found = False
        for i in range(1, len(parts)):
            suffix_insstr = ' ; '.join(parts[i:])
            suffix_g = by_insstr.get(suffix_insstr)
            if suffix_g is not None and suffix_g is not g:
                suffix_len = len(suffix_g.insns)
                if g.insns[-suffix_len:] == suffix_g.insns:
                    found = True
                    break
        if found:
            extensions.append(g)
        else:
            bases.append(g)
    return bases, extensions


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
            # Pass 1: partition into bases and extensions
            bases, extensions = _build_suffix_index(self.gadgets)
            n_bases = len(bases)

            # Pass 2: analyze bases with Pool (no suffix dict)
            _gadget_mod._suffix_dict = None
            if n_bases > 1:
                p = Pool(num_process)
                results = []
                for i, gadget in enumerate(p.imap_unordered(analyzeGadget, bases), 1):
                    results.append(gadget)
                    if i % 100 == 0 or i == n_bases:
                        self._progress(i, total)
                p.close()
                p.join()
                by_addr = {g.addr: g for g in results}
                bases = [by_addr[g.addr] for g in bases]
            else:
                for gadget in bases:
                    gadget.analyzeGadget()

            # Pass 3: analyze extensions with suffix dict (early exit in analyzeGadget).
            # Sort by address, divide into 1000-gadget chunks sorted short-to-long.
            # Workers inherit base dict via fork COW and accumulate extensions,
            # so depth>1 suffixes in the same worker also get early exit.
            _gadget_mod._suffix_dict = {g.insstr: g for g in bases}
            n_ext = len(extensions)
            if n_ext > 1:
                extensions.sort(key=lambda g: g.addr)
                chunks = []
                for i in range(0, n_ext, 1000):
                    chunk = extensions[i:i + 1000]
                    chunk.sort(key=lambda g: len(g.insns))
                    chunks.append(chunk)

                p = Pool(num_process)
                done = n_bases
                ext_by_addr = {}
                for chunk in p.imap_unordered(_analyze_chunk, chunks):
                    for g in chunk:
                        ext_by_addr[g.addr] = g
                    done += len(chunk)
                    self._progress(done, total)
                p.close()
                p.join()
                extensions = [ext_by_addr[g.addr] for g in extensions]
            else:
                for gadget in extensions:
                    gadget.analyzeGadget()
            _gadget_mod._suffix_dict = None

            self._clear_progress(total)
            # Rebuild full gadget list
            all_by_addr = {g.addr: g for g in bases}
            for g in extensions:
                all_by_addr[g.addr] = g
            self.gadgets = [all_by_addr[g.addr] for g in self.gadgets]

        self.gadgets.sort(key=lambda g: len(g.insns))

    def save_analyzed_gadgets(self):
        saved = pickle.dumps(self.gadgets)
        return saved

    def load_analyzed_gadgets(self, pickled_data):
        self.gadgets = pickle.loads(pickled_data)
        self.gadgets.sort(key=lambda g: len(g.insns))
