from Solver import ChainBuilder
from os import popen

def parseRopGadget(filename):
    cmd = 'ROPgadget --nojop --binary {} --only "pop|xchg|add|sub|xor|mov|ret" | grep "ret$"'.format(filename)
    with popen(cmd) as fp:
        sample_gadgets = dict()
        datas = fp.read().strip().split("\n")
        for data in datas:
            addr,insns = data.split(" : ")
            addr = int(addr, 16)
            sample_gadgets[addr] = insns
        return sample_gadgets

class Exrop(object):
    def __init__(self, binary):
        self.binary = binary
        self.chain_builder = ChainBuilder()

    def find_gadgets(self):
        gadgets = parseRopGadget(self.binary)
        self.chain_builder.load_list_gadget_string(gadgets)
        self.chain_builder.analyzeAll()

    def load_raw_gadgets(self, gadgets):
        pass

    def set_regs(self, regs):
        self.chain_builder.set_regs(regs)
        self.chain_builder.solve_chain()
        ropchain = self.chain_builder.build_chain()
        return ropchain

