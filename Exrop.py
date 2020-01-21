from Solver import ChainBuilder
from os import popen

def parseRopGadget(filename):
    cmd = 'ROPgadget --nojop --binary {} --only "pop|xchg|add|sub|xor|mov|ret" | grep "ret$"'.format(filename)
    with popen(cmd) as fp:
        sample_gadgets = dict()
        datas = fp.read().strip().split("\n")
        datas.sort(key=len) # sort by length
        for data in datas:
            addr,insns = data.split(" : ")
            addr = int(addr, 16)
            sample_gadgets[addr] = insns
        return sample_gadgets

class Exrop(object):
    def __init__(self, binary):
        self.binary = binary
        self.chain_builder = ChainBuilder()

    def find_gadgets(self, cache=False):
        if cache:
            fcname = "./{}.exrop_cache".format(self.binary.replace("/", "_"))
            try:
                with open(fcname, "rb") as fc:
                    objpic = fc.read()
                    self.chain_builder.load_analyzed_gadgets(objpic)
                    return
            except FileNotFoundError:
                fc = open(fcname, "wb")
        gadgets = parseRopGadget(self.binary)
        self.chain_builder.load_list_gadget_string(gadgets)
        self.chain_builder.analyzeAll()
        if cache:
            objpic = self.chain_builder.save_analyzed_gadgets()
            fc.write(objpic)
            fc.close()

    def load_raw_gadgets(self, gadgets):
        pass

    def set_regs(self, regs):
        self.chain_builder.set_regs(regs)
        self.chain_builder.solve_chain()
        ropchain = self.chain_builder.build_chain()
        return ropchain

    def set_writes(self, writes):
        self.chain_builder.set_writes(writes)
        self.chain_builder.solve_chain_write()
        ropchain = self.chain_builder.build_chain()
        return ropchain

