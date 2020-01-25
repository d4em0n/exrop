from ChainBuilder import ChainBuilder
from Exrop import Exrop
from Gadget import *
import sys
from keystone import *

def asm_ins(code):
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    insns = bytes(ks.asm(code)[0])
    return insns

if len(sys.argv) == 1:
    print("use: {} test_file".format(sys.argv[0]))
    sys.exit(1)

with open(sys.argv[1], "rb") as fp:
    data_test = eval(fp.read())
    gadgets = data_test['gadgets']
    for addr in gadgets:
        gadgets[addr] = (gadgets[addr], asm_ins(gadgets[addr]))
    chain_builder = ChainBuilder()
    chain_builder.load_list_gadget_string(gadgets)
    chain_builder.analyzeAll()
    chain_builder.set_regs(data_test['find'])
    avoid_char = None
    if 'badchars' in data_test:
        avoid_char = data_test['badchars']
    chain_builder.solve_chain(avoid_char=avoid_char)
    build_chain = chain_builder.build_chain()
    build_chain.dump()
