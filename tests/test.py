from ChainBuilder import ChainBuilder
from Exrop import Exrop
from Gadget import *
import sys
import code
from keystone import *

def asm_ins(code):
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    insns = bytes(ks.asm(code)[0])
    return insns

if len(sys.argv) == 1:
    print("use: {} test_file".format(sys.argv[0]))
    sys.exit(1)

def test_reg(data_test):
    chain_builder.set_regs(data_test['find'])
    avoid_char = None
    if 'badchars' in data_test:
        avoid_char = data_test['badchars']
    chain_builder.solve_chain(avoid_char=avoid_char)

def test_write(data_test):
    chain_builder.set_writes(data_test['find'])
    avoid_char = None
    if 'badchars' in data_test:
        avoid_char = data_test['badchars']
    chain_builder.solve_chain_write(avoid_char=avoid_char)

def test_pivot(data_test):
    avoid_char = None
    if 'badchars' in data_test:
        avoid_char = data_test['badchars']
    chain_builder.solve_pivot(data_test['find'], avoid_char=avoid_char)

with open(sys.argv[1], "rb") as fp:
    data_test = eval(fp.read())
    gadgets = data_test['gadgets']
    for addr in gadgets:
        gadgets[addr] = (gadgets[addr], asm_ins(gadgets[addr]))
    chain_builder = ChainBuilder()
    chain_builder.load_list_gadget_string(gadgets)
    chain_builder.analyzeAll()
    code.interact(local=locals())

    if "type" not in data_test or data_test['type'] == 'reg':
        test_reg(data_test)
    elif data_test['type'] == 'write_mem':
        test_write(data_test)
    elif data_test['type'] == 'pivot':
        test_pivot(data_test)

    build_chain = chain_builder.build_chain()
    build_chain.dump()
