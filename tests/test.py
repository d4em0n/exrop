from Solver import ChainBuilder
from Exrop import Exrop
from Gadget import *
import sys

if len(sys.argv) == 1:
    print("use: {} test_file".format(sys.argv[0]))
    sys.exit(1)

with open(sys.argv[1], "rb") as fp:
    data_test = eval(fp.read())
    chain_builder = ChainBuilder()
    chain_builder.load_list_gadget_string(data_test['gadgets'])
    chain_builder.analyzeAll()
    chain_builder.set_regs(data_test['find'])
    avoid_char = None
    if 'badchars' in data_test:
        avoid_char = data_test['badchars']
    chain_builder.solve_chain(avoid_char=avoid_char)
    build_chain = chain_builder.build_chain()
    build_chain.dump()
