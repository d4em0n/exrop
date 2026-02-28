import os
import sys
import pytest
from keystone import Ks, KS_ARCH_X86, KS_MODE_64

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ChainBuilder import ChainBuilder

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))

def asm_ins(code):
    ks = Ks(KS_ARCH_X86, KS_MODE_64)
    return bytes(ks.asm(code)[0])

def discover_test_files():
    skip = {'test.py', '__pycache__'}
    tests = []
    for name in sorted(os.listdir(TESTS_DIR)):
        if name.startswith('.') or name in skip:
            continue
        path = os.path.join(TESTS_DIR, name)
        if os.path.isfile(path) and not name.endswith('.py') and not name.endswith('.swp'):
            tests.append(name)
    return tests

def load_and_run(test_name):
    path = os.path.join(TESTS_DIR, test_name)
    with open(path, "rb") as fp:
        data_test = eval(fp.read())

    gadgets = data_test['gadgets']
    for addr in gadgets:
        gadgets[addr] = (gadgets[addr], asm_ins(gadgets[addr]))

    chain_builder = ChainBuilder()
    chain_builder.load_list_gadget_string(gadgets)
    chain_builder.analyzeAll()

    test_type = data_test.get('type', 'reg')
    avoid_char = data_test.get('badchars', None)

    if test_type == 'reg':
        chain_builder.set_regs(data_test['find'])
        chain_builder.solve_chain(avoid_char=avoid_char)
    elif test_type == 'write_mem':
        chain_builder.set_writes(data_test['find'])
        chain_builder.solve_chain_write(avoid_char=avoid_char)
    elif test_type == 'pivot':
        chain_builder.solve_pivot(data_test['find'], avoid_char=avoid_char)

    return chain_builder.build_chain()

# Tests prefixed with "invalid" are expected to fail (unsolvable constraints)
# Tests that are intentionally unsolvable (missing gadgets for required constraints)
EXPECTED_FAIL = {"invalid_no_return", "syscall"}

@pytest.mark.parametrize("test_name", discover_test_files())
@pytest.mark.timeout(30)
def test_gadget_chain(test_name):
    chain = load_and_run(test_name)
    if test_name in EXPECTED_FAIL:
        assert chain is None or chain == [], f"Expected no chain for {test_name}, but got one"
    else:
        assert chain is not None, f"No chain found for {test_name}"
        assert len(chain.get_chains()) > 0, f"Empty chain for {test_name}"
        chain.dump()

if __name__ == "__main__":
    if len(sys.argv) > 1 and not sys.argv[1].startswith('-'):
        chain = load_and_run(sys.argv[1])
        if chain:
            chain.dump()
        else:
            print("No chain found")
            sys.exit(1)
    else:
        pytest.main([__file__, "-v"] + sys.argv[1:])
