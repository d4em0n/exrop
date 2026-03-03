import os
import sys
import pytest
from keystone import Ks, KS_ARCH_X86, KS_MODE_64

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ChainBuilder import ChainBuilder
from ThunkRewriter import ThunkConfig, rewrite_gadgets

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

    # Apply thunk rewriting if test specifies thunk_config
    thunk_data = data_test.get('thunk_config')
    if thunk_data:
        tc = ThunkConfig(
            return_thunks=thunk_data.get('return_thunks'),
            indirect_thunks=thunk_data.get('indirect_thunks'),
        )
        gadgets = rewrite_gadgets(gadgets, tc)

    chain_builder = ChainBuilder()
    chain_builder.load_list_gadget_string(gadgets)
    chain_builder.analyzeAll(num_process=1)

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
    elif test_type == 'pivot_reg':
        results = chain_builder.solve_pivot_reg(data_test['find'], avoid_char=avoid_char)
        return results  # returns list of PivotInfo, not a RopChain

    return chain_builder.build_chain()

# Tests prefixed with "invalid" are expected to fail (unsolvable constraints)
# Tests that are intentionally unsolvable (missing gadgets for required constraints)
EXPECTED_FAIL = {"invalid_no_return", "syscall"}

@pytest.mark.parametrize("test_name", discover_test_files())
@pytest.mark.timeout(30)
def test_gadget_chain(test_name):
    result = load_and_run(test_name)

    # Load test data to check type and expectations
    path = os.path.join(TESTS_DIR, test_name)
    with open(path, "rb") as fp:
        data_test = eval(fp.read())
    test_type = data_test.get('type', 'reg')

    if test_type == 'pivot_reg':
        assert isinstance(result, list), f"Expected list of PivotInfo for {test_name}"
        assert len(result) > 0, f"No pivot found for {test_name}"
        expect = data_test.get('expect')
        if expect:
            pivot = result[0]
            assert pivot.pivot_type == expect['pivot_type'], f"Expected type {expect['pivot_type']}, got {pivot.pivot_type}"
            assert pivot.src_reg == expect['src_reg'], f"Expected src_reg {expect['src_reg']}, got {pivot.src_reg}"
            if 'offset' in expect:
                assert pivot.offset == expect['offset'], f"Expected offset {expect['offset']}, got {pivot.offset}"
            if expect.get('pivot_type') in ('jop', 'jop_indirect'):
                assert pivot.jop_gadget is not None, f"Expected jop_gadget for {test_name}"
                assert pivot.pivot_gadget is not None, f"Expected pivot_gadget for {test_name}"
                if 'dispatch_offset' in expect:
                    assert pivot.dispatch_offset == expect['dispatch_offset'], f"Expected dispatch_offset {expect['dispatch_offset']}, got {pivot.dispatch_offset}"
                if 'chain_offset' in expect:
                    assert pivot.chain_offset_computed == expect['chain_offset'], f"Expected chain_offset {expect['chain_offset']}, got {pivot.chain_offset_computed}"
            pivot.dump()
        if 'expect_count' in data_test:
            assert len(result) >= data_test['expect_count'], f"Expected {data_test['expect_count']} pivots, got {len(result)}"
            for p in result:
                p.dump()
    elif test_name in EXPECTED_FAIL:
        assert result is None or result == [], f"Expected no chain for {test_name}, but got one"
    else:
        assert result is not None, f"No chain found for {test_name}"
        assert len(result.get_chains()) > 0, f"Empty chain for {test_name}"
        result.dump()

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
