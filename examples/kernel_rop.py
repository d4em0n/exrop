"""Example: Kernel ROP chain generation with automatic thunk rewriting.

Usage:
    PYTHONPATH=. python3 examples/kernel_rop.py /path/to/vmlinux

For retpoline-mitigated kernels, kernel_mode=True will:
  1. Auto-detect __x86_return_thunk and __x86_indirect_thunk_* symbols
  2. Auto-detect .text section range (passed as --range to ROPgadget)
  3. Rewrite thunk jumps to equivalent simple instructions
  4. Filter out non-thunk internal jumps (~1.26M -> ~130k gadgets)
"""

import sys
from Exrop import Exrop

if len(sys.argv) < 2:
    print("Usage: {} <vmlinux>".format(sys.argv[0]))
    sys.exit(1)

VMLINUX = sys.argv[1]

e = Exrop(VMLINUX)
e.find_gadgets(cache=True, kernel_mode=True)

# Example: set registers for a syscall
print("\n=== Setting registers ===")
try:
    chain = e.set_regs({'rdi': 0x41414141, 'rsi': 0})
    chain.dump()
except Exception as ex:
    print("set_regs failed: {}".format(ex))

# Example: find pivot gadgets
print("\n=== Stack pivot from rdi ===")
try:
    pivots = e.stack_pivot_reg('rdi')
    for p in pivots[:5]:
        p.dump()
except Exception as ex:
    print("stack_pivot_reg failed: {}".format(ex))
