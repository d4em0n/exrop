#!/usr/bin/env python3
"""
Example: kernel-style stack pivot gadget search.

Simulates a UAF exploit scenario where:
- rdi points to a controlled object (Linux kernel convention)
- A hijacked function pointer calls into our pivot gadget
- The pivot redirects rsp to the controlled object
- The ROP chain embedded in the object executes

Usage:
    PYTHONPATH=. python3 examples/kernel_pivot.py
"""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from Exrop import Exrop

LIBC = "/lib/x86_64-linux-gnu/libc.so.6"

def main():
    print("=" * 70)
    print("  Kernel-style stack pivot search on libc")
    print("=" * 70)

    e = Exrop(LIBC)
    e.find_gadgets(cache=True)

    # Search for pivot gadgets that read from rdi
    for reg in ['rdi', 'rsi', 'rdx']:
        pivots = e.stack_pivot_reg(reg)
        print("\nPivot gadgets for {}:  {} found".format(reg, len(pivots)))
        for p in pivots[:5]:
            print("  [{}] 0x{:016x} # {} (offset=0x{:x})".format(
                p.pivot_type, p.gadget_addr, p.gadget, p.offset))
        if len(pivots) > 5:
            print("  ... and {} more".format(len(pivots) - 5))

    # Demonstrate build_payload with the first rdi pivot
    pivots = e.stack_pivot_reg('rdi')
    if pivots:
        pivot = pivots[0]
        print("\n" + "=" * 70)
        print("  Using best pivot for exploit layout")
        print("=" * 70)
        pivot.dump()

        # Build a post-pivot ROP chain (e.g., set registers for a syscall)
        print("\nBuilding post-pivot ROP chain (set rdi=0x41414141, rsi=0):")
        chain = e.set_regs({'rdi': 0x41414141, 'rsi': 0})
        chain.dump()

        # Generate the exploit object layout
        layout = pivot.build_payload(chain, obj_size=0x200)
        print("Exploit layout:")
        print("  Function pointer: 0x{:016x}".format(layout['func_ptr']))
        print("  {}".format(layout['description']))
        print("  Chain offset in object: 0x{:x}".format(layout['chain_offset']))
        print("  Object size: {} bytes".format(len(layout['obj_layout'])))

if __name__ == "__main__":
    main()
