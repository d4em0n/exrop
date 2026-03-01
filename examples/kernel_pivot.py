#!/usr/bin/env python3
"""
Example: kernel-style stack pivot gadget search.

Simulates a UAF exploit scenario where:
- rdi points to a controlled object (Linux kernel convention)
- A hijacked function pointer calls into our pivot gadget
- The pivot redirects rsp to the controlled object
- The ROP chain embedded in the object executes

Supports three search modes:
- Default depth: fast scan with ROPgadget's default instruction depth
- Deep scan (--depth N): finds longer gadgets like vtable dispatchers

Usage:
    PYTHONPATH=. python3 examples/kernel_pivot.py
    PYTHONPATH=. python3 examples/kernel_pivot.py --depth 15
"""

import sys
import os
import argparse

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from Exrop import Exrop

LIBC = "/lib/x86_64-linux-gnu/libc.so.6"

def print_pivot(p):
    if p.pivot_type in ('jop', 'jop_indirect'):
        n = len(p.jop_chain)
        label = "{} ({}-step)".format(p.pivot_type, n) if n > 1 else p.pivot_type
        for i, (g, off) in enumerate(p.jop_chain):
            prefix = "  [{}]".format(label) if i == 0 else "      "
            print("{} 0x{:016x} # {}".format(prefix, g.addr, g))
        print("        -> 0x{:016x} # {}".format(p.pivot_gadget.addr, p.pivot_gadget))
        print("        chain=[{}+0x{:x}]".format(p.src_reg, p.chain_offset_computed))
    else:
        print("  [{}] 0x{:016x} # {} (offset=0x{:x})".format(
            p.pivot_type, p.gadget_addr, p.gadget, p.offset))

def main():
    parser = argparse.ArgumentParser(description="Kernel-style stack pivot search")
    parser.add_argument('--depth', type=int, default=15,
                        help='ROPgadget instruction depth (default: 15)')
    parser.add_argument('--binary', default=LIBC, help='Binary to scan')
    args = parser.parse_args()

    depth_str = " (depth={})".format(args.depth) if args.depth else ""
    print("=" * 70)
    print("  Kernel-style stack pivot search on {}{}".format(
        os.path.basename(args.binary), depth_str))
    print("=" * 70)

    e = Exrop(args.binary)
    e.find_gadgets(cache=True, depth=args.depth)

    # Search for pivot gadgets for common kernel registers
    for reg in ['rdi', 'rsi', 'rdx']:
        pivots = e.stack_pivot_reg(reg)
        print("\nPivot gadgets for {}:  {} found".format(reg, len(pivots)))
        for p in pivots[:5]:
            print_pivot(p)
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
        if 'ptr_offset' in layout:
            print("  Pointer offset in object: 0x{:x}".format(layout['ptr_offset']))
        print("  Object size: {} bytes".format(len(layout['obj_layout'])))
    else:
        print("\nNo pivot found for rdi.")

if __name__ == "__main__":
    main()
