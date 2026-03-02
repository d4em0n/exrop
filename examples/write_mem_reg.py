#!/usr/bin/env python3
"""
Test register-based memory write support on libc.

Exercises all combinations:
  - *(reg) = const     register address, constant value
  - *(const) = reg     constant address, register value
  - *(reg) = reg       register address, register value
  - indirect forwarding (e.g. *(rcx) when only mov [rdx],... exists)
  - multi-write in a single solve
"""

import sys, os, time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from Exrop import Exrop

LIBC = "/lib/x86_64-linux-gnu/libc.so.6"

TIMEOUT = 100

tests = [
    # --- reg addr, const val ---
    ("*(rdi) = 0x41414141",          {"rdi": 0x41414141}),
    ("*(rax) = 0x41414141",          {"rax": 0x41414141}),
    ("*(rsi) = 0xdeadbeef",          {"rsi": 0xdeadbeef}),
    ("*(rdx) = 0x41414141",          {"rdx": 0x41414141}),

    # --- indirect addr forwarding ---
    ("*(rcx) = 0x41414141",          {"rcx": 0x41414141}),
    ("*(rbx) = 0xdeadbeef",          {"rbx": 0xdeadbeef}),
    ("*(r12) = 0xcafecafe",          {"r12": 0xcafecafe}),

    # --- const addr, reg val ---
    ("*(0x414141) = rax",            {0x414141: "rax"}),
    ("*(0x414141) = rdi",            {0x414141: "rdi"}),
    ("*(0x414141) = rsi",            {0x414141: "rsi"}),
    ("*(0x414141) = rbx",            {0x414141: "rbx"}),

    # --- reg addr, reg val ---
    ("*(rdi) = rax",                 {"rdi": "rax"}),
    ("*(rdi) = rcx",                 {"rdi": "rcx"}),
    ("*(rdi) = rdx",                 {"rdi": "rdx"}),
    ("*(rsi) = rdi",                 {"rsi": "rdi"}),
    ("*(rdx) = rax",                 {"rdx": "rax"}),

    # --- both sides forwarded ---
    ("*(rcx) = rbx",                 {"rcx": "rbx"}),
    ("*(rbx) = rcx",                 {"rbx": "rcx"}),
    ("*(r15) = rcx",                 {"r15": "rcx"}),

    # --- multi-write ---
    ("*(0x414141)=rax + *(rdi)=0xBB", {0x414141: "rax", "rdi": 0xbbbbbbbb}),
    ("*(rdi)=rax + *(rsi)=rbx",      {"rdi": "rax", "rsi": "rbx"}),
    ("*(rdi)=0xAA + *(rsi)=0xBB",    {"rdi": 0xaaaaaaaa, "rsi": 0xbbbbbbbb}),
]

def main():
    e = Exrop(LIBC)
    print("Loading gadgets from {}...".format(LIBC), file=sys.stderr)
    e.find_gadgets(cache=True)
    print("Gadgets loaded.\n", file=sys.stderr)

    passed = 0
    failed = 0
    timeout_count = 0

    for i, (desc, writes) in enumerate(tests, 1):
        sys.stdout.write("Test {:2d}: {:42s} ... ".format(i, desc))
        sys.stdout.flush()
        t0 = time.time()
        try:
            chain = e.set_writes(writes)
            elapsed = time.time() - t0
            if elapsed > TIMEOUT:
                print("TIMEOUT ({:.1f}s)".format(elapsed))
                timeout_count += 1
            elif chain and len(chain.get_chains()) > 0:
                print("PASS ({:.3f}s, {} bytes)".format(elapsed, len(chain.payload_str())))
                chain.dump()
                passed += 1
            else:
                print("FAIL (no chain, {:.3f}s)".format(elapsed))
                failed += 1
        except Exception as ex:
            elapsed = time.time() - t0
            print("ERROR ({:.3f}s): {}".format(elapsed, ex))
            failed += 1
        print()

    print("=" * 60)
    print("Results: {} passed, {} failed, {} timeout out of {}".format(
        passed, failed, timeout_count, len(tests)))
    return 1 if failed > 0 else 0

if __name__ == "__main__":
    sys.exit(main())
