"""Example: Register-to-register moves using libc gadgets.

Demonstrates set_regs with register name values, e.g. {'rdi': 'rax'}
which finds gadgets like `mov rdi, rax ; ret`.

Usage:
    PYTHONPATH=. python3 examples/move_regs.py
"""

from Exrop import Exrop

LIBC = "/lib/x86_64-linux-gnu/libc.so.6"

e = Exrop(LIBC)
e.find_gadgets(cache=True)

# Move rax into both rdi and rsi
print("=== set rdi=rax, rsi=rax ===")
try:
    chain = e.set_regs({'rdi': 'rax', 'rsi': 'rax'})
    chain.dump()
except Exception as ex:
    print("Failed: {}".format(ex))

# Move rax into rdi, rdx into rsi
print("\n=== set rdi=rax, rsi=rdx ===")
try:
    chain = e.set_regs({'rdi': 'rax', 'rsi': 'rdx'})
    chain.dump()
except Exception as ex:
    print("Failed: {}".format(ex))

# Move rdi into rsi (swap-like)
print("\n=== set rsi=rdi ===")
try:
    chain = e.set_regs({'rsi': 'rdi'})
    chain.dump()
except Exception as ex:
    print("Failed: {}".format(ex))

# Mix: move rax into rdi, set rsi to a constant
print("\n=== set rdi=rax, rsi=0x42424242 ===")
try:
    chain = e.set_regs({'rdi': 'rax', 'rsi': 0x42424242})
    chain.dump()
except Exception as ex:
    print("Failed: {}".format(ex))
