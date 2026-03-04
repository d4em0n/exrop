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

# Move rdi into rsi
print("=== set rsi=rdi ===")
chain = e.set_regs({'rsi': 'rdi'})
chain.dump()

# Mix: move rax into rdi, set rsi to a constant
print("\n=== set rdi=rax, rsi=0x42424242 ===")
chain = e.set_regs({'rdi': 'rax', 'rsi': 0x42424242})
chain.dump()

# Output:
# === set rsi=rdi ===
# $RSP+0x0000 : 0x00000000000dd237 # pop rax ; ret
# $RSP+0x0008 : 0x0000000000054472
# $RSP+0x0010 : 0x00000000000b22ce # xchg edx, eax ; mov eax, 0xf7000000 ; ret 0
# $RSP+0x0018 : 0x0000000000078740 # mov r12, rdi ; jmp rdx: next -> (0x00054472) # mov esi, 0x83480143 ; ret
# $RSP+0x0020 : 0x00000000000dd237 # pop rax ; ret
# $RSP+0x0028 : 0x00000000000dd237
# $RSP+0x0030 : 0x00000000000af7d9 # mov rsi, r12 ; call rax: next -> (0x000dd237) # pop rax ; ret
#
# === set rdi=rax, rsi=0x42424242 ===
# $RSP+0x0000 : 0x00000000000586e4 # pop rbx ; ret
# $RSP+0x0008 : 0x0000000000110a7d
# $RSP+0x0010 : 0x00000000000de942 # mov rdi, rax ; call rbx: next -> (0x00110a7d) # pop rsi ; ret
# $RSP+0x0018 : 0x0000000000110a7d # pop rsi ; ret
# $RSP+0x0020 : 0x0000000042424242
