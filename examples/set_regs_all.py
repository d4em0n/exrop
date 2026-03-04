"""Example: Setting many general-purpose registers at once.

Usage:
    PYTHONPATH=. python3 examples/set_regs_all.py
"""

from Exrop import Exrop

rop = Exrop("/lib/x86_64-linux-gnu/libc.so.6")
rop.find_gadgets(cache=True)
print("set_regs: 8 GP registers")
chain = rop.set_regs({
    'rdi': 0x41414141,
    'rsi': 0x42424242,
    'rdx': 0x43434343,
    'rax': 0x44444444,
    'rbx': 0x45454545,
    'rcx': 0x4b4b4b4b,
    'r12': 0x50505050,
    'r15': 0x53535353,
})
chain.dump()

# Output:
# set_regs: 8 GP registers
# $RSP+0x0000 : 0x00000000000586e4 # pop rbx ; ret
# $RSP+0x0008 : 0x0000000043434343
# $RSP+0x0010 : 0x00000000000b0154 # mov edx, ebx ; pop rbx ; pop r12 ; pop rbp ; ret
# $RSP+0x0018 : 0x0000000000000000
# $RSP+0x0020 : 0x0000000000000000
# $RSP+0x0028 : 0x0000000000000000
# $RSP+0x0030 : 0x00000000000dd237 # pop rax ; ret
# $RSP+0x0038 : 0x0000000044444444
# $RSP+0x0040 : 0x00000000000586e4 # pop rbx ; ret
# $RSP+0x0048 : 0x0000000045454545
# $RSP+0x0050 : 0x00000000000a877e # pop rcx ; ret
# $RSP+0x0058 : 0x000000004b4b4b4b
# $RSP+0x0060 : 0x000000000010f78b # pop rdi ; ret
# $RSP+0x0068 : 0x0000000041414141
# $RSP+0x0070 : 0x0000000000110a7d # pop rsi ; ret
# $RSP+0x0078 : 0x0000000042424242
# $RSP+0x0080 : 0x0000000000110981 # pop r12 ; ret
# $RSP+0x0088 : 0x0000000050505050
# $RSP+0x0090 : 0x000000000010f78a # pop r15 ; ret
# $RSP+0x0098 : 0x0000000053535353
