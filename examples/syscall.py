"""Example: syscall(1, (1, 2, 3)) — write(1, 2, 3).

Usage:
    PYTHONPATH=. python3 examples/syscall.py
"""

from Exrop import Exrop

rop = Exrop("/lib/x86_64-linux-gnu/libc.so.6")
rop.find_gadgets(cache=True)
print("syscall(1, (1, 2, 3))")
chain = rop.syscall(1, (1,2,3))
chain.dump()

# Output:
# syscall(1, (1, 2, 3))
# $RSP+0x0000 : 0x00000000000a877e # pop rcx ; ret
# $RSP+0x0008 : 0x00000000fffffffd
# $RSP+0x0010 : 0x00000000000b505c # pop rdx ; xor eax, eax ; pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret
# $RSP+0x0018 : 0x0000000000000000
# $RSP+0x0020 : 0x0000000000000000
# $RSP+0x0028 : 0x0000000000000000
# $RSP+0x0030 : 0x0000000000000000
# $RSP+0x0038 : 0x0000000000000000
# $RSP+0x0040 : 0x000000000016ea83 # pop rax ; sub edx, ecx ; pop rbx ; mov eax, edx ; pop r12 ; pop rbp ; ret
# $RSP+0x0048 : 0x0000000000000000
# $RSP+0x0050 : 0x0000000000000000
# $RSP+0x0058 : 0x0000000000000000
# $RSP+0x0060 : 0x0000000000000000
# $RSP+0x0068 : 0x0000000000059226 # mov eax, 1 ; ret
# $RSP+0x0070 : 0x000000000010f78b # pop rdi ; ret
# $RSP+0x0078 : 0x0000000000000001
# $RSP+0x0080 : 0x0000000000110a7d # pop rsi ; ret
# $RSP+0x0088 : 0x0000000000000002
# $RSP+0x0090 : 0x0000000000098fb6 # syscall ; ret
