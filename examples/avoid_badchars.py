"""Example: Avoiding bad bytes in ROP chains via arithmetic gadgets.

When target values contain forbidden bytes, the solver uses add/sub/xchg
gadgets to compute them from badchar-free stack values.

Usage:
    PYTHONPATH=. python3 examples/avoid_badchars.py
"""

from Exrop import Exrop

rop = Exrop("/lib/x86_64-linux-gnu/libc.so.6")
rop.find_gadgets(cache=True)

# Values containing the avoided bytes — solver must compute them
# from badchar-free stack values using arithmetic gadgets.
print("=== set_regs: values contain 0x0a/0x0d ===")
chain = rop.set_regs({'rsi': 0x330a330d, 'rdx': 0x33330a3333, 'rax': 0x0d33440a}, avoid_char=b'\x0a\x0d')
chain.dump()

print("\n=== set_regs: rdi=0x0a0a0a0a, avoid 0x0a ===")
chain = rop.set_regs({'rdi': 0x0a0a0a0a}, avoid_char=b'\x0a')
chain.dump()

print("\n=== set_regs: multiple regs with badchar values ===")
chain = rop.set_regs({'rdi': 0x4141410a, 'rsi': 0x0a424242}, avoid_char=b'\x0a')
chain.dump()

print("\n=== write: [0x41414141]=0x0a0a0a0a, avoid 0x0a ===")
chain = rop.set_writes({0x41414141: 0x0a0a0a0a}, avoid_char=b'\x0a')
chain.dump()

# Output:
# === set_regs: values contain 0x0a/0x0d ===
# $RSP+0x0000 : 0x00000000000586e4 # pop rbx ; ret
# $RSP+0x0008 : 0x000000003080310b
# $RSP+0x0010 : 0x00000000000b0154 # mov edx, ebx ; pop rbx ; pop r12 ; pop rbp ; ret
# $RSP+0x0018 : 0x0000000000000000
# $RSP+0x0020 : 0x0000000000000000
# $RSP+0x0028 : 0x0000000000000000
# $RSP+0x0030 : 0x0000000000028a91 # pop rbp ; ret
# $RSP+0x0038 : 0x00000000028a0202
# $RSP+0x0040 : 0x0000000000098bbb # add ebp, edx ; xor eax, eax ; ret
# $RSP+0x0048 : 0x000000000002d1bd # xchg ebp, eax ; ret
# $RSP+0x0050 : 0x00000000000e0f53 # xchg esi, eax ; ret
# $RSP+0x0058 : 0x0000000000110981 # pop r12 ; ret
# $RSP+0x0060 : 0x00000031197ff931
# $RSP+0x0068 : 0x00000000000584d9 # pop r13 ; ret
# $RSP+0x0070 : 0x0000000000120409
# $RSP+0x0078 : 0x0000000000151227 # mov r8, r12 ; mov rdi, r14 ; call r13: next -> (0x00120409) # mov edx, 1 ; mov eax, edx ; pop rbp ; ret
# $RSP+0x0080 : 0x00000000000b505c # pop rdx ; xor eax, eax ; pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret
# $RSP+0x0088 : 0x00000002198a3a02
# $RSP+0x0090 : 0x0000000000000000
# $RSP+0x0098 : 0x0000000000000000
# $RSP+0x00a0 : 0x0000000000000000
# $RSP+0x00a8 : 0x0000000000000000
# $RSP+0x00b0 : 0x0000000000059cc1 # add rdx, r8 ; mov rax, rdx ; pop rbx ; ret
# $RSP+0x00b8 : 0x0000000000000000
# $RSP+0x00c0 : 0x00000000000586e4 # pop rbx ; ret
# $RSP+0x00c8 : 0x000000000415c149
# $RSP+0x00d0 : 0x00000000000ff5f5 # xchg ebx, eax ; pop rbx ; pop r12 ; pop rbp ; ret
# $RSP+0x00d8 : 0x0000000000000000
# $RSP+0x00e0 : 0x0000000000000000
# $RSP+0x00e8 : 0x0000000000000000
# $RSP+0x00f0 : 0x00000000000586e4 # pop rbx ; ret
# $RSP+0x00f8 : 0x00000000091d82c1
# $RSP+0x0100 : 0x0000000000129a5c # add ebx, eax ; xor ebp, ebp ; pop rax ; pop rdi ; call rax: next -> (0x00028a91) # pop rbp ; ret
# $RSP+0x0108 : 0x0000000000028a91
# $RSP+0x0110 : 0x0000000000000000
# $RSP+0x0118 : 0x000000000013c0b9 # mov ebp, ebx ; ret
# $RSP+0x0120 : 0x000000000003c0c9 # mov eax, ebp ; pop r12 ; pop r13 ; pop rbp ; ret
# $RSP+0x0128 : 0x0000000000000000
# $RSP+0x0130 : 0x0000000000000000
# $RSP+0x0138 : 0x0000000000000000
#
#
# === set_regs: rdi=0x0a0a0a0a, avoid 0x0a ===
# $RSP+0x0000 : 0x000000000004443f # pop rcx ; add eax, 0x1919a3 ; ret
# $RSP+0x0008 : 0x00000000a8213d08
# $RSP+0x0010 : 0x00000000000dd237 # pop rax ; ret
# $RSP+0x0018 : 0xffffffff800001db
# $RSP+0x0020 : 0x000000000010f78b # pop rdi ; ret
# $RSP+0x0028 : 0x00000000322b4537
# $RSP+0x0030 : 0x000000000019ba54 # sub edi, ecx ; add rax, rdi ; ret
# $RSP+0x0038 : 0x000000000011b045 # xchg edi, eax ; ret
#
#
# === set_regs: multiple regs with badchar values ===
# $RSP+0x0000 : 0x00000000000dd237 # pop rax ; ret
# $RSP+0x0008 : 0x00000000414141fb
# $RSP+0x0010 : 0x0000000000138fd1 # add al, 0xf ; xchg esi, eax ; ret
# $RSP+0x0018 : 0x00000000000e0f53 # xchg esi, eax ; ret
# $RSP+0x0020 : 0x000000000011b045 # xchg edi, eax ; ret
# $RSP+0x0028 : 0x000000000002b46b # pop rsi ; pop rbp ; ret
# $RSP+0x0030 : 0x0000000005212121
# $RSP+0x0038 : 0x0000000000000000
# $RSP+0x0040 : 0x00000000000fcf5c # add esi, esi ; ret
#
#
# === write: [0x41414141]=0x0a0a0a0a, avoid 0x0a ===
# $RSP+0x0000 : 0x0000000000110981 # pop r12 ; ret
# $RSP+0x0008 : 0x0000000041414141
# $RSP+0x0010 : 0x00000000000584d9 # pop r13 ; ret
# $RSP+0x0018 : 0x0000000000138f5a
# $RSP+0x0020 : 0x0000000000151227 # mov r8, r12 ; mov rdi, r14 ; call r13: next -> (0x00138f5a) # pop rdi ; add ebx, ebp ; xchg esi, eax ; xor eax, eax ; ret
# $RSP+0x0028 : 0x000000000004443f # pop rcx ; add eax, 0x1919a3 ; ret
# $RSP+0x0030 : 0x00000000e4015352
# $RSP+0x0038 : 0x00000000000dd237 # pop rax ; ret
# $RSP+0x0040 : 0x000000002608b6b8
# $RSP+0x0048 : 0x00000000000b49dc # add eax, ecx ; pop rbp ; ret
# $RSP+0x0050 : 0x0000000000000000
# $RSP+0x0058 : 0x00000000000e0f53 # xchg esi, eax ; ret
# $RSP+0x0060 : 0x00000000000b00a7 # mov qword ptr [r8], rsi ; ret
