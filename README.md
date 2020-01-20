# exrop
Automatic ROP Chain Generation

requirements : triton, ROPGagdget
``` python
Python 3.6.9 (default, Nov  7 2019, 10:44:02)
[GCC 8.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from Exrop import Exrop
>>> rop = Exrop("/bin/ls")
>>> rop.find_gadgets()
>>> chain = rop.set_regs({'rdi':0x41414141, 'rsi': 0x42424242, 'rdx':0x43434343, 'rax':0x44444444})
>>> chain
<RopChain.RopChain object at 0x7fed103997b8>
>>> chain.dump()
$RSP+0x0000 : 0x0000000000003a62 # {14946: 'pop rdx', 14947: 'ret'}
$RSP+0x0000 : 0x0000000044444444
$RSP+0x0010 : 0x000000000000cd94 # {52628: 'add esp, 8', 52631: 'mov rax, rdx', 52634: 'pop rbx', 52635: 'pop rbp', 52636: 'ret'}
$RSP+0x0010 : 0x0000000000000000
$RSP+0x0018 : 0x0000000000000000
$RSP+0x0020 : 0x0000000000000000
$RSP+0x0030 : 0x0000000000009cc6 # {40134: 'pop rdi', 40135: 'pop rbp', 40136: 'ret'}
$RSP+0x0030 : 0x0000000041414141
$RSP+0x0038 : 0x0000000000000000
$RSP+0x0048 : 0x0000000000009cc4 # {40132: 'pop rsi', 40133: 'pop r15', 40135: 'pop rbp', 40136: 'ret'}
$RSP+0x0048 : 0x0000000042424242
$RSP+0x0050 : 0x0000000000000000
$RSP+0x0058 : 0x0000000000000000
$RSP+0x0068 : 0x0000000000003a62 # {14946: 'pop rdx', 14947: 'ret'}
$RSP+0x0068 : 0x0000000043434343
```
