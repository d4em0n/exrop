# exrop
Automatic ROP Chain Generation

requirements : [Triton](https://github.com/JonathanSalwan/Triton), [ROPGagdget](https://github.com/JonathanSalwan/ROPgadget)

``` python
from Exrop import Exrop

rop = Exrop("/bin/ls")
rop.find_gadgets(cache=True)
print("write-regs gadget: rdi=0x41414141, rsi:0x42424242, rdx: 0x43434343, rax:0x44444444")
chain = rop.set_regs({'rdi':0x41414141, 'rsi': 0x42424242, 'rdx':0x43434343, 'rax':0x44444444})
chain.dump()
print("write-what-where gadgets: [0x41414141]=0xdeadbeefff, [0x43434343]=0x110011")
chain = rop.set_writes({0x41414141: 0xdeadbeefff, 0x43434343: 0x00110011})
chain.dump()
```
Output:
```
write-regs gadget: rdi=0x41414141, rsi:0x42424242, rdx: 0x43434343, rax:0x44444444
$RSP+0x0000 : 0x0000000000004ce5 # pop rdi; ret
$RSP+0x0008 : 0x0000000041414141
$RSP+0x0010 : 0x0000000000004ce3 # pop rsi; pop r15; ret
$RSP+0x0018 : 0x0000000042424242
$RSP+0x0020 : 0x0000000000000000
$RSP+0x0028 : 0x0000000000003a62 # pop rdx; ret
$RSP+0x0030 : 0x0000000043434343
$RSP+0x0038 : 0x0000000000014852 # mov rax, rbx; pop rbx; ret
$RSP+0x0040 : 0x0000000044444444
$RSP+0x0048 : 0x0000000000014852 # mov rax, rbx; pop rbx; ret
$RSP+0x0050 : 0x0000000000000000

write-what-where gadgets: [0x41414141]=0xdeadbeefff, [0x43434343]=0x110011
$RSP+0x0000 : 0x000000000000e941 # add esp, 0x10; pop rbx; ret
$RSP+0x0008 : 0x0000000000000000
$RSP+0x0010 : 0x0000000000000000
$RSP+0x0018 : 0x0000000041414139
$RSP+0x0020 : 0x0000000000004ce3 # pop rsi; pop r15; ret
$RSP+0x0028 : 0x000000deadbeefff
$RSP+0x0030 : 0x0000000000000000
$RSP+0x0038 : 0x000000000001567c # mov qword ptr [rbx + 8], rsi; pop rbx; pop rbp; pop r12; ret
$RSP+0x0040 : 0x0000000000000000
$RSP+0x0048 : 0x0000000000000000
$RSP+0x0050 : 0x0000000000000000
$RSP+0x0058 : 0x000000000000e941 # add esp, 0x10; pop rbx; ret
$RSP+0x0060 : 0x0000000000000000
$RSP+0x0068 : 0x0000000000000000
$RSP+0x0070 : 0x000000004343433b
$RSP+0x0078 : 0x0000000000004ce3 # pop rsi; pop r15; ret
$RSP+0x0080 : 0x0000000000110011
$RSP+0x0088 : 0x0000000000000000
$RSP+0x0090 : 0x000000000001567c # mov qword ptr [rbx + 8], rsi; pop rbx; pop rbp; pop r12; ret
$RSP+0x0098 : 0x0000000000000000
$RSP+0x00a0 : 0x0000000000000000
$RSP+0x00a8 : 0x0000000000000000
```
