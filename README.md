# exrop
Automatic ROP Chain Generation

``` python
Python 3.6.9 (default, Nov  7 2019, 10:44:02)
[GCC 8.3.0] on linux
Type "help", "copyright", "credits" or "license" for more information.
>>> from Exrop import Exrop
>>> rop = Exrop("/bin/ls")
>>> rop.find_gadgets()
>>> chain = rop.set_regs({'rdi': 0x41414141, 'rsi': 0x42424242, 'r15': 0x43434343})
>>> chain.dump()
$RSP+0x0000 : 0x0000000000009cc4 # {40132: 'pop rsi', 40133: 'pop r15', 40135: 'pop rbp', 40136: 'ret'}
$RSP+0x0000 : 0x0000000042424242
$RSP+0x0008 : 0x0000000043434343
$RSP+0x0010 : 0x0000000000000000
$RSP+0x0020 : 0x0000000000009cc6 # {40134: 'pop rdi', 40135: 'pop rbp', 40136: 'ret'}
$RSP+0x0020 : 0x0000000041414141
$RSP+0x0028 : 0x0000000000000000

>>> chain.payload_str()
b'\xc4\x9c\x00\x00\x00\x00\x00\x00BBBB\x00\x00\x00\x00CCCC\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xc6\x9c\x00\x00\x00\x00\x00\x00AAAA\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
```
