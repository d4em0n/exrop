from pwn import *
import time
from Exrop import Exrop

binname = "libc.so.6"
libc = ELF(binname, checksec=False)
open = libc.symbols['open']
read = libc.symbols['read']
write = libc.symbols['write']
bss = libc.bss()

t = time.mktime(time.gmtime())
rop = Exrop(binname)
rop.find_gadgets(cache=True) # it's slow for first analyze keep waiting
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
#print(chain.payload_str())
