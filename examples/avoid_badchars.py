from Exrop import Exrop
import time

rop = Exrop("libc.so.6")
rop.find_gadgets(cache=True) # it's slow for first analyze keep waiting
chain = rop.set_regs({'rsi': 0x330a330d, 'rdx': 0x33330a3333, 'rax': 0x0d33440a}, avoid_char=b'\x0a\x0d')
chain.dump()
#print(chain.payload_str())
