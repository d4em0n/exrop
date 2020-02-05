from Exrop import Exrop
import time

rop = Exrop("libc.so.6")
t = time.mktime(time.gmtime())
rop.find_gadgets(cache=True) # it's slow for first analyze keep waiting
print("Analyzing done in {}s".format(time.mktime(time.gmtime()) - t))
print("write-regs gadgets: rdi=0x41414141, rsi=0x42424242, rdx=0x43434343, rax:0x44444444, rbx=0x45454545, rcx=0x4b4b4b4b, r8=0x47474747, r9=0x48484848, r10=0x49494949, r11=0x4a4a4a4a, r12=0x50505050, r13=0x51515151, r14=0x52525252, r15=0x53535353")
chain = rop.set_regs({'rdi':0x41414141, 'rsi': 0x42424242, 'rdx':0x43434343, 'rax':0x44444444, 'rbx': 0x45454545, 'rcx':0x4b4b4b4b, 'r8': 0x47474747, 'r9': 0x48484848, 'r10':0x49494949, 'r11': 0x4a4a4a4a, 'r12': 0x50505050, 'r13': 0x51515151, 'r14':0x52525252, 'r15': 0x53535353})
chain.dump()
#print(chain.payload_str())
