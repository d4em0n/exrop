from Exrop import Exrop

rop = Exrop("/lib/x86_64-linux-gnu/libc.so.6")
rop.find_gadgets(cache=True)

# Values containing the avoided bytes — solver must compute them
# from badchar-free stack values using arithmetic gadgets.
print("=== set_regs: values contain 0x0a/0x0d ===")
chain = rop.set_regs({'rsi': 0x330a330d, 'rdx': 0x33330a3333, 'rax': 0x0d33440a}, avoid_char=b'\x0a\x0d')
chain.dump()

print("\n=== set_regs: rdi=0x0a0a0a0a, avoid 0x0a ===")
chain = rop.set_regs({'rdi': 0x0a0a0a0a}, avoid_char=b'\x0a')
chain.dump()

print("\n=== set_regs: multiple regs with badchar values ===")
chain = rop.set_regs({'rdi': 0x4141410a, 'rsi': 0x0a424242}, avoid_char=b'\x0a')
chain.dump()

print("\n=== write: [0x41414141]=0x0a0a0a0a, avoid 0x0a ===")
chain = rop.set_writes({0x41414141: 0x0a0a0a0a}, avoid_char=b'\x0a')
chain.dump()
