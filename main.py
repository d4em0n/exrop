#!/usr/bin/env python3
from Gadget import *
from Solver import ChainBuilder
import code
from Exrop import Exrop

sample_gadgets2 = {
    0x1000: 'pop rsi; ret',
    0x2000: 'mov rbx, rsi; ret',
    0x3000: 'mov rax, rcx; ret',
    0x4000: 'mov rcx, rbx; add rcx, 100; ret',
    0x5000: 'mov rdx, rsi; ret',
    0x6000: 'mov rdi, rax; ret',
}

sample_gadgets2_find = {
    'rax': 0x12345678,
    'rbx': 0x87654321,
    'rcx': 0x22222222,
    'rdx': 0x7fffffff,
    'rsi': 0x41414141,
    'rdi': 0x42424242
}

sample_gadgets1_find = {'rdi': 0x41414242, 'rsi': 0xffffffff, 'rdx': 0xccbbddee, 'r12': 0xdeadbeef, 'rbx': 0x43434343}

sample_gadgets7 = {
    0x1000: 'pop rdx; mov eax, ebp; pop rbx; pop rbp; pop r12; pop r13; ret',
    0x2000: 'pop rsi; add rsp, 0x18; pop rbx; pop rbp; ret',
    0x3000: 'pop rdi; ret',
}
"""

chain_builder = ChainBuilder()
chain_builder.load_list_gadget_string(sample_gadgets7)
chain_builder.set_regs(sample_gadgets1_find)
chain_builder.analyzeAll()
chain_builder.solve_chain()
raw_chain = chain_builder.raw_chain
build_chain = chain_builder.build_chain()
build_chain.set_base_addr(0x400000)
build_chain.dump()
"""

rop = Exrop("/bin/bash")
rop.find_gadgets(cache=True)
chain = rop.set_regs({'rdi':0x41414141, 'rsi': 0x42424242, 'rdx':0x43434343, 'rax':0x44444444})
chain.dump()
