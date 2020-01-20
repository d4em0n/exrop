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
sample_gadgets8 = {
    0x1000: "mov qword ptr [rdx+0x10], r10 ; mov eax, 1 ; ret",
    0x2000: "pop r10; pop rdx; ret"
}

sample_gadgets9 = {
    0x1000: "pop rdi; pop rbp; ret",
    0x2000: "mov ah, 0x3f; mov qword ptr [rdi + 8], rax; ret"
}

sample_gadgets10 = {
    0x1000: "mov dword ptr [rdi + 0x28], esi; mov qword ptr [rdi + 0x30], rdx; ret",
    0x2000: "pop rdx; ret",
    0x3000: "pop rsi; ret",
    0x4000: "pop rdi; ret"
}
find_write = {0x41414141:0x42424242, 0x43434343: 0x44444444}
find_write = {0x43434343: 0x44444444}

chain_builder = ChainBuilder()
chain_builder.load_list_gadget_string(sample_gadgets10)
chain_builder.set_writes(find_write)
chain_builder.analyzeAll()
chain_builder.solve_chain_write()
raw_chain = chain_builder.raw_chain
build_chain = chain_builder.build_chain()
build_chain.set_base_addr(0x400000)
build_chain.dump()
