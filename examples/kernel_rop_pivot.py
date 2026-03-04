"""Example: Kernel ROP chain generation with automatic thunk rewriting.

Usage:
    PYTHONPATH=. python3 examples/kernel_rop_pivot.py /path/to/vmlinux

For retpoline-mitigated kernels, kernel_mode=True will:
  1. Auto-detect __x86_return_thunk and __x86_indirect_thunk_* symbols
  2. Auto-detect .text section range (passed as --range to ROPgadget)
  3. Rewrite thunk jumps to equivalent simple instructions
  4. Filter out non-thunk internal jumps (~1.26M -> ~130k gadgets)
"""

import sys
from Exrop import Exrop

if len(sys.argv) < 2:
    print("Usage: {} <vmlinux>".format(sys.argv[0]))
    sys.exit(1)

VMLINUX = sys.argv[1]

e = Exrop(VMLINUX)
e.find_gadgets(cache=True, kernel_mode=True)
e.clean_only = True

# Example: set registers for a syscall
print("\n=== Setting registers ===")
try:
    chain = e.set_regs({'rdi': 0x41414141, 'rsi': 0})
    chain.dump()
except Exception as ex:
    print("set_regs failed: {}".format(ex))

# Example: find pivot gadgets
for reg in ['rdi', 'rsi', 'rdx']:
    print(f"\n=== Stack pivot from {reg} ===")
    try:
        pivots = e.stack_pivot_reg(reg)
        for p in pivots:
            p.dump()
    except Exception as ex:
        print("stack_pivot_reg failed: {}".format(ex))

# Output depends on vmlinux — sample:
"""
=== Setting registers ===
$RSP+0x0000 : 0xffffffff81177704 # pop rdi ; ret
$RSP+0x0008 : 0x0000000041414141
$RSP+0x0010 : 0xffffffff8115fbce # pop rsi ; ret
$RSP+0x0018 : 0x0000000000000000


=== Stack pivot from rdi ===
Pivot type: jop (chained)
  Step 1: 0xffffffff81e3f0d6 # mov rbx, rdi ; mov rax, qword ptr [rdi + 8] ; call rax
  Pivot:  0xffffffff81ccac6f # push rbx ; pop rsp ; add ecx, dword ptr [rax - 0x39] ; ret
  Dispatch: place 0xffffffff81ccac6f at [rdi+0x8]
  ROP chain starts at [rdi+0x0]
Pivot type: jop (chained)
  Step 1: 0xffffffff81e3f0d6 # mov rbx, rdi ; mov rax, qword ptr [rdi + 8] ; call rax
  Pivot:  0xffffffff81878d56 # push rbx ; lea eax, [rdi + 0x415d5b81] ; pop rsp ; pop r13 ; pop r14 ; ret
  Dispatch: place 0xffffffff81878d56 at [rdi+0x8]
  ROP chain starts at [rdi+0x10]
Pivot type: jop (chained)
  Step 1: 0xffffffff81e3f0d6 # mov rbx, rdi ; mov rax, qword ptr [rdi + 8] ; call rax
  Pivot:  0xffffffff821fdecd # push rbx ; pop rsp ; mov eax, dword ptr [rax + 0xd8] ; mov dword ptr [rbx + 0x60], eax ; pop rbx ; pop rbp ; ret
  Dispatch: place 0xffffffff821fdecd at [rdi+0x8]
  ROP chain starts at [rdi+0x10]
Pivot type: jop (chained)
  Step 1: 0xffffffff81e3f0d6 # mov rbx, rdi ; mov rax, qword ptr [rdi + 8] ; call rax
  Pivot:  0xffffffff81704143 # push rbx ; or byte ptr [rbx + 0x41], bl ; pop rsp ; pop r13 ; pop r14 ; pop rbp ; ret
  Dispatch: place 0xffffffff81704143 at [rdi+0x8]
  ROP chain starts at [rdi+0x18]
Pivot type: jop_indirect (chained, pointer)
  Step 1: 0xffffffff81e3f0d9 # mov rax, qword ptr [rdi + 8] ; call rax
  Pivot:  0xffffffff811b6e72 # push rax ; pop rsp ; add dword ptr [rax - 1], edi ; ret
  Dispatch: place 0xffffffff811b6e72 at [rdi+0x8]
  Place ROP chain address at [rdi+0x8]
Pivot type: jop_indirect (chained, pointer)
  Step 1: 0xffffffff81e3f0d9 # mov rax, qword ptr [rdi + 8] ; call rax
  Pivot:  0xffffffff811b6e68 # push rax ; pop rsp ; add dword ptr [rax - 0x16], edi ; ret
  Dispatch: place 0xffffffff811b6e68 at [rdi+0x8]
  Place ROP chain address at [rdi+0x8]
Pivot type: jop_indirect (chained, pointer)
  Step 1: 0xffffffff81e3f0d9 # mov rax, qword ptr [rdi + 8] ; call rax
  Pivot:  0xffffffff81728911 # push rax ; add byte ptr [rbx + 0x41], bl ; pop rsp ; pop rbp ; ret
  Dispatch: place 0xffffffff81728911 at [rdi+0x8]
  Place ROP chain address at [rdi+0x10]
Pivot type: jop_indirect (chained, pointer)
  Step 1: 0xffffffff81e3f0d9 # mov rax, qword ptr [rdi + 8] ; call rax
  Pivot:  0xffffffff8226ad44 # push rax ; add dword ptr [rax], eax ; add byte ptr [rbx + 0x41], bl ; pop rsp ; pop r13 ; pop r14 ; pop r15 ; pop rbp ; ret
  Dispatch: place 0xffffffff8226ad44 at [rdi+0x8]
  Place ROP chain address at [rdi+0x28]
Pivot type: jop (2-step chain)
  Step 1: 0xffffffff81e3f0d6 # mov rbx, rdi ; mov rax, qword ptr [rdi + 8] ; call rax
  Step 2: 0xffffffff81cfe2a2 # mov rsi, rbx ; mov edi, eax ; mov rax, qword ptr [rbx + 0x60] ; pop rbx ; jmp rax
  Pivot:  0xffffffff815665aa # push rsi ; or byte ptr [rbx + 0x41], bl ; pop rsp ; pop r13 ; pop r14 ; pop rbp ; ret
  Dispatch: place 0xffffffff81cfe2a2 at [rdi+0x8]
  Dispatch: place 0xffffffff815665aa at [rdi+0x60]
  ROP chain starts at [rdi+0x18]

=== Stack pivot from rsi ===
Pivot type: offset
  Gadget: 0xffffffff815665aa # push rsi ; or byte ptr [rbx + 0x41], bl ; pop rsp ; pop r13 ; pop r14 ; pop rbp ; ret
  Source register: rsi
  Offset: 0x18
  ROP chain starts at [rsi+0x18]
Pivot type: jop_indirect (chained, pointer)
  Step 1: 0xffffffff81e0892c # mov rax, qword ptr [rsi + 8] ; jmp rax
  Pivot:  0xffffffff811b6e72 # push rax ; pop rsp ; add dword ptr [rax - 1], edi ; ret
  Dispatch: place 0xffffffff811b6e72 at [rsi+0x8]
  Place ROP chain address at [rsi+0x8]
Pivot type: jop_indirect (chained, pointer)
  Step 1: 0xffffffff81e0892c # mov rax, qword ptr [rsi + 8] ; jmp rax
  Pivot:  0xffffffff811b6e68 # push rax ; pop rsp ; add dword ptr [rax - 0x16], edi ; ret
  Dispatch: place 0xffffffff811b6e68 at [rsi+0x8]
  Place ROP chain address at [rsi+0x8]
Pivot type: jop_indirect (chained, pointer)
  Step 1: 0xffffffff81e0892c # mov rax, qword ptr [rsi + 8] ; jmp rax
  Pivot:  0xffffffff81728911 # push rax ; add byte ptr [rbx + 0x41], bl ; pop rsp ; pop rbp ; ret
  Dispatch: place 0xffffffff81728911 at [rsi+0x8]
  Place ROP chain address at [rsi+0x10]
Pivot type: jop_indirect (chained, pointer)
  Step 1: 0xffffffff81e0892c # mov rax, qword ptr [rsi + 8] ; jmp rax
  Pivot:  0xffffffff8226ad44 # push rax ; add dword ptr [rax], eax ; add byte ptr [rbx + 0x41], bl ; pop rsp ; pop r13 ; pop r14 ; pop r15 ; pop rbp ; ret
  Dispatch: place 0xffffffff8226ad44 at [rsi+0x8]
  Place ROP chain address at [rsi+0x28]

=== Stack pivot from rdx ===
Pivot type: jop_indirect (chained, pointer)
  Step 1: 0xffffffff812dd1d5 # mov rax, qword ptr [rdx + 0x20] ; jmp rax
  Pivot:  0xffffffff811b6e72 # push rax ; pop rsp ; add dword ptr [rax - 1], edi ; ret
  Dispatch: place 0xffffffff811b6e72 at [rdx+0x20]
  Place ROP chain address at [rdx+0x20]
Pivot type: jop_indirect (chained, pointer)
  Step 1: 0xffffffff812dd1d5 # mov rax, qword ptr [rdx + 0x20] ; jmp rax
  Pivot:  0xffffffff811b6e68 # push rax ; pop rsp ; add dword ptr [rax - 0x16], edi ; ret
  Dispatch: place 0xffffffff811b6e68 at [rdx+0x20]
  Place ROP chain address at [rdx+0x20]
Pivot type: jop_indirect (chained, pointer)
  Step 1: 0xffffffff812dd1d5 # mov rax, qword ptr [rdx + 0x20] ; jmp rax
  Pivot:  0xffffffff81728911 # push rax ; add byte ptr [rbx + 0x41], bl ; pop rsp ; pop rbp ; ret
  Dispatch: place 0xffffffff81728911 at [rdx+0x20]
  Place ROP chain address at [rdx+0x28]
Pivot type: jop_indirect (chained, pointer)
  Step 1: 0xffffffff812dd1d5 # mov rax, qword ptr [rdx + 0x20] ; jmp rax
  Pivot:  0xffffffff8226ad44 # push rax ; add dword ptr [rax], eax ; add byte ptr [rbx + 0x41], bl ; pop rsp ; pop r13 ; pop r14 ; pop r15 ; pop rbp ; ret
  Dispatch: place 0xffffffff8226ad44 at [rdx+0x20]
  Place ROP chain address at [rdx+0x40]
"""
