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
# e.clean_only = True

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

# Output depends on vmlinux — sample (one example per pivot type, trimmed):
"""
=== Setting registers ===
$RSP+0x0000 : 0xffffffff81177704 # pop rdi ; ret
$RSP+0x0008 : 0x0000000041414141
$RSP+0x0010 : 0xffffffff8115fbce # pop rsi ; ret
$RSP+0x0018 : 0x0000000000000000


=== Stack pivot from rdi ===
Pivot type: offset
  Gadget: 0xffffffff8220779d # push rdi ; add byte ptr [rcx + 0x415d5be8], cl ; pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
  Source register: rdi
  Offset: 0x18
  ROP chain starts at [rdi+0x18]
Pivot type: jop (chained)
  Step 1: 0xffffffff81e3f0d6 # mov rbx, rdi ; mov rax, qword ptr [rdi + 8] ; call rax
  Pivot:  0xffffffff81ccac6f # push rbx ; pop rsp ; add ecx, dword ptr [rax - 0x39] ; ret
  Dispatch: place 0xffffffff81ccac6f at [rdi+0x8]
  ROP chain starts at [rdi+0x0]
Pivot type: jop (2-step chain)
  Step 1: 0xffffffff81e3f0d6 # mov rbx, rdi ; mov rax, qword ptr [rdi + 8] ; call rax
  Step 2: 0xffffffff81cfe2a2 # mov rsi, rbx ; mov edi, eax ; mov rax, qword ptr [rbx + 0x60] ; pop rbx ; jmp rax
  Pivot:  0xffffffff815665aa # push rsi ; or byte ptr [rbx + 0x41], bl ; pop rsp ; pop r13 ; pop r14 ; pop rbp ; ret
  Dispatch: place 0xffffffff81cfe2a2 at [rdi+0x8]
  Dispatch: place 0xffffffff815665aa at [rdi+0x60]
  ROP chain starts at [rdi+0x18]
Pivot type: jop_indirect (chained, pointer)
  Step 1: 0xffffffff81ac8d6e # mov rdx, qword ptr [rdi + 0x38] ; mov rax, qword ptr [rdi + 0x30] ; mov rdi, rdx ; jmp rax
  Pivot:  0xffffffff81254fba # push rdx ; add dword ptr [rcx + 0x415d5bd8], ecx ; pop rsp ; ret
  Dispatch: place 0xffffffff81254fba at [rdi+0x30]
  Place ROP chain address at [rdi+0x38]
Pivot type: jop_indirect (2-step chain)
  Step 1: 0xffffffff81e3f0d6 # mov rbx, rdi ; mov rax, qword ptr [rdi + 8] ; call rax
  Step 2: 0xffffffff82091ed7 # mov rdi, qword ptr [rbx + 0x10] ; mov rax, qword ptr [rbx] ; pop rbx ; jmp rax
  Pivot:  0xffffffff8220779d # push rdi ; add byte ptr [rcx + 0x415d5be8], cl ; pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
  Dispatch: place 0xffffffff82091ed7 at [rdi+0x8]
  Dispatch: place 0xffffffff8220779d at [rdi+0x0]
  Place ROP chain address at [rdi+0x10]
  ... (11 more, 17 total)

=== Stack pivot from rsi ===
Pivot type: offset
  Gadget: 0xffffffff815665aa # push rsi ; or byte ptr [rbx + 0x41], bl ; pop rsp ; pop r13 ; pop r14 ; pop rbp ; ret
  Source register: rsi
  Offset: 0x18
  ROP chain starts at [rsi+0x18]
Pivot type: jop_push (stack transfer)
  Step 1: 0xffffffff81f15198 # push rsi ; jmp qword ptr [rsi + 0xf]
  Pivot:  0xffffffff8102fbd0 # pop rsp ; ret
  Dispatch: place 0xffffffff8102fbd0 at [rsi+0xf]
  ROP chain starts at [rsi+0x0]
Pivot type: jop (chained)
  Step 1: 0xffffffff81558306 # push rsi ; or dword ptr [rax - 0x75], 0x48 ; sub cl, ch ; pop rdi ; and al, 0xfe ; jmp qword ptr [rsi + 0x66]
  Pivot:  0xffffffff8220779d # push rdi ; add byte ptr [rcx + 0x415d5be8], cl ; pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
  Dispatch: place 0xffffffff8220779d at [rsi+0x66]
  ROP chain starts at [rsi+0x18]
Pivot type: jop_indirect (chained, pointer)
  Step 1: 0xffffffff81e08929 # mov rdi, qword ptr [rsi] ; mov rax, qword ptr [rsi + 8] ; jmp rax
  Pivot:  0xffffffff8220779d # push rdi ; add byte ptr [rcx + 0x415d5be8], cl ; pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
  Dispatch: place 0xffffffff8220779d at [rsi+0x8]
  Place ROP chain address at [rsi+0x0]
  ... (1997 more, 2001 total)

=== Stack pivot from rdx ===
Pivot type: direct
  Gadget: 0xffffffff81254fba # push rdx ; add dword ptr [rcx + 0x415d5bd8], ecx ; pop rsp ; ret
  Source register: rdx
  ROP chain starts at [rdx]
Pivot type: offset
  Gadget: 0xffffffff81ce6e7a # push rdx ; and edx, dword ptr [rdx] ; add byte ptr [rcx + 0x415d5be8], cl ; pop rsp ; pop r13 ; pop r14 ; ret
  Source register: rdx
  Offset: 0x10
  ROP chain starts at [rdx+0x10]
  ... (1 more, 3 total)
"""
