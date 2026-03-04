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

# Output depends on vmlinux — sample:
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
Pivot type: jop (chained)
  Step 1: 0xffffffff81e3f0d6 # mov rbx, rdi ; mov rax, qword ptr [rdi + 8] ; call rax
  Pivot:  0xffffffff8223e558 # push rbx ; add byte ptr [rcx + 0x415d5bd8], cl ; pop rsp ; pop r13 ; pop r14 ; ret
  Dispatch: place 0xffffffff8223e558 at [rdi+0x8]
  ROP chain starts at [rdi+0x10]
Pivot type: jop_indirect (chained, pointer)
  Step 1: 0xffffffff81e3f0d9 # mov rax, qword ptr [rdi + 8] ; call rax
  Pivot:  0xffffffff8226eb20 # push rax ; add byte ptr [rcx + 0x415d5bd8], cl ; pop rsp ; ret
  Dispatch: place 0xffffffff8226eb20 at [rdi+0x8]
  Place ROP chain address at [rdi+0x8]
Pivot type: jop_indirect (chained, pointer)
  Step 1: 0xffffffff81e3f0d9 # mov rax, qword ptr [rdi + 8] ; call rax
  Pivot:  0xffffffff8227fd84 # push rax ; add byte ptr [r9 + 0x415d5bd8], r9b ; pop rsp ; ret
  Dispatch: place 0xffffffff8227fd84 at [rdi+0x8]
  Place ROP chain address at [rdi+0x8]
Pivot type: jop_indirect (chained, pointer)
  Step 1: 0xffffffff81e3f0d9 # mov rax, qword ptr [rdi + 8] ; call rax
  Pivot:  0xffffffff81272042 # push rax ; add dword ptr [rcx + 0x415d5bd8], ecx ; pop rsp ; pop r13 ; pop r14 ; ret
  Dispatch: place 0xffffffff81272042 at [rdi+0x8]
  Place ROP chain address at [rdi+0x18]
Pivot type: jop_indirect (chained, pointer)
  Step 1: 0xffffffff81ac8d6e # mov rdx, qword ptr [rdi + 0x38] ; mov rax, qword ptr [rdi + 0x30] ; mov rdi, rdx ; jmp rax
  Pivot:  0xffffffff81254fba # push rdx ; add dword ptr [rcx + 0x415d5bd8], ecx ; pop rsp ; ret
  Dispatch: place 0xffffffff81254fba at [rdi+0x30]
  Place ROP chain address at [rdi+0x38]
Pivot type: jop_indirect (chained, pointer)
  Step 1: 0xffffffff81ac8d6e # mov rdx, qword ptr [rdi + 0x38] ; mov rax, qword ptr [rdi + 0x30] ; mov rdi, rdx ; jmp rax
  Pivot:  0xffffffff81254fb9 # push rbx ; push rdx ; add dword ptr [rcx + 0x415d5bd8], ecx ; pop rsp ; ret
  Dispatch: place 0xffffffff81254fb9 at [rdi+0x30]
  Place ROP chain address at [rdi+0x38]
Pivot type: jop (2-step chain)
  Step 1: 0xffffffff81e3f0d6 # mov rbx, rdi ; mov rax, qword ptr [rdi + 8] ; call rax
  Step 2: 0xffffffff81cfe2a2 # mov rsi, rbx ; mov edi, eax ; mov rax, qword ptr [rbx + 0x60] ; pop rbx ; jmp rax
  Pivot:  0xffffffff81209111 # push rsi ; add dword ptr [rcx + 0x415d5bd8], ecx ; pop rsp ; pop r13 ; pop r14 ; ret
  Dispatch: place 0xffffffff81cfe2a2 at [rdi+0x8]
  Dispatch: place 0xffffffff81209111 at [rdi+0x60]
  ROP chain starts at [rdi+0x10]
Pivot type: jop (chained)
  Step 1: 0xffffffff81e3f0d6 # mov rbx, rdi ; mov rax, qword ptr [rdi + 8] ; call rax
  Pivot:  0xffffffff8123f36c # push rbx ; add dword ptr [rcx + 0x415d5be8], ecx ; pop rsp ; ret
  Dispatch: place 0xffffffff8123f36c at [rdi+0x8]
  ROP chain starts at [rdi+0x0]
Pivot type: jop (chained)
  Step 1: 0xffffffff81e3f0d6 # mov rbx, rdi ; mov rax, qword ptr [rdi + 8] ; call rax
  Pivot:  0xffffffff81a4c709 # push rbx ; xor al, 0x88 ; add byte ptr [rcx + 0x415d5be8], cl ; pop rsp ; ret
  Dispatch: place 0xffffffff81a4c709 at [rdi+0x8]
  ROP chain starts at [rdi+0x0]
Pivot type: jop (chained)
  Step 1: 0xffffffff81e3f0d6 # mov rbx, rdi ; mov rax, qword ptr [rdi + 8] ; call rax
  Pivot:  0xffffffff81a4c707 # add al, ch ; push rbx ; xor al, 0x88 ; add byte ptr [rcx + 0x415d5be8], cl ; pop rsp ; ret
  Dispatch: place 0xffffffff81a4c707 at [rdi+0x8]
  ROP chain starts at [rdi+0x0]
Pivot type: jop (chained)
  Step 1: 0xffffffff81e3f0d6 # mov rbx, rdi ; mov rax, qword ptr [rdi + 8] ; call rax
  Pivot:  0xffffffff81a4c705 # add al, 0 ; add al, ch ; push rbx ; xor al, 0x88 ; add byte ptr [rcx + 0x415d5be8], cl ; pop rsp ; ret
  Dispatch: place 0xffffffff81a4c705 at [rdi+0x8]
  ROP chain starts at [rdi+0x0]
Pivot type: jop (chained)
  Step 1: 0xffffffff81e3f0d6 # mov rbx, rdi ; mov rax, qword ptr [rdi + 8] ; call rax
  Pivot:  0xffffffff8123a45b # push rbx ; add dword ptr [rcx + 0x415d5be8], ecx ; pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
  Dispatch: place 0xffffffff8123a45b at [rdi+0x8]
  ROP chain starts at [rdi+0x18]
Pivot type: jop_indirect (chained, pointer)
  Step 1: 0xffffffff81e3f0d9 # mov rax, qword ptr [rdi + 8] ; call rax
  Pivot:  0xffffffff8226a421 # push rax ; add byte ptr [rcx + 0x415d5be8], cl ; pop rsp ; pop r13 ; ret
  Dispatch: place 0xffffffff8226a421 at [rdi+0x8]
  Place ROP chain address at [rdi+0x10]
Pivot type: jop_indirect (chained, pointer)
  Step 1: 0xffffffff81e3f0d9 # mov rax, qword ptr [rdi + 8] ; call rax
  Pivot:  0xffffffff817344d3 # push rax ; xor byte ptr [rcx + 0x415d5be8], cl ; pop rsp ; pop r13 ; ret
  Dispatch: place 0xffffffff817344d3 at [rdi+0x8]
  Place ROP chain address at [rdi+0x10]
Pivot type: jop_indirect (chained, pointer)
  Step 1: 0xffffffff81e3f0d9 # mov rax, qword ptr [rdi + 8] ; call rax
  Pivot:  0xffffffff822577e7 # push rax ; add eax, dword ptr [rax] ; add byte ptr [rcx + 0x415d5be8], cl ; pop rsp ; pop r13 ; pop r14 ; ret
  Dispatch: place 0xffffffff822577e7 at [rdi+0x8]
  Place ROP chain address at [rdi+0x18]
Pivot type: jop_indirect (chained, pointer)
  Step 1: 0xffffffff821e57df # mov rdi, qword ptr [rdi + 0x18] ; mov rax, qword ptr [rdi + 0x28] ; jmp rax
  Pivot:  0xffffffff8220779d # push rdi ; add byte ptr [rcx + 0x415d5be8], cl ; pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
  Dispatch: place 0xffffffff8220779d at [rdi+0x28]
  Place ROP chain address at [rdi+0x30]
Pivot type: jop_indirect (chained, pointer)
  Step 1: 0xffffffff81ac8d6e # mov rdx, qword ptr [rdi + 0x38] ; mov rax, qword ptr [rdi + 0x30] ; mov rdi, rdx ; jmp rax
  Pivot:  0xffffffff81ce6e7a # push rdx ; and edx, dword ptr [rdx] ; add byte ptr [rcx + 0x415d5be8], cl ; pop rsp ; pop r13 ; pop r14 ; ret
  Dispatch: place 0xffffffff81ce6e7a at [rdi+0x30]
  Place ROP chain address at [rdi+0x48]

=== Stack pivot from rsi ===
Pivot type: offset
  Gadget: 0xffffffff815665aa # push rsi ; or byte ptr [rbx + 0x41], bl ; pop rsp ; pop r13 ; pop r14 ; pop rbp ; ret
  Source register: rsi
  Offset: 0x18
  ROP chain starts at [rsi+0x18]
Pivot type: offset
  Gadget: 0xffffffff81fe13de # push rsi ; or byte ptr [rsi*2 + 0x415d5b1c], r9b ; pop rsp ; pop r13 ; ret
  Source register: rsi
  Offset: 0x8
  ROP chain starts at [rsi+0x8]
Pivot type: offset
  Gadget: 0xffffffff81209111 # push rsi ; add dword ptr [rcx + 0x415d5bd8], ecx ; pop rsp ; pop r13 ; pop r14 ; ret
  Source register: rsi
  Offset: 0x10
  ROP chain starts at [rsi+0x10]
Pivot type: offset
  Gadget: 0xffffffff82209c7b # push rsi ; add byte ptr [rcx + 0x415d5be8], cl ; pop rsp ; pop r13 ; ret
  Source register: rsi
  Offset: 0x8
  ROP chain starts at [rsi+0x8]
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
Pivot type: jop_indirect (chained, pointer)
  Step 1: 0xffffffff81e0892c # mov rax, qword ptr [rsi + 8] ; jmp rax
  Pivot:  0xffffffff8226eb20 # push rax ; add byte ptr [rcx + 0x415d5bd8], cl ; pop rsp ; ret
  Dispatch: place 0xffffffff8226eb20 at [rsi+0x8]
  Place ROP chain address at [rsi+0x8]
Pivot type: jop_indirect (chained, pointer)
  Step 1: 0xffffffff81e0892c # mov rax, qword ptr [rsi + 8] ; jmp rax
  Pivot:  0xffffffff8227fd84 # push rax ; add byte ptr [r9 + 0x415d5bd8], r9b ; pop rsp ; ret
  Dispatch: place 0xffffffff8227fd84 at [rsi+0x8]
  Place ROP chain address at [rsi+0x8]
Pivot type: jop_indirect (chained, pointer)
  Step 1: 0xffffffff81e0892c # mov rax, qword ptr [rsi + 8] ; jmp rax
  Pivot:  0xffffffff81272042 # push rax ; add dword ptr [rcx + 0x415d5bd8], ecx ; pop rsp ; pop r13 ; pop r14 ; ret
  Dispatch: place 0xffffffff81272042 at [rsi+0x8]
  Place ROP chain address at [rsi+0x18]
Pivot type: jop (chained)
  Step 1: 0xffffffff81558306 # push rsi ; or dword ptr [rax - 0x75], 0x48 ; sub cl, ch ; pop rdi ; and al, 0xfe ; jmp qword ptr [rsi + 0x66]
  Pivot:  0xffffffff8220779d # push rdi ; add byte ptr [rcx + 0x415d5be8], cl ; pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
  Dispatch: place 0xffffffff8220779d at [rsi+0x66]
  ROP chain starts at [rsi+0x18]
Pivot type: jop_indirect (chained, pointer)
  Step 1: 0xffffffff81e0892c # mov rax, qword ptr [rsi + 8] ; jmp rax
  Pivot:  0xffffffff8226a421 # push rax ; add byte ptr [rcx + 0x415d5be8], cl ; pop rsp ; pop r13 ; ret
  Dispatch: place 0xffffffff8226a421 at [rsi+0x8]
  Place ROP chain address at [rsi+0x10]
Pivot type: jop_indirect (chained, pointer)
  Step 1: 0xffffffff81e0892c # mov rax, qword ptr [rsi + 8] ; jmp rax
  Pivot:  0xffffffff817344d3 # push rax ; xor byte ptr [rcx + 0x415d5be8], cl ; pop rsp ; pop r13 ; ret
  Dispatch: place 0xffffffff817344d3 at [rsi+0x8]
  Place ROP chain address at [rsi+0x10]
Pivot type: jop_indirect (chained, pointer)
  Step 1: 0xffffffff81e0892c # mov rax, qword ptr [rsi + 8] ; jmp rax
  Pivot:  0xffffffff822577e7 # push rax ; add eax, dword ptr [rax] ; add byte ptr [rcx + 0x415d5be8], cl ; pop rsp ; pop r13 ; pop r14 ; ret
  Dispatch: place 0xffffffff822577e7 at [rsi+0x8]
  Place ROP chain address at [rsi+0x18]
Pivot type: jop_indirect (chained, pointer)
  Step 1: 0xffffffff81e08929 # mov rdi, qword ptr [rsi] ; mov rax, qword ptr [rsi + 8] ; jmp rax
  Pivot:  0xffffffff8220779d # push rdi ; add byte ptr [rcx + 0x415d5be8], cl ; pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
  Dispatch: place 0xffffffff8220779d at [rsi+0x8]
  Place ROP chain address at [rsi+0x18]

=== Stack pivot from rdx ===
Pivot type: direct
  Gadget: 0xffffffff81254fba # push rdx ; add dword ptr [rcx + 0x415d5bd8], ecx ; pop rsp ; ret
  Source register: rdx
  ROP chain starts at [rdx]
Pivot type: direct
  Gadget: 0xffffffff81254fb9 # push rbx ; push rdx ; add dword ptr [rcx + 0x415d5bd8], ecx ; pop rsp ; ret
  Source register: rdx
  ROP chain starts at [rdx]
Pivot type: offset
  Gadget: 0xffffffff81ce6e7a # push rdx ; and edx, dword ptr [rdx] ; add byte ptr [rcx + 0x415d5be8], cl ; pop rsp ; pop r13 ; pop r14 ; ret
  Source register: rdx
  Offset: 0x10
  ROP chain starts at [rdx+0x10]
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
Pivot type: jop_indirect (chained, pointer)
  Step 1: 0xffffffff81e5fcb1 # mov rdx, qword ptr [rdx + 0x10] ; jmp rdx
  Pivot:  0xffffffff81254fba # push rdx ; add dword ptr [rcx + 0x415d5bd8], ecx ; pop rsp ; ret
  Dispatch: place 0xffffffff81254fba at [rdx+0x10]
  Place ROP chain address at [rdx+0x10]
Pivot type: jop_indirect (chained, pointer)
  Step 1: 0xffffffff81e5fcb1 # mov rdx, qword ptr [rdx + 0x10] ; jmp rdx
  Pivot:  0xffffffff81254fb9 # push rbx ; push rdx ; add dword ptr [rcx + 0x415d5bd8], ecx ; pop rsp ; ret
  Dispatch: place 0xffffffff81254fb9 at [rdx+0x10]
  Place ROP chain address at [rdx+0x10]
Pivot type: jop_indirect (chained, pointer)
  Step 1: 0xffffffff812dd1d5 # mov rax, qword ptr [rdx + 0x20] ; jmp rax
  Pivot:  0xffffffff8226eb20 # push rax ; add byte ptr [rcx + 0x415d5bd8], cl ; pop rsp ; ret
  Dispatch: place 0xffffffff8226eb20 at [rdx+0x20]
  Place ROP chain address at [rdx+0x20]
Pivot type: jop_indirect (chained, pointer)
  Step 1: 0xffffffff812dd1d5 # mov rax, qword ptr [rdx + 0x20] ; jmp rax
  Pivot:  0xffffffff8227fd84 # push rax ; add byte ptr [r9 + 0x415d5bd8], r9b ; pop rsp ; ret
  Dispatch: place 0xffffffff8227fd84 at [rdx+0x20]
  Place ROP chain address at [rdx+0x20]
Pivot type: jop_indirect (chained, pointer)
  Step 1: 0xffffffff812dd1d5 # mov rax, qword ptr [rdx + 0x20] ; jmp rax
  Pivot:  0xffffffff81272042 # push rax ; add dword ptr [rcx + 0x415d5bd8], ecx ; pop rsp ; pop r13 ; pop r14 ; ret
  Dispatch: place 0xffffffff81272042 at [rdx+0x20]
  Place ROP chain address at [rdx+0x30]
Pivot type: jop_indirect (chained, pointer)
  Step 1: 0xffffffff81f241c8 # mov rcx, qword ptr [rdx + 0x80] ; xor edx, edx ; jmp rcx
  Pivot:  0xffffffff82223bc9 # push rcx ; add byte ptr [rcx + 0x415d5bd8], cl ; pop rsp ; ret
  Dispatch: place 0xffffffff82223bc9 at [rdx+0x80]
  Place ROP chain address at [rdx+0x80]
Pivot type: jop_indirect (chained, pointer)
  Step 1: 0xffffffff81f241c8 # mov rcx, qword ptr [rdx + 0x80] ; xor edx, edx ; jmp rcx
  Pivot:  0xffffffff8226092f # push rcx ; add byte ptr [rcx + 0x415d5bd8], cl ; pop rsp ; pop r13 ; ret
  Dispatch: place 0xffffffff8226092f at [rdx+0x80]
  Place ROP chain address at [rdx+0x88]
Pivot type: jop_indirect (chained, pointer)
  Step 1: 0xffffffff81f241c8 # mov rcx, qword ptr [rdx + 0x80] ; xor edx, edx ; jmp rcx
  Pivot:  0xffffffff8225f1b6 # push rcx ; add byte ptr [rcx + 0x415d5bd8], cl ; pop rsp ; pop r13 ; pop r14 ; ret
  Dispatch: place 0xffffffff8225f1b6 at [rdx+0x80]
  Place ROP chain address at [rdx+0x90]
Pivot type: jop_indirect (chained, pointer)
  Step 1: 0xffffffff81f241c8 # mov rcx, qword ptr [rdx + 0x80] ; xor edx, edx ; jmp rcx
  Pivot:  0xffffffff81048979 # push rcx ; add byte ptr [rcx + 0x415d5bd8], cl ; pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
  Dispatch: place 0xffffffff81048979 at [rdx+0x80]
  Place ROP chain address at [rdx+0x98]
Pivot type: jop_indirect (chained, pointer)
  Step 1: 0xffffffff81e5fcb1 # mov rdx, qword ptr [rdx + 0x10] ; jmp rdx
  Pivot:  0xffffffff81ce6e7a # push rdx ; and edx, dword ptr [rdx] ; add byte ptr [rcx + 0x415d5be8], cl ; pop rsp ; pop r13 ; pop r14 ; ret
  Dispatch: place 0xffffffff81ce6e7a at [rdx+0x10]
  Place ROP chain address at [rdx+0x20]
Pivot type: jop_indirect (chained, pointer)
  Step 1: 0xffffffff812dd1d5 # mov rax, qword ptr [rdx + 0x20] ; jmp rax
  Pivot:  0xffffffff8226a421 # push rax ; add byte ptr [rcx + 0x415d5be8], cl ; pop rsp ; pop r13 ; ret
  Dispatch: place 0xffffffff8226a421 at [rdx+0x20]
  Place ROP chain address at [rdx+0x28]
Pivot type: jop_indirect (chained, pointer)
  Step 1: 0xffffffff812dd1d5 # mov rax, qword ptr [rdx + 0x20] ; jmp rax
  Pivot:  0xffffffff817344d3 # push rax ; xor byte ptr [rcx + 0x415d5be8], cl ; pop rsp ; pop r13 ; ret
  Dispatch: place 0xffffffff817344d3 at [rdx+0x20]
  Place ROP chain address at [rdx+0x28]
Pivot type: jop_indirect (chained, pointer)
  Step 1: 0xffffffff812dd1d5 # mov rax, qword ptr [rdx + 0x20] ; jmp rax
  Pivot:  0xffffffff822577e7 # push rax ; add eax, dword ptr [rax] ; add byte ptr [rcx + 0x415d5be8], cl ; pop rsp ; pop r13 ; pop r14 ; ret
  Dispatch: place 0xffffffff822577e7 at [rdx+0x20]
  Place ROP chain address at [rdx+0x30]
Pivot type: jop_indirect (chained, pointer)
  Step 1: 0xffffffff81f241c8 # mov rcx, qword ptr [rdx + 0x80] ; xor edx, edx ; jmp rcx
  Pivot:  0xffffffff82220c60 # push rcx ; add byte ptr [rcx + 0x415d5be8], cl ; pop rsp ; ret
  Dispatch: place 0xffffffff82220c60 at [rdx+0x80]
  Place ROP chain address at [rdx+0x80]
"""
