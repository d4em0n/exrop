# Exrop

Automatic ROP chain generator for x86-64 binaries, powered by [Triton](https://github.com/JonathanSalwan/Triton) symbolic execution.

## Features

- Set registers to constants or other registers (`rdi=0x41414141`, `rdi=rax`)
- Write to memory (constant and register-based addresses/values)
- Write strings/bytes to memory
- Function calls with mixed constant/register/string arguments (`open("/etc/passwd", 0)`)
- Syscall chains
- Badchar avoidance
- Non-return gadget support (jmp reg, call reg)
- Stack pivoting with JOP chain search for kernel exploits
- Kernel mode with automatic retpoline thunk rewriting
- Clean-only mode to filter gadgets with dangerous side-effect memory writes
- Suffix-based composition: multi-instruction gadgets built from already-analyzed suffixes
- Multiprocessing gadget analysis with progress bar
- Gadget caching (pickle) for fast re-use

## Installation

### pip (recommended)

```bash
pip install git+https://github.com/d4em0n/exrop.git
```

This installs exrop and its Python dependencies (`pyelftools`, `ROPGadget`, `triton-library`).

> **Note:** The `triton-library` pip package may not work on all platforms. If installation fails, [build Triton from source](https://triton-library.github.io/documentation/doxygen/index.html#linux_install_sec) and install exrop without the Triton dependency:
> ```bash
> pip install --no-deps git+https://github.com/d4em0n/exrop.git
> pip install pyelftools ROPGadget
> ```

For development (editable install with test dependencies):

```bash
git clone https://github.com/d4em0n/exrop.git
cd exrop
pip install -e ".[dev]"
```

### Manual

1. Install Python 3.6+
2. Install [Triton](https://triton-library.github.io/documentation/doxygen/index.html#linux_install_sec)
3. Install [ROPGadget](https://github.com/JonathanSalwan/ROPgadget)
4. Optional: install [Keystone](https://www.keystone-engine.org/) (only needed for tests)
5. Clone this repo and add it to your Python path:
   ```bash
   git clone https://github.com/d4em0n/exrop.git
   export PYTHONPATH=/path/to/exrop:$PYTHONPATH
   ```

## Quick Start

```python
from Exrop import Exrop

rop = Exrop("/bin/ls")
rop.find_gadgets(cache=True)

# Set registers
chain = rop.set_regs({'rdi': 0x41414141, 'rsi': 0x42424242, 'rdx': 0x43434343})
chain.dump()

# Write to memory
chain = rop.set_writes({0x41414141: 0xdeadbeefff, 0x43434343: 0x00110011})
chain.dump()

# Write string to memory
chain = rop.set_string({0x41414141: "Hello world!\n"})
chain.dump()

# Function call
chain = rop.func_call(0x41414141, (0x20, 0x30, "Hello"), 0x7fffff00)
chain.dump()
```

Output:

```
$RSP+0x0000 : 0x00000000000060d0 # pop rbx; ret
$RSP+0x0008 : 0x0000000044444444
$RSP+0x0010 : 0x0000000000014852 # mov rax, rbx; pop rbx; ret
$RSP+0x0018 : 0x0000000000000000
$RSP+0x0020 : 0x0000000000004ce5 # pop rdi; ret
$RSP+0x0028 : 0x0000000041414141
$RSP+0x0030 : 0x000000000000629c # pop rsi; ret
$RSP+0x0038 : 0x0000000042424242
$RSP+0x0040 : 0x0000000000003a62 # pop rdx; ret
$RSP+0x0048 : 0x0000000043434343
$RSP+0x0050 : 0x00000000000060d0 # pop rbx; ret
$RSP+0x0058 : 0x0000000045454545
```

## Kernel Mode

For Linux kernels with retpoline mitigations, `kernel_mode=True` automatically detects thunk symbols, rewrites gadgets, and restricts to the `.text` section:

```python
from Exrop import Exrop

rop = Exrop("/path/to/vmlinux")
rop.find_gadgets(cache=True, kernel_mode=True)
rop.clean_only = True  # exclude gadgets with dangerous side-effect writes

# Set registers
chain = rop.set_regs({'rdi': 0x41414141, 'rsi': 0})
chain.dump()

# Find pivot gadgets (direct, JOP-chained, indirect)
pivots = rop.stack_pivot_reg('rdi')
for p in pivots[:5]:
    p.dump()

# Build payload for a pivot
payload = pivots[0].build_payload(chain)
```

## exkrop CLI

The `exkrop` command provides an interactive workflow for kernel ROP chain generation with pivot selection and C code output:

```bash
exkrop <vmlinux>
# or: python3 -m exkrop <vmlinux>
```

Features: exploit templates (privesc, core_pattern overwrite), KASLR-relative output, pivot gadget browser, reserved offset handling, and C code generation. See [exkrop/README.md](exkrop/README.md) for details.

## Userspace Example: open-read-write

```python
from pwn import *
from Exrop import Exrop

libc = ELF("/lib/x86_64-linux-gnu/libc.so.6", checksec=False)
rop = Exrop(libc.path)
rop.find_gadgets(cache=True)

bss = libc.bss()

chain = rop.func_call(libc.symbols['open'], ("/etc/passwd", 0), bss)
chain.set_base_addr(0x00007ffff79e4000)
chain.dump()

chain = rop.func_call(libc.symbols['read'], ('rax', bss, 0x100))
chain.set_base_addr(0x00007ffff79e4000)
chain.dump()

chain = rop.func_call(libc.symbols['write'], (1, bss, 0x100))
chain.set_base_addr(0x00007ffff79e4000)
chain.dump()
```

More examples in the [examples/](examples) directory.
