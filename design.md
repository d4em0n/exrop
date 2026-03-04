# exrop Design Document

Automatic ROP chain generator for x86-64 binaries using symbolic execution.

## Architecture Overview

```
User API (Exrop)
    |
    v
ChainBuilder          -- orchestrates gadget loading, analysis, solving
    |
    +-- Gadget         -- symbolic analysis of individual gadgets via Triton
    +-- Solver         -- constraint solving to compose gadgets into chains
    +-- RopChain       -- chain ordering, serialization, output
```

## Pipeline

```
Binary ──> ROPgadget ──> Raw gadgets ──> Triton analysis ──> Candidate search ──> SMT solving ──> Chain assembly
           (extract)     (addr,asm,bytes)  (per-gadget)       (filter+rank)       (constraint)    (ordering)
```

### 1. Gadget Extraction (`Exrop.parseRopGadget`)

Runs ROPgadget with `--multibr --dump` to extract gadgets from the binary.
Filters to useful instruction classes: `pop|xchg|add|sub|xor|mov|ret|jmp|call|syscall|leave`.
Output sorted by instruction length (shorter = simpler = preferred).

### 2. Gadget Analysis (`Gadget.analyzeGadget`)

Each gadget is symbolically executed in an isolated Triton context:

- All 15 general-purpose registers are symbolized (rax..r15)
- 128 stack slots are symbolized as `STACK0..STACK127`
- RSP is set to a concrete address (`0x7fffff00`)

The gadget's opcodes are executed instruction-by-instruction. For each instruction:

- **Written/read registers** are tracked via `inst.getWrittenRegisters()` / `getReadRegisters()`
- **Pop detection**: if a register is written and RSP increased by 8, it's a pop
- **Memory writes**: `mov`-based stores record `(addr_ast, val_ast)` as symbolic ASTs
- **Memory reads** (non-pop): flagged to avoid gadgets with uncontrolled memory loads
- **Syscall detection**: marks gadgets containing `syscall`
- **Stack pivot**: if RSP is symbolized at the end, the gadget can pivot the stack

At the control flow terminator (ret/jmp/call):

| End Type | Condition | Effect |
|---|---|---|
| `TYPE_RETURN` | RSP increased by 8 (normal ret) | Clean gadget ending |
| `TYPE_JMP_REG` | RSP unchanged, jumps via register | Needs a helper ret gadget |
| `TYPE_CALL_REG` | RSP decreased by 8, calls register | Needs a helper ret gadget (diff_sp += 8) |
| `TYPE_JMP_MEM` / `TYPE_CALL_MEM` | Indirect via memory | Used by JOP pivot search |

**Per-register memory symbolization**: each GP register gets a memory region
(`REG_MEM_BASES`) with 32 symbolic slots (e.g., `RDI0`, `RDI1`, ...). The register's
concrete value is set to the region's base before symbolization, so loads like
`mov rdx, [rdi+8]` hit symbolized memory and produce trackable symbolic results.
This enables JOP dispatch analysis and indirect pivot detection.

**Stack pivot detection**: if RSP is symbolized after execution, the gadget can
redirect the stack. The analysis validates the pivot AST:

- **Direct pivot**: AST is a simple register expression (e.g., `mov rsp, rdi` → `pivot_src_reg="rdi"`, `pivot_offset=0`), or register+offset (`lea rsp, [r10-8]` → `pivot_src_reg="r10"`, `pivot_offset=-8`)
- **Indirect pivot**: AST matches exactly one REG memory variable (e.g., `mov rsp, [rdi]` → `pivot_src_reg="rdi"`, `pivot_offset=0`, `pivot_indirect=1`)
- **Rejected**: partial operations (`or esp, [rdi]`, `sub esp, [rdi]`), 32-bit truncation (`mov esp, [rdi]`), or STACK base address leaks (`add rsp, rdi`) are not marked as pivots

**Segment register filtering**: Triton does not symbolize segment registers (ES, CS,
SS, DS, FS, GS) — they default to concrete 0. Instructions like `mov edx, es` would
be incorrectly treated as `defined_regs["rdx"] = 0`. During analysis, if an instruction
reads a segment register, any GP registers it writes are marked as "segment-tainted"
and excluded from `defined_regs`.

**Side-effect scoring** (`side_effect_score`): each gadget is scored for dangerous
side-effect memory writes. Instructions that write to memory at large constant offsets
(> 0x1000) from a register — e.g., `add byte ptr [rcx + 0x415d5be8], cl` — almost
certainly hit unmapped memory and crash. The score is the max offset found; 0 means
clean. Used by pivot sorting (clean gadgets first) and the `clean_only` filter.

**Suffix-based early exit**: when a module-level `_suffix_dict` is populated (by
`ChainBuilder.analyzeAll`), the analysis loop checks after each non-control-flow
instruction whether the remaining instructions match an already-analyzed gadget.
If a match is found and the suffix has `diff_sp >= 0` (i.e., RSP wasn't redirected
by the suffix), the gadget composes its analysis from the live Triton state plus
the suffix's stored results — avoiding re-executing the suffix through Triton.

Composition (`_compose_from_suffix`) reads the prefix's symbolic register values
from Triton, then substitutes them into the suffix's `regAst_str` and `end_ast_str`
using single-pass regex replacement. Stack slot references (`STACK0`, `STACK1`, ...)
are shifted by the prefix's stack consumption. Fields like `written_regs`,
`popped_regs`, `read_regs`, `diff_sp`, pivot info, and end type are merged from
both prefix execution and suffix analysis.

The `diff_sp >= 0` guard is critical: suffixes containing `pop rsp` or `mov rsp, reg`
produce very negative `diff_sp` values (e.g., -2147483368) because RSP is redirected
away from the symbolic stack. Composing from such a suffix would produce garbage
pivot and register ASTs. The guard forces fall-through to full Triton execution,
where pivot detection handles RSP redirection correctly.

After execution, for each written register:

- `regAst[reg]` stores the full symbolic AST
- `defined_regs[reg]` stores the simplified value if it's a constant (`xor rax,rax` -> `0`)
  or a direct register copy (`mov rax,rbx` -> `"rbx"`)
- `depends_regs` = read registers minus constant-defined registers
- `regAst_str[reg]` / `end_ast_str` store string representations that survive pickle
  (used by JOP search to avoid expensive `buildAst()` on all candidates)

### 3. Caching and Sorting (`ChainBuilder`)

**Caching**: analyzed gadgets are serialized with pickle. AST nodes (Triton `AstNode` objects) cannot
be pickled, so `__getstate__` strips them. On cache load, gadgets have `is_asted=False`
and ASTs are rebuilt on-demand via `buildAst()` when the solver needs them.

**Sorting**: after analysis or cache load, gadgets are sorted by opcode length
(`len(g.insns)`). Shorter gadgets are simpler and tried first by all solver functions,
producing cleaner chains (e.g., `pop rdi; ret` over `mov rdi, rax; ... ; ret`).

**Clean-only filtering**: `ChainBuilder.clean_only = True` (exposed as `Exrop.clean_only`)
filters out gadgets with `side_effect_score > 0` before passing them to any solver
function. This removes ~7% of kernel gadgets that have dangerous side-effect memory
writes, ensuring all gadgets in the resulting chain are safe to execute.

**Multiprocessing — rounds by instruction length**: `analyzeAll()` groups gadgets by
instruction count and analyzes them in rounds (1-instruction first, then 2-instruction,
etc.). Each round forks a new `Pool` that inherits the current `_suffix_dict` via
copy-on-write. As each round completes, its analyzed gadgets are added to the dict,
so the next round's workers have full suffix coverage for all shorter gadgets.

This gives 100% suffix hit rate at every depth level. On vmlinux (~122k gadgets),
suffix composition avoids redundant Triton execution for the majority of multi-
instruction gadgets, reducing analysis time from ~163s to ~132s. On libc (~58k
gadgets), analysis takes ~18s.

In single-process mode (`num_process=1`), gadgets are sorted short-to-long and the
suffix dict is built incrementally as each gadget is analyzed, achieving the same
coverage without fork overhead.

## Solver Design (`Solver.py`)

### Register Solving (`solveGadgets`)

Goal: given `{reg: value, ...}`, find a chain of gadgets that sets each register.

**Candidate search** (`findCandidatesGadgets`) prioritizes gadgets by type:

```
1. candidates_defined2_ret   -- exact (reg, value) match + clean ret ending
2. candidates_pop            -- gadget pops the target register from stack
3. candidates_defined2_other -- exact (reg, value) match but needs jmp/call fixup
4. candidates_defined        -- gadget defines the target register (but different value)
5. candidates_write          -- gadget writes the target register (computed, not pop/define)
6. candidates_depends        -- recursive: gadgets for dependency registers
7. candidates_for_ret        -- small helper gadgets (diff_sp 0 or 8) for non-return fixups
```

The `defined2` split ensures that gadgets like `xor esi, esi; pop rbx; pop rbp; jmp rax`
(exact match for `rsi=0` but needs jmp fixup) don't take priority over simpler `pop rsi; ret`.

Gadgets with `is_memory_read`, `is_memory_write`, or unusable end types are excluded.
The `keep_regs` set prevents gadgets that clobber protected registers.

**Solving loop** iterates candidates and for each gadget:

1. Checks if the gadget writes the target register(s)
2. For constant values: queries Triton's SMT solver with `ctx.getModel(regAst == value)`
3. For register values (`rax = "rbx"`): checks `defined_regs` for direct copies,
   otherwise builds a `refind_dict` to recursively solve the intermediate register
4. If the SMT model requires setting other registers (not on the stack),
   recursively calls `solveGadgets` for those dependencies

**Non-return fixup**: gadgets ending with `jmp reg` or `call reg` are paired with a
helper gadget found by `findForRet` — a minimal gadget that just returns. The end
register is solved to point to the helper's address. The helper's `not_write_regs`
includes both already-solved registers and `keep_regs`.

**Bad character avoidance**: when `avoid_char` is set, gadget addresses containing
forbidden bytes are excluded. For values containing forbidden bytes, the solver
adds per-byte constraints (`filter_byte`) to find stack values that avoid those bytes
while still producing the desired register value.

**Recursion limit**: `rec_limit >= 30` terminates to prevent infinite loops.

### Memory Write Solving (`solveWriteGadgets`)

Goal: given `{addr: value, ...}` where addr/value can be integers or register names,
find gadgets that perform `*(addr) = value`.

Supported operand combinations:

| Address | Value | Example | Mechanism |
|---|---|---|---|
| constant | constant | `*(0x414141) = 0xdead` | Original behavior, SMT solve both sides |
| register | constant | `*(rdi) = 0x41414141` | Match addr AST to reg, SMT solve value |
| constant | register | `*(0x414141) = rax` | SMT solve addr, match val AST to reg |
| register | register | `*(rdi) = rax` | Match both ASTs to registers |

**Operand resolution** (`_resolve_write_operand`):

For register targets: compares the gadget's AST string to the target register name.
If it matches directly (`mov [rdi], rax` for addr=rdi), no further solving needed.
If the AST is a different register (`mov [rdx], rax` for addr=rdi), adds a forwarding
entry: `refind_dict["rdx"] = "rdi"` (solve rdx = rdi via `solveGadgets`).

For constant targets: uses `ctx.getModel(operand_ast == target)` to find register
values that produce the desired constant (e.g., `pop rdx = 0x414141`).

**Three-level progressive forwarding** (`_try_write_gadgets`):

To avoid expensive recursive searches, write solving uses three passes:

```
Level 0: No reg-to-reg forwarding — both sides resolve directly or via constants
         Example: *(rdi) = 0x41414141 using mov [rdi], rcx + pop rcx
Level 1: One side can need forwarding — the other must be direct
         Example: *(rbx) = rcx using mov [rdi], rcx + solve rdi=rbx
Level 2: Both sides can need forwarding
         Example: *(rcx) = rbx using mov [rdx], rsi + solve rdx=rcx + solve rsi=rbx
```

This ordering ensures direct-match gadgets (fast, no recursive calls) are tried first,
and expensive double-forwarding searches are only attempted as a last resort.

**Register preservation** (`keep_regs`):

When solving dependencies for a write gadget, register operands must be protected.
For `*(rdi) = rax`, solving `rcx = 0x41414141` must not clobber rdi or rax.
The `keep_regs` set is propagated through all recursive `solveGadgets` calls and
to `findForRet` for non-return fixup gadgets.

**Post-write clobber tolerance**:

A gadget like `mov [rbx], rax; xor eax, eax; pop rbx; ret` is valid for `*(rbx) = val`
because the write reads rbx and rax *before* they are clobbered by subsequent
instructions. The Triton AST captures this: `memory_write_ast[0]` reflects the
register values at the time of the store, not after. Only gadgets ending with `ret`
are used (non-return write gadgets are filtered out).

### Stack Pivot Solving

#### Absolute Pivot (`solvePivot`)

Finds gadgets that set RSP to a specific address (e.g., `xchg rsp, rax; ret` where
rax is solved to the target address). Used for userspace exploits where the pivot
target is a known writable address.

#### Register-Based Pivot (`solvePivotForReg`)

For kernel exploits where a hijacked function pointer is called with a register
(typically `rdi`) pointing to a controlled object. Finds pivot gadgets that redirect
RSP to the object so a ROP chain embedded in it executes.

Returns a list of `PivotInfo` objects with `build_payload()` for layout generation.

**Phase 1 — Direct pivots** (`findPivotForReg`): ret-ending gadgets where
`pivot_src_reg` matches the target register. Sorted by
`(side_effect_score, is_indirect, abs(offset))` — clean gadgets first.

Examples: `mov rsp, rdi; ret`, `lea rsp, [r10-8]; ret`, `xchg rsp, rax; ret`.

**Phase 2 — JOP-chained pivots** (`findJopPivotCandidates`): when no direct pivot
exists for the target register (common in kernels — typically only `rax`, `rbp`,
`r10`, `r13` have direct pivots), the solver searches for JOP gadget chains that
bridge the gap.

Example chain for `rdi` pivot (no direct `mov rsp, rdi` exists):
```
Step 1: mov rax, [rdi+0x18]; jmp rax    — loads pivot addr from controlled object
Pivot:  xchg rsp, rax; ret              — redirects RSP
Layout: place xchg_addr at [rdi+0x18], ROP chain follows
```

**JOP index** (`_build_jop_index`): pre-analyzes all JOP gadgets (those ending with
`jmp reg`, `jmp [reg+off]`, `call reg`, `call [reg+off]`) using string representations
(`regAst_str`, `end_ast_str`) — no `buildAst()` needed. Builds a lookup table grouped
by written register for O(1) access.

Quality filters:
- Identity writes filtered (e.g., `and ah, ah` where `rax_out == rax_in`)
- Entries sorted by opcode length (shorter gadgets tried first)

**Recursive search** (`_find_jop_chain`): works backwards from the pivot's required
register, finding JOP gadgets to satisfy dependencies. Tracks `used_dispatch` offsets
to prevent collisions where two steps need different values at the same memory slot.
Max depth of 3 (configurable).

**Dispatch collision detection** (`RopChain.from_jop_chain`): validates that all
dispatch entries in a chain use unique offsets. Checks for memory region overlaps
between dispatch entries and the ROP chain payload.

## Kernel Support (`ThunkRewriter.py`)

Linux kernels with retpoline mitigations replace control flow instructions:
- `ret` → `jmp __x86_return_thunk` (semantically = ret)
- `jmp reg` → `jmp __x86_indirect_thunk_<reg>` (semantically = jmp reg)
- `call reg` → `call __x86_indirect_thunk_<reg>` (semantically = call reg)

ROPgadget extracts ~1.3M gadgets from a typical vmlinux, but Triton can't analyze
thunk-ending gadgets because the `jmp` goes to an address outside the gadget's opcode
buffer → `TYPE_UNKNOWN` → discarded.

### Thunk Detection (`ThunkConfig.from_elf`)

Auto-detects thunks from ELF `.symtab` symbols:
- `__x86_return_thunk` → return thunk addresses
- `__x86_indirect_thunk_<reg>` → indirect thunk addresses mapped to register names
- `.text` section bounds for `--range` filtering

### Gadget Rewriting (`rewrite_gadgets`)

Pre-processes gadgets before Triton analysis:

| Gadget ending | Action |
|---|---|
| `jmp __x86_return_thunk` | Rewrite to `ret` (0xc3 + NOP padding) |
| `jmp __x86_indirect_thunk_<reg>` | Rewrite to `jmp reg` opcode + NOP padding |
| `call __x86_indirect_thunk_<reg>` | Rewrite to `call reg` opcode + NOP padding |
| `call __x86_return_thunk` | Filter out (push+ret = nop, useless) |
| `jmp/call` to unknown address | Filter out (internal branch, not a gadget) |
| `ret N` (return with stack adjust) | Filter out (complicates chain layout) |
| `jmp [rip + N]` | Filter out (PC-relative indirect, not controllable) |

Opcode replacement handles 5-byte near jmp/call (`0xe9`/`0xe8`) and 2-byte short
jmp (`0xeb`), padding with NOPs to maintain gadget length.

Typical impact: ~1.3M raw gadgets → ~117k usable gadgets.

### Usage

```python
e = Exrop("vmlinux")
e.find_gadgets(cache=True, kernel_mode=True)  # auto-detect + rewrite + analyze
chain = e.set_regs({'rdi': 0x41414141})
pivots = e.stack_pivot_reg('rdi')
```

`kernel_mode=True` automatically:
- Detects thunks from ELF symbols
- Sets `--range` to `.text` section
- Uses expanded instruction filter (`or|and|lea|nop` added)
- Sets depth=15 (default for kernel gadget complexity)
- Applies thunk rewriting before Triton analysis

## Chain Assembly (`RopChain`)

### Data Model

```
RopChain
  +-- chains: [Chain, ...]     ordered list of chain segments
  +-- next_call: Chain          optional function call appended at the end
  +-- base_addr: int            base address for ASLR-relative addresses

Chain
  +-- gadget: Gadget            the gadget this chain segment uses
  +-- chain_values: [ChainItem] stack layout (gadget addr + popped values + padding)
  +-- solved_regs: set          registers this chain solves
  +-- written_regs: set         registers this chain clobbers (including side effects)
  +-- depends_regs: set         registers this chain depends on (must be set before)

ChainItem
  +-- value: int                concrete value to place on stack
  +-- type_val: 0|1             0=raw value, 1=address (add base_addr)
  +-- idx_chain: int            position in the stack layout
  +-- comment: str              annotation (gadget disassembly)
```

### Chain Ordering (`insert_chain`)

When a new chain segment is inserted, it must be ordered to avoid clobbering:

- If the new chain's `written_regs` overlap with already-solved registers,
  it is inserted at the correct position so that:
  - Chains whose results it depends on execute before it
  - Chains that depend on registers it clobbers execute after it
- If no valid position exists (circular dependency), insertion fails

### Output

`dump()` prints the stack layout:
```
$RSP+0x0000 : 0x0000000000001000 # pop rdi ; ret
$RSP+0x0008 : 0x0000000041414141
$RSP+0x0010 : 0x0000000000002000 # mov qword ptr [rdi], rcx ; ret
```

`payload_str()` returns raw bytes for exploit integration.

## High-Level API (`Exrop`)

| Method | Description |
|---|---|
| `set_regs({reg: val})` | Set registers to values |
| `set_writes({addr: val})` | Write values to memory addresses |
| `set_string({addr: str})` | Write null-terminated strings (splits into 8-byte writes) |
| `func_call(addr, args)` | Set up sysv calling convention + call target |
| `syscall(num, args)` | Set up syscall registers + find syscall gadget |
| `stack_pivot(addr)` | Redirect RSP to controlled memory |
| `stack_pivot_reg(reg)` | Find kernel-style pivots from a register (direct + JOP) |
| `find_gadgets(kernel_mode=True)` | Auto-detect thunks, rewrite, analyze |
| `clean_only = True` | Filter out gadgets with dangerous side-effect memory writes |

Chains can be composed via `merge_ropchain()` / `+` operator for multi-stage payloads:
```python
chain  = e.func_call(open_addr, ["flag.txt", 0])
chain += e.func_call(read_addr, [3, buf_addr, 0x100])
chain += e.func_call(write_addr, [1, buf_addr, 0x100])
```

## File Map

| File | Role |
|---|---|
| `Exrop.py` | User-facing API, ROPgadget integration |
| `ChainBuilder.py` | Gadget management, multiprocessing, pickle cache, sorting |
| `Gadget.py` | Per-gadget symbolic execution with Triton |
| `Solver.py` | Constraint solving: registers, memory writes, pivots, JOP chains |
| `RopChain.py` | Chain data structures, ordering, serialization, PivotInfo |
| `ThunkRewriter.py` | Kernel thunk detection and gadget rewriting |
| `tests/test.py` | Pytest harness, auto-discovers test data files |
| `tests/*` | Test data files (gadget dicts with expected solve type) |
| `examples/` | Usage examples on real binaries |
