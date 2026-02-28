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
| `TYPE_JMP_MEM` / `TYPE_CALL_MEM` | Indirect via memory | Rejected by solver |

After execution, for each written register:

- `regAst[reg]` stores the full symbolic AST
- `defined_regs[reg]` stores the simplified value if it's a constant (`xor rax,rax` -> `0`)
  or a direct register copy (`mov rax,rbx` -> `"rbx"`)
- `depends_regs` = read registers minus constant-defined registers

### 3. Caching (`ChainBuilder.save_analyzed_gadgets`)

Analyzed gadgets are serialized with pickle. AST nodes (Triton `AstNode` objects) cannot
be pickled, so `__getstate__` strips them. On cache load, gadgets have `is_asted=False`
and ASTs are rebuilt on-demand via `buildAst()` when the solver needs them.

Multiprocessing (`Pool.imap_unordered`) parallelizes analysis across CPU cores.

## Solver Design (`Solver.py`)

### Register Solving (`solveGadgets`)

Goal: given `{reg: value, ...}`, find a chain of gadgets that sets each register.

**Candidate search** (`findCandidatesGadgets`) prioritizes gadgets by type:

```
1. candidates_defined2  -- gadget defines reg to exact (reg, value) pair needed
2. candidates_pop       -- gadget pops the target register from stack
3. candidates_defined   -- gadget defines the target register (but different value)
4. candidates_write     -- gadget writes the target register (computed, not pop/define)
5. candidates_depends   -- recursive: gadgets for dependency registers
6. candidates_for_ret   -- small helper gadgets (diff_sp 0 or 8) for non-return fixups
```

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

### Stack Pivot Solving (`solvePivot`)

Finds gadgets that modify RSP to a controlled value (e.g., `xchg rsp, rax`).
The `pivot_ast` captures the symbolic expression for the new RSP value.

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
| `ChainBuilder.py` | Gadget management, multiprocessing, pickle cache |
| `Gadget.py` | Per-gadget symbolic execution with Triton |
| `Solver.py` | Constraint solving: registers, memory writes, pivots |
| `RopChain.py` | Chain data structures, ordering, serialization |
| `tests/test.py` | Pytest harness, auto-discovers test data files |
| `tests/*` | Test data files (gadget dicts with expected solve type) |
| `examples/` | Usage examples on real binaries |
