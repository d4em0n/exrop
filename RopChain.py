import struct

def isintersect(a, b):
    return not a.isdisjoint(b)


class PivotInfo(object):
    """Result of a kernel-style pivot gadget search.

    Attributes:
        gadget_addr: Address of the pivot gadget (for the hijacked function pointer).
        gadget: The Gadget object.
        src_reg: Register the pivot reads from (e.g., 'rdi').
        offset: Offset from src_reg where pivot reads/starts.
        is_indirect: True if pivot loads rsp from memory (Type 3).
        pivot_type: 'direct', 'offset', or 'indirect'.
    """

    def __init__(self, gadget, src_reg, offset=0, is_indirect=False):
        self.gadget_addr = gadget.addr
        self.gadget = gadget
        self.src_reg = src_reg
        self.offset = offset
        self.is_indirect = is_indirect
        self.jop_gadget = None
        self.pivot_gadget = None
        self.dispatch_offset = None
        self.chain_offset_computed = None
        self.dispatch_entries = []  # list of (offset, target_addr) for multi-step JOP
        self.jop_chain = []  # list of (gadget, dispatch_offset) for all JOP steps

        if is_indirect:
            self.pivot_type = 'indirect'
        elif offset != 0:
            self.pivot_type = 'offset'
        else:
            self.pivot_type = 'direct'

    @classmethod
    def from_jop_chain(cls, jop_steps, pivot_gadget, src_reg,
                       chain_offset, jop_indirect=False):
        """Create PivotInfo for a JOP->pivot chain (supports multi-step).

        jop_steps: list of (gadget, dispatch_offset_from_src_reg), entry first.
        jop_indirect: True if the pivot register gets a value LOADED from
        memory (pointer) rather than a direct src_reg+offset expression.

        Returns None if the layout is invalid (overlap or negative offsets).
        """
        if not jop_steps or chain_offset < 0:
            return None

        entry_gadget = jop_steps[0][0]
        info = cls(entry_gadget, src_reg)
        info.pivot_type = 'jop_indirect' if jop_indirect else 'jop'
        info.jop_gadget = entry_gadget
        info.pivot_gadget = pivot_gadget
        info.dispatch_offset = jop_steps[0][1]  # first dispatch (backward compat)
        info.chain_offset_computed = chain_offset
        info.gadget_addr = entry_gadget.addr
        info.jop_chain = list(jop_steps)

        # Build dispatch_entries: each step dispatches to the next gadget
        info.dispatch_entries = []
        for i, (g, off) in enumerate(jop_steps):
            if off < 0:
                return None
            if i + 1 < len(jop_steps):
                target_addr = jop_steps[i + 1][0].addr
            else:
                target_addr = pivot_gadget.addr
            info.dispatch_entries.append((off, target_addr))

        # Check for dispatch offset collisions: same offset but different targets
        seen_offsets = {}
        for off, addr in info.dispatch_entries:
            if off in seen_offsets and seen_offsets[off] != addr:
                return None  # same slot needs different values
            seen_offsets[off] = addr

        # Check for overlaps between all dispatch slots and chain_offset
        used_ranges = list(set((off, off + 8) for off, _ in info.dispatch_entries))
        for i, (s1, e1) in enumerate(used_ranges):
            for j, (s2, e2) in enumerate(used_ranges):
                if i == j:
                    continue
                if s1 < e2 and s2 < e1:
                    return None  # dispatch slots overlap
            if not jop_indirect:
                if s1 < chain_offset + 8 and chain_offset < e1:
                    return None  # dispatch overlaps chain

        return info

    def dump(self):
        if self.pivot_type in ('jop', 'jop_indirect', 'jop_push'):
            n_steps = len(self.jop_chain)
            if self.pivot_type == 'jop_push':
                label = "jop_push (stack transfer)"
            elif self.pivot_type == 'jop':
                label = "jop"
            else:
                label = "jop_indirect"
            if n_steps > 1:
                label += " ({}-step chain)".format(n_steps)
            elif self.pivot_type == 'jop':
                label += " (chained)"
            elif self.pivot_type == 'jop_indirect':
                label += " (chained, pointer)"
            print("Pivot type: {}".format(label))
            for i, (g, off) in enumerate(self.jop_chain):
                print("  Step {}: 0x{:016x} # {}".format(i + 1, g.addr, g))
            print("  Pivot:  0x{:016x} # {}".format(self.pivot_gadget.addr, self.pivot_gadget))
            for off, addr in self.dispatch_entries:
                print("  Dispatch: place 0x{:x} at [{}+0x{:x}]".format(addr, self.src_reg, off))
            if self.pivot_type == 'jop_indirect':
                print("  Place ROP chain address at [{}+0x{:x}]".format(self.src_reg, self.chain_offset_computed))
            else:
                print("  ROP chain starts at [{}+0x{:x}]".format(self.src_reg, self.chain_offset_computed))
            return
        print("Pivot type: {}".format(self.pivot_type))
        print("  Gadget: 0x{:016x} # {}".format(self.gadget_addr, self.gadget))
        print("  Source register: {}".format(self.src_reg))
        if self.offset:
            print("  Offset: 0x{:x}".format(self.offset))
        if self.is_indirect:
            print("  Place ROP chain address at [{}+0x{:x}]".format(self.src_reg, self.offset))
        elif self.offset:
            print("  ROP chain starts at [{}+0x{:x}]".format(self.src_reg, self.offset))
        else:
            print("  ROP chain starts at [{}]".format(self.src_reg))

    def build_payload(self, rop_chain, obj_size=0x100):
        """Build exploit object layout with the ROP chain placed at the correct offset.

        Args:
            rop_chain: RopChain object containing the post-pivot chain.
            obj_size: Total size of the controlled object.

        Returns:
            dict with:
            - 'func_ptr': gadget address (for hijacked vtable/function pointer)
            - 'obj_layout': bytearray of the object
            - 'chain_offset': where the ROP chain was placed
            - 'description': human-readable layout description
        """
        obj = bytearray(obj_size)
        chain_bytes = rop_chain.payload_str()

        if self.pivot_type in ('jop', 'jop_indirect', 'jop_push'):
            # Place all dispatch entries in the object
            for off, addr in self.dispatch_entries:
                struct.pack_into('<Q', obj, off, addr)

            if self.pivot_type in ('jop', 'jop_push'):
                chain_start = self.chain_offset_computed
                obj[chain_start:chain_start + len(chain_bytes)] = chain_bytes
                desc_parts = []
                for off, addr in self.dispatch_entries:
                    desc_parts.append("0x{:x} at object+0x{:x}".format(addr, off))
                return {
                    'func_ptr': self.jop_gadget.addr,
                    'obj_layout': bytes(obj),
                    'chain_offset': chain_start,
                    'dispatch_entries': list(self.dispatch_entries),
                    'description': "JOP chain: place {}, ROP chain at object+0x{:x}".format(
                        ", ".join(desc_parts), chain_start),
                }
            else:  # jop_indirect
                ptr_offset = self.chain_offset_computed
                # Find safe location for chain data after all used slots
                max_used = max(off + 8 for off, _ in self.dispatch_entries)
                chain_data_start = max(max_used, ptr_offset + 8)
                struct.pack_into('<Q', obj, ptr_offset, chain_data_start)
                obj[chain_data_start:chain_data_start + len(chain_bytes)] = chain_bytes
                desc_parts = []
                for off, addr in self.dispatch_entries:
                    desc_parts.append("0x{:x} at object+0x{:x}".format(addr, off))
                return {
                    'func_ptr': self.jop_gadget.addr,
                    'obj_layout': bytes(obj),
                    'chain_offset': chain_data_start,
                    'ptr_offset': ptr_offset,
                    'dispatch_entries': list(self.dispatch_entries),
                    'description': (
                        "JOP indirect: place {}, "
                        "ROP chain pointer at object+0x{:x}, chain data at object+0x{:x}"
                    ).format(", ".join(desc_parts), ptr_offset, chain_data_start),
                }

        if self.is_indirect:
            # Pointer to ROP chain goes at [src_reg + offset]
            # Place chain data right after the pointer
            chain_start = self.offset + 8
            # Write a relative offset as placeholder; user adds base address at runtime
            struct.pack_into('<Q', obj, self.offset, chain_start)
            obj[chain_start:chain_start + len(chain_bytes)] = chain_bytes
            return {
                'func_ptr': self.gadget_addr,
                'obj_layout': bytes(obj),
                'chain_offset': chain_start,
                'ptr_offset': self.offset,
                'description': "Place ROP chain address at object+0x{:x}, ROP chain at object+0x{:x}".format(
                    self.offset, chain_start),
            }
        else:
            # Direct/offset: ROP chain starts at [src_reg + offset]
            obj[self.offset:self.offset + len(chain_bytes)] = chain_bytes
            return {
                'func_ptr': self.gadget_addr,
                'obj_layout': bytes(obj),
                'chain_offset': self.offset,
                'description': "Place ROP chain at object+0x{:x}".format(self.offset),
            }

    def __repr__(self):
        if self.pivot_type in ('jop', 'jop_indirect', 'jop_push'):
            steps_str = "->".join("0x{:x}".format(g.addr) for g, _ in self.jop_chain)
            return "PivotInfo(jop=[{}]->pivot=0x{:x}, {}, type={}, chain=0x{:x})".format(
                steps_str, self.pivot_gadget.addr,
                self.src_reg, self.pivot_type, self.chain_offset_computed)
        return "PivotInfo(0x{:x}, {}, type={}, offset=0x{:x})".format(
            self.gadget_addr, self.src_reg, self.pivot_type, self.offset)

class RopChain(object):
    def __init__(self):
        self.chains = []
        self.dump_str = None
        self.payload = b""
        self.base_addr = 0
        self.next_call = None
        self.is_noreturn = False

    def merge_ropchain(self, ropchain):
        assert not self.is_noreturn, "can't merge ropchain, this chain is no-return"
        assert isinstance(ropchain, RopChain), "not RopChain instance"
        if self.next_call:
            self.append(self.next_call)
        for chain in ropchain.chains:
            self.append(chain)
        self.next_call = ropchain.next_call

    def __add__(self, ropchain):
        self.merge_ropchain(ropchain)
        return self

    def set_next_call(self, addr, type_val=0, comment=""):
        chain = Chain()
        chain.set_chain_values([ChainItem(addr, type_val, comment)])
        self.next_call = chain

    def set_base_addr(self, addr):
        self.base_addr = addr

    def insert(self, idx, chain):
        self.chains.insert(idx, chain)

    def append(self, chain):
        self.chains.append(chain)

    def insert_chain(self, chain):
        intersect = False
        if isintersect(chain.written_regs, set(self.get_solved_regs())):
            intersect = True
        if intersect and len(self.chains) > 0:
            for i in range(len(self.chains)-1, -1, -1):
                solved_before = set(self.get_solved_regs(0,i+1))
                written_before = set(self.get_written_regs(0, i+1))
                if isintersect(chain.solved_regs, self.chains[i].written_regs) and not isintersect(solved_before, chain.written_regs):
                    self.insert(i+1, chain)
                    break

                if i == 0:
                    regs_used_after = set(self.get_written_regs())
                    depends_regs_after = set(self.get_depends_regs())
                    if not isintersect(chain.solved_regs, regs_used_after) and not isintersect(chain.written_regs, depends_regs_after):
                        self.insert(0, chain)
                    else:
                        return False
        else:
            self.append(chain)
        return True

    def evict_clobbered(self):
        """Remove later chains that clobber an earlier chain's solved_regs.

        Returns set of solved_regs from removed chains."""
        evicted = set()
        changed = True
        while changed:
            changed = False
            for i in range(len(self.chains)):
                written_after = self.get_written_regs(i+1)
                clobbered = self.chains[i].solved_regs & written_after
                if clobbered:
                    # Find the last chain that does the clobbering
                    for j in range(len(self.chains)-1, i, -1):
                        if self.chains[i].solved_regs & self.chains[j].written_regs:
                            evicted.update(self.chains[j].solved_regs)
                            self.chains.pop(j)
                            changed = True
                            break
                    break
        return evicted

    def get_solved_regs(self, start_chain=None, end_chain=None):
        regs_solved = set()
        chains = self.chains[start_chain:end_chain]
        for chain in chains:
            regs_solved.update(chain.solved_regs)
        return regs_solved

    def get_written_regs(self, start_chain=None, end_chain=None):
        regs_written = set()
        chains = self.chains[start_chain:end_chain]
        for chain in chains:
            regs_written.update(chain.written_regs)
        return regs_written

    def get_depends_regs(self, start_chain=None, end_chain=None):
        regs_depends = set()
        chains = self.chains[start_chain:end_chain]
        for chain in chains:
            regs_depends.update(chain.depends_regs)
        return regs_depends

    def get_chains(self):
        chains = []
        for chain in self.chains:
            chains.extend(chain.get_chains())
        return chains

    def get_comment(self):
        comments = []
        for chain in self.chains:
            comments.extend(chain.comment)
        return comments

    def dump(self):
        next_sp = 0
        for chain in self.chains:
            next_sp = chain.dump(next_sp, self.base_addr)
        if self.next_call:
            self.next_call.dump(next_sp, self.base_addr)
        print("")

    def payload_str(self):
        payload = b""
        for chain in self.chains:
            payload += chain.payload_str(self.base_addr)
        if self.next_call:
            payload += self.next_call.payload_str(self.base_addr)
        return payload

CHAINITEM_TYPE_VALUE = 0
CHAINITEM_TYPE_ADDR = 1

class ChainItem(object):
    def __init__(self, value=0, idx_chain=-1, comment="", type_val=0):
        self.value = value
        self.type_val = type_val
        self.comment = comment
        self.idx_chain = idx_chain

    def parseFromModel(chain_value_model, comment="", type_val=0):
        chain_item = chain_value_model[0]
        alias = chain_item.getVariable().getAlias()
        idxchain = int(alias.replace("STACK", "")) + 1
        chain_value = chain_item.getValue()
        return ChainItem(chain_value, idxchain, comment, type_val)

    def getValue(self, base_addr=0):
        if base_addr and self.type_val == 1: # check if value is address
            return self.value + base_addr
        return self.value

class Chain(object):
    def __init__(self):
        self.written_regs = set()
        self.solved_regs = set()
        self.depends_regs = set()
        self.gadget = None
        self.chain_values = []

    def set_chain_values(self, chain_values):
        self.chain_values = chain_values

    def set_solved(self, gadget, values, regs=None, written_regs=None, depends_regs=None):
        if regs is None:
            regs = set()
        if written_regs is None:
            written_regs = set()
        if depends_regs is None:
            depends_regs = set()
        self.solved_regs.update(regs)
        self.written_regs.update(gadget.written_regs)
        self.written_regs.update(written_regs)
        self.depends_regs.update(depends_regs)
        self.gadget = gadget
        depends_chain_values = []
        num_slots = max(gadget.diff_sp // 8 + 1, 1)
        chain_values = [ChainItem(0)] * num_slots
        chain_values[0] = ChainItem(gadget.addr, 0, str(gadget), CHAINITEM_TYPE_ADDR)
        for chain_item in values:
            if isinstance(chain_item, RopChain):
                self.written_regs.update(chain_item.get_written_regs())
                self.depends_regs.update(chain_item.get_depends_regs())
                depends_chain_values += chain_item.get_chains()
                continue
            if chain_item:
                if chain_item.idx_chain >= num_slots:
                    return False
                chain_values[chain_item.idx_chain] = chain_item

        self.chain_values += depends_chain_values + chain_values
        if gadget.end_gadget:
            self.written_regs.update(gadget.end_gadget.written_regs)

    def get_chains(self):
        return self.chain_values

    def get_written_regs(self):
        return self.written_regs

    def get_solved_regs(self):
        return self.solved_regs

    def dump(self, sp, base_addr=0):
        chains = self.get_chains()
        dump_str = ""
        for i in range(len(chains)):
            chain = chains[i]
            com = ""
            if chain.comment:
                com = " # {}".format(chain.comment)
            dump_str += "$RSP+0x{:04x} : 0x{:016x}{}\n".format(sp, chain.getValue(base_addr), com)
            sp += 8
        print(dump_str, end="")
        return sp

    def payload_str(self, base_addr=0):
        chains = self.get_chains()
        payload = b""
        for i in range(len(chains)):
            chain = chains[i]
            payload += chain.getValue(base_addr).to_bytes(8, 'little')
        return payload

    def __repr__(self):
        return "written_regs : {}\nsolved_regs: {}\n".format(self.written_regs, self.solved_regs)

    def __str__(self):
        return "written_regs : {}\nsolved_regs: {}\n".format(self.written_regs, self.solved_regs)
