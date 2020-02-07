def isintersect(a,b):
    for i in a:
        for j in b:
            if i==j:
                return True
    return False

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

    def set_solved(self, gadget, values, regs=set(), written_regs=set(), depends_regs=set()):
        self.solved_regs.update(regs)
        self.written_regs.update(gadget.written_regs)
        self.written_regs.update(written_regs)
        self.depends_regs.update(depends_regs)
        self.gadget = gadget
        depends_chain_values = []
        chain_values = [ChainItem(0)]*(gadget.diff_sp//8 + 1)
        chain_values[0] = ChainItem(gadget.addr, 0, str(gadget), CHAINITEM_TYPE_ADDR)
        for chain_item in values:
            if isinstance(chain_item, RopChain):
                self.written_regs.update(chain_item.get_written_regs())
                self.depends_regs.update(chain_item.get_depends_regs())
                depends_chain_values += chain_item.get_chains()
                continue
            if chain_item:
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
