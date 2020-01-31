class RopChain(object):
    def __init__(self):
        self.chains = []
        self.dump_str = None
        self.payload = b""
        self.base_addr = 0

    def add(self, gadget, values):
        self.chains.append((gadget, values))
        self.dump_str = None

    def merge_ropchain(self, ropchain):
        for gadget,values in ropchain.chains:
            self.add(gadget, values)

    def dump(self):
        sp = 0
        dump_str = ""
        for gadget,values in self.chains:
            dump_str += "$RSP+0x{:04x} : 0x{:016x} # {}\n".format(sp, self.base_addr + gadget.addr, gadget)
            sp += 8
            for value in values:
                dump_str += "$RSP+0x{:04x} : 0x{:016x}\n".format(sp, value)
                sp += 8
        print(dump_str)

    def payload_str(self):
        payload = b""
        for gadget,values in self.chains:
            payload += (self.base_addr + gadget.addr).to_bytes(8, 'little')
            for value in values:
                payload += value.to_bytes(8, 'little')
        return payload

    def set_base_addr(self, addr):
        self.base_addr = addr

    def insert(self, idx, chain):
        self.chains.insert(idx, chain)

    def append(self, chain):
        self.chains.append(chain)

    def insert_chain(self, chain):
        intersect = False
        if set.intersection(chain.written_regs, set(self.get_solved_regs())):
            intersect = True
        if intersect and len(self.chains) > 0:
            for i in range(len(self.chains)-1, -1, -1):
                solved_before = set(self.get_solved_regs(0,i+1))
                if set.intersection(chain.solved_regs, self.chains[i].written_regs) and not set.intersection(solved_before, chain.written_regs):
                    self.insert(i+1, chain)
                    break

                regs_used_after = set(self.get_written_regs())
                if i == 0:
                    if not set.intersection(chain.solved_regs, regs_used_after):
                        self.insert(0, chain)
                    else:
                        return False
        else:
            self.append(chain)
        return True

    def get_solved_regs(self, start_chain=None, end_chain=None):
        regs_solved = []
        chains = self.chains[start_chain:end_chain]
        for chain in chains:
            regs_solved.extend(chain.solved_regs)
        return regs_solved

    def get_written_regs(self, start_chain=None, end_chain=None):
        regs_written = []
        chains = self.chains[start_chain:end_chain]
        for chain in chains:
            regs_written.extend(chain.written_regs)
        return regs_written

    def get_chains(self):
        chains = []
        for chain in self.chains:
            chains.extend(chain.chains())
        return chains

    def get_comment(self):
        comments = []
        for chain in self.chains:
            comments.extend(chain.comment)
        return comments

    def dump_chains(self):
        next_sp = 0
        for chain in self.chains:
            next_sp = chain.dump(next_sp)
        print("")

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

class Chain(object):
    def __init__(self):
        self.written_regs = set()
        self.solved_regs = set()
        self.chain_values = []
        self.gadget = None

    def set_solved(self, gadget, values, regs=set(), written_regs=set()):
        self.solved_regs.update(regs)
        self.written_regs.update(gadget.written_regs)
        self.written_regs.update(written_regs)
        self.gadget = gadget
        depends_chain_values = []
        chain_values = [ChainItem(0)]*(gadget.diff_sp//8 + 1)
        chain_values[0] = ChainItem(gadget.addr, 0, str(gadget), 1)
        for chain_item in values:
            if isinstance(chain_item, RopChain):
                self.written_regs.update(chain_item.get_written_regs())
                depends_chain_values += chain_item.get_chains()
                continue
            if chain_item:
                chain_values[chain_item.idx_chain] = chain_item

        self.chain_values += depends_chain_values + chain_values
        if gadget.end_gadget:
            self.written_regs.update(gadget.end_gadget.written_regs)

    def chains(self):
        return self.chain_values

    def dump(self, sp):
        chains = self.chains()
        dump_str = ""
        for i in range(len(chains)):
            chain = chains[i]
            com = ""
            if chain.comment:
                com = " # {}".format(chain.comment)
            dump_str += "$RSP+0x{:04x} : 0x{:016x}{}\n".format(sp, chain.value, com)
            sp += 8
        print(dump_str, end="")
        return sp

    def __repr__(self):
        return "written_regs : {}\nsolved_regs: {}\n".format(self.written_regs, self.solved_regs)

    def __str__(self):
        return "written_regs : {}\nsolved_regs: {}\n".format(self.written_regs, self.solved_regs)
