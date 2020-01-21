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
