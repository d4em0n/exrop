from Solver import ChainBuilder

sample_gadgets2 = {
    0x1000: 'pop rsi; ret',
    0x2000: 'mov rbx, rsi; ret',
    0x3000: 'mov rax, rcx; ret',
    0x4000: 'mov rcx, rbx; add rcx, 100; ret',
    0x5000: 'mov rdx, rsi; ret',
    0x6000: 'mov rdi, rax; ret',
}

sample_gadgets2_find = {
    'rax': 0x12345678,
    'rbx': 0x87654321,
    'rcx': 0x22222222,
    'rdx': 0x7fffffff,
    'rsi': 0x41414141,
    'rdi': 0x42424242
}
class Exrop(object):
    def __init__(self, binary, set_regs):
        self.binary = binary
        self.chain_builder = ChainBuilder(set_regs)
        self.gadgets = []

    def load_raw_gadgets(self, gadgets):
        pass
