from ChainBuilder import ChainBuilder
from RopChain import RopChain
from Gadget import TYPE_RETURN
from os import popen
import code

def parseRopGadget(filename, opt=""):
    from subprocess import Popen, PIPE, STDOUT
    import re

    cmd = ['ROPgadget', '--binary', filename, '--multibr', '--only',
            'pop|xchg|add|sub|xor|mov|ret|jmp|call|syscall|leave', '--dump']
    if opt:
        cmd.append(opt)
    process = Popen(cmd, stdout=PIPE, stderr=STDOUT)
    stdout, _ = process.communicate()
    output_lines = stdout.splitlines()
    output_lines.sort(key=len)

    sample_gadgets = dict()
    regexp = re.compile(b"(0x.*) : (.*) // (.*)")
    for line in output_lines:
        match = regexp.match(line)
        if match:
            addr = int(match.group(1).decode(), 16)
            insstr = match.group(2).decode()
            opcode = bytes.fromhex(match.group(3).decode())
            sample_gadgets[addr] = (insstr,opcode)
    return sample_gadgets

class Exrop(object):
    def __init__(self, binary):
        self.binary = binary
        self.chain_builder = ChainBuilder()

    def find_gadgets(self, cache=False, add_opt="", num_process=1):
        if cache:
            fcname = "./{}.exrop_cache".format(self.binary.replace("/", "_"))
            try:
                with open(fcname, "rb") as fc:
                    objpic = fc.read()
                    self.chain_builder.load_analyzed_gadgets(objpic)
                    return
            except FileNotFoundError:
                fc = open(fcname, "wb")
        gadgets = parseRopGadget(self.binary, add_opt)
        self.chain_builder.load_list_gadget_string(gadgets)
        self.chain_builder.analyzeAll(num_process)
        if cache:
            objpic = self.chain_builder.save_analyzed_gadgets()
            fc.write(objpic)
            fc.close()

    def load_raw_gadgets(self, gadgets):
        pass

    def stack_pivot(self, addr, avoid_char=None):
        self.chain_builder.solve_pivot(addr, avoid_char)
        ropchain = self.chain_builder.build_chain()
        return ropchain

    def set_regs(self, regs, next_call=None, avoid_char=None):
        self.chain_builder.set_regs(regs)
        self.chain_builder.solve_chain(avoid_char)
        ropchain = self.chain_builder.build_chain(next_call)
        return ropchain

    def set_writes(self, writes, next_call=None, avoid_char=None):
        self.chain_builder.set_writes(writes)
        self.chain_builder.solve_chain_write(avoid_char=avoid_char)
        ropchain = self.chain_builder.build_chain(next_call)
        return ropchain

    def set_string(self, strs, next_call=None, avoid_char=None):
        BSIZE = 8
        writes = dict()
        for addr,sstr in strs.items():
            tmpaddr = 0
            sstr += "\x00"
            for i in range(0, len(sstr), BSIZE):
                tmpstr = int.from_bytes(bytes(sstr[i:i+BSIZE], 'utf-8'), 'little')
                writes[addr+tmpaddr] = tmpstr
                tmpaddr += BSIZE
        return self.set_writes(writes, next_call, avoid_char=avoid_char)

    def func_call(self, func_addr, args, rwaddr=None, convention="sysv", type_val_addr=0, comment=""):
        call_convention = {
            "sysv": ["rdi", "rsi", "rdx", "rcx", "r8", "r9"],
            "syscall_x86-64": ["rax", "rdi", "rsi", "rdx", "r10", "r8", "r9"]
        }

        order_reg = call_convention[convention]
        regsx86_64 = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
        regs = dict()
        ropchain = RopChain()
        for i in range(len(args)):
            arg = args[i]
            if isinstance(arg, str) and arg not in regsx86_64:
                assert rwaddr, "Please define read write addr"
                chain = self.set_string({rwaddr:arg})
                ropchain.merge_ropchain(chain)
                regs[order_reg[i]] = rwaddr
                rwaddr += len(arg) + 1 # for null byte
                continue
            regs[order_reg[i]] = arg
        chain = self.set_regs(regs)
        ropchain.merge_ropchain(chain)
        ropchain.set_next_call(func_addr, type_val_addr, comment=comment)
        return ropchain

    def syscall(self, sysnum, args, rwaddr=None):
        reg_used_syscall = set(["rax", "rdi", "rsi", "rdx", "r10", "r8", "r9"])
        args = (sysnum,) + args
        syscall = self.chain_builder.get_syscall_addr(not_write_regs=reg_used_syscall)
        assert syscall,"can't find syscall gadget!"
        chain = self.func_call(syscall.addr, args, rwaddr, convention="syscall_x86-64", type_val_addr=1, comment=str(syscall))
        if syscall.end_type != TYPE_RETURN:
            chain.is_noreturn = True
        return chain
