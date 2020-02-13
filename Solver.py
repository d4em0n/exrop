import code
import pickle
from itertools import combinations, chain
from triton import *
from Gadget import *
from RopChain import *

def initialize():
    ctx = TritonContext()
    ctx.setArchitecture(ARCH.X86_64)
    ctx.setMode(MODE.ALIGNED_MEMORY, True)
    ctx.setAstRepresentationMode(AST_REPRESENTATION.PYTHON)
    return ctx

def isintersect(a,b):
    for i in a:
        for j in b:
            if i==j:
                return True
    return False

def findCandidatesWriteGadgets(gadgets, avoid_char=None):
    candidates = {}
    for gadget in list(gadgets):
        badchar = False
        if avoid_char:
            for char in avoid_char:
                addrb = gadget.addr.to_bytes(8, 'little')
                if char in addrb:
                    badchar = True
                    break
        if badchar:
            continue
        if gadget.is_memory_write:
            isw = gadget.is_memory_write
            if not isw in candidates:
                candidates[isw] = [gadget]
                continue
            candidates[isw].append(gadget)
    return candidates

def findForRet(gadgets, min_diff_sp=0, not_write_regs=set(), avoid_char=None):
    for gadget in list(gadgets):
        badchar = False
        if avoid_char:
            for char in avoid_char:
                addrb = gadget.addr.to_bytes(8, 'little')
                if char in addrb:
                    badchar = True
                    break
        if badchar:
            continue
        if isintersect(not_write_regs, gadget.written_regs):
            continue
        if not gadget.is_memory_read and not gadget.is_memory_write and not gadget.is_syscall and gadget.end_type == TYPE_RETURN and gadget.diff_sp == min_diff_sp:
            return gadget

def findPivot(gadgets, not_write_regs=set(), avoid_char=None):
    candidates = []
    for gadget in list(gadgets):
        badchar = False
        if avoid_char:
            for char in avoid_char:
                addrb = gadget.addr.to_bytes(8, 'little')
                if char in addrb:
                    badchar = True
                    break
        if badchar:
            continue
        if isintersect(not_write_regs, gadget.written_regs):
            continue
        if gadget.pivot:
            candidates.append(gadget)
    return candidates

def findSyscall(gadgets, not_write_regs=set(), avoid_char=None):
    syscall_noret = None
    for gadget in list(gadgets):
        badchar = False
        if avoid_char:
            for char in avoid_char:
                addrb = gadget.addr.to_bytes(8, 'little')
                if char in addrb:
                    badchar = True
                    break
        if badchar:
            continue
        if isintersect(not_write_regs, gadget.written_regs):
            continue

        if not gadget.is_memory_read and not gadget.is_memory_write and gadget.is_syscall:
            if gadget.end_type == TYPE_RETURN:
                return gadget
            syscall_noret = gadget

    return syscall_noret

def findCandidatesGadgets(gadgets, regs_write, regs_items, not_write_regs=set(), avoid_char=None, cand_write_first=False):
    candidates_pop = []
    candidates_write = []
    candidates_depends = []
    candidates_defined = []
    candidates_defined2 = []
    candidates_no_return = []
    candidates_for_ret = []
    depends_regs = set()
    for gadget in list(gadgets):
        if isintersect(not_write_regs, gadget.written_regs) or gadget.is_memory_read or gadget.is_memory_write or gadget.end_type in [TYPE_UNKNOWN, TYPE_JMP_MEM, TYPE_CALL_MEM]:
            gadgets.remove(gadget)
            continue
        badchar = False
        if avoid_char:
            for char in avoid_char:
                addrb = gadget.addr.to_bytes(8, 'little')
                if char in addrb:
                    badchar = True
                    break
        if badchar:
            continue

        if isintersect(regs_write,set(gadget.defined_regs.keys())):
            if regs_items and isintersect(regs_items, set(gadget.defined_regs.items())):
                candidates_defined2.append(gadget)
            else:
                candidates_defined.append(gadget)
            gadgets.remove(gadget)
            depends_regs.update(gadget.depends_regs)
            continue

        if isintersect(regs_write,gadget.popped_regs):
            candidates_pop.append(gadget)
            gadgets.remove(gadget)
            depends_regs.update(gadget.depends_regs)
            continue

        if isintersect(regs_write,gadget.written_regs):
            candidates_write.append(gadget)
            gadgets.remove(gadget)
            depends_regs.update(gadget.depends_regs)
            continue

    if depends_regs:
        candidates_depends = findCandidatesGadgets(gadgets, depends_regs, set(), not_write_regs)
    if cand_write_first:
        candidates = candidates_write + candidates_defined2 + candidates_pop + candidates_defined + candidates_depends  # ordered by useful gadgets
    else:
        candidates = candidates_defined2 + candidates_pop + candidates_defined + candidates_write + candidates_no_return + candidates_depends  # ordered by useful gadgets

    for gadget in gadgets:
        if gadget.diff_sp in [8,0]:
            candidates_for_ret.append(gadget)
            gadgets.remove(gadget)

    candidates += candidates_for_ret
    return candidates

def extract_byte(bv, pos):
    return (bv >> pos*8) & 0xff

def filter_byte(astctxt, bv, bc, bsize):
    nbv = []
    for i in range(bsize):
        nbv.append(astctxt.lnot(astctxt.equal(astctxt.extract(i*8+7, i*8, bv),astctxt.bv(bc, 8))))
    return nbv

def check_contain_avoid_char(regvals, avoid_char):
    for char in avoid_char:
        for val in regvals:
            if isinstance(val, str):
                continue
            valb = val.to_bytes(8, 'little')
            if char in valb:
                return True
    return False

def get_all_written(tmp_solved):
    written_regs = set()
    for solved in tmp_solved:
        written_regs.update(solved.get_written_regs())
    return written_regs

def get_all_solved(tmp_solved):
    solved_regs = set()
    for solved in tmp_solved:
        solved_regs.update(solved.get_solved_regs())
    return solved_regs

def insert_tmp_solved(tmp_solved, solved):
    intersect = False
    if isintersect(solved.get_written_regs(), get_all_solved(tmp_solved)):
        intersect = True
    if intersect and len(tmp_solved) > 0:
        for i in range(len(tmp_solved)-1, -1, -1):
            solved_before = get_all_solved(tmp_solved[:i+1])
            if isintersect(solved.get_solved_regs(), tmp_solved[i].get_written_regs()) and not isintersect(solved_before, solved.get_written_regs()):
                tmp_solved.insert(i+1, solved)
                break
            regs_used_after = get_all_written(tmp_solved)
            if i == 0:
                if not isintersect(solved.get_solved_regs(), regs_used_after):
                    tmp_solved.insert(0, solved)
                else:
                    return False
    else:
        tmp_solved.append(solved)
    return True

def solveGadgets(gadgets, solves, avoid_char=None, keep_regs=set(), add_type=dict(), for_refind=set(), rec_limit=0):
    regs = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
    find_write_first = False
    if avoid_char:
        find_write_first = check_contain_avoid_char(solves.values(), avoid_char)
    candidates = findCandidatesGadgets(gadgets[:], set(solves.keys()), set(solves.items()), avoid_char=avoid_char, cand_write_first=find_write_first)
    ctx = initialize()
    astCtxt = ctx.getAstContext()
    chains = RopChain()
    reg_refind = set()

    if rec_limit >= 30: # maximum recursion
        return []

    for gadget in candidates:
        tmp_solved_ordered = []
        tmp_solved_regs = set()
        tmp_solved_ordered2 = []
        if not gadget.is_asted:
            gadget.buildAst()
        reg_to_reg_solve = set()

        if isintersect(keep_regs, gadget.written_regs):
            continue

        for reg,val in solves.items():
            if reg not in gadget.written_regs or reg in gadget.end_reg_used:
                continue

            regAst = gadget.regAst[reg]
            if reg in gadget.defined_regs and gadget.defined_regs[reg] == val:
                tmp_solved_regs.add(reg)
                tmp_solved_ordered.append([])
                if isinstance(val, str):
                    reg_to_reg_solve.add(val)
                continue

            refind_dict = {}
            if isinstance(val, str): # probably registers
                if reg in gadget.defined_regs and isinstance(gadget.defined_regs[reg], str) and gadget.defined_regs[reg] != reg:
                    refind_dict[gadget.defined_regs[reg]] = val
                    hasil = []
                else:
                    continue
            else:
                if avoid_char:
                    if reg in gadget.defined_regs and isinstance(gadget.defined_regs[reg],int):
                        continue
                    childs = astCtxt.search(regAst, AST_NODE.VARIABLE)
                    filterbyte = []
                    hasil = False
                    valb = val.to_bytes(8, 'little')
                    lval = len(valb.strip(b"\x00"))
                    for char in avoid_char:
                        if char in valb:
                            for child in childs:
                                for char in avoid_char:
                                    fb = filter_byte(astCtxt, child, char, lval)
                                    filterbyte.extend(fb)
                            if filterbyte:
                                filterbyte.append(regAst == astCtxt.bv(val,64))
                    if filterbyte:
                        filterbyte = astCtxt.land(filterbyte)
                        hasil = list(ctx.getModel(filterbyte).values())
                    if not hasil: # try to find again
                        hasil = list(ctx.getModel(regAst == astCtxt.bv(val,64)).values())

                else:
                    hasil = list(ctx.getModel(regAst == astCtxt.bv(val,64)).values())

            for v in hasil:
                alias = v.getVariable().getAlias()
                if 'STACK' not in alias: # check if value is found not in stack
                    if alias in regs and alias not in refind_dict: # check if value is found in reg

                        # check if reg for next search contain avoid char, if
                        # true break
                        if alias == reg and avoid_char:
                            valb = v.getValue().to_bytes(8, 'little')
                            for char in avoid_char:
                                if char in valb:
                                    hasil = False
                                    refind_dict = False
                            if not hasil:
                                break

                        if ((alias != reg and (alias,val) not in for_refind) or v.getValue() != val):
                            refind_dict[alias] = v.getValue() # re-search value with new reg
                        else:
                            hasil = False
                            refind_dict = False
                            break
                    else:
                        hasil = False
                        break
                elif avoid_char: # check if stack is popped contain avoid char
                    for char in avoid_char:
                        if char in val.to_bytes(8, 'little'):
                            hasil = False
                            refind_dict = False
                            break
            if refind_dict:
#                print((gadget,refind_dict,rec_limit))
                tmp_for_refind = for_refind.copy() # don't overwrite old value
                tmp_for_refind.add((reg,val))
                reg_refind.update(set(list(refind_dict.keys())))
                hasil = solveGadgets(candidates[:], refind_dict, avoid_char, for_refind=tmp_for_refind, rec_limit=rec_limit+1)

            if hasil:
                if isinstance(val, str):
                    reg_to_reg_solve.add(gadget.defined_regs[reg])
                if not isinstance(hasil, RopChain):
                    type_chain = CHAINITEM_TYPE_VALUE
                    if add_type and reg in add_type and add_type[reg] == CHAINITEM_TYPE_ADDR:
                        type_chain = CHAINITEM_TYPE_ADDR
                    hasil = ChainItem.parseFromModel(hasil, type_val=type_chain)
                    tmp_solved_ordered.append(hasil)
                    tmp_solved_regs.add(reg)
                else:
                    if insert_tmp_solved(tmp_solved_ordered2, hasil):
                        tmp_solved_regs.add(reg)

        if not tmp_solved_regs:
            continue

        if gadget.end_type != TYPE_RETURN:
            if isintersect(set(list(solves.keys())), gadget.end_reg_used) or not gadget.end_ast:
                continue
            next_gadget = None
#            print("handling no return gadget")
            diff = 0
            if gadget.end_type == TYPE_JMP_REG:
                next_gadget = findForRet(candidates[:], 0, tmp_solved_regs, avoid_char=avoid_char)
            elif gadget.end_type == TYPE_CALL_REG:
                next_gadget = findForRet(candidates[:], 8, tmp_solved_regs, avoid_char=avoid_char)
                diff = 8
            if not next_gadget:
                continue
            gadget.end_gadget = next_gadget
            gadget.diff_sp += next_gadget.diff_sp - diff

            regAst = gadget.end_ast
            val = gadget.end_gadget.addr
            hasil = list(ctx.getModel(regAst == val).values())

            refind_dict = {}
            type_chains = {}
            for v in hasil:
                alias = v.getVariable().getAlias()
                if 'STACK' not in alias:
                    if alias in regs and alias not in refind_dict:
                        refind_dict[alias] = v.getValue()
                        type_chains[alias] = CHAINITEM_TYPE_ADDR
                    else:
                        hasil = False
                        break
            if refind_dict:
                reg_to_reg_solve.update(tmp_solved_regs)
                reg_to_reg_solve.update(reg_refind)
                hasil = solveGadgets(gadgets, refind_dict, avoid_char, add_type=type_chains, keep_regs=reg_to_reg_solve, rec_limit=rec_limit+1)
            if not hasil:
                continue
            if not isinstance(hasil, RopChain):
                type_chain = CHAINITEM_TYPE_ADDR
                hasil = ChainItem.parseFromModel(hasil, type_val=type_chain)
                tmp_solved_ordered.append(hasil)
            else:
                insert_tmp_solved(tmp_solved_ordered2, hasil)

        tmp_solved_ordered.extend(tmp_solved_ordered2)
        dep_regs = set()
        if reg_to_reg_solve:
            dep_regs = reg_to_reg_solve - tmp_solved_regs

        tmp_chain = Chain()
        tmp_chain.set_solved(gadget, tmp_solved_ordered, tmp_solved_regs, depends_regs=dep_regs)

        if not chains.insert_chain(tmp_chain):
#            print("failed insert")
            continue # can't insert chain

        for reg in tmp_solved_regs:
            if reg in solves:
                del solves[reg]

        if not solves:
            return chains

    return []

def solveWriteGadgets(gadgets, solves, avoid_char=None):
    regs = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
    final_solved = []
    candidates = findCandidatesWriteGadgets(gadgets[:], avoid_char=avoid_char)
    ctx = initialize()
    gwr = list(candidates.keys())
    chains = RopChain()
    gwr.sort()
    for w in gwr:
        for gadget in candidates[w]:
            if not gadget.is_asted:
                gadget.buildAst()
            for addr,val in list(solves.items())[:]:
                mem_ast = gadget.memory_write_ast[0]
                if mem_ast[1].getBitvectorSize() != 64:
                    break
                addrhasil = ctx.getModel(mem_ast[0] == addr).values()
                valhasil = ctx.getModel(mem_ast[1] == val).values()
                if not addrhasil or not valhasil:
                    break
                hasil = list(addrhasil) + list(valhasil)
                refind_dict = {}
#                code.interact(local=locals())
                for v in hasil:
                    alias = v.getVariable().getAlias()
                    if 'STACK' not in alias:
                        if alias in regs and alias not in refind_dict:
                            refind_dict[alias] = v.getValue()
                        else:
                            hasil = False
                            break
                if hasil and refind_dict:
                    hasil = solveGadgets(gadgets[:], refind_dict, avoid_char=avoid_char)
                if hasil:
                    del solves[addr]
                    chain = Chain()
                    chain.set_solved(gadget, [hasil])
                    chains.insert_chain(chain)
                    if not solves:
                        return chains

def solvePivot(gadgets, addr_pivot, avoid_char=None):
    regs = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
    candidates = findPivot(gadgets, avoid_char=avoid_char)
    ctx = initialize()
    chains = RopChain()
    for gadget in candidates:
        if not gadget.is_asted:
            gadget.buildAst()
        hasil = ctx.getModel(gadget.pivot_ast == addr_pivot).values()
        for v in hasil:
            alias = v.getVariable().getAlias()
            refind_dict = dict()
            if 'STACK' not in alias:
                if alias in regs and alias not in refind_dict:
                    refind_dict[alias] = v.getValue()
                else:
                    hasil = False
                    break
            else:
                idxchain = int(alias.replace("STACK", ""))
                new_diff_sp = (idxchain+1)*8
        if hasil and refind_dict:
            hasil = solveGadgets(gadgets[:], refind_dict, avoid_char=avoid_char)
            new_diff_sp = 0
        if not hasil:
            continue
        gadget.diff_sp = new_diff_sp
        chain = Chain()
        chain.set_solved(gadget, [hasil])
        chains.insert_chain(chain)
        return chains
