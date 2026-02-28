import copy
from triton import *
from Gadget import *
from RopChain import *

def _has_badchar(addr, avoid_char):
    addrb = addr.to_bytes(8, 'little')
    for char in avoid_char:
        if char in addrb:
            return True
    return False

def findCandidatesWriteGadgets(gadgets, avoid_char=None):
    candidates = {}
    for gadget in gadgets:
        if avoid_char and _has_badchar(gadget.addr, avoid_char):
            continue
        if gadget.is_memory_write:
            isw = gadget.is_memory_write
            if isw not in candidates:
                candidates[isw] = [gadget]
            else:
                candidates[isw].append(gadget)
    return candidates

def findForRet(gadgets, min_diff_sp=0, not_write_regs=None, avoid_char=None):
    if not_write_regs is None:
        not_write_regs = set()
    for gadget in gadgets:
        if avoid_char and _has_badchar(gadget.addr, avoid_char):
            continue
        if isintersect(not_write_regs, gadget.written_regs):
            continue
        if not gadget.is_memory_read and not gadget.is_memory_write and not gadget.is_syscall and gadget.end_type == TYPE_RETURN and gadget.diff_sp == min_diff_sp:
            return gadget

def findPivot(gadgets, not_write_regs=None, avoid_char=None):
    if not_write_regs is None:
        not_write_regs = set()
    candidates = []
    for gadget in gadgets:
        if avoid_char and _has_badchar(gadget.addr, avoid_char):
            continue
        if isintersect(not_write_regs, gadget.written_regs):
            continue
        if gadget.pivot:
            candidates.append(gadget)
    return candidates

def findSyscall(gadgets, not_write_regs=None, avoid_char=None):
    if not_write_regs is None:
        not_write_regs = set()
    syscall_noret = None
    for gadget in gadgets:
        if avoid_char and _has_badchar(gadget.addr, avoid_char):
            continue
        if isintersect(not_write_regs, gadget.written_regs):
            continue
        if not gadget.is_memory_read and not gadget.is_memory_write and gadget.is_syscall:
            if gadget.end_type == TYPE_RETURN:
                return gadget
            syscall_noret = gadget
    return syscall_noret

def findCandidatesGadgets(gadgets, regs_write, regs_items, not_write_regs=None, avoid_char=None, cand_write_first=False):
    if not_write_regs is None:
        not_write_regs = set()
    candidates_pop = []
    candidates_write = []
    candidates_defined = []
    candidates_defined2 = []
    candidates_for_ret = []
    depends_regs = set()
    remaining = []

    for gadget in gadgets:
        # Filter out unusable gadgets entirely
        if (isintersect(not_write_regs, gadget.written_regs) or
                gadget.is_memory_read or gadget.is_memory_write or
                gadget.end_type in (TYPE_UNKNOWN, TYPE_JMP_MEM, TYPE_CALL_MEM)):
            continue

        if avoid_char and _has_badchar(gadget.addr, avoid_char):
            continue

        # Categorize by how the gadget writes target registers
        if isintersect(regs_write, set(gadget.defined_regs.keys())):
            if regs_items and isintersect(regs_items, set(gadget.defined_regs.items())):
                candidates_defined2.append(gadget)
            else:
                candidates_defined.append(gadget)
            depends_regs.update(gadget.depends_regs)
        elif isintersect(regs_write, gadget.popped_regs):
            candidates_pop.append(gadget)
            depends_regs.update(gadget.depends_regs)
        elif isintersect(regs_write, gadget.written_regs):
            candidates_write.append(gadget)
            depends_regs.update(gadget.depends_regs)
        else:
            remaining.append(gadget)

    # Recursively find gadgets for dependency registers from unclaimed gadgets
    candidates_depends = []
    if depends_regs:
        candidates_depends = findCandidatesGadgets(remaining, depends_regs, set(), not_write_regs)

    if cand_write_first:
        candidates = candidates_write + candidates_defined2 + candidates_pop + candidates_defined + candidates_depends
    else:
        candidates = candidates_defined2 + candidates_pop + candidates_defined + candidates_write + candidates_depends

    # Add small ret/nop gadgets as helpers for non-return fixups
    for gadget in remaining:
        if gadget.diff_sp in (8, 0):
            candidates_for_ret.append(gadget)

    candidates += candidates_for_ret
    return candidates

def filter_byte(astctxt, bv, bc, bsize):
    nbv = []
    for i in range(bsize):
        nbv.append(astctxt.lnot(astctxt.equal(astctxt.extract(i*8+7, i*8, bv), astctxt.bv(bc, 8))))
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

def solveGadgets(gadgets, solves, avoid_char=None, keep_regs=None, add_type=None, for_refind=None, rec_limit=0):
    if keep_regs is None:
        keep_regs = set()
    if add_type is None:
        add_type = dict()
    if for_refind is None:
        for_refind = set()

    # Work on a copy so partial failures don't corrupt the caller's dict
    solves = dict(solves)

    regs = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
    find_write_first = False
    if avoid_char:
        find_write_first = check_contain_avoid_char(solves.values(), avoid_char)
    candidates = findCandidatesGadgets(gadgets[:], set(solves.keys()), set(solves.items()), avoid_char=avoid_char, cand_write_first=find_write_first)
    ctx = initialize()
    astCtxt = ctx.getAstContext()
    chains = RopChain()
    reg_refind = set()

    if rec_limit >= 30:
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

        for reg, val in solves.items():
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
            if isinstance(val, str):
                if reg in gadget.defined_regs and isinstance(gadget.defined_regs[reg], str) and gadget.defined_regs[reg] != reg:
                    refind_dict[gadget.defined_regs[reg]] = val
                    result = []
                else:
                    continue
            else:
                if avoid_char:
                    if reg in gadget.defined_regs and isinstance(gadget.defined_regs[reg], int):
                        continue
                    childs = astCtxt.search(regAst, AST_NODE.VARIABLE)
                    filterbyte = []
                    result = False
                    valb = val.to_bytes(8, 'little')
                    lval = len(valb.strip(b"\x00"))
                    for char in avoid_char:
                        if char in valb:
                            for child in childs:
                                for char in avoid_char:
                                    fb = filter_byte(astCtxt, child, char, lval)
                                    filterbyte.extend(fb)
                            if filterbyte:
                                filterbyte.append(regAst == astCtxt.bv(val, 64))
                    if filterbyte:
                        filterbyte = astCtxt.land(filterbyte)
                        result = list(ctx.getModel(filterbyte).values())
                    if not result:
                        result = list(ctx.getModel(regAst == astCtxt.bv(val, 64)).values())

                else:
                    result = list(ctx.getModel(regAst == astCtxt.bv(val, 64)).values())

            for v in result:
                alias = v.getVariable().getAlias()
                if 'STACK' not in alias:
                    if alias in regs and alias not in refind_dict:
                        if alias == reg and avoid_char:
                            valb = v.getValue().to_bytes(8, 'little')
                            for char in avoid_char:
                                if char in valb:
                                    result = False
                                    refind_dict = False
                            if not result:
                                break

                        if ((alias != reg and (alias, val) not in for_refind) or v.getValue() != val):
                            refind_dict[alias] = v.getValue()
                        else:
                            result = False
                            refind_dict = False
                            break
                    else:
                        result = False
                        break
                elif avoid_char:
                    for char in avoid_char:
                        if char in val.to_bytes(8, 'little'):
                            result = False
                            refind_dict = False
                            break
            if refind_dict:
                tmp_for_refind = for_refind.copy()
                tmp_for_refind.add((reg, val))
                reg_refind.update(set(list(refind_dict.keys())))
                result = solveGadgets(candidates[:], refind_dict, avoid_char, keep_regs=keep_regs, for_refind=tmp_for_refind, rec_limit=rec_limit+1)

            if result:
                if isinstance(val, str):
                    reg_to_reg_solve.add(gadget.defined_regs[reg])
                if not isinstance(result, RopChain):
                    type_chain = CHAINITEM_TYPE_VALUE
                    if add_type and reg in add_type and add_type[reg] == CHAINITEM_TYPE_ADDR:
                        type_chain = CHAINITEM_TYPE_ADDR
                    result = ChainItem.parseFromModel(result, type_val=type_chain)
                    tmp_solved_ordered.append(result)
                    tmp_solved_regs.add(reg)
                else:
                    if insert_tmp_solved(tmp_solved_ordered2, result):
                        tmp_solved_regs.add(reg)

        if not tmp_solved_regs:
            continue

        if gadget.end_type != TYPE_RETURN:
            if isintersect(set(list(solves.keys())), gadget.end_reg_used) or not gadget.end_ast:
                continue
            next_gadget = None
            diff = 0
            not_write = tmp_solved_regs | keep_regs
            if gadget.end_type == TYPE_JMP_REG:
                next_gadget = findForRet(candidates[:], 0, not_write, avoid_char=avoid_char)
            elif gadget.end_type == TYPE_CALL_REG:
                next_gadget = findForRet(candidates[:], 8, not_write, avoid_char=avoid_char)
                diff = 8
            if not next_gadget:
                continue

            # Shallow copy to avoid permanently mutating the shared gadget object
            gadget = copy.copy(gadget)
            gadget.end_gadget = next_gadget
            gadget.diff_sp += next_gadget.diff_sp - diff

            regAst = gadget.end_ast
            val = gadget.end_gadget.addr
            result = list(ctx.getModel(regAst == val).values())

            refind_dict = {}
            type_chains = {}
            for v in result:
                alias = v.getVariable().getAlias()
                if 'STACK' not in alias:
                    if alias in regs and alias not in refind_dict:
                        refind_dict[alias] = v.getValue()
                        type_chains[alias] = CHAINITEM_TYPE_ADDR
                    else:
                        result = False
                        break
            if refind_dict:
                reg_to_reg_solve.update(tmp_solved_regs)
                reg_to_reg_solve.update(reg_refind)
                result = solveGadgets(gadgets, refind_dict, avoid_char, add_type=type_chains, keep_regs=reg_to_reg_solve | keep_regs, rec_limit=rec_limit+1)
            if not result:
                continue
            if not isinstance(result, RopChain):
                type_chain = CHAINITEM_TYPE_ADDR
                result = ChainItem.parseFromModel(result, type_val=type_chain)
                tmp_solved_ordered.append(result)
            else:
                insert_tmp_solved(tmp_solved_ordered2, result)

        tmp_solved_ordered.extend(tmp_solved_ordered2)
        dep_regs = set()
        if reg_to_reg_solve:
            dep_regs = reg_to_reg_solve - tmp_solved_regs

        tmp_chain = Chain()
        tmp_chain.set_solved(gadget, tmp_solved_ordered, tmp_solved_regs, depends_regs=dep_regs)

        if not chains.insert_chain(tmp_chain):
            continue

        for reg in tmp_solved_regs:
            if reg in solves:
                del solves[reg]

        if not solves:
            return chains

    return []

def _resolve_write_operand(ctx, operand_ast, target, regs, refind_dict):
    """Resolve one side (addr or val) of a write gadget.

    target is either an int (constant) or a str (register name).
    Returns True on success, False on failure.  On success, any register
    dependencies are added to refind_dict.
    """
    if isinstance(target, str) and target in regs:
        # Register-based operand
        ast_str = str(operand_ast)
        if ast_str == target:
            return True  # direct match, nothing to solve
        if ast_str in regs:
            # Gadget uses a different register — need reg-to-reg forwarding
            if ast_str in refind_dict and refind_dict[ast_str] != target:
                return False  # conflict
            refind_dict[ast_str] = target
            return True
        return False  # complex AST expression, can't handle
    else:
        # Constant operand — solve via SMT model
        model = list(ctx.getModel(operand_ast == target).values())
        if not model:
            return False
        for v in model:
            alias = v.getVariable().getAlias()
            if 'STACK' not in alias:
                if alias in regs and alias not in refind_dict:
                    refind_dict[alias] = v.getValue()
                else:
                    return False
        return True

def _try_write_gadgets(gadgets, candidates_list, solves, regs, ctx, chains, fwd_level, avoid_char=None):
    """Try to solve write gadgets with increasing forwarding tolerance.

    fwd_level controls how much forwarding is allowed:
      0 = no forwarding (both addr and val must resolve without reg-to-reg)
      1 = one side can need reg-to-reg forwarding (the other must be direct/const)
      2 = both sides can need reg-to-reg forwarding
    """
    for gadget in candidates_list:
        # Only use gadgets that end with ret
        if gadget.end_type != TYPE_RETURN:
            continue
        if not gadget.is_asted:
            gadget.buildAst()
        for addr, val in list(solves.items()):
            mem_ast = gadget.memory_write_ast[0]
            if mem_ast[1].getBitvectorSize() != 64:
                break

            refind_dict_addr = {}
            if not _resolve_write_operand(ctx, mem_ast[0], addr, regs, refind_dict_addr):
                break
            refind_dict_val = {}
            if not _resolve_write_operand(ctx, mem_ast[1], val, regs, refind_dict_val):
                break

            # Count how many sides need reg-to-reg forwarding
            addr_fwd = any(isinstance(v, str) for v in refind_dict_addr.values())
            val_fwd = any(isinstance(v, str) for v in refind_dict_val.values())
            fwd_count = int(addr_fwd) + int(val_fwd)
            if fwd_count > fwd_level:
                break

            refind_dict = {**refind_dict_addr, **refind_dict_val}
            result = True
            if refind_dict:
                # Protect register operands from being clobbered by the refind solve
                keep = set()
                if isinstance(addr, str) and addr in regs:
                    keep.add(addr)
                if isinstance(val, str) and val in regs:
                    keep.add(val)
                result = solveGadgets(gadgets[:], refind_dict, avoid_char=avoid_char, keep_regs=keep)
            if result:
                del solves[addr]
                chain = Chain()
                chain.set_solved(gadget, [result] if isinstance(result, (list, RopChain)) else [])
                chains.insert_chain(chain)
                if not solves:
                    return True
    return False

def solveWriteGadgets(gadgets, solves, avoid_char=None):
    # Work on a copy so partial failures don't corrupt the caller's dict
    solves = dict(solves)

    regs = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
    candidates = findCandidatesWriteGadgets(gadgets[:], avoid_char=avoid_char)
    ctx = initialize()
    gwr = list(candidates.keys())
    chains = RopChain()
    gwr.sort()

    # Progressive passes with increasing forwarding tolerance:
    #   0: no forwarding (both sides direct/const-solvable)
    #   1: one side can need reg-to-reg forwarding
    #   2: both sides can need reg-to-reg forwarding
    for level in range(3):
        if not solves:
            break
        for w in gwr:
            if _try_write_gadgets(gadgets, candidates[w], solves, regs, ctx, chains, fwd_level=level, avoid_char=avoid_char):
                return chains

def solvePivot(gadgets, addr_pivot, avoid_char=None):
    regs = ["rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"]
    candidates = findPivot(gadgets, avoid_char=avoid_char)
    ctx = initialize()
    chains = RopChain()
    for gadget in candidates:
        if not gadget.is_asted:
            gadget.buildAst()
        result = ctx.getModel(gadget.pivot_ast == addr_pivot).values()
        new_diff_sp = 0
        for v in result:
            alias = v.getVariable().getAlias()
            refind_dict = dict()
            if 'STACK' not in alias:
                if alias in regs and alias not in refind_dict:
                    refind_dict[alias] = v.getValue()
                else:
                    result = False
                    break
            else:
                idxchain = int(alias.replace("STACK", ""))
                new_diff_sp = (idxchain+1)*8
        if result and refind_dict:
            result = solveGadgets(gadgets[:], refind_dict, avoid_char=avoid_char)
            new_diff_sp = 0
        if not result:
            continue
        # Shallow copy to avoid permanently mutating the shared gadget object
        gadget = copy.copy(gadget)
        gadget.diff_sp = new_diff_sp
        chain = Chain()
        chain.set_solved(gadget, [result])
        chains.insert_chain(chain)
        return chains
