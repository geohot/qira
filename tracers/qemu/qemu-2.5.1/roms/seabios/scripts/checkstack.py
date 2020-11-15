#!/usr/bin/env python
# Script that tries to find how much stack space each function in an
# object is using.
#
# Copyright (C) 2008  Kevin O'Connor <kevin@koconnor.net>
#
# This file may be distributed under the terms of the GNU GPLv3 license.

# Usage:
#   objdump -m i386 -M i8086 -M suffix -d out/rom16.o | scripts/checkstack.py

import sys
import re

# Functions that change stacks
STACKHOP = ['stack_hop', 'stack_hop_back']
# List of functions we can assume are never called.
#IGNORE = ['panic', '__dprintf']
IGNORE = ['panic']

OUTPUTDESC = """
#funcname1[preamble_stack_usage,max_usage_with_callers]:
#    insn_addr:called_function [usage_at_call_point+caller_preamble,total_usage]
#
#funcname2[p,m,max_usage_to_yield_point]:
#    insn_addr:called_function [u+c,t,usage_to_yield_point]
"""

# Find out maximum stack usage for a function
def calcmaxstack(funcs, funcaddr):
    info = funcs[funcaddr]
    # Find max of all nested calls.
    maxusage = info[1]
    maxyieldusage = doesyield = 0
    if info[3] is not None:
        maxyieldusage = info[3]
        doesyield = 1
    info[2] = maxusage
    info[4] = info[3]
    seenbefore = {}
    totcalls = 0
    for insnaddr, calladdr, usage in info[6]:
        callinfo = funcs.get(calladdr)
        if callinfo is None:
            continue
        if callinfo[2] is None:
            calcmaxstack(funcs, calladdr)
        if callinfo[0] not in seenbefore:
            seenbefore[callinfo[0]] = 1
            totcalls += 1 + callinfo[5]
        funcnameroot = callinfo[0].split('.')[0]
        if funcnameroot in IGNORE:
            # This called function is ignored - don't contribute it to
            # the max stack.
            continue
        if funcnameroot in STACKHOP:
            if usage > maxusage:
                maxusage = usage
            if callinfo[4] is not None:
                doesyield = 1
                if usage > maxyieldusage:
                    maxyieldusage = usage
            continue
        totusage = usage + callinfo[2]
        if totusage > maxusage:
            maxusage = totusage
        if callinfo[4] is not None:
            doesyield = 1
            totyieldusage = usage + callinfo[4]
            if totyieldusage > maxyieldusage:
                maxyieldusage = totyieldusage
    info[2] = maxusage
    if doesyield:
        info[4] = maxyieldusage
    info[5] = totcalls

# Try to arrange output so that functions that call each other are
# near each other.
def orderfuncs(funcaddrs, availfuncs):
    l = [(availfuncs[funcaddr][5], availfuncs[funcaddr][0], funcaddr)
         for funcaddr in funcaddrs if funcaddr in availfuncs]
    l.sort()
    l.reverse()
    out = []
    while l:
        count, name, funcaddr = l.pop(0)
        if funcaddr not in availfuncs:
            continue
        calladdrs = [calls[1] for calls in availfuncs[funcaddr][6]]
        del availfuncs[funcaddr]
        out = out + orderfuncs(calladdrs, availfuncs) + [funcaddr]
    return out

# Update function info with a found "yield" point.
def noteYield(info, stackusage):
    prevyield = info[3]
    if prevyield is None or prevyield < stackusage:
        info[3] = stackusage

# Update function info with a found "call" point.
def noteCall(info, subfuncs, insnaddr, calladdr, stackusage):
    if (calladdr, stackusage) in subfuncs:
        # Already noted a nearly identical call - ignore this one.
        return
    info[6].append((insnaddr, calladdr, stackusage))
    subfuncs[(calladdr, stackusage)] = 1

hex_s = r'[0-9a-f]+'
re_func = re.compile(r'^(?P<funcaddr>' + hex_s + r') <(?P<func>.*)>:$')
re_asm = re.compile(
    r'^[ ]*(?P<insnaddr>' + hex_s
    + r'):\t.*\t(addr32 )?(?P<insn>.+?)[ ]*((?P<calladdr>' + hex_s
    + r') <(?P<ref>.*)>)?$')
re_usestack = re.compile(
    r'^(push[f]?[lw])|(sub.* [$](?P<num>0x' + hex_s + r'),%esp)$')

def calc():
    # funcs[funcaddr] = [funcname, basicstackusage, maxstackusage
    #                    , yieldusage, maxyieldusage, totalcalls
    #                    , [(insnaddr, calladdr, stackusage), ...]]
    funcs = {-1: ['<indirect>', 0, 0, None, None, 0, []]}
    cur = None
    atstart = 0
    stackusage = 0

    # Parse input lines
    for line in sys.stdin.readlines():
        m = re_func.match(line)
        if m is not None:
            # Found function
            funcaddr = int(m.group('funcaddr'), 16)
            funcs[funcaddr] = cur = [m.group('func'), 0, None, None, None, 0, []]
            stackusage = 0
            atstart = 1
            subfuncs = {}
            continue
        m = re_asm.match(line)
        if m is not None:
            insn = m.group('insn')

            im = re_usestack.match(insn)
            if im is not None:
                if insn.startswith('pushl') or insn.startswith('pushfl'):
                    stackusage += 4
                    continue
                elif insn.startswith('pushw') or insn.startswith('pushfw'):
                    stackusage += 2
                    continue
                stackusage += int(im.group('num'), 16)

            if atstart:
                if '%esp' in insn or insn.startswith('leal'):
                    # Still part of initial header
                    continue
                cur[1] = stackusage
                atstart = 0

            insnaddr = m.group('insnaddr')
            calladdr = m.group('calladdr')
            if calladdr is None:
                if insn.startswith('lcallw'):
                    noteCall(cur, subfuncs, insnaddr, -1, stackusage + 4)
                    noteYield(cur, stackusage + 4)
                elif insn.startswith('int'):
                    noteCall(cur, subfuncs, insnaddr, -1, stackusage + 6)
                    noteYield(cur, stackusage + 6)
                elif insn.startswith('sti'):
                    noteYield(cur, stackusage)
                else:
                    # misc instruction
                    continue
            else:
                # Jump or call insn
                calladdr = int(calladdr, 16)
                ref = m.group('ref')
                if '+' in ref:
                    # Inter-function jump.
                    pass
                elif insn.startswith('j'):
                    # Tail call
                    noteCall(cur, subfuncs, insnaddr, calladdr, 0)
                elif insn.startswith('calll'):
                    noteCall(cur, subfuncs, insnaddr, calladdr, stackusage + 4)
                elif insn.startswith('callw'):
                    noteCall(cur, subfuncs, insnaddr, calladdr, stackusage + 2)
                else:
                    print("unknown call", ref)
                    noteCall(cur, subfuncs, insnaddr, calladdr, stackusage)
            # Reset stack usage to preamble usage
            stackusage = cur[1]

        #print("other", repr(line))

    # Calculate maxstackusage
    for funcaddr, info in funcs.items():
        if info[2] is not None:
            continue
        calcmaxstack(funcs, funcaddr)

    # Sort functions for output
    funcaddrs = orderfuncs(funcs.keys(), funcs.copy())

    # Show all functions
    print(OUTPUTDESC)
    for funcaddr in funcaddrs:
        name, basicusage, maxusage, yieldusage, maxyieldusage, count, calls = \
            funcs[funcaddr]
        if maxusage == 0 and maxyieldusage is None:
            continue
        yieldstr = ""
        if maxyieldusage is not None:
            yieldstr = ",%d" % maxyieldusage
        print("\n%s[%d,%d%s]:" % (name, basicusage, maxusage, yieldstr))
        for insnaddr, calladdr, stackusage in calls:
            callinfo = funcs.get(calladdr, ("<unknown>", 0, 0, 0, None))
            yieldstr = ""
            if callinfo[4] is not None:
                yieldstr = ",%d" % (stackusage + callinfo[4])
            print("    %04s:%-40s [%d+%d,%d%s]" % (
                insnaddr, callinfo[0], stackusage, callinfo[1]
                , stackusage+callinfo[2], yieldstr))

def main():
    calc()

if __name__ == '__main__':
    main()
