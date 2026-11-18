#!/usr/bin/env python3
"""Compare two QIRA trace directories and summarise their differences.

Written for Task 2 (UPGRADE.md): diff a trace of ``qira_tests/bin/loop`` taken
with the Python 3 middleware + QEMU plugin tracer against the legacy reference
capture in ``samples/legacy/``.  It reuses the in-repo log reader
(:mod:`qira.legacy.qira_log`) and the arch register tables
(:mod:`qira.legacy.arch`) rather than re-parsing the binary format.

It compares, for a numbered trace (default ``0``) in each directory:

* the ``logstate`` header (entry count, parent/fork id);
* the record counts per type (``I``/``L``/``S``/``R``/``W``);
* the main binary's instruction sequence (pc per clnum, normalised to a
  module-relative offset so ASLR/base differences do not matter);
* the register values written at matched main-binary instructions;
* the syscall list from ``<id>_strace`` (clnum, name, return value);
* the module list from ``<id>_base``;
* whether ``<id>_env`` is present.

Usage::

    python qira_tests/compare_traces.py DIR_A DIR_B [--id 0] [-n 20] [--arch x86-64]

``DIR_A`` is treated as the reference (e.g. ``samples/legacy``) and ``DIR_B`` as
the capture under test (e.g. ``samples/port``).
"""
from __future__ import annotations

import argparse
import os
import re
import struct
import sys
from collections import Counter
from dataclasses import dataclass, field

from qira.legacy import arch, qira_log

# arch descriptor tables: [regname_list, regsize, is_big_endian, arch_name, ...]
ARCHES = {
    "x86-64": arch.X64REGS,
    "i386": arch.X86REGS,
    "arm": arch.ARMREGS,
    "aarch64": arch.AARCH64REGS,
    "mips": arch.MIPSREGS,
    "ppc": arch.PPCREGS,
}

_SYSCALL_N = re.compile(r"^syscall_\d+$")


@dataclass
class Module:
    start: int
    end: int
    offset: int
    path: str

    @property
    def name(self) -> str:
        return os.path.basename(self.path.rstrip("/")) or self.path


@dataclass
class Syscall:
    clnum: int
    pid: int
    name: str
    text: str
    ret: str


@dataclass
class Trace:
    directory: str
    trace_id: str
    count: int
    parent_id: int
    changes: list  # (address, data, clnum, flags)
    modules: list  # list[Module]
    strace: list   # list[Syscall]
    has_env: bool
    has_asm: bool
    asm_size: int

    # ---- derived views -------------------------------------------------
    @property
    def insns(self):
        """(clnum, pc, size_bits) for every IS_START record, in order."""
        out = []
        for (address, _data, clnum, flags) in self.changes:
            if flags & qira_log.IS_START:
                out.append((clnum, address, flags & qira_log.SIZE_MASK))
        return out

    def type_counts(self) -> Counter:
        c = Counter()
        for (_a, _d, _c, flags) in self.changes:
            c[qira_log.flag_to_type(flags)] += 1
        return c

    def module_for(self, addr: int):
        for m in self.modules:
            if m.start <= addr < m.end:
                return m
        return None

    def main_module(self):
        """The module loaded at the lowest address (the traced binary)."""
        return min(self.modules, key=lambda m: m.start) if self.modules else None


def read_header(logpath: str):
    with open(logpath, "rb") as f:
        head = f.read(0x18)
    if len(head) < 0x18:
        raise ValueError("%s: truncated log header" % logpath)
    count = struct.unpack("I", head[0:4])[0]
    # the fork/parent id lives in the header's clnum slot (offset 0x10)
    parent_id = struct.unpack("i", head[0x10:0x14])[0]
    return count, parent_id


def parse_base(path: str):
    mods = []
    if not os.path.exists(path):
        return mods
    with open(path) as f:
        for ln in f.read().split("\n"):
            parts = ln.split(" ")
            if len(parts) < 3 or "-" not in parts[0]:
                continue
            ss, se = parts[0].split("-")
            try:
                mods.append(Module(int(ss, 16), int(se, 16), int(parts[1], 16),
                                   " ".join(parts[2:])))
            except ValueError:
                continue
    return mods


def parse_strace(path: str):
    out = []
    if not os.path.exists(path):
        return out
    with open(path) as f:
        for ln in f.read().split("\n"):
            ff = ln.split(" ")
            if len(ff) < 3:
                continue
            try:
                clnum = int(ff[0])
                pid = int(ff[1])
            except ValueError:
                continue  # e.g. the synthetic "garbage line" in test fixtures
            text = " ".join(ff[2:])
            name = text.split("(", 1)[0].strip()
            ret = text.split(") = ", 1)[1] if ") = " in text else ""
            out.append(Syscall(clnum, pid, name, text, ret))
    return out


def load_trace(directory: str, trace_id: str = "0") -> Trace:
    logpath = os.path.join(directory, trace_id)
    count, parent_id = read_header(logpath)
    with open(logpath, "rb") as f:
        changes = qira_log.read_log(f)
    asm = os.path.join(directory, trace_id + "_asm")
    return Trace(
        directory=directory,
        trace_id=trace_id,
        count=count,
        parent_id=parent_id,
        changes=changes,
        modules=parse_base(os.path.join(directory, trace_id + "_base")),
        strace=parse_strace(os.path.join(directory, trace_id + "_strace")),
        has_env=os.path.exists(os.path.join(directory, trace_id + "_env")),
        has_asm=os.path.exists(asm),
        asm_size=os.path.getsize(asm) if os.path.exists(asm) else 0,
    )


# ---------------------------------------------------------------------------
# register reconstruction
# ---------------------------------------------------------------------------

def register_file(changes, tregs):
    """Yield (clnum, pc, {regname: value}) at each instruction start.

    Values are tracked from both R and W register records (both carry the
    current value in ``data``).  Registers QIRA does not name (padding / out of
    range) are ignored.
    """
    names, regsize = tregs[0], tregs[1]
    nregs = len(names)
    state = {}
    cur = None
    for (address, data, clnum, flags) in changes:
        if flags & qira_log.IS_START:
            if cur is not None:
                yield cur
            cur = (clnum, address, dict(state))
        elif not (flags & qira_log.IS_MEM):
            # register read or write: address = index * regsize
            if address < regsize * nregs and address % regsize == 0:
                nm = names[address // regsize]
                if nm is not None:
                    state[nm] = data
                    if cur is not None:
                        cur[2][nm] = data
    if cur is not None:
        yield cur


# ---------------------------------------------------------------------------
# comparisons; each returns (headline, list_of_detail_lines)
# ---------------------------------------------------------------------------

def cmp_header(a: Trace, b: Trace):
    lines = [
        "entry count : A=%d  B=%d  (delta %+d)" % (a.count, b.count, b.count - a.count),
        "parent/fork : A=%d  B=%d%s" % (a.parent_id, b.parent_id,
                                        "" if a.parent_id == b.parent_id else "  <-- DIFFERS"),
    ]
    same = a.parent_id == b.parent_id
    return "logstate header" + ("" if same else "  (parent id differs)"), lines


def cmp_type_counts(a: Trace, b: Trace):
    ca, cb = a.type_counts(), b.type_counts()
    lines = ["type    A        B      delta"]
    for t in "ILSRW":
        lines.append("  %s  %8d %8d  %+d" % (t, ca.get(t, 0), cb.get(t, 0),
                                             cb.get(t, 0) - ca.get(t, 0)))
    missing = [t for t in "ILSRW" if ca.get(t, 0) and not cb.get(t, 0)]
    head = "record counts per type"
    if missing:
        head += "  (B has no %s records)" % "/".join(missing)
    return head, lines


def _main_insn_offsets(t: Trace):
    """Normalised (offset, size) of the main binary's instructions, in order."""
    main = t.main_module()
    if main is None:
        return [], None
    base = min(m.start for m in t.modules if m.name == main.name)
    seq = []
    for (clnum, pc, size) in t.insns:
        m = t.module_for(pc)
        if m is not None and m.name == main.name:
            seq.append((pc - base, size, clnum))
    return seq, main.name


def cmp_main_insns(a: Trace, b: Trace, n: int):
    sa, na = _main_insn_offsets(a)
    sb, nb = _main_insn_offsets(b)
    lines = ["main module: A=%s (%d insns)  B=%s (%d insns)"
             % (na, len(sa), nb, len(sb))]
    diffs = []
    for i in range(max(len(sa), len(sb))):
        ea = sa[i] if i < len(sa) else None
        eb = sb[i] if i < len(sb) else None
        oa = (ea[0], ea[1]) if ea else None
        ob = (eb[0], eb[1]) if eb else None
        if oa != ob:
            diffs.append("  #%d  A=%s  B=%s"
                         % (i, "+0x%x/%db" % oa if oa else "-",
                            "+0x%x/%db" % ob if ob else "-"))
    if diffs:
        lines.append("%d differing positions (offset/size); first %d:"
                     % (len(diffs), min(n, len(diffs))))
        lines.extend(diffs[:n])
    else:
        lines.append("identical instruction sequence (%d instructions)" % len(sa))
    head = "main-binary instruction sequence" + ("" if not diffs else "  (%d diffs)" % len(diffs))
    return head, lines


def cmp_registers(a: Trace, b: Trace, tregs, n: int):
    """Compare register values at matched main-binary instructions.

    Instructions are matched by their position in the main-binary instruction
    subsequence (so library code, which differs, does not shift the match).
    """
    # map clnum -> register snapshot
    ra = {clnum: regs for (clnum, _pc, regs) in register_file(a.changes, tregs)}
    rb = {clnum: regs for (clnum, _pc, regs) in register_file(b.changes, tregs)}
    sa, _ = _main_insn_offsets(a)
    sb, _ = _main_insn_offsets(b)
    pairs = min(len(sa), len(sb))
    diff_positions = 0
    detail = []
    for i in range(pairs):
        ca, cb = sa[i][2], sb[i][2]
        rega, regb = ra.get(ca, {}), rb.get(cb, {})
        names = set(rega) | set(regb)
        d = [nm for nm in names if rega.get(nm) != regb.get(nm)]
        if d:
            diff_positions += 1
            if len(detail) < n:
                detail.append("  main#%d (A cl%d / B cl%d): %s"
                              % (i, ca, cb, ", ".join(
                                  "%s A=%s B=%s" % (
                                      nm,
                                      "0x%x" % rega[nm] if nm in rega else "-",
                                      "0x%x" % regb[nm] if nm in regb else "-")
                                  for nm in sorted(d))))
    lines = ["matched %d main-binary instructions" % pairs,
             "%d positions differ in at least one register value" % diff_positions]
    if detail:
        lines.append("first %d:" % len(detail))
        lines.extend(detail)
    head = "register values at matched instructions"
    if not a.type_counts().get("R", 0) or not b.type_counts().get("R", 0):
        head += "  (note: one side has no R records)"
    return head, lines


def cmp_syscalls(a: Trace, b: Trace, n: int):
    sa, sb = a.strace, b.strace
    unresolved_a = sum(1 for s in sa if _SYSCALL_N.match(s.name))
    unresolved_b = sum(1 for s in sb if _SYSCALL_N.match(s.name))
    lines = [
        "syscall records: A=%d  B=%d" % (len(sa), len(sb)),
        "unresolved (syscall_N) names: A=%d  B=%d" % (unresolved_a, unresolved_b),
    ]
    # align by position and show the first N where name or ret differ
    diffs = []
    for i in range(max(len(sa), len(sb))):
        ea = sa[i] if i < len(sa) else None
        eb = sb[i] if i < len(sb) else None
        ka = (ea.name, ea.ret) if ea else None
        kb = (eb.name, eb.ret) if eb else None
        if ka != kb:
            diffs.append("  #%d  A=%s  B=%s"
                         % (i,
                            "%s=%s" % (ea.name, ea.ret) if ea else "-",
                            "%s=%s" % (eb.name, eb.ret) if eb else "-"))
    if diffs:
        lines.append("%d differing positions; first %d:" % (len(diffs), min(n, len(diffs))))
        lines.extend(diffs[:n])
    head = "syscall list (_strace)"
    if unresolved_b and not unresolved_a:
        head += "  (B leaves syscall names unresolved)"
    return head, lines


def cmp_modules(a: Trace, b: Trace):
    na = sorted({m.name for m in a.modules})
    nb = sorted({m.name for m in b.modules})
    only_a = [x for x in na if x not in nb]
    only_b = [x for x in nb if x not in na]
    lines = ["module mappings: A=%d (%d names)  B=%d (%d names)"
             % (len(a.modules), len(na), len(b.modules), len(nb))]
    if only_a:
        lines.append("only in A: " + ", ".join(only_a))
    if only_b:
        lines.append("only in B: " + ", ".join(only_b))
    if not only_a and not only_b:
        lines.append("same module name set")
    head = "module list (_base)"
    if only_a:
        head += "  (B is missing %d modules)" % len(only_a)
    return head, lines


def cmp_env(a: Trace, b: Trace):
    lines = ["_env present : A=%s  B=%s" % (a.has_env, b.has_env),
             "_asm present : A=%s (%d bytes)  B=%s (%d bytes)"
             % (a.has_asm, a.asm_size, b.has_asm, b.asm_size)]
    head = "sidecar files (_env / _asm)"
    if a.has_env != b.has_env or (a.has_asm and a.asm_size) != (b.has_asm and b.asm_size):
        head += "  (differs)"
    return head, lines


def compare(a: Trace, b: Trace, tregs, n: int):
    sections = [
        cmp_header(a, b),
        cmp_type_counts(a, b),
        cmp_main_insns(a, b, n),
        cmp_registers(a, b, tregs, n),
        cmp_syscalls(a, b, n),
        cmp_modules(a, b),
        cmp_env(a, b),
    ]
    return sections


def render(sections) -> str:
    out = []
    for head, lines in sections:
        out.append("== %s ==" % head)
        out.extend(lines)
        out.append("")
    return "\n".join(out)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dir_a", help="reference trace directory (e.g. samples/legacy)")
    ap.add_argument("dir_b", help="trace directory under test (e.g. samples/port)")
    ap.add_argument("--id", default="0", help="numbered trace id to compare (default 0)")
    ap.add_argument("-n", type=int, default=20, help="max differing records to list per category")
    ap.add_argument("--arch", default="x86-64", choices=sorted(ARCHES),
                    help="architecture for register naming (default x86-64)")
    args = ap.parse_args(argv)

    a = load_trace(args.dir_a, args.id)
    b = load_trace(args.dir_b, args.id)
    sections = compare(a, b, ARCHES[args.arch], args.n)
    sys.stdout.write("comparing A=%s  B=%s  (trace %s, arch %s)\n\n"
                     % (args.dir_a, args.dir_b, args.id, args.arch))
    sys.stdout.write(render(sections))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
