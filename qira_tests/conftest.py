import os
import struct
import time

import pytest

from qira.legacy import qira_config, qira_log

TESTS = os.path.dirname(os.path.realpath(__file__))
REPO = os.path.dirname(TESTS)
LOOP = os.path.join(TESTS, "bin", "loop")              # x86-64 ELF
HELLO_TRACE = os.path.join(TESTS, "bin", "hello_trace")  # i386 change log
LEGACY = os.path.join(REPO, "samples", "legacy")       # local only, see UPGRADE.md

V, W, M, S = qira_log.IS_VALID, qira_log.IS_WRITE, qira_log.IS_MEM, qira_log.IS_START
REGSIZE = 8  # x86-64: change address of register i is i*8 (arch.X64REGS)
RSP, RBP, RIP = 4 * REGSIZE, 5 * REGSIZE, 16 * REGSIZE
STACK = 0x7FFFFFF0

# a few instructions from the start of main() in qira_tests/bin/loop:
#   0x400536 push rbp / 0x400537 mov rbp, rsp / 0x40053a sub rsp, 0x10 /
#   0x40053e mov dword ptr [rbp - 4], 0
LOOP_CHANGES = [
  (0x400536, 1, 0, V | S),
  (RSP, STACK, 0, V | 64),
  (RSP, STACK - 8, 0, V | W | 64),
  (STACK - 8, 0x1122334455667788, 0, V | W | M | 64),
  (RIP, 0x400537, 0, V | W | 64),
  (0x400537, 3, 1, V | S),
  (RSP, STACK - 8, 1, V | 64),
  (RBP, STACK - 8, 1, V | W | 64),
  (RIP, 0x40053A, 1, V | W | 64),
  (0x40053A, 4, 2, V | S),
  (RSP, STACK - 0x18, 2, V | W | 64),
  (RIP, 0x40053E, 2, V | W | 64),
  (0x40053E, 7, 3, V | S),
  (RBP, STACK - 8, 3, V | 64),
  (STACK - 12, 0, 3, V | W | M | 32),
  (RIP, 0x400545, 3, V | W | 64),
]


def wait_for_update(db, timeout=10.0):
  end = time.time() + timeout
  while not db.did_update():
    if time.time() > end:
      raise TimeoutError("qiradb did not process the log")
    time.sleep(0.02)


@pytest.fixture
def trace_dir(tmp_path, monkeypatch):
  """An empty trace folder, used by qira_config for this test."""
  d = tmp_path / "qira_logs"
  d.mkdir()
  monkeypatch.setattr(qira_config, "TRACE_FILE_BASE", str(d) + "/")
  monkeypatch.setattr(qira_config, "ASM_FILE", str(tmp_path / "qira_asm"))
  return d


@pytest.fixture
def loop_trace(trace_dir):
  """trace 0: the synthetic log above, plus a _strace and a _base file."""
  qira_log.write_log(str(trace_dir / "0"), LOOP_CHANGES)
  # parent_id (offset 0x10 of the header) = -1, like a top-level run of the tracer
  with open(trace_dir / "0", "r+b") as f:
    f.seek(0x10)
    f.write(struct.pack("i", -1))
  (trace_dir / "0_strace").write_text(
    '0 77 open("%s",O_RDONLY|O_CLOEXEC) = 3\n'
    '0 77 mmap(NULL,4096,PROT_READ,MAP_PRIVATE,3,0) = 0x10000000\n'
    '1 77 write(1,0x601000,6) = 6\n'
    'garbage line\n'
    '2 77 exit_group(0)\n' % LOOP)
  (trace_dir / "0_base").write_text(
    "0000000000400000-0000000000401000 0 %s\n"
    "0000000020000000-0000000020000100 100 %s\n"
    "00007ffff7ffa000-00007ffff7ffc000 0 [vdso]\n" % (LOOP, LOOP))
  return trace_dir
