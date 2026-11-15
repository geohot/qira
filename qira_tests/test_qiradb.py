import os

import pytest

from qira.legacy import qiradb, qira_log
from conftest import HELLO_TRACE, LEGACY, LOOP_CHANGES, RBP, RIP, RSP, STACK, wait_for_update

LIMIT = 10000


def test_hello_trace():
  # i386: register size 4, register count 9
  t = qiradb.PyTrace(HELLO_TRACE, 0, 4, 9, False)
  wait_for_update(t)

  assert t.get_maxclnum() == 116
  assert t.get_minclnum() == 0

  # who loads argc?
  assert t.fetch_clnums_by_address_and_type(0xf6fff090, 'L', 0, 1000, LIMIT) == [0, 2]
  assert t.fetch_clnums_by_address_and_type(0xf6fff090, b'L', 0, 1000, 1) == [0]

  regs = t.fetch_registers(113)
  assert len(regs) == 9
  assert regs[8] == 0x80484d1
  assert regs[4] == 0xf6ffef00

  for clnum in (0, 7, 116, -1):
    mem = t.fetch_memory(clnum, 0xf6fff080, 0x10)
    assert len(mem) == 0x10
    assert all(0 <= m <= 0x1ff for m in mem)

  # was a pop %esi
  changes = t.fetch_changes_by_clnum(2, LIMIT)
  assert changes[0] == {'address': 0x8048332, 'data': 1, 'clnum': 2, 'type': 'I', 'size': 0}
  assert [c['type'] for c in changes] == ['I', 'R', 'L', 'R', 'W', 'W', 'W']
  assert t.fetch_changes_by_clnum(2, 1) == changes[:1]

  pmaps = t.get_pmaps()
  assert pmaps[0x8048000] == "instruction"
  assert set(pmaps.values()) == {"instruction", "memory", "romemory"}


def test_synthetic_log(tmp_path):
  fn = str(tmp_path / "0")
  qira_log.write_log(fn, LOOP_CHANGES)
  t = qiradb.PyTrace(fn, 0, 8, 17, False)
  wait_for_update(t)

  assert (t.get_minclnum(), t.get_maxclnum()) == (0, 3)
  assert t.fetch_registers(0)[RSP // 8] == STACK - 8
  assert t.fetch_registers(2)[RSP // 8] == STACK - 0x18
  assert t.fetch_registers(3)[RBP // 8] == STACK - 8
  assert t.fetch_registers(-1)[RIP // 8] == 0x400545
  # little endian 64-bit store at clnum 0, then a 32-bit store of 0 over its upper half at clnum 3
  assert t.fetch_memory(0, STACK - 8, 8) == [0x100 | b for b in bytes.fromhex("8877665544332211")]
  assert t.fetch_memory(3, STACK - 12, 8) == [0x100] * 4 + [0x100 | b for b in bytes.fromhex("88776655")]
  assert t.fetch_memory(0, STACK - 12, 4) == [0, 0, 0, 0]   # not written yet: invalid
  assert t.fetch_clnums_by_address_and_type(RSP, 'W', 0, 10, LIMIT) == [0, 2]
  assert t.fetch_clnums_by_address_and_type(0x400537, 'I', 0, 10, LIMIT) == [1]
  assert t.get_pmaps() == {0x400000: "instruction", (STACK - 0x10) & ~0xfff: "memory"}


def test_missing_file_raises(tmp_path):
  with pytest.raises(IOError):
    qiradb.PyTrace(str(tmp_path / "nope"), 0, 8, 17, False)


@pytest.mark.skipif(not os.path.isfile(os.path.join(LEGACY, "0")), reason="samples/legacy/0 (local only) not present")
def test_legacy_loop_capture():
  # samples/legacy/0 is the loop capture from the qira-legacy image (x86-64)
  fn = os.path.join(LEGACY, "0")
  with open(fn, "rb") as f:
    entries = qira_log.get_log_length(f)
  t = qiradb.PyTrace(fn, 0, 8, 17, False)
  wait_for_update(t, timeout=30)   # qiradb takes up to 1M entries per pass
  assert entries < 1000000
  # cross-check qiradb against a plain Python read of the same log
  with open(fn, "rb") as f:
    changes = qira_log.read_log(f, cnt=entries - 1)
  starts = [c for c in changes if qira_log.flag_to_type(c[3]) == "I"]
  assert t.get_minclnum() == min(c[2] for c in changes)
  assert t.get_maxclnum() == max(c[2] for c in changes)
  clnum = starts[len(starts) // 2][2]
  assert [(c['address'], c['data']) for c in t.fetch_changes_by_clnum(clnum, 0)] == \
         [(c[0], c[1]) for c in changes if c[2] == clnum]
  assert "instruction" in t.get_pmaps().values()
