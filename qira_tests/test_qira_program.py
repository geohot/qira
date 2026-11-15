import os

import pytest

from qira.legacy import arch, qira_config, qira_program
from conftest import LOOP, wait_for_update


@pytest.fixture
def program(trace_dir):
  p = qira_program.Program(LOOP)
  p.create_asm_file()
  return p


def test_which(tmp_path):
  assert qira_program.which(LOOP) == os.path.realpath(LOOP)
  assert qira_program.which("sh") == os.path.realpath("/bin/sh") or qira_program.which("sh").endswith("sh")
  with pytest.raises(Exception):
    qira_program.which(str(tmp_path / "does-not-exist"))


def test_identify_x86_64(program):
  assert program.runnable
  assert program.fb == 0x3e
  assert program.tregs is arch.X64REGS
  assert program.qirabinary == os.path.realpath(os.path.join(qira_config.TRACER_DIR, "qemu", "qira-x86_64"))
  assert isinstance(program.program, str)


def test_identify_pe(tmp_path, trace_dir):
  pe = bytearray(0x200)
  pe[0:2] = b"MZ"
  pe[0x3c:0x40] = (0x80).to_bytes(4, "little")
  pe[0x80:0x84] = b"PE\0\0"
  pe[0x84:0x86] = (0x8664).to_bytes(2, "little")
  fn = tmp_path / "x.exe"
  fn.write_bytes(bytes(pe))
  p = qira_program.Program(str(fn))
  assert p.tregs is arch.X64REGS and not p.runnable


def test_trace_strace_and_base(program, loop_trace):
  t = program.add_trace(str(loop_trace / "0"), 0)
  try:
    wait_for_update(t.db)
    assert program.get_maxclnum() == {0: [0, 3]}
    assert program.get_pmaps()["0x400000"] == "instruction"

    # _strace: clnum, pid and the call; lines without a clnum are skipped
    t.read_strace_file()
    assert [s["clnum"] for s in t.strace] == [0, 0, 1, 2]
    assert t.strace[0]["pid"] == 77
    assert t.strace[2]["sc"] == "write(1,0x601000,6) = 6"
    # the mmap of the opened file was loaded into static memory
    with open(LOOP, "rb") as f:
      head = f.read(16)
    assert program.static.memory(0x10000000, 16) == head

    # _base: start-end, hex file offset, path; [vdso] can't be read and is skipped.
    # 0x400000 is already loaded from the ELF segments and is kept (same as legacy)
    assert (0x400000, 0x400724) in program.static.base_memory
    assert program.static.memory(0x20000000, 0x100) == open(LOOP, "rb").read()[0x100:0x200]

    # registers and memory through the Trace proxy
    regs = t.db.fetch_registers(1)
    assert regs[arch.X64REGS[0].index("RBP")] == 0x7FFFFFF0 - 8
    raw = t.fetch_raw_memory(0, 0x7FFFFFF0 - 8, 8)
    assert raw == bytes.fromhex("8877665544332211")
    # not in the trace: falls back to the static (ELF) bytes
    assert t.fetch_raw_memory(0, 0x400536, 4) == bytes.fromhex("554889e5")
  finally:
    t.keep_analysis_thread = False


def test_missing_strace(program, trace_dir):
  from qira.legacy import qira_log
  from conftest import LOOP_CHANGES
  qira_log.write_log(str(trace_dir / "5"), LOOP_CHANGES)
  t = program.add_trace(str(trace_dir / "5"), 5)
  t.keep_analysis_thread = False
  assert t.read_strace_file() == "no strace"
  assert t.strace == []


def test_strace_non_ascii(program, loop_trace):
  (loop_trace / "0_strace").write_bytes(b'3 77 write(1,"\xff\xfeok",4) = 4\n')
  t = program.add_trace(str(loop_trace / "0"), 0)
  t.keep_analysis_thread = False
  t.read_strace_file()
  assert t.strace == [{"clnum": 3, "pid": 77, "sc": 'write(1,"ok",4) = 4'}]


def test_config_env(monkeypatch, tmp_path):
  import importlib
  monkeypatch.setenv("QIRA_TRACE_DIR", str(tmp_path / "t"))
  monkeypatch.setenv("QIRA_STATIC_CACHE_DIR", str(tmp_path / "c"))
  monkeypatch.setenv("QIRA_TRACER_DIR", str(tmp_path / "tr"))
  try:
    importlib.reload(qira_config)
    assert qira_config.TRACE_FILE_BASE == str(tmp_path / "t") + "/"
    assert qira_config.STATIC_CACHE_BASE == str(tmp_path / "c") + "/"
    assert qira_config.TRACER_DIR == str(tmp_path / "tr") + "/"
  finally:
    monkeypatch.undo()
    importlib.reload(qira_config)
  assert qira_config.TRACE_FILE_BASE == "/tmp/qira_logs/"


def test_delete_old_runs_keeps_dir(program, trace_dir):
  # the trace dir may be a mount point (sandbox bind mount), so it is emptied, not removed
  base = qira_config.TRACE_FILE_BASE
  ino = os.stat(base).st_ino
  open(base + "0", "wb").close()
  os.mkdir(base + "0_images")
  open(base + "0_images/x", "wb").close()
  program.delete_old_runs()
  assert os.listdir(base) == []
  assert os.stat(base).st_ino == ino


def test_create_asm_file_truncates(program):
  with open(qira_config.ASM_FILE, "w") as f:
    f.write("0x400000|old\n")
  ino = os.stat(qira_config.ASM_FILE).st_ino
  program.create_asm_file()
  assert os.path.getsize(qira_config.ASM_FILE) == 0
  assert os.stat(qira_config.ASM_FILE).st_ino == ino


def test_flush_caches(trace_dir, tmp_path, monkeypatch):
  # --flush-cache used to run `rm -rfv /tmp/qira*`; now it empties the configured paths only
  cache = tmp_path / "static_cache"
  cache.mkdir()
  (cache / "abc").write_text("x")
  monkeypatch.setattr(qira_config, "STATIC_CACHE_BASE", str(cache) + "/")
  (trace_dir / "0").write_bytes(b"x")
  (trace_dir / "0_images").mkdir()
  asm = tmp_path / "qira_asm"
  asm.write_text("0x400000|old\n")
  other = tmp_path / "qira_other"
  other.write_text("keep")
  ino = os.stat(trace_dir).st_ino

  qira_program.flush_caches()

  assert os.listdir(trace_dir) == [] and os.stat(trace_dir).st_ino == ino
  assert os.listdir(cache) == []
  assert asm.read_text() == ""
  assert other.read_text() == "keep"


def test_flush_caches_missing_paths(tmp_path, monkeypatch):
  monkeypatch.setattr(qira_config, "TRACE_FILE_BASE", str(tmp_path / "nope") + "/")
  monkeypatch.setattr(qira_config, "STATIC_CACHE_BASE", str(tmp_path / "nope2") + "/")
  monkeypatch.setattr(qira_config, "ASM_FILE", str(tmp_path / "nope3"))
  qira_program.flush_caches()
  assert os.listdir(tmp_path) == []


def test_default_tracer_dir():
  # a checkout: next to middleware/
  assert qira_config.TRACER_DIR == os.path.join(qira_config.BASEDIR, "tracers", "")
  assert qira_config.default_dir("libs", "/src/qira/middleware", {}) == "/src/qira/libs"
  # an installed copy: the per-user data folder
  site = "/home/u/.local/share/uv/tools/qira/lib/python3.13/site-packages/qira"
  assert qira_config.default_dir("tracers", site, {"XDG_DATA_HOME": "/xdg"}) == "/xdg/qira/tracers"
  assert qira_config.default_dir("tracers", site, {}) == os.path.expanduser("~/.local/share/qira/tracers")
