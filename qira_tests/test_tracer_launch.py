"""Starting the tracer: execqira, forkat and the socat bind server.

There is no tracer on this host (issue I2), so a shell script stands in for it.
These used to os.fork() from the threaded server process; now they use subprocess
and a thread.
"""
import argparse
import os
import socket
import stat
import time

import pytest

from qira.legacy import qira_config, qira_program, qira_socat, qira_webserver as ws
from conftest import LOOP

FAKE_TRACER = """#!/bin/sh
echo "$@" > "%s"
echo "tracer up"
read line
echo "got $line"
"""


@pytest.fixture
def program(trace_dir, tmp_path):
  p = qira_program.Program(LOOP)
  p.use_plugin = False          # these tests exercise the legacy subprocess/fork path
  fake = tmp_path / "qira-fake"
  fake.write_text(FAKE_TRACER % (tmp_path / "argv"))
  fake.chmod(fake.stat().st_mode | stat.S_IXUSR)
  p.qirabinary = str(fake)
  return p


def wait_for(path, timeout=10):
  end = time.time() + timeout
  while not (os.path.exists(path) and os.path.getsize(path) > 0):
    assert time.time() < end, "the fake tracer did not run"
    time.sleep(0.02)
  return open(path).read().split()


def test_execqira_starts_a_child(program, tmp_path):
  with open(os.devnull, "r+b") as null:
    proc = program.execqira(["-qirachild", "0 5 1"], stdio=null.fileno())
  assert proc.wait(timeout=10) == 0
  argv = wait_for(tmp_path / "argv")
  assert argv[:len(program.defaultargs)] == program.defaultargs
  assert argv[-4:] == ["0", "5", "1", program.program]
  assert "-qirachild" in argv


def test_execqira_missing_tracer(program):
  program.qirabinary = "/does/not/exist/qira-x86_64"
  with pytest.raises(qira_program.TracerNotFound):
    program.execqira()


def test_forkat_writes_mods_and_starts_tracer(program, loop_trace, tmp_path, monkeypatch):
  monkeypatch.setattr(ws, "program", program, raising=False)
  monkeypatch.setattr(ws, "args", argparse.Namespace(server=False), raising=False)
  ws.forkat(0, 2, [{"daddr": hex(0x601000), "ddata": "0x41"}])
  argv = wait_for(tmp_path / "argv")
  # trace 0 exists, so the fork is run 1 and starts from clnum 2 of trace 0
  assert argv[argv.index("-qirachild") + 1:][:3] == ["0", "2", "1"]
  assert os.path.getsize(loop_trace / "1_mods") > 0


def _free_port():
  s = socket.socket()
  s.bind(("127.0.0.1", 0))
  port = s.getsockname()[1]
  s.close()
  return port


@pytest.mark.parametrize("loop", [False, True])
def test_bindserver(program, monkeypatch, loop):
  monkeypatch.setattr(qira_config, "HOST", "127.0.0.1")
  port = _free_port()
  t = qira_socat.start_bindserver(program, port, -1, 1, loop)
  try:
    for i in range(2 if loop else 1):
      with socket.create_connection(("127.0.0.1", port), timeout=10) as c:
        f = c.makefile("rwb")
        assert f.readline() == b"tracer up\n"
        f.write(b"hello %d\n" % i)
        f.flush()
        assert f.readline() == b"got hello %d\n" % i
    if not loop:
      t.join(timeout=10)
      assert not t.is_alive()  # one client only
  finally:
    qira_socat.bound_ports.pop(port).close()
