import argparse
import time

import pytest

from qira.legacy import qira_program, qira_webserver as ws
from qira.legacy import qira_webstatic  # registers its routes, as run_server() does before serving
from conftest import LOOP, RSP, STACK, wait_for_update


@pytest.fixture
def http():
  return ws.app.test_client()


def test_index(http):
  r = http.get("/")
  assert r.status_code == 200
  assert b"<title>qira</title>" in r.data
  assert r.mimetype == "text/html"


def test_static_files(http):
  # binary files must come through unchanged
  r = http.get("/favicon.ico")
  assert r.status_code == 200 and r.data[:4] == b"\x00\x00\x01\x00"
  # client/*.js is wrapped, client/compatibility/*.js is not
  r = http.get("/client/controls.js")
  assert r.mimetype == "application/javascript"
  assert r.data.startswith(b"(function(){") and r.data.endswith(b"})();")
  r = http.get("/client/compatibility/socket.io.min.js")
  assert b"Socket.IO v4" in r.data[:100]
  assert ws.serve("../pyproject.toml") == ("", 404)
  assert http.get("/does-not-exist.js").data == b""


@pytest.fixture
def sio(trace_dir, loop_trace):
  program = qira_program.Program(LOOP)
  program.create_asm_file()
  t = program.add_trace(str(loop_trace / "0"), 0)
  wait_for_update(t.db)
  ws.program = program
  ws.args = argparse.Namespace(server=False)
  qira_webstatic.init(program)
  client = ws.socketio.test_client(ws.app, namespace="/qira")
  yield client
  client.disconnect(namespace="/qira")
  t.keep_analysis_thread = False


def received(client, name):
  return [m["args"] for m in client.get_received("/qira") if m["name"] == name]


def test_socketio_connect_pushes_state(sio):
  msgs = {m["name"]: m["args"] for m in sio.get_received("/qira")}
  assert msgs["maxclnum"] == [{"0": [0, 3]}]
  assert msgs["arch"][0][3] == "x86-64"
  assert msgs["pmaps"][0]["0x400000"] == "instruction"
  assert msgs["strace"][0]["forknum"] == 0


def test_socketio_queries(sio):
  sio.get_received("/qira")

  sio.emit("getregisters", 0, 2, namespace="/qira")
  regs = received(sio, "registers")[0][0]
  rsp = [r for r in regs if r["name"] == "RSP"][0]
  assert rsp["value"] == hex(STACK - 0x18) and rsp["address"] == RSP
  # regactions show what the next change (clnum 3) does: read RBP, write RIP
  actions = {r["name"]: r["regactions"] for r in regs}
  assert (actions["RSP"], actions["RBP"], actions["RIP"]) == ("", "regread", "regwrite")
  assert len(regs) == 17

  sio.emit("getmemory", 0, 0, hex(STACK - 8), 8, namespace="/qira")
  mem = received(sio, "memory")[0][0]
  assert mem["address"] == hex(STACK - 8) and mem["ptrsize"] == 8
  # JSON on the wire: the byte offsets arrive as string keys
  assert [mem["dat"][str(i)] for i in range(8)] == list(bytes.fromhex("8877665544332211"))

  sio.emit("getinstructions", 0, 1, 0, 3, namespace="/qira")
  ins = received(sio, "instructions")[0][0]
  assert [(i["address"], i["instruction"]) for i in ins] == [
    ("0x400536", "push\trbp"), ("0x400537", "mov\trbp, rsp"), ("0x40053a", "sub\trsp, 0x10")]

  sio.emit("getclnum", 0, 0, "IWS", 10, namespace="/qira")
  cl = received(sio, "clnum")[0][0]
  assert [c["type"] for c in cl] == ["I", "W", "S", "W"]

  sio.emit("getchanges", 0, hex(RSP), "W", [0, 10], 1, 2, namespace="/qira")
  assert received(sio, "changes")[0][0] == {"type": "W", "clnums": {"0": [0, 2]}}

  sio.emit("getnames", ["0x400536"], namespace="/qira")
  assert received(sio, "names")[0][0] == {"0x400536": "main"}


def test_doanalysis_sends_picture(sio):
  t = ws.program.traces[0]
  end = time.time() + 10
  while t.maxclnum is None:  # wait for the analysis thread
    assert time.time() < end, "analysis thread did not finish"
    time.sleep(0.05)
  sio.get_received("/qira")
  # the synthetic trace has no calls, so its depth map is flat and there is no picture
  sio.emit("doanalysis", 0, namespace="/qira")
  assert received(sio, "setpicture") == []

  t.keep_analysis_thread = False
  t.dmap, t.maxd = [0, 1, 2, 1], 2
  sio.emit("doanalysis", 0, namespace="/qira")
  pic = received(sio, "setpicture")[0][0]
  assert pic["forknum"] == 0 and (pic["minclnum"], pic["maxclnum"]) == (t.minclnum, t.maxclnum)
  assert pic["data"].startswith("data:image/png;base64,")
