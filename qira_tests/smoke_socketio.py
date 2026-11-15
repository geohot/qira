#!/usr/bin/env python3
"""Socket.IO smoke test against a running QIRA server.

  uv run python qira_tests/smoke_socketio.py [--url http://127.0.0.1:3012] [--fork 0]

Connects to the /qira namespace, waits for the state the server pushes on connect
(maxclnum, arch, pmaps, strace), then asks for registers, memory and instructions at a
few clnums of one fork and checks that a reply arrives for each. Exits non-zero on failure.
"""
import argparse
import queue
import sys
import time

import socketio

PUSHED = ("maxclnum", "arch", "pmaps", "strace")
REPLIES = ("registers", "memory", "instructions")


def main():
  ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
  ap.add_argument("--url", default="http://127.0.0.1:3012")
  ap.add_argument("--fork", type=int, default=0)
  ap.add_argument("--timeout", type=float, default=20.0, help="seconds to wait for each reply")
  args = ap.parse_args()

  events = queue.Queue()
  sio = socketio.Client()
  for name in PUSHED + REPLIES + ("setpicture",):
    sio.on(name, (lambda n: lambda *a: events.put((n, a)))(name), namespace="/qira")

  def wait_for(name, pred=lambda a: True):
    end = time.time() + args.timeout
    while time.time() < end:
      try:
        n, a = events.get(timeout=max(0.01, end - time.time()))
      except queue.Empty:
        break
      if n == name and pred(a):
        return a
    raise SystemExit("FAIL: no '%s' within %.0fs" % (name, args.timeout))

  sio.connect(args.url, namespaces=["/qira"], transports=["websocket"], wait_timeout=args.timeout)
  print("connected to %s (transport %s)" % (args.url, sio.transport()))

  # the trace loads in the background; wait until the fork shows up in maxclnum
  key = str(args.fork)
  (maxclnum,) = wait_for("maxclnum", lambda a: key in a[0] and a[0][key][1] > 0)
  minc, maxc = maxclnum[key]
  print("maxclnum:", maxclnum)
  (arch,) = wait_for("arch")
  print("arch: %s, %d registers of %d bytes" % (arch[3], len(arch[0]), arch[1]))

  ok = True
  clnums = sorted({minc, minc + 1, (minc + maxc) // 2, maxc - 1})
  for clnum in clnums:
    sio.emit("getregisters", (args.fork, clnum), namespace="/qira")
    (regs,) = wait_for("registers")
    named = {r["name"]: r["value"] for r in regs}
    pc = named.get(arch[0][-1])

    sio.emit("getinstructions", (args.fork, clnum, clnum - 2, clnum + 3), namespace="/qira")
    (ins,) = wait_for("instructions")

    sp_name = {8: "RSP", 4: "ESP"}.get(arch[1], arch[0][4])
    sp = named.get(sp_name) or "0x0"
    sio.emit("getmemory", (args.fork, clnum, sp, 32), namespace="/qira")
    (mem,) = wait_for("memory")

    here = [i for i in ins if i.get("depth") is not None]
    print("clnum %6d: %2d regs, pc %s, %s=%s, %d instructions (%s), %d/32 memory bytes" % (
      clnum, len(regs), pc, sp_name, sp, len(ins),
      (here[min(2, len(here) - 1)]["address"] + " " + here[min(2, len(here) - 1)]["instruction"]) if here else "-",
      len(mem["dat"])))
    if not regs or not ins:
      ok = False

  sio.disconnect()
  print("PASS" if ok else "FAIL: empty replies")
  return 0 if ok else 1


if __name__ == "__main__":
  sys.exit(main())
