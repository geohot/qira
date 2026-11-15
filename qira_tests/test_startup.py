"""Import the entry point in a fresh interpreter.

The other tests run inside pytest, which has already loaded modules (e.g. zlib) that
the real `qira` command may load later or not at all. A clean subprocess catches
import-order problems such as Pillow's wheel needing the system libz.so.1, which the
Nix Python of the devenv shell cannot find unless Python's own zlib is loaded first.
"""
import subprocess
import sys


def _fresh(code):
  return subprocess.run([sys.executable, "-I", "-c", code], capture_output=True, text=True, timeout=60)


def test_entry_point_imports_in_a_fresh_interpreter():
  r = _fresh("from qira.qira import main; print('ok')")
  assert r.returncode == 0, r.stderr
  assert r.stdout.strip() == "ok"


def test_qira_help_runs():
  r = _fresh("import sys; sys.argv = ['qira', '--help']; from qira.qira import main; main()")
  assert r.returncode == 0, r.stderr
  assert "usage" in r.stdout.lower()
