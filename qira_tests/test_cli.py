import socket
import sys

import pytest

from qira.legacy import qira, qira_config, qira_socat, qira_webserver
from conftest import LOOP


@pytest.fixture
def listener():
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.bind(("127.0.0.1", 0))
  s.listen(1)
  yield s.getsockname()[1]
  s.close()


def test_qira_is_running(listener):
  assert qira.qira_is_running("127.0.0.1", listener)
  # a wildcard listen address is checked through loopback
  assert qira.qira_is_running("0.0.0.0", listener)


def test_qira_is_not_running():
  s = socket.socket()
  s.bind(("127.0.0.1", 0))
  port = s.getsockname()[1]
  s.close()  # bound once, nothing listens now
  assert not qira.qira_is_running("127.0.0.1", port)


def test_server_refuses_when_qira_is_running(listener, trace_dir, monkeypatch):
  # this used to be swallowed by a bare except, and a second server was started
  for name in ("HOST", "WEB_PORT", "SOCAT_PORT", "FORK_PORT", "USE_PIN"):
    monkeypatch.setattr(qira_config, name, getattr(qira_config, name))  # main() sets them
  monkeypatch.setattr(sys, "argv", ["qira", "--server", "--no-run", "--host", "127.0.0.1",
                                    "--web-port", str(listener), LOOP])
  def second_server(*a, **kw):
    raise AssertionError("a second server was started")
  monkeypatch.setattr(qira_webserver, "run_server", second_server)
  monkeypatch.setattr(qira_socat, "start_bindserver", second_server)
  with pytest.raises(SystemExit) as e:
    qira.main()
  assert "already running" in str(e.value)
