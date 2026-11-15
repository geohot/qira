"""The web UI in a real browser (headless Firefox via Selenium).

Starts ./qira on the synthetic trace from conftest.py and checks that the panes fill in.
This caught the socket.io 4 regression where every client module opened its own
connection, so registers, instructions and memory never rendered.

Skipped when Firefox or geckodriver (fetched by Selenium Manager from github.com) is missing.
"""
import os
import shutil
import socket
import subprocess
import sys
import time

import pytest

from conftest import LOOP, REPO, STACK

selenium = pytest.importorskip("selenium")
from selenium import webdriver  # noqa: E402
from selenium.common.exceptions import WebDriverException  # noqa: E402
from selenium.webdriver.common.by import By  # noqa: E402
from selenium.webdriver.firefox.service import Service  # noqa: E402
from selenium.webdriver.support.ui import WebDriverWait  # noqa: E402

os.environ.setdefault("SE_AVOID_STATS", "true")


def _free_port():
  s = socket.socket()
  s.bind(("127.0.0.1", 0))
  port = s.getsockname()[1]
  s.close()
  return port


@pytest.fixture
def server(loop_trace, tmp_path):
  port = _free_port()
  env = dict(os.environ, QIRA_TRACE_DIR=str(loop_trace), QIRA_ASM_FILE=str(tmp_path / "qira_asm"),
             QIRA_STATIC_CACHE_DIR=str(tmp_path / "static_cache"))
  log = open(tmp_path / "server.log", "w")
  proc = subprocess.Popen([sys.executable, "-m", "qira", "--no-run", "--no-delete-runs", "--host", "127.0.0.1",
                           "--web-port", str(port), "--socat-port", str(_free_port()), LOOP],
                          cwd=REPO, env=env, stdout=log, stderr=subprocess.STDOUT)
  try:
    end = time.time() + 30
    while True:
      try:
        socket.create_connection(("127.0.0.1", port), timeout=1).close()
        break
      except OSError:
        assert proc.poll() is None, open(tmp_path / "server.log").read()
        assert time.time() < end, "server did not start"
        time.sleep(0.2)
    yield "http://127.0.0.1:%d/" % port
  finally:
    proc.terminate()
    proc.wait(10)


@pytest.fixture
def browser(tmp_path):
  if not shutil.which("firefox"):
    pytest.skip("firefox not installed")
  opts = webdriver.FirefoxOptions()
  opts.add_argument("-headless")
  # Firefox hangs at startup if it cannot write $HOME (e.g. in Claude's sandbox)
  home = tmp_path / "home"
  home.mkdir()
  try:
    driver = webdriver.Firefox(options=opts, service=Service(env=dict(os.environ, HOME=str(home))))
  except WebDriverException as e:
    pytest.skip("no geckodriver: %s" % e.msg)
  driver.set_window_size(1600, 1000)
  yield driver
  driver.quit()


def _text(driver, sel):
  return driver.find_element(By.CSS_SELECTOR, sel).text


def test_ui_panes_fill_in(server, browser):
  browser.get(server)
  wait = WebDriverWait(browser, 20)
  # the client uses a single Socket.IO connection for all modules
  wait.until(lambda d: d.execute_script("return typeof stream !== 'undefined' && stream.connected"))
  browser.execute_script('$("#control_clnum").val("2").trigger("change");')

  wait.until(lambda d: "push" in _text(d, "#idump"))
  idump = _text(browser, "#idump")
  assert "main" in idump and "mov" in idump and "sub" in idump

  wait.until(lambda d: "RSP" in _text(d, "#regviewer"))
  # the UI shows the registers before the selected change: after `mov rbp, rsp`, before `sub rsp, 0x10`
  regs = _text(browser, "#regviewer")
  assert "RSP: %s" % hex(STACK - 8) in regs and "RIP: 0x40053a" in regs

  # select the stack slot written at clnum 0; the hexdump shows the stored bytes
  browser.execute_script('$("#control_daddr").val("%s").trigger("change");' % hex(STACK - 8))
  wait.until(lambda d: "88 77 66 55 44 33 22 11" in _text(d, "#hexdump"))
