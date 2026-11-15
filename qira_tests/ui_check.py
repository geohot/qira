"""Open a running QIRA UI in headless Firefox (Selenium) and report what the browser sees.

Prints JavaScript errors and console messages, the text of the main panes, and saves a
screenshot. Start the server first (same command in the sandbox), e.g.

  ./qira --no-run --no-delete-runs --host 127.0.0.1 --web-port 3012 qira_tests/bin/loop &
  uv run python qira_tests/ui_check.py --url http://127.0.0.1:3012 --screenshot ui.png

Needs Firefox; Selenium Manager downloads geckodriver (from github.com) on first use.
Exit status 1 if the page logged JavaScript errors.
"""
import argparse
import os
import shutil
import sys
import tempfile
import time

os.environ.setdefault("SE_AVOID_STATS", "true")  # no usage statistics from Selenium Manager

from selenium import webdriver
from selenium.webdriver.common.by import By
from selenium.webdriver.firefox.service import Service

PANES = ["#controls", "#idump", "#regviewer", "#datachanges", "#hexdump", "#strace", "#vtimelinebox"]


def main():
  ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
  ap.add_argument("--url", default="http://127.0.0.1:3012/")
  ap.add_argument("--wait", type=float, default=5.0, help="seconds to let the page load data")
  ap.add_argument("--screenshot", help="save a PNG here")
  ap.add_argument("--size", default="1600x1000")
  ap.add_argument("--eval", action="append", default=[], metavar="JS",
                  help="run this JavaScript after loading (as a function body) and print what it returns")
  ap.add_argument("--wait-after", type=float, default=0, help="seconds to wait after each --eval")
  # ida.js always tries the optional IDA plugin bridge on ws://localhost:3003 (legacy behaviour)
  ap.add_argument("--ignore", action="append", default=["localhost:3003"],
                  help="JS errors containing this text don't count for the exit status")
  args = ap.parse_args()

  opts = webdriver.FirefoxOptions()
  opts.add_argument("-headless")
  opts.enable_bidi = True
  # Firefox hangs at startup if it cannot write $HOME (e.g. in Claude's sandbox)
  home = tempfile.mkdtemp(prefix="qira-ui-home-")
  driver = webdriver.Firefox(options=opts, service=Service(env=dict(os.environ, HOME=home)))
  messages, errors = [], []
  try:
    driver.script.add_javascript_error_handler(lambda e: errors.append(e))
    driver.script.add_console_message_handler(lambda e: messages.append(e))
    w, h = (int(x) for x in args.size.split("x"))
    driver.set_window_size(w, h)
    driver.get(args.url)
    time.sleep(args.wait)

    for js in args.eval:
      print("eval: %s\n  -> %r" % (js, driver.execute_script(js)))
      time.sleep(args.wait_after)

    print("title:", driver.title)
    for e in errors:
      print("JS ERROR:", e.text, _where(e))
    for m in messages:
      print("console.%s:" % m.level, m.text, _where(m))
    for sel in PANES:
      found = driver.find_elements(By.CSS_SELECTOR, sel)
      if not found:
        print("%-14s (not on the page)" % sel)
        continue
      text = " ".join(found[0].text.split())
      if not text:  # e.g. #controls: input fields only
        text = " ".join(i.get_attribute("value") or "''" for i in found[0].find_elements(By.TAG_NAME, "input"))
      print("%-14s %s" % (sel, (text[:200] + "…") if len(text) > 200 else (text or "(empty)")))
    if args.screenshot:
      driver.save_screenshot(args.screenshot)
      print("screenshot:", args.screenshot)
  finally:
    driver.quit()
    shutil.rmtree(home, ignore_errors=True)
  return 1 if [e for e in errors if not any(i in e.text for i in args.ignore)] else 0


def _where(entry):
  frames = getattr(getattr(entry, "stacktrace", None), "call_frames", None) or []
  if not frames:
    return ""
  f = frames[0]
  return "  @ %s:%s" % (f.url.rsplit("/", 1)[-1], f.line_number + 1)


if __name__ == "__main__":
  sys.exit(main())
