import os,sys

WITH_CDA = False
WITH_DWARF = False
TRACE_LIBRARIES = False
HOST = '127.0.0.1'
WEB_PORT = 3002
SOCAT_PORT = 4000
FORK_PORT = SOCAT_PORT + 1
USE_PIN = False
if os.name == "nt":
  TRACE_FILE_BASE = "c:/qiratmp"
else:
  TRACE_FILE_BASE = "/tmp/qira_logs/"

BASEDIR = os.path.realpath(os.path.dirname(os.path.realpath(__file__))+"/../")
sys.path.append(BASEDIR)
CODESEARCHDIR = BASEDIR+"/cda/codesearch-latest/"
#CODESEARCHDIR = "/usr/bin/"

CALLED_AS_CDA = False

# turn this off for now on releases
# this should all be removed
WITH_STATIC = False
WITH_CAPSTONE = False
WITH_RADARE = False

WITH_STATIC2 = False

WITH_IDA = False

WEBSOCKET_DEBUG = False

# enable radare if it's installed
"""
try:
  from r2.r_core import RCore
  WITH_RADARE = True
  WITH_STATIC = True
except:
  WITH_RADARE = False
"""

