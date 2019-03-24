import os,sys

TRACE_LIBRARIES = False
HOST = '0.0.0.0'
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

# TODO: make this true in v3
WITH_STATIC = False
STATIC_CACHE_BASE = "/tmp/qira_static_cache/"

WEBSOCKET_DEBUG = False

