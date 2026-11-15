import os

TRACE_LIBRARIES = False
HOST = '0.0.0.0'
WEB_PORT = 3002
SOCAT_PORT = 4000
FORK_PORT = SOCAT_PORT + 1
USE_PIN = False

def _dir_from_env(name, default):
  # directories are used as prefixes ("<dir>" + "0_strace"), keep the trailing slash
  return os.path.join(os.environ.get(name) or default, "")

# where the package lives (middleware/ in a checkout, site-packages/qira when installed)
PKGDIR = os.path.dirname(os.path.realpath(__file__))
# root of the source checkout; tracers/ and libs/ are only found here
BASEDIR = os.path.realpath(os.path.join(PKGDIR, ".."))

# web/ is shipped inside the package when installed, next to middleware/ in a checkout
WEB_DIR = os.path.join(PKGDIR, "web")
if not os.path.isdir(WEB_DIR):
  WEB_DIR = os.path.join(BASEDIR, "web")

def data_dir(environ=os.environ):
  """Per-user data folder for installed copies: $XDG_DATA_HOME/qira (~/.local/share/qira)."""
  return os.path.join(environ.get("XDG_DATA_HOME") or os.path.join(os.path.expanduser("~"), ".local", "share"), "qira")

def default_dir(name, pkgdir=PKGDIR, environ=os.environ):
  """Where tracers/ or libs/ live: next to middleware/ in a source checkout (the package
  is mapped from it), in data_dir() for an installed copy (uv tool install, a wheel)."""
  if os.path.basename(pkgdir) == "middleware":
    return os.path.join(os.path.dirname(pkgdir), name)
  return os.path.join(data_dir(environ), name)

# tracers/ (qemu/qira-<arch>, pin/) and the libs/ from fetchlibs.sh
TRACER_DIR = _dir_from_env("QIRA_TRACER_DIR", default_dir("tracers"))
LIBS_DIR = _dir_from_env("QIRA_LIBS_DIR", default_dir("libs"))

# QIRA QEMU TCG plugin (tracers/qemu-plugin/libqira.so). Loaded into an upstream
# qemu-<arch> found in TRACER_DIR/qemu/ or on PATH (the devenv shell provides it).
# Used for x86_64; other arches fall back to the legacy qira-<arch> for now.
QEMU_PLUGIN = os.environ.get("QIRA_QEMU_PLUGIN") or os.path.join(TRACER_DIR, "qemu-plugin", "libqira.so")

# NOTE: the QEMU and PIN tracers write to /tmp/qira_logs/ and /tmp/qira_asm themselves,
# these settings only change where the middleware reads from
if os.name == "nt":
  TRACE_FILE_BASE = _dir_from_env("QIRA_TRACE_DIR", "c:/qiratmp")
else:
  TRACE_FILE_BASE = _dir_from_env("QIRA_TRACE_DIR", "/tmp/qira_logs/")
ASM_FILE = os.environ.get("QIRA_ASM_FILE") or "/tmp/qira_asm"

# TODO: make this true in v3
WITH_STATIC = False
STATIC_CACHE_BASE = _dir_from_env("QIRA_STATIC_CACHE_DIR", "/tmp/qira_static_cache/")

WEBSOCKET_DEBUG = False
