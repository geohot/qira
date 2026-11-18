# QIRA

* QIRA is a competitor to strace and gdb
* See http://qira.me/ for high level usage information
* All QIRA code is released under MIT license
* Other code in this repo released under its respective license

## Status

This is the Python 3 fork of QIRA, being modernised to run on Debian 13. See
[UPGRADE.md](UPGRADE.md) for the roadmap and what is done. Tasks 1, 3 and 5 are complete
(Python 3 port, tracer decision, and the first QEMU 11.1 plugin tracer).

## Supported OS

<pre>
Debian 13 (x86_64) is the supported host.
The tracer is the QEMU 11.1 TCG plugin (tracers/qemu-plugin/, libqira.so); x86_64 only today.
Other architectures still need the legacy QEMU fork and are not ported yet.
Docker images for debian:13 and ubuntu:26.04 are defined in docker/ (not built in CI yet).
Windows binaries are view-only (from a trace captured elsewhere) until Stage 1B.
</pre>

## Installing release

See instructions on [qira.me](http://qira.me/) to install 1.3

## Installing trunk (Debian 13, Python 3)

QIRA is a [uv](https://docs.astral.sh/uv/) project. The development shell is defined with
[devenv](https://devenv.sh/) (`devenv.nix`); with [direnv](https://direnv.net/) it is entered
automatically and `.env` is loaded:

<pre>
git clone https://github.com/geohot/qira.git
cd qira/
cp .env.example .env # QIRA_* settings, edit as needed
direnv allow         # or: devenv shell (runs uv sync: creates .venv and compiles qiradb)
make -C tracers/qemu-plugin   # build libqira.so (needed before ./qira can trace)
uv run pytest        # tests
./qira /bin/ls /     # or: uv run qira /bin/ls /
</pre>

The devenv shell provides the plugin-enabled `qemu-user` 11.1.x; the plugin (`libqira.so`) is
built from `tracers/qemu-plugin/`. Without it, `qira` can only open existing traces.

Without devenv you need `python3-dev`, `build-essential` and uv; run `uv sync` yourself and pass
the settings with `uv run --env-file .env qira …`.

Or install the `qira` command as a uv tool:

<pre>
uv tool install .
</pre>

An installed copy looks for the tracer in `${XDG_DATA_HOME:-~/.local/share}/qira/tracers/`;
nothing installs it there yet, so `uv tool install .` currently gives a `qira` that can only open
existing traces until Task 4 adds the install step. For tracing, use the devenv shell above.

Settings (environment variables, usually set in `.env`): `QIRA_TRACE_DIR` (default `/tmp/qira_logs`),
`QIRA_ASM_FILE` (`/tmp/qira_asm`), `QIRA_STATIC_CACHE_DIR`. The QEMU plugin tracer takes its output
paths as plugin arguments (`dir=`/`asm=`) and writes straight to the configured trace/asm paths;
only the legacy per-arch binaries still hardcode `/tmp/qira_logs` and `/tmp/qira_asm`.
`QIRA_TRACER_DIR` is no longer needed (the install location is used instead); `QIRA_LIBS_DIR` (the
`libs/` folder from `fetchlibs.sh`) is legacy and goes away in Task 6.

`install.sh` still targets Ubuntu 16.04; see [UPGRADE.md](UPGRADE.md) Task 4.

## Tests

<pre>
uv run pytest             # everything
uv run pytest -m unit     # quick unit level
uv run pytest -m functional
uv run pytest -m ui       # web UI in headless Firefox (Selenium)
uv run pytest --cov       # coverage of the qira package
</pre>

Every test is marked `unit`, `functional` or `ui`; see the Testing strategy in
[UPGRADE.md](UPGRADE.md).

## Installation Extras (legacy)

These belong to the old stack and are removed in Task 6; they are not supported with the QEMU
plugin tracer:

* ./fetchlibs.sh fetched the libraries for i386, armhf, armel, aarch64, mips, mipsel, and ppc
* ./tracers/pin_build.sh installed the QIRA PIN plugin (`--pin`); PIN is not carried over


## Releases

* v1.3 -- Update using pinned python packages
* v1.2 -- Many many changes. Forced release due to v1.0 not working anymore.
* v1.1 -- Support for names and comments. Static stuff added. Register colors.
* v1.0 -- Perf is good! Tons of bugfixes. Quality software. http://qira.me/
* v0.9 -- Function indentation. haddrline added (look familiar?). Register highlighting in hexdump.
* v0.8 -- Intel syntax! Shipping CDA (cda a.out) and experimental PIN backend. Bugfixes. Windows support?
* v0.7 -- DWARF support. Builds QEMU if distributed binaries don't work. Windows IDA plugin.
* v0.6 -- Added changes before webforking. Highlight strace addresses. Default on analysis.
* v0.5 -- Fixed regression in C++ database causing wrong values. Added PowerPC support. Added "A" button.
* v0.4 -- Using 50x faster C++ database. strace support. argv and envp are there.
* v0.3 -- Built in socat, multiple traces, forks (experimental). Somewhat working x86-64 and ARM support
* v0.2 -- Removed dependency on mongodb, much faster. IDA plugin fixes, Mac version.
* v0.1 -- Initial release


## UI

<pre>
At the top, you have 4 boxes, called the controls.
  Blue = change number, grey = fork number
  red = instruction address (iaddr), yellow = data address (daddr).

On the left you have the vtimeline, this is the full trace of the program.
  The top is the start of the program, the bottom is the end/current state.
  More green = deeper into a function.
  The currently selected change is blue, red is every passthrough of the current iaddr
  Bright yellow is a write to the daddr, dark yellow is a read from the daddr.
  This color scheme is followed everywhere.

Below the controls, you have the idump, showing instructions near the current change
Under that is the regviewer, datachanges, hexeditor, and strace, all self explanatory.
</pre>


## Mouse Actions
Click on vtimeline to navigate around. Right-click forks to delete them. Click on data (or doubleclick if highlightable) to follow in data. Right-click on instruction address to follow in instruction.

## Keyboard Shortcuts in web/client/controls.js
<pre>
j -- next invocation of instruction
k -- prev invocation of instruction

shift-j -- next toucher of data
shift-k -- prev toucher of data

m -- go to return from current function
, -- go to start of current function

z -- zoom out max on vtimeline

left  -- -1 fork
right -- +1 fork
up    -- -1 clnum
down  -- +1 clnum

esc -- back

shift-c -- clear all forks

n -- rename instruction
shift-n -- rename data
: -- add comment at instruction
shift-: -- add comment at data

g -- go to change, address, or name
space -- toggle flat/function view

p -- analyze function at iaddr
c -- make code at iaddr, one instruction
a -- make ascii at iaddr
d -- make data at iaddr
u -- make undefined at iaddr
</pre>

## Windows

Windows binaries are currently **view-only**: QIRA can display a trace captured elsewhere (e.g.
`tests_manual/windows/`), but cannot record on Windows yet. Tracing Windows binaries under Wine is
planned for Stage 1B, and a Windows-native tracer (DynamoRIO) for Stage 5 (see
[UPGRADE.md](UPGRADE.md)). The old Python 2.7 `install.bat` path is gone.


## Session state
<pre>
clnum -- selected changelist number
forknum -- selected fork number
iaddr -- selected instruction address
daddr -- selected data address

cview -- viewed changelists in the vtimeline
dview -- viewed window into data in the hexeditor
iview -- viewed address in the static view

max_clnum -- max changelist number for each fork
dirtyiaddr -- whether we should update the clnum based on the iaddr or not
flat -- if we are in flat view
</pre>


## Static

QIRA static has historically been such a trash heap it's gated behind -S. QIRA should not be trying to compete with IDA.

User input and the actual traces of the program should drive creation of the static database. Don't try to recover all CFGs, only what ran.

The basic idea of static is that it exists at change -1 and doesn't change ever. Each address has a set of tags, including things like name.

