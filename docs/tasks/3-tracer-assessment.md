# Task 3 — Assess the QEMU tracer

The assessment is in [docs/tracer-assessment.md](../tracer-assessment.md).

**Decision proposed:** replace the tracer with a QEMU TCG plugin, pinned to QEMU 11.1.x
(nixpkgs `qemu-user` for development, built from source for `install.sh`/Docker). Do not rebase
the qira patches (QEMU 2.5.1 + 780 lines in the TCG interpreter).

## How it was checked

* `git clone --filter=blob:none --single-branch --branch qira https://github.com/geohot/qemu.git`
  → base `v2.5.1`, `git diff --stat v2.5.1 qira`: 10 files, +780/−34.
* `include/{qemu,plugins}/qemu-plugin.h` fetched for QEMU 8.2, 9.0, 9.1, 9.2, 10.0, 10.1, 10.2,
  11.0 and 11.1.3 from `github.com/qemu/qemu` (shallow, blobless): API version and functions per
  release.
* Debian: `apt-cache show/search qemu-user` (offline); QEMU v10.0.0 `configure` rejects static +
  plugins.
* nixpkgs at the `devenv.lock` pin `674a202`: `pkgs/by-name/qe/qemu/package.nix` and
  `all-packages.nix` (`qemu-user`, 11.1.2, plugins on).
* Spike: QEMU v11.1.3 built from GitHub sources in `$TMPDIR`
  (`--target-list=x86_64-linux-user --enable-plugins`, 80 s), `tracers/qemu-plugin/spike/qira_spike.c`
  run on `qira_tests/bin/loop` and compared with `samples/legacy/0` using `qira_log.read_log`:
  identical `(clnum, pc, size)` sequence (149 instructions); store counts equal at 32 of 42 clnums
  (the rest are libc calls: glibc 2.23 vs 2.41).

## Not verified

* That `cache.nixos.org` serves `qemu-user` 11.1.2 for the pinned nixpkgs (not reachable from the
  sandbox). The user sees it when entering the devenv shell after Task 5 adds it.
* Plugin throughput (the `loop` run is too short); Stage 1A / Task 5 measures it.
* Debian's packaging files (salsa.debian.org is not reachable); the static build is stated in the
  package description and enforced by QEMU's configure.

## For the next tasks

* Task 5 (new): a minimal plugin tracer the legacy middleware can use, so Task 4 has something
  to install. See UPGRADE.md.
* Build hints: `qemu_plugin_start_code()` is not valid during `qemu_plugin_install`; API 7 callbacks
  take a `userdata` argument; QEMU's subprojects (`keycodemapdb`, `berkeley-softfloat-3`,
  `berkeley-testfloat-3`) are mirrored at `github.com/qemu/<name>`; configure needs PyPI (`wheel`).
