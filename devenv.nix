{ pkgs, lib, config, ... }:

# Development shell for QIRA: Python 3.13 + uv, plus the C++ compiler from stdenv
# (needed to build the qiradb extension), and QEMU user mode with TCG plugins for the
# tracer (docs/tracer-assessment.md). Enter it with `devenv shell`, or automatically
# with direnv (see .envrc). QIRA_* settings come from .env.
{
  languages.python = {
    enable = true;
    package = pkgs.python313;
    uv.enable = true;
  };

  # the tracer: qemu-<arch> user-mode emulators with plugin support (QEMU 11.1.x at the
  # devenv.lock pin) and what the plugin build needs (glib headers, pkg-config)
  packages = [
    pkgs.qemu-user
    pkgs.glib.dev
    pkgs.pkg-config
  ];

  env = {
    # qemu-plugin.h for tracers/qemu-plugin/ (the plugin must match this QEMU's API)
    QEMU_PLUGIN_INCLUDE = "${pkgs.qemu-user}/include";
    # keep the project environment where ./qira and the docs expect it
    UV_PROJECT_ENVIRONMENT = lib.mkForce "${config.devenv.root}/.venv";
    # use the Python from this shell, never a downloaded one
    UV_PYTHON = "${config.languages.python.package}/bin/python3";
    UV_PYTHON_DOWNLOADS = "never";
  };

  # .env is loaded by direnv (.envrc), not by devenv's deprecated dotenv integration
  dotenv.disableHint = true;

  enterShell = ''
    uv sync --quiet
  '';

  enterTest = ''
    uv run pytest
  '';
}
