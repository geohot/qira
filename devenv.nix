{ pkgs, lib, config, ... }:

# Development shell for QIRA: Python 3.13 + uv, plus the C++ compiler from stdenv
# (needed to build the qiradb extension). Enter it with `devenv shell`, or
# automatically with direnv (see .envrc). QIRA_* settings come from .env.
{
  languages.python = {
    enable = true;
    package = pkgs.python313;
    uv.enable = true;
  };

  env = {
    # keep the project environment where ./qira and the docs expect it
    UV_PROJECT_ENVIRONMENT = lib.mkForce "${config.devenv.root}/.venv";
    # use the Python from this shell, never a downloaded one
    UV_PYTHON = "${config.languages.python.package}/bin/python3";
    UV_PYTHON_DOWNLOADS = "never";
  };

  enterShell = ''
    uv sync --quiet
  '';

  enterTest = ''
    uv run pytest
  '';
}
