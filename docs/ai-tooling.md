# AI tooling and agents for the QIRA repo

How Claude Code and other tooling manage this repo, during the port (UPGRADE.md) and afterwards.
Each item is **in place**, or **proposed** with who applies it. Claude cannot write
`~/.claude/settings.json`, `.claude/settings.json`, `.claude/skills/` or `.claude/hooks/` (managed
settings and its sandbox protect them), so the user applies those, e.g. with `/update-config`.
Hooks and CI call `uv`, never `devenv`, so they keep working if the devenv decision in Task 4 goes
the other way.

## During the port

| What | Status | Notes |
|---|---|---|
| Task queue: "Do Task N in UPGRADE.md" | in place | One task per session, rules 1–11 in UPGRADE.md, report in `docs/tasks/`. |
| `shelfware-auditor` agent | in place | Finds custom code that should move to maintained tools; writes `docs/assessments/shelfware-<date>.md`. Run before planning a stage and when a task adds custom code. |
| `cleanup-steward` agent | in place | Removes unused or deprecated code, unused features and dependencies (vulture, ruff, deptry), and tests that point at code that is gone; fixes READMEs about removed functionality. Follows the removal order (Task 6, Stage 3). |
| `test-author` agent | in place | Writes unit/functional/ui tests from a task's "Done when" bullets; returns the criterion → test table for the report. |
| `trace-verifier` agent | in place | Captures traces and compares them with `samples/legacy/`, golden fixtures or another tracer; classifies differences. |
| `plan-steward` agent | in place | Removes fulfilled tasks, plans the next ones in the queue format, keeps UPGRADE.md/TODO.md/CLAUDE.md consistent with git, and updates README.md for what is implemented and ported. Run after each merge. |
| `/code-review` | in place (built in) | On each task branch before the user merges. |
| `/security-review` | in place (built in) | Stage 2 (network surface of the server, `--server`/socat) and changes to the plugin's C code. |
| `/simplify` | in place (built in) | Quality pass on large diffs. |
| `/code-review ultra` | in place (user-triggered, billed) | Multi-agent cloud review for big branches: Stage 1A, Stage 2, Task 6. |
| Project skill `/task <n>` | proposed (user creates `.claude/skills/task/`) | Holds rules 1–11 and the report template, so CLAUDE.md stays short and every task starts the same way. |
| Hook: format on edit | proposed (user, after Stage 0 adds ruff) | PostToolUse on Edit/Write of `*.py`: `uv run ruff format` + `uv run ruff check --fix` on the file. |
| Hook: quick tests at the end of a turn | proposed (user) | Stop hook: `uv run pytest -m unit -q`, so failures show up before a commit. |
| devenv `git-hooks` | proposed (Stage 0) | ruff, mypy, shellcheck, hadolint, codespell, nixfmt on commit; the same checks run in CI. |

Typical flow for one task: `plan-steward` (task is ready) → "Do Task N" (with `test-author` and
`trace-verifier` as needed) → `/code-review` → user merges → `plan-steward` (removes the task,
updates README) → `cleanup-steward` (what the task made obsolete) → `shelfware-auditor` before the
next stage.

## Long term (after the port)

| What | Status | Notes |
|---|---|---|
| GitHub Actions CI | proposed (Stage 0) | Lint, `pytest -m unit` and `-m functional` on every push, `-m ui` where Firefox is available, coverage threshold for `src/qira`, `docker/test.sh` for both images. |
| Claude Code GitHub Action (`anthropics/claude-code-action`) | proposed (user decides) | PR review and `@claude` in issues and PRs. Needs an `ANTHROPIC_API_KEY` repository secret. |
| Renovate | proposed | Updates `uv.lock`, GitHub Actions, npm (from Stage 3) and the pinned QEMU tag (regex manager on `QEMU_TAG`). Chosen over Dependabot because it covers all of these in one place. |
| `devenv update` workflow | proposed | Scheduled job that runs `devenv update` and opens a PR; no bot updates `devenv.lock`. |
| `pip-audit` / OSV-Scanner, GitHub CodeQL | proposed | Dependency CVEs in CI; static analysis for Python, C (plugin) and JavaScript. |
| Scheduled routines (`/schedule`) | proposed | Monthly `shelfware-auditor` and `cleanup-steward` runs; weekly triage of dependency and CVE PRs; a watch for QEMU releases that change the plugin API. |
| release-please | proposed | Versions and changelogs from conventional commits (the history already roughly follows `docs:`, `test:`, …). |
| MkDocs Material + mkdocstrings | proposed (after Stage 1D) | Documentation site with the core API reference; the REST reference comes from FastAPI's OpenAPI. |
| GitHub Issues for open issues | proposed (with CI) | Move the "Open issues" table of UPGRADE.md to issues; `plan-steward` keeps the two in sync until then. |
