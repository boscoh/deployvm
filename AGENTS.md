# AGENTS.md — Development Guide

deployvm is a Python CLI that deploys web applications to cloud providers
(DigitalOcean, AWS, Vultr). `README.md` is the user-facing reference for the
commands, the options, and the provider behaviour. Read it before you change a
command signature or a deploy step. `docs/ssl.md` documents the SSL flow and
`docs/NUXT_DEPLOY_NOTES.md` documents the Nuxt deploy notes.

## Commands

- `uv run pytest -m "not integration"` — unit tests. These tests use no cloud
  account and no SSH connection. They are the default quality gate.
- `uv run ruff check deployvm tests` — lint.
- `uv run ruff format <files>` — format.

The repository has no Makefile and no CI script. Run the two commands above by
hand after a code change.

Integration tests create a real cloud instance and delete it at the end:

```bash
uv run pytest tests/ -m integration --provider vultr -s -v
uv run pytest tests/test_integration.py::test_01_create -m integration -s
```

These tests need provider credentials and `vultr-cli`. Run them only when the
user asks. A failed run can leave a real instance behind, so check the provider
after a failure.

## Project structure

- `deployvm/cli.py` — the `deployvm` cyclopts application: `instance`, `uv`,
  `npm`, `ssl`, `nameservers`, `probe`, and `serve` commands
- `deployvm/rdomain.py` — the separate `rdomain` domain-registration CLI
- `deployvm/providers.py` — `DigitalOceanProvider`, `AWSProvider`, and
  `VultrProvider`, behind the `Provider` protocol, plus `get_provider()`
- `deployvm/server.py` — remote work over SSH: users, swap, firewall, nginx,
  certbot, file sync, and the deploy checks
- `deployvm/apps.py` — the app lifecycle for `uv` apps (`UVApp`, supervisord)
  and `npm` apps (`NpmApp`, pm2), including the exclude matcher and the sync
  hash
- `deployvm/types.py` — the shared `TypedDict`s and `Literal` aliases
- `deployvm/utils.py` — logging, subprocess helpers, and the SSH user lookup
- `tests/conftest.py` — the session fixture that creates and deletes the real
  instance for the integration tests
- `tests/fixtures/` — the small FastAPI and Flask apps that the integration
  tests deploy

## Architecture & invariants

- **The instance file is the local record.** `load_instance`/`save_instance`
  read and write `<name>.instance.json`. It holds the instance id, the IP, the
  provider, and the app list. `resolve_instance` turns a name or an IP into the
  record. Keep this file in step with the remote state after every change.
- **The provider is chosen at one point.** Every command resolves a provider
  through `get_provider()` and `DEPLOY_VM_PROVIDER`. A new provider must
  satisfy the `Provider` protocol, and the `ProviderName` alias in `types.py`
  must include the new name.
- **nginx owns the public port.** A `uv` app or an `npm` app listens on
  `127.0.0.1` on `--port`. nginx listens on the public `--outgoing-port`
  (default 80). The internal port and the outgoing port must differ.
- **Two app managers.** `uv` apps run under supervisord and need a
  `pyproject.toml`. `npm` apps run under pm2 and need a `package.json` with a
  `build` script. `BaseApp` holds the shared sync logic; `UVApp` and `NpmApp`
  hold the differences.
- **The exclude matcher must agree with rsync.** `_is_excluded_path` computes
  the same set the transfer skips, and `compute_hash` feeds the sync decision.
  A pattern on one side only ships a file without a deploy, or deploys without
  a file. `tests/test_excludes.py` guards this.
- **AWS gets no stored credentials.** `filter_aws_credentials_from_env` strips
  `AWS_PROFILE`, `AWS_ACCESS_KEY_ID`, and `AWS_SECRET_ACCESS_KEY` from the
  uploaded `.env`. The instance uses its IAM role. `AWS_REGION` stays.
- **The staging swap is not concurrent-safe.** `npm sync --staging` writes to
  `<app-dir>.staging` and promotes it. Run one staged deploy at a time, and do
  not delete `<app-dir>.previous` by hand: it is the rollback.

## Code style

- Python 3.10 or newer. Type hints on the public functions.
- 4-space indent, ruff formatting, and ruff lint clean.
- `snake_case` for functions and variables, `PascalCase` for classes.
- `cyclopts` registers each command with a decorator. Add a `help` string to a
  new command and a `sort_key` when the order matters.
- Keep the module docstring factual. Do not add a comment that restates the
  code.
- Match the pattern of a neighbouring function before you add code.

## Issue tracking (Beads)

Work is tracked in **Beads** (`bd`, Dolt-backed). `bd prime` is the single
source of truth for the workflow. Run it after compaction or in a new session.
The `beads` skill lives at `.agents/skills/beads/SKILL.md`. Do not keep a
second task list in markdown.

```bash
bd ready                       # unblocked work (includes epic containers)
bd ready --exclude-type=epic   # only the actionable children
bd create "title" -t task -p 2 # new issue; add --json for structured output
bd update <id> --claim         # claim atomically
bd close <id> --reason "..."   # complete
bd sync                        # pull → conflict-check → push (at handoff)
```

- Issues live in a local Dolt database (`.beads/embeddeddolt/`). Dolt refs are
  the sync protocol; `.beads/issues.jsonl` is an ignored local artifact and
  never a source of truth.
- The Dolt remote is `origin` (`git+ssh://git@github.com/boscoh/deployvm.git`)
  and it lives in `refs/dolt/data` on the GitHub repo. `bd sync` owns the push.
  Auto-push is off (`dolt.auto-push: false`), so run `bd sync` at handoff.
- Never use `bd edit`; it opens an interactive `$EDITOR`. Update a field with a
  flag such as `bd update <id> --description ...`.
- Link discovered work with `--deps discovered-from:<id>`.
- Git hooks are shared and committable: `git config core.hooksPath .beads-hooks`
  (installed with `bd hooks install --shared`). Do not use `.git/hooks`.

**Git & task policy.** Use `bd` for all task tracking. The handoff `bd sync`
run owns the Dolt push, so agents never run `bd dolt push` by hand. Git commits
and `git push` stay conservative: do not commit or push the working tree unless
the user asks. At handoff, report the changed files, the validation, and the
suggested next commands. An explicit user or orchestrator instruction overrides
this section.

When a session ends: file beads for the remaining work, run the quality gate
(`uv run pytest -m "not integration"`) when code changed, update the issue
status, run `bd sync`, then hand off.
