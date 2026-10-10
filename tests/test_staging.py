"""Unit tests for the opt-in staging swap in NpmApp.sync.

The swap is a remote directory move, so these tests replace the transfer and
ssh helpers with recorders. No cloud instance and no SSH connection is used.
One test runs the recorded promote script locally under a stub ``sudo``.
"""

import os
import subprocess
from pathlib import Path

import pytest

from deployvm import apps
from deployvm.apps import NPM_LIVE_PATHS, NpmApp

APP_DIR = "/home/deploy/tspots"
STAGING_DIR = f"{APP_DIR}.staging"
PREVIOUS_DIR = f"{APP_DIR}.previous"
LIVE_PATHS = " ".join(NPM_LIVE_PATHS)


class Recorder:
    """Record the ssh, rsync, and file-write calls sync makes."""

    def __init__(self):
        self.events: list[tuple[str, str]] = []

    def rsync(self, local, ip, remote, exclude=None, user="deploy"):
        self.events.append(("rsync", remote))

    def ssh(self, ip, cmd, user="deploy", show_output=False):
        self.events.append(("ssh", cmd))
        return ""

    def ssh_script(self, ip, script, user="deploy", show_output=False):
        self.events.append(("script", script))
        return ""

    def ssh_write_file(self, ip, path, content, user="deploy"):
        self.events.append(("write", path))

    def transfers(self) -> list[str]:
        return [value for kind, value in self.events if kind == "rsync"]

    def scripts(self) -> list[str]:
        return [value for kind, value in self.events if kind == "script"]

    def promote_scripts(self) -> list[str]:
        return [script for script in self.scripts() if ".previous" in script]

    def transfer_index(self) -> int:
        for index, (kind, _) in enumerate(self.events):
            if kind == "rsync":
                return index
        raise AssertionError("no transfer was recorded")

    def script_index(self, needle: str) -> int:
        for index, (kind, value) in enumerate(self.events):
            if kind == "script" and needle in value:
                return index
        raise AssertionError(f"no script contains {needle!r}")


def make_source(tmp_path: Path) -> Path:
    source = tmp_path / "source"
    (source / ".output" / "server").mkdir(parents=True)
    (source / ".output" / "server" / "index.mjs").write_text("export default {}\n")
    (source / "package.json").write_text('{"name": "tspots"}')
    return source


def make_app(monkeypatch) -> NpmApp:
    # BaseApp.__init__ validates cloud credentials, which these tests do not use.
    monkeypatch.setattr(apps, "check_instance_auth", lambda instance: None)
    return NpmApp(
        {"ip": "203.0.113.10", "provider": "digitalocean", "apps": []},
        "digitalocean",
        user="deploy",
        app_name="tspots",
    )


def patch_transfer(monkeypatch, recorder: Recorder, *, patch_local_build: bool = True):
    monkeypatch.setattr(apps, "rsync", recorder.rsync)
    monkeypatch.setattr(apps, "ssh", recorder.ssh)
    monkeypatch.setattr(apps, "ssh_script", recorder.ssh_script)
    monkeypatch.setattr(apps, "ssh_write_file", recorder.ssh_write_file)
    if patch_local_build:
        # No npm install or build runs locally in these tests.
        monkeypatch.setattr(apps.subprocess, "run", lambda *args, **kwargs: None)


def sync_with_app_dir(
    tmp_path, monkeypatch, app_dir: str, *, patch_local_build: bool = True, **kwargs
):
    app = make_app(monkeypatch)
    app.app_dir = app_dir
    recorder = Recorder()
    patch_transfer(monkeypatch, recorder, patch_local_build=patch_local_build)
    app.sync(str(make_source(tmp_path)), **kwargs)
    return app, recorder


def run_sync(tmp_path, monkeypatch, **kwargs):
    return sync_with_app_dir(tmp_path, monkeypatch, APP_DIR, **kwargs)


def test_sync_without_staging_transfers_into_the_app_dir(tmp_path, monkeypatch):
    app, recorder = run_sync(tmp_path, monkeypatch)

    assert recorder.transfers() == [app.app_dir]
    assert recorder.promote_scripts() == []


def test_staging_transfers_into_a_sibling_staging_dir(tmp_path, monkeypatch):
    app, recorder = run_sync(tmp_path, monkeypatch, staging=True)

    assert app.app_dir == APP_DIR
    assert recorder.transfers() == [STAGING_DIR]


def test_the_staging_dir_is_prepared_before_the_transfer(tmp_path, monkeypatch):
    _app, recorder = run_sync(tmp_path, monkeypatch, staging=True)

    assert recorder.script_index(f"mkdir -p {STAGING_DIR}") < recorder.transfer_index()


def test_the_prepare_removes_stale_live_paths_from_the_staging_dir(
    tmp_path, monkeypatch
):
    _app, recorder = run_sync(tmp_path, monkeypatch, staging=True)

    prepare = next(s for s in recorder.scripts() if f"mkdir -p {STAGING_DIR}" in s)
    assert f"for path in {LIVE_PATHS}; do" in prepare
    assert f'sudo rm -rf "{STAGING_DIR}/$path"' in prepare


def test_staging_promote_swaps_the_staging_dir_into_place(tmp_path, monkeypatch):
    _app, recorder = run_sync(tmp_path, monkeypatch, staging=True)

    [promote] = recorder.promote_scripts()
    # The live ecosystem config is excluded from the transfer, so the promote
    # copies it into the staging dir before the swap.
    assert (
        f"cp {APP_DIR}/ecosystem.config.cjs {STAGING_DIR}/ecosystem.config.cjs"
        in promote
    )
    # The live excluded paths are moved into the staging dir, because the
    # transfer never carries them.
    assert f"for path in {LIVE_PATHS}; do" in promote
    assert f"sudo mv {APP_DIR}/$path {STAGING_DIR}/$path" in promote
    assert f"sudo mv {STAGING_DIR} {APP_DIR}" in promote
    # The rollback restores the replaced directory only when nothing occupies
    # the app dir, so it can never nest one directory inside another.
    assert f"if [ ! -e {APP_DIR} ] && [ -d {PREVIOUS_DIR} ]; then" in promote
    assert f"sudo mv {PREVIOUS_DIR} {APP_DIR}" in promote
    assert "exit 1" in promote


def test_the_promote_orders_removal_before_the_two_moves(tmp_path, monkeypatch):
    _app, recorder = run_sync(tmp_path, monkeypatch, staging=True)

    [promote] = recorder.promote_scripts()
    assert (
        promote.index(f"sudo rm -rf {PREVIOUS_DIR}")
        < promote.index(f"sudo mv {APP_DIR} {PREVIOUS_DIR}")
        < promote.index(f"sudo mv {STAGING_DIR} {APP_DIR}")
    )


def test_staging_promotes_only_after_the_transfer(tmp_path, monkeypatch):
    _app, recorder = run_sync(tmp_path, monkeypatch, staging=True)

    assert recorder.transfer_index() < recorder.script_index(PREVIOUS_DIR)


def test_the_source_hash_and_chown_act_on_the_promoted_dir(tmp_path, monkeypatch):
    _app, recorder = run_sync(tmp_path, monkeypatch, staging=True)

    [start] = [script for script in recorder.scripts() if ".source_hash" in script]
    assert f"> {APP_DIR}/.source_hash" in start
    assert "chown -R deploy:deploy /home/deploy/tspots" in start
    # Never leave the new hash on the directory that was replaced.
    assert not any(f"{STAGING_DIR}/.source_hash" in s for s in recorder.scripts())
    assert not any(f"{PREVIOUS_DIR}/.source_hash" in s for s in recorder.scripts())


def test_a_failing_transfer_never_promotes(tmp_path, monkeypatch):
    app = make_app(monkeypatch)
    recorder = Recorder()
    patch_transfer(monkeypatch, recorder)

    def failing_rsync(*args, **kwargs):
        raise RuntimeError("rsync failed")

    monkeypatch.setattr(apps, "rsync", failing_rsync)

    with pytest.raises(RuntimeError):
        app.sync(str(make_source(tmp_path)), staging=True)

    assert recorder.promote_scripts() == []


def test_the_server_build_runs_inside_the_staging_dir(tmp_path, monkeypatch):
    _app, recorder = run_sync(tmp_path, monkeypatch, staging=True, local_build=False)

    assert recorder.script_index(
        f"cd {STAGING_DIR} && rm -rf package-lock.json"
    ) < recorder.script_index(PREVIOUS_DIR)


def test_the_server_build_targets_the_app_dir_without_staging(tmp_path, monkeypatch):
    _app, recorder = run_sync(tmp_path, monkeypatch, local_build=False)

    assert recorder.script_index(f"cd {APP_DIR} && rm -rf package-lock.json") > 0
    assert recorder.promote_scripts() == []


def test_every_recorded_script_parses(tmp_path, monkeypatch):
    # local_build=False and patch_local_build=False keep subprocess.run real.
    _app, recorder = run_sync(
        tmp_path, monkeypatch, staging=True, local_build=False, patch_local_build=False
    )

    for index, script in enumerate(recorder.scripts()):
        result = subprocess.run(
            ["bash", "-n"], input=script, capture_output=True, text=True
        )
        assert result.returncode == 0, f"script {index}: {result.stderr}"


def record_promote_script(tmp_path, monkeypatch):
    """Sync once to record the promote script; return the fake paths and script.

    local_build=False and patch_local_build=False keep subprocess.run real for
    the bash call in run_promote.
    """
    app_dir = tmp_path / "tspots"
    staging = tmp_path / "tspots.staging"
    previous = tmp_path / "tspots.previous"
    _app, recorder = sync_with_app_dir(
        tmp_path,
        monkeypatch,
        str(app_dir),
        patch_local_build=False,
        staging=True,
        local_build=False,
    )
    [promote] = recorder.promote_scripts()
    return app_dir, staging, previous, promote


def build_fake_layout(
    app_dir: Path, staging: Path, previous: Path, *, fresh_node_modules: bool = False
):
    """Build the layout the promote script meets under tmp_path.

    The live app holds its excluded paths, the staging tree holds the transfer,
    and ``previous`` is a stale rollback directory. ``fresh_node_modules``
    gives the staging tree its own ``node_modules``, as an on-server build
    leaves it.
    """
    (app_dir / "node_modules").mkdir(parents=True)
    (app_dir / "node_modules" / "keep.txt").write_text("keep\n")
    (app_dir / "public" / "projects").mkdir(parents=True)
    (app_dir / "public" / "projects" / "old.png").write_text("old\n")
    (app_dir / "ecosystem.config.cjs").write_text("module.exports = {}\n")
    (app_dir / "old.txt").write_text("old\n")
    (staging / ".output" / "server").mkdir(parents=True)
    (staging / ".output" / "server" / "index.mjs").write_text("new\n")
    if fresh_node_modules:
        (staging / "node_modules").mkdir(parents=True)
        (staging / "node_modules" / "fresh.txt").write_text("fresh\n")
    previous.mkdir()
    (previous / "junk.txt").write_text("stale\n")


def write_stub_sudo(bin_dir: Path, fail_move_of: Path | None = None):
    """Write a sudo stub that only runs its arguments.

    It is not root, so this test does not exercise root permissions. When
    ``fail_move_of`` is set, the stub fails a move whose source is that path,
    to run the rollback branch.
    """
    guard = ""
    if fail_move_of is not None:
        guard = (
            f'if [ "$1" = "mv" ] && [ "$2" = "{fail_move_of}" ]; then\n'
            '    echo "injected failure" >&2\n'
            "    exit 1\n"
            "fi\n"
        )
    stub = bin_dir / "sudo"
    stub.write_text(f'#!/bin/sh\n{guard}exec "$@"\n')
    stub.chmod(0o755)


def run_promote(tmp_path, promote, fail_move_of: Path | None = None):
    script = tmp_path / "promote.sh"
    script.write_text(promote)
    stub_bin = tmp_path / "bin"
    stub_bin.mkdir()
    write_stub_sudo(stub_bin, fail_move_of)
    env = {**os.environ, "PATH": f"{stub_bin}:{os.environ['PATH']}"}
    return subprocess.run(
        ["bash", str(script)], env=env, capture_output=True, text=True
    )


def test_the_promote_script_runs_and_keeps_the_live_paths(tmp_path, monkeypatch):
    app_dir, staging, previous, promote = record_promote_script(tmp_path, monkeypatch)
    build_fake_layout(app_dir, staging, previous)

    result = run_promote(tmp_path, promote)
    assert result.returncode == 0, result.stderr

    # The promoted directory holds the staged tree, the copied config, and the
    # live excluded paths, exactly as a direct transfer would leave it.
    assert (app_dir / ".output" / "server" / "index.mjs").read_text() == "new\n"
    assert (app_dir / "ecosystem.config.cjs").read_text() == "module.exports = {}\n"
    assert (app_dir / "node_modules" / "keep.txt").read_text() == "keep\n"
    assert (app_dir / "public" / "projects" / "old.png").read_text() == "old\n"
    # The carried paths did not nest inside themselves.
    assert not (app_dir / "node_modules" / "node_modules").exists()
    assert not (app_dir / "public" / "projects" / "projects").exists()
    # The replaced directory is next to the promoted one, without the moved
    # paths, and the stale rollback directory is gone.
    assert (previous / "old.txt").read_text() == "old\n"
    assert not (previous / "node_modules").exists()
    assert not (previous / "junk.txt").exists()
    assert not staging.exists()


def test_the_rollback_restores_the_previous_dir_when_the_swap_fails(
    tmp_path, monkeypatch
):
    app_dir, staging, previous, promote = record_promote_script(tmp_path, monkeypatch)
    build_fake_layout(app_dir, staging, previous)

    result = run_promote(tmp_path, promote, fail_move_of=staging)
    assert result.returncode == 1

    # The replaced directory came back, with the paths the promote had taken
    # from it, and the staged tree did not reach the app dir.
    assert (app_dir / "old.txt").read_text() == "old\n"
    assert (app_dir / "ecosystem.config.cjs").read_text() == "module.exports = {}\n"
    assert (app_dir / "node_modules" / "keep.txt").read_text() == "keep\n"
    assert (app_dir / "public" / "projects" / "old.png").read_text() == "old\n"
    assert not (app_dir / ".output").exists()
    assert (staging / ".output" / "server" / "index.mjs").exists()
    assert not previous.exists()


def test_a_fresh_staging_node_modules_wins_and_the_live_one_stays_previous(
    tmp_path, monkeypatch
):
    app_dir, staging, previous, promote = record_promote_script(tmp_path, monkeypatch)
    build_fake_layout(app_dir, staging, previous, fresh_node_modules=True)

    result = run_promote(tmp_path, promote)
    assert result.returncode == 0, result.stderr

    # The staging dir already held node_modules, so the fresh install wins and
    # the carry guard leaves the live copy alone.
    assert (app_dir / "node_modules" / "fresh.txt").read_text() == "fresh\n"
    assert not (app_dir / "node_modules" / "keep.txt").exists()
    assert not (app_dir / "node_modules" / "node_modules").exists()
    # The staging dir had no public/projects, so the live copy is carried.
    assert (app_dir / "public" / "projects" / "old.png").read_text() == "old\n"
    # The live node_modules left with the replaced directory.
    assert (previous / "node_modules" / "keep.txt").read_text() == "keep\n"
