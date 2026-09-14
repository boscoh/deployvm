"""Unit tests for rsync fallback handling (excludes, stale pruning, retry)."""

import subprocess

from deployvm.server import (
    _delete_stale_remote_files,
    _remote_find_prunes,
    _tar_should_exclude,
    rsync,
)


def test_exclude_directory_names():
    assert _tar_should_exclude(".venv", [".venv"])
    assert _tar_should_exclude(".venv/lib/python3/site.py", [".venv"])
    assert _tar_should_exclude("a/__pycache__/x.pyc", ["__pycache__"])


def test_exclude_globs():
    assert _tar_should_exclude("pkg/mod.pyc", ["*.pyc"])
    assert not _tar_should_exclude("pkg/mod.py", ["*.pyc"])


def test_exclude_root_anchored():
    assert _tar_should_exclude("node_modules", ["/node_modules"])
    assert not _tar_should_exclude("app/node_modules", ["/node_modules"])


def test_exclude_exact_path():
    assert _tar_should_exclude("data/scripts/models", ["data/scripts/models"])
    assert _tar_should_exclude("data/scripts/models/a.json", ["data/scripts/models"])
    assert not _tar_should_exclude("data/scripts", ["data/scripts/models"])


def test_remote_find_prunes():
    prune = _remote_find_prunes([".venv", "__pycache__", "*.pyc", "/node_modules"])
    assert "! -path './.venv/*'" in prune
    assert "! -path '*/.venv/*'" in prune
    assert "! -path './node_modules/*'" in prune
    assert "*.pyc" not in prune  # glob excludes are filtered locally


def test_delete_stale_remote_files(monkeypatch):
    commands: list[tuple[str, str]] = []

    def fake_ssh(ip, cmd, user="deploy", show_output=False):
        commands.append(("ssh", cmd))
        return "keep.py\nstale.py\n.venv/lib/x.py\n__pycache__/m.pyc\n"

    def fake_ssh_script(ip, script, user="deploy", show_output=False):
        commands.append(("script", script))

    monkeypatch.setattr("deployvm.server.ssh", fake_ssh)
    monkeypatch.setattr("deployvm.server.ssh_script", fake_ssh_script)

    _delete_stale_remote_files(
        "203.0.113.10",
        "/home/deploy/uvapp",
        [".venv", "__pycache__"],
        {"keep.py"},
        "deploy",
    )

    script = next(s for kind, s in commands if kind == "script")
    assert "rm -f -- stale.py" in script
    assert "keep.py" not in script
    assert ".venv/lib/x.py" not in script
    assert "__pycache__/m.pyc" not in script


def test_delete_stale_noop_when_nothing_stale(monkeypatch):
    calls: list[tuple] = []
    monkeypatch.setattr("deployvm.server.ssh", lambda *a, **k: "keep.py\n")
    monkeypatch.setattr("deployvm.server.ssh_script", lambda *a, **k: calls.append(a))

    _delete_stale_remote_files("203.0.113.10", "/remote", [], {"keep.py"}, "deploy")
    assert calls == []


def test_rsync_installs_missing_remote_rsync_and_retries(monkeypatch):
    results = [
        subprocess.CompletedProcess(
            [], 255, "", "bash: line 1: rsync: command not found"
        ),
        subprocess.CompletedProcess([], 0, "", ""),
    ]
    monkeypatch.setattr(
        "deployvm.server.subprocess.run", lambda *a, **k: results.pop(0)
    )
    installed: list[str] = []
    monkeypatch.setattr(
        "deployvm.server.ssh_script",
        lambda ip, script, user="deploy", show_output=False: installed.append(script),
    )

    rsync("/tmp/src", "203.0.113.10", "/home/deploy/uvapp", [], "deploy")

    assert any("install -y rsync" in s for s in installed)
    assert results == []  # the retry succeeded
