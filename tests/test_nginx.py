"""Unit tests for nginx version handling (no SSH)."""

import pytest

from deployvm.server import (
    _nginx_at_least_1_22,
    _parse_nginx_version,
    install_nginx,
)


@pytest.mark.parametrize(
    "version, supported",
    [
        ("1.22.0", True),
        ("1.22.1", True),
        ("1.23.0", True),
        ("1.26.2", True),
        ("2.0.0", True),
        ("1.21.6", False),
        ("1.18.0", False),
    ],
)
def test_nginx_at_least_1_22(version: str, supported: bool):
    parsed = _parse_nginx_version(f"nginx version: nginx/{version}")
    assert _nginx_at_least_1_22(parsed) is supported


def test_parse_nginx_version_real_output():
    assert _parse_nginx_version("nginx version: nginx/1.22.1") == (1, 22, 1)


def test_parse_nginx_version_unparseable():
    assert _parse_nginx_version("nginx: command not found") is None


def test_install_nginx_checks_version_via_sudo(monkeypatch):
    # nginx lives in /usr/sbin, which is not on the deploy user's PATH; a bare
    # `nginx -v` exits 127 and used to fail the deploy on a valid install.
    commands: list[str] = []

    def fake_ssh_script(ip, script, user="deploy", show_output=False):
        commands.append(script)

    def fake_ssh(ip, cmd, user="deploy", show_output=False):
        commands.append(cmd)
        return "nginx version: nginx/1.22.1"

    monkeypatch.setattr("deployvm.server.ssh_script", fake_ssh_script)
    monkeypatch.setattr("deployvm.server.ssh", fake_ssh)

    install_nginx("203.0.113.10")

    assert "sudo nginx -v 2>&1" in commands
