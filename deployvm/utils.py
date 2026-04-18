"""Shared utility functions."""

import json
import logging
import subprocess
import sys

from rich.console import Console
from rich.logging import RichHandler

logger = logging.getLogger("deployvm")

# Prefix for lines from remote SSH commands (Fabric streams, captured output, errors).
REMOTE_OUTPUT_LOG_PREFIX = "→ "

# Supplemental hints (registrar nameservers, follow-ups); not live remote output (→).
EXTRA_OUTPUT_LOG_PREFIX = "extra | "

# Pass to uvicorn.run(log_config=UVICORN_LOG_CONFIG) to prevent uvicorn from
# installing its own StreamHandler, so all logs flow through our RichHandler.
UVICORN_LOG_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {},
    "handlers": {},
    "loggers": {
        "uvicorn": {"propagate": True, "level": "INFO"},
        "uvicorn.access": {"propagate": False, "level": "WARNING"},
        "uvicorn.error": {"propagate": True, "level": "INFO"},
    },
}


def remote_line_for_log(line: str) -> str:
    """:return: Log line with standard remote-output prefix."""
    return f"{REMOTE_OUTPUT_LOG_PREFIX}{line}"


def extra_line_for_log(line: str) -> str:
    """:return: Log line with standard extra-hint prefix (registrar notes, etc.)."""
    return f"{EXTRA_OUTPUT_LOG_PREFIX}{line}"


def log_extra_section(title: str, lines: list[str] | None = None) -> None:
    """Log a titled block of supplemental hints, distinct from remote command output (→).

    :param title: One-line summary shown to the user
    :param lines: Optional detail lines (e.g. nameserver hostnames)
    """
    logger.info(extra_line_for_log(title))
    for raw in lines or []:
        item = raw.strip()
        if item:
            logger.info(extra_line_for_log(f"  {item}"))


def log_remote_output(text: str, *, level: int = logging.INFO) -> None:
    """Log each line of remote (or captured SSH) output with the standard prefix.

    Empty or whitespace-only lines are skipped.

    :param text: Multiline stdout/stderr from a remote command
    :param level: logging level (default INFO; use ERROR for failure excerpts)
    """
    for line in (text or "").splitlines():
        if line.strip():
            logger.log(level, remote_line_for_log(line))


def format_remote_output_for_message(text: str) -> str:
    """Prefix each line for multi-line error messages or logs.

    :param text: Raw remote stdout or stderr
    :return: Text with ``REMOTE_OUTPUT_LOG_PREFIX`` on each line
    """
    if not (text or "").strip():
        return ""
    out_lines: list[str] = []
    for line in text.splitlines():
        out_lines.append(remote_line_for_log(line) if line.strip() else line)
    return "\n".join(out_lines).rstrip()


class LogStream:
    """File-like stream that routes output through the logger line by line.

    Use as out_stream/err_stream in fabric c.run() calls so remote SSH output
    goes through the logging system instead of directly to the terminal.
    """

    def __init__(self) -> None:
        self._buf = ""

    def write(self, text: str) -> None:
        self._buf += text
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            if line.strip():
                logger.info(remote_line_for_log(line))

    def flush(self) -> None:
        if self._buf.strip():
            logger.info(remote_line_for_log(self._buf))
            self._buf = ""


def setup_logging(level: int | str = logging.INFO) -> None:
    """Set up logging with Rich handler to stderr."""
    if isinstance(level, str):
        level = getattr(logging, level.upper())
    rich_handler = RichHandler(
        console=Console(stderr=True),
        log_time_format="[%X]",
        show_path=False,
        markup=True,
    )
    rich_handler.setLevel(level)

    root_logger = logging.getLogger()
    root_logger.setLevel(level)
    for handler in root_logger.handlers[:]:
        handler.close()
        root_logger.removeHandler(handler)
    root_logger.addHandler(rich_handler)

    for name, lvl, propagate in [
        ("boto3", logging.INFO, True),
        # ERROR: botocore logs SSO/credential refresh failures at WARNING with
        # exc_info=True; Rich would print multi-page tracebacks before our message.
        ("botocore", logging.ERROR, True),
        ("urllib3", logging.WARNING, True),
        ("httpx", logging.WARNING, True),
        ("paramiko", logging.WARNING, True),
        ("fabric", logging.WARNING, True),
        ("uvicorn", logging.INFO, True),
        ("uvicorn.access", logging.WARNING, True),
        ("uvicorn.error", logging.INFO, True),
    ]:
        lg = logging.getLogger(name)
        for h in lg.handlers[:]:
            lg.removeHandler(h)
        lg.setLevel(lvl)
        lg.propagate = propagate


def log(msg: str) -> None:
    """Log info message."""
    logger.info(msg)


def warn(msg: str) -> None:
    """Log warning message."""
    logger.warning(msg)


def error(msg: str) -> None:
    """Log error message and exit."""
    logger.error(msg)
    sys.exit(1)


def get_ssh_user(provider_name: str) -> str:
    """Get default SSH user for cloud provider.

    :param provider_name: Cloud provider (aws, digitalocean, or vultr)
    :return: SSH username (admin for AWS, root for DigitalOcean and Vultr)
    """
    return "admin" if provider_name == "aws" else "root"


def resolve_app_name(
    apps: list[dict],
    app_type: str,
    app_name: str | None = None,
    fallback: str | None = None,
) -> str:
    """Resolve app name when multiple apps exist on instance.

    :param apps: List of app dicts with 'name' and 'type' keys
    :param app_type: App type to filter by (npm or uv)
    :param app_name: Explicit app name (optional)
    :param fallback: Fallback name if no apps found
    :return: Resolved app name
    :raises: SystemExit if multiple apps found without explicit name
    """
    if app_name is not None:
        return app_name

    if len(apps) == 1:
        return apps[0]["name"]
    elif len(apps) > 1:
        app_names = ", ".join(app["name"] for app in apps)
        error(
            f"Multiple '{app_type}' apps found: '{app_names}'. Use --app-name to specify."
        )
    else:
        return fallback if fallback else app_type


def run_cmd(*args, check: bool = True) -> str:
    """Execute local command and return stdout."""
    result = subprocess.run(args, capture_output=True, text=True)
    if check and result.returncode != 0:
        error(f"Command failed: {result.stderr}")
    return result.stdout.strip()


def run_cmd_json(*args) -> dict | list:
    """Execute command with -o json flag and parse output."""
    output = run_cmd(*args, "-o", "json")
    return json.loads(output) if output else []
