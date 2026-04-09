"""Server operations: SSH, rsync, network validation, and server setup."""

import base64
import hashlib
import json
import os
import re
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path
from textwrap import dedent, indent
from typing import Literal

import dns.resolver
from fabric import Connection
from rich import print

from .providers import check_aws_auth, get_provider
from .utils import (
    LogStream,
    error,
    format_remote_output_for_message,
    log,
    log_remote_output,
    remote_line_for_log,
    warn,
)

ProviderName = Literal["digitalocean", "aws", "vultr"]

SSH_TIMEOUT = 600
HTTP_VERIFY_RETRIES = 6
HTTP_VERIFY_DELAY = 5
DNS_VERIFY_RETRIES = 30
DNS_VERIFY_DELAY = 10

_ENSURE_SITES_ENABLED_SCRIPT = dedent(r"""
    set -e
    if grep -q 'sites-enabled' /etc/nginx/nginx.conf 2>/dev/null; then
        exit 0
    fi
    if grep -qE 'include[[:space:]]+.*/etc/nginx/conf\.d/\*\.conf' /etc/nginx/nginx.conf; then
        sudo sed -i '/include[[:space:]]\+.*\/etc\/nginx\/conf\.d\/\*.conf;/a\    include /etc/nginx/sites-enabled/*;' /etc/nginx/nginx.conf
    else
        echo "deployvm: no conf.d include in /etc/nginx/nginx.conf; add include /etc/nginx/sites-enabled/*; inside http { }" >&2
        exit 1
    fi
    sudo nginx -t
""").strip()


def ensure_nginx_sites_enabled_included(ip: str, ssh_user: str = "deploy") -> None:
    """Ensure main nginx.conf loads sites-enabled (Ubuntu default; omitted by some upstream packages)."""
    ssh_script(ip, _ENSURE_SITES_ENABLED_SCRIPT, user=ssh_user)


def _parse_nginx_version(text: str) -> tuple[int, int, int] | None:
    m = re.search(r"nginx/(\d+)\.(\d+)(?:\.(\d+))?", text)
    if not m:
        return None
    patch = int(m.group(3) or 0)
    return int(m.group(1)), int(m.group(2)), patch


def _nginx_newer_than_1_22_line(v: tuple[int, int, int]) -> bool:
    major, minor, _ = v
    if major > 1:
        return True
    if major < 1:
        return False
    return minor > 22


def install_nginx(ip: str, ssh_user: str = "deploy") -> None:
    """Install nginx from apt and ensure it is newer than the entire 1.22.x line (e.g. 1.23+)."""
    ssh_script(
        ip,
        "sudo apt-get update && sudo apt-get install -y nginx",
        user=ssh_user,
    )
    ver_line = ssh(ip, "nginx -v 2>&1", user=ssh_user).strip()
    parsed = _parse_nginx_version(ver_line)
    if parsed is None or not _nginx_newer_than_1_22_line(parsed):
        error(
            f"nginx must be newer than 1.22.* (parsed from: {ver_line!r}). "
            "Use a newer OS image or install a current nginx package (e.g. from nginx.org or your distro backports)."
        )


def check_instance_auth(instance: dict) -> None:
    """Validate cloud provider auth for instance, fail fast if credentials expired.

    :param instance: Instance data dictionary (must have 'provider' key)
    """
    provider = instance.get("provider")
    aws_profile = instance.get("aws_profile")
    p = get_provider(provider, aws_profile=aws_profile)
    p.validate_auth()


def check_instance_reachable(ip: str, ssh_user: str = "deploy", timeout: int = 10) -> bool:
    """Quick check if instance is reachable via SSH.

    :param ip: Instance IP address
    :param ssh_user: SSH user for connection
    :param timeout: Connection timeout in seconds
    :return: True if reachable, False otherwise
    """
    try:
        with Connection(
            ip, user=ssh_user, connect_kwargs={"look_for_keys": True, "timeout": timeout}
        ) as c:
            c.run("echo ping", hide=True, in_stream=False)
        return True
    except Exception:
        return False


def _format_ssh_command_failure(result, remote_cmd: str) -> str:
    """Build a log-friendly message for a failed remote command.

    apt/dpkg and many scripts write errors to stdout; stderr may be empty.

    :param result: Fabric/Invoke ``Result`` from ``Connection.run(..., warn=True)``
    :param remote_cmd: Command string (truncated in the message if very long)
    :return: Multi-line description for logs and ``RuntimeError``
    """
    parts: list[str] = []
    snippet = remote_cmd if len(remote_cmd) <= 400 else remote_cmd[:400] + "..."
    parts.append(f"command: {snippet}")
    exited = getattr(result, "exited", None)
    if exited is not None:
        parts.append(f"exit code: {exited}")
    stdout = (getattr(result, "stdout", None) or "").rstrip()
    stderr = (getattr(result, "stderr", None) or "").rstrip()
    if stderr:
        parts.append("--- stderr ---")
        parts.append(format_remote_output_for_message(stderr))
    if stdout:
        parts.append("--- stdout ---")
        parts.append(format_remote_output_for_message(stdout))
    if not stderr and not stdout:
        parts.append(
            "(no stdout/stderr from remote; check shell, sudo, or connection)"
        )
    return "\n".join(parts)


def _run_ssh(ip: str, cmd: str, user: str, show_output: bool) -> str:
    """Single SSH attempt - open connection, run cmd, return stdout."""
    with Connection(ip, user=user, connect_kwargs={"look_for_keys": True}) as c:
        if show_output:
            stream = LogStream()
            result = c.run(cmd, hide=True, warn=True, in_stream=False,
                           out_stream=stream, err_stream=stream)
            stream.flush()
        else:
            result = c.run(cmd, hide=True, warn=True, in_stream=False)
        if result.failed:
            raise RuntimeError(_format_ssh_command_failure(result, cmd))
        return result.stdout


def _retry_ssh(ip: str, cmd: str, user: str, show_output: bool, fail_msg: str) -> str:
    """Run SSH command with up to 3 retries on transient connection resets."""
    from paramiko.ssh_exception import SSHException as ParamikoSSH

    for attempt in range(3):
        try:
            return _run_ssh(ip, cmd, user, show_output)
        except RuntimeError as e:
            error(f"{fail_msg.rstrip()}\n{str(e)}")
        except ParamikoSSH as e:
            if "Error reading SSH protocol banner" in str(e) and attempt < 2:
                time.sleep(5)
                continue
            error(f"SSH connection failed: {e}")
    error(f"SSH connection failed after retries")  # unreachable but satisfies type checker


def ssh(ip: str, cmd: str, user: str = "deploy", show_output: bool = False) -> str:
    return _retry_ssh(ip, cmd, user, show_output, "SSH command failed: ")


def ssh_script(ip: str, script: str, user: str = "deploy", show_output: bool = False) -> str:
    escaped = script.replace("'", "'\\''")
    return _retry_ssh(ip, f"bash -c '{escaped}'", user, show_output, "SSH script failed: ")


def ssh_as_user(ip: str, app_user: str, cmd: str, ssh_user: str = "deploy") -> str:
    return ssh(ip, f'su - {app_user} -c "{cmd}"', user=ssh_user)


def ssh_write_file(ip: str, path: str, content: str, user: str = "deploy"):
    encoded = base64.b64encode(content.encode()).decode()
    if user != "root" and (path.startswith("/etc/") or path.startswith("/var/")):
        ssh(
            ip, f"echo '{encoded}' | base64 -d | sudo tee {path} > /dev/null", user=user
        )
    else:
        ssh(ip, f"echo '{encoded}' | base64 -d > {path}", user=user)


def rsync(
    local: str, ip: str, remote: str, exclude: list[str] = None, user: str = "deploy"
):
    ssh_opts = (
        "ssh -o StrictHostKeyChecking=no "
        "-o UserKnownHostsFile=/dev/null "
        "-o ServerAliveInterval=60 "
        "-o ServerAliveCountMax=3 "
        "-o TCPKeepAlive=yes "
        "-o Compression=yes "
        "-o LogLevel=ERROR"
    )

    cmd = [
        "rsync",
        "-avz",
        "--delete",
        "--partial",
        "--inplace",
        "--no-whole-file",
        "--block-size=8192",
        "-e",
        ssh_opts,
    ]
    for ex in exclude or []:
        cmd.extend(["--exclude", ex])
    cmd.extend([f"{local}/", f"{user}@{ip}:{remote}/"])

    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode == 0:
        return

    if "Result too large" in result.stderr or "unexpected end of file" in result.stderr:
        log("rsync failed with large file error, falling back to tar+ssh...")
        _rsync_tar_fallback(local, ip, remote, exclude, user)
    else:
        error(f"rsync failed: {result.stderr}")


def _tar_should_exclude(arcpath: str, exclude: list[str]) -> bool:
    """Mirror rsync exclude semantics for tar archive paths.

    - Leading '/' in pattern: root-relative, only match at the top level.
    - Pattern containing '/' (no leading): match at that exact relative path.
    - Pattern with no '/': match any item with that basename at any depth.

    :param arcpath: Relative path inside the archive (e.g. 'dir/file.txt')
    :param exclude: List of rsync-style exclude patterns
    :return: True if the path should be excluded
    """
    parts = arcpath.replace("\\", "/").split("/")
    basename = parts[-1]
    for ex in exclude or []:
        if ex.startswith("/"):
            root_name = ex.lstrip("/")
            if len(parts) == 1 and parts[0] == root_name:
                return True
        elif "/" in ex:
            if arcpath == ex or arcpath.startswith(ex + "/"):
                return True
        else:
            if basename == ex:
                return True
    return False


def _rsync_tar_fallback(
    local: str, ip: str, remote: str, exclude: list[str], user: str
):
    import tarfile
    import tempfile

    log("Creating tar archive...")
    with tempfile.NamedTemporaryFile(suffix=".tar.gz", delete=False) as tmp:
        tar_path = tmp.name

    try:
        with tarfile.open(tar_path, "w:gz") as tar:
            for dirpath, dirnames, filenames in os.walk(local):
                reldir = os.path.relpath(dirpath, local)
                reldir = "" if reldir == "." else reldir

                # Prune excluded directories in-place so os.walk skips them
                dirnames[:] = [
                    d for d in dirnames
                    if not _tar_should_exclude(
                        os.path.join(reldir, d).replace("\\", "/") if reldir else d,
                        exclude,
                    )
                ]

                for filename in filenames:
                    arcpath = (
                        os.path.join(reldir, filename).replace("\\", "/")
                        if reldir
                        else filename
                    )
                    if not _tar_should_exclude(arcpath, exclude):
                        tar.add(os.path.join(dirpath, filename), arcname=arcpath)
    except Exception as e:
        Path(tar_path).unlink(missing_ok=True)
        error(f"tar creation failed: {e}")

    tar_path_obj = Path(tar_path)

    try:
        log("Uploading tar archive...")
        remote_tar = f"/tmp/deploy_{int(time.time())}.tar.gz"

        scp_cmd = [
            "scp",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "-o",
            "Compression=yes",
            tar_path,
            f"{user}@{ip}:{remote_tar}",
        ]
        result = subprocess.run(scp_cmd, capture_output=True, text=True)
        if result.returncode != 0:
            error(f"scp upload failed: {result.stderr}")

        log("Extracting on remote server...")
        app_user = remote.split("/")[2] if remote.startswith("/home/") else user
        extract_script = f"""
            set -e
            sudo mkdir -p {remote}
            sudo tar -xzf {remote_tar} -C {remote}
            sudo chown -R {app_user}:{app_user} {remote}
            sudo rm -f {remote_tar}
        """
        ssh_script(ip, extract_script, user=user)
        log("Transfer complete")
    finally:
        tar_path_obj.unlink(missing_ok=True)


def load_instance(name: str) -> dict:
    """Load instance data from JSON file and migrate legacy format.

    :param name: Instance name (JSON file prefix)
    :return: Instance data dictionary with apps list
    """
    path = Path(f"{name}.instance.json")
    if not path.exists():
        error(f"Instance file not found: '{path}'")
    data = json.loads(path.read_text())
    if "apps" not in data and "app_name" in data:
        app_data = {"name": data["app_name"], "type": data.get("app_type", "npm")}
        if "port" in data:
            app_data["port"] = data["port"]
        data["apps"] = [app_data]
        data.pop("app_name", None)
        data.pop("app_type", None)
        save_instance(name, data)
    # Migrate legacy app types
    changed = False
    for app in data.get("apps", []):
        if app.get("type") == "fastapi":
            app["type"] = "uv"
            changed = True
        elif app.get("type") == "nuxt":
            app["type"] = "npm"
            changed = True
    if changed:
        save_instance(name, data)
    return data


def save_instance(name: str, data: dict):
    """Save instance data to JSON file.

    :param name: Instance name (JSON file prefix)
    :param data: Instance data dictionary to save
    """
    Path(f"{name}.instance.json").write_text(json.dumps(data, indent=2))


def get_instance_apps(instance: dict) -> list[dict]:
    if "apps" in instance:
        return instance["apps"]
    if "app_name" in instance:
        return [
            {"name": instance["app_name"], "type": instance.get("app_type", "npm")}
        ]
    return []


def add_app_to_instance(
    instance: dict, app_name: str, app_type: str, port: int | None = None, **extra
):
    """Add or update app in instance with conflict detection.

    :param instance: Instance data dictionary to modify
    :param app_name: Application name
    :param app_type: App type (npm or uv)
    :param port: Port number (optional)
    :param extra: Additional fields to store on the app (source, command, domain, etc.)
    """
    if "apps" not in instance:
        instance["apps"] = []

    existing_app = None
    for app in instance["apps"]:
        if app["name"] == app_name:
            existing_app = app
            break

    if existing_app:
        old_type = existing_app.get("type", "unknown")
        old_port = existing_app.get("port")

        if old_type != app_type:
            warn(f"App '{app_name}' type changing from '{old_type}' to '{app_type}'")

        if port is not None and port != old_port:
            conflicting_apps = [
                app
                for app in instance["apps"]
                if app["name"] != app_name and app.get("port") == port
            ]
            if conflicting_apps:
                conflict_names = ", ".join(app["name"] for app in conflicting_apps)
                warn(f"Port {port} already in use by: {conflict_names}")

        existing_app["type"] = app_type
        if port is not None:
            existing_app["port"] = port
        elif "port" in existing_app and old_port is not None:
            pass
        existing_app.update({k: v for k, v in extra.items() if v is not None})

        log(f"Updated app '{app_name}' ('{old_type}' -> '{app_type}')")
    else:
        if port is not None:
            conflicting_apps = [
                app for app in instance["apps"] if app.get("port") == port
            ]
            if conflicting_apps:
                conflict_names = ", ".join(app["name"] for app in conflicting_apps)
                warn(f"Port {port} already in use by: {conflict_names}")

        app_data = {"name": app_name, "type": app_type}
        if port is not None:
            app_data["port"] = port
        app_data.update({k: v for k, v in extra.items() if v is not None})
        instance["apps"].append(app_data)
        log(f"Added app '{app_name}' ('{app_type}')")


def is_valid_ip(ip: str) -> bool:
    parts = ip.split(".")
    return len(parts) == 4 and all(
        part.isdigit() and 0 <= int(part) <= 255 for part in parts
    )


def resolve_dns_a(domain: str, nameserver: str = "8.8.8.8") -> str | None:
    """Resolve domain to IPv4 address.

    :param nameserver: DNS nameserver IP (default: 8.8.8.8)
    :return: First A record IP or None
    """
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [nameserver]
        answer = resolver.resolve(domain, "A")
        return str(answer[0]) if answer else None
    except Exception:
        return None


def resolve_authoritative_ns_ip(domain: str) -> str | None:
    """Return the IP of the first authoritative nameserver for a domain.

    :return: IP address string or None if lookup fails
    """
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["8.8.8.8"]
        ns_answer = resolver.resolve(domain, "NS")
        ns_hostname = str(ns_answer[0]).rstrip(".")
        a_answer = resolver.resolve(ns_hostname, "A")
        return str(a_answer[0]) if a_answer else None
    except Exception:
        return None


def resolve_dns_ns(domain: str, nameserver: str = "8.8.8.8") -> set[str]:
    """Resolve NS records for a domain.

    :param nameserver: DNS nameserver IP to query (default: 8.8.8.8)
    :return: Set of nameserver hostnames (lowercase, no trailing dot), empty set on failure
    """
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [nameserver]
        answer = resolver.resolve(domain, "NS")
        return {str(r).lower().rstrip(".") for r in answer}
    except Exception:
        return set()


def check_http_status(url: str, timeout: int = 5) -> tuple[int | None, str]:
    """:return: (status_code, response_text) or (None, error_message)"""
    try:
        req = urllib.request.Request(url, method="HEAD")
        with urllib.request.urlopen(req, timeout=timeout) as response:
            status_code = response.getcode()
            return (
                status_code,
                f"HTTP/{response.version} {status_code} {response.reason}",
            )
    except urllib.error.HTTPError as e:
        return e.code, f"HTTP/{e.version} {e.code} {e.reason}"
    except urllib.error.URLError as e:
        return None, str(e)
    except Exception as e:
        return None, str(e)


def resolve_ip(target: str) -> str:
    if is_valid_ip(target):
        return target
    data = load_instance(target)
    return data["ip"]


def resolve_instance(target: str) -> dict:
    """:return: Instance dict with at least ``ip`` key"""
    if is_valid_ip(target):
        return {"ip": target}
    return load_instance(target)


def detect_node_version(source: str) -> int | None:
    source_path = Path(source)

    for filename in [".nvmrc", ".node-version"]:
        version_file = source_path / filename
        if version_file.exists():
            content = version_file.read_text().strip().lstrip("v")
            try:
                return int(content.split(".")[0])
            except ValueError:
                pass

    package_json = source_path / "package.json"
    if package_json.exists():
        try:
            data = json.loads(package_json.read_text())
            node_constraint = data.get("engines", {}).get("node", "")
            match = re.search(r"(\d+)", node_constraint)
            if match:
                return int(match.group(1))
        except (json.JSONDecodeError, ValueError):
            pass

    return None


def compute_hash(source: str, exclude: list[str] | None = None) -> str:
    source_path = Path(source)
    if exclude is None:
        exclude = [".git"]

    hasher = hashlib.md5()
    for f in sorted(source_path.rglob("*")):
        if f.is_file() and not any(ex in str(f) for ex in exclude):
            hasher.update(str(f.relative_to(source_path)).encode())
            hasher.update(f.read_bytes())
    return hasher.hexdigest()


def wait_for_ssh(ip: str, user: str = "deploy", timeout: int = SSH_TIMEOUT):
    log(f"Waiting for SSH on '{ip}'...")
    start = time.time()
    ever_connected = False  # True once we see TCP response (not pure timeout)
    thread_exc_start = None  # When we first saw ThreadException(OSError)
    while time.time() - start < timeout:
        try:
            with Connection(
                ip, user=user, connect_kwargs={"look_for_keys": True, "timeout": 5}
            ) as c:
                c.run("echo ok", hide=True, in_stream=False)
                log("SSH ready")
                return
        except Exception as e:
            elapsed = int(time.time() - start)
            exc_name = type(e).__name__
            # NoValidConnectionsError = connection refused (port reachable, SSH not up)
            # AuthenticationException = SSH up but key rejected
            # TimeoutError / socket.timeout = no route or firewall block
            # ThreadException(OSError) = TCP connects but SSH banner fails (broken sshd)
            if exc_name not in ("TimeoutError", "socket.timeout"):
                ever_connected = True
            # After 60s if still only seeing timeouts, the IP is likely unreachable
            if elapsed > 60 and not ever_connected:
                error(
                    f"IP '{ip}' appears unreachable after {elapsed}s "
                    "(only connection timeouts, no TCP response). "
                    "Check firewall rules or try recreating the instance."
                )
            if exc_name == "ThreadException":
                inner_types = [x.type.__name__ for x in e.exceptions]
                inner_vals = [str(x.value)[:60] for x in e.exceptions]
                detail = f"inner: {', '.join(f'{t}: {v}' for t, v in zip(inner_types, inner_vals))}"
                # Track when we first started seeing ThreadException(OSError)
                if any(t == "OSError" for t in inner_types):
                    if thread_exc_start is None:
                        thread_exc_start = time.time()
                    elif time.time() - thread_exc_start > 120:
                        error(
                            f"SSH on '{ip}' appears broken after {elapsed}s "
                            "(TCP connects but SSH banner fails with OSError for >120s). "
                            "Try recreating the instance."
                        )
            else:
                detail = ""
                thread_exc_start = None  # Reset if we see a different error
            suffix = f" ({detail})" if detail else ""
            log(f"SSH not ready yet ({elapsed}s, {exc_name}){suffix}, retrying...")
        time.sleep(5)
    error(f"SSH timeout after '{timeout}s'")


def verify_http(ip: str, domain: str | None = None, port: int = 80) -> bool:
    # Use domain URL when available — nginx server_name won't match raw IP requests
    base = domain if domain else ip
    url = f"http://{base}/" if port == 80 else f"http://{base}:{port}/"
    log(f"Verifying HTTP connectivity on port {port} via '{url}'...")
    for i in range(HTTP_VERIFY_RETRIES):
        try:
            req = urllib.request.Request(url)
            with urllib.request.urlopen(req, timeout=5) as response:
                status_code = response.getcode()
                if str(status_code)[0] in "2345":
                    log("HTTP connectivity verified")
                    return True
        except (urllib.error.URLError, urllib.error.HTTPError, Exception):
            pass
        warn(f"Cannot connect to '{url}' ({i + 1}/{HTTP_VERIFY_RETRIES})")
        time.sleep(HTTP_VERIFY_DELAY)
    error(f"Cannot connect to '{url}' on port {port}. Check UFW: ssh deploy@'{ip}' 'sudo ufw status'")


def setup_firewall(ip: str, ssh_user: str = "root"):
    """Configure UFW firewall to allow OpenSSH access.

    :param ip: Server IP address
    :param ssh_user: SSH user for remote connection
    """
    script = dedent("""
        set -e
        echo "Configuring firewall..."
        sudo ufw allow OpenSSH
        sudo ufw --force enable
    """).strip()
    ssh_script(ip, script, user=ssh_user)


def setup_swap(ip: str, swap_size: str = "4G", ssh_user: str = "root"):
    """Create and enable swap file if not already present.

    :param ip: Server IP address
    :param swap_size: Swap file size (e.g., "4G")
    :param ssh_user: SSH user for remote connection
    """
    script = dedent(f"""
        set -e
        echo "Setting up swap..."
        if ! swapon --show | grep -q swapfile; then
            sudo fallocate -l {swap_size} /swapfile
            sudo chmod 600 /swapfile
            sudo mkswap /swapfile
            sudo swapon /swapfile
            echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab
        fi
    """).strip()
    ssh_script(ip, script, user=ssh_user)


def create_user(ip: str, user: str = "deploy", ssh_user: str = "root"):
    """Create deploy user with sudo privileges and SSH key access.

    :param ip: Server IP address
    :param user: Username to create
    :param ssh_user: SSH user for remote connection
    """
    auth_keys_path = (
        "~/.ssh/authorized_keys"
        if ssh_user == "root"
        else f"/home/{ssh_user}/.ssh/authorized_keys"
    )

    script = dedent(f"""
        set -e
        if id "{user}" &>/dev/null; then
            echo "User {user} already exists"
        else
            sudo adduser --disabled-password --gecos "" {user}
            sudo usermod -aG sudo {user}
            echo "{user} ALL=(ALL) NOPASSWD:ALL" | sudo tee /etc/sudoers.d/{user}
            sudo chmod 440 /etc/sudoers.d/{user}
            sudo mkdir -p /home/{user}/.ssh
            sudo cp {auth_keys_path} /home/{user}/.ssh/
            sudo chown -R {user}:{user} /home/{user}/.ssh
            sudo chmod 700 /home/{user}/.ssh
            sudo chmod 600 /home/{user}/.ssh/authorized_keys
            echo "User {user} created"
        fi
        # Allow nginx (www-data) to traverse the home directory for static file serving
        sudo chmod o+x /home/{user}
    """).strip()
    ssh_script(ip, script, user=ssh_user)


def setup_server(
    ip: str, *, user: str = "deploy", ssh_user: str = "root", swap_size: str = "4G"
):
    log(f"Setting up server at '{ip}'...")

    script = dedent("""
        set -e
        echo "Waiting for cloud-init..."
        sudo cloud-init status --wait > /dev/null 2>&1 || true

        echo "Installing packages..."
        sudo apt-get update
        sudo apt-get install -y curl wget git ufw
        echo "Done!"
    """).strip()
    log_remote_output(ssh_script(ip, script, user=ssh_user))

    setup_firewall(ip, ssh_user=ssh_user)
    setup_swap(ip, swap_size=swap_size, ssh_user=ssh_user)

    log(f"Creating user: '{user}'")
    create_user(ip, user=user, ssh_user=ssh_user)
    log("Server setup complete")


def _ufw_line_matches_tcp_port(line: str, port: int) -> bool:
    """True if this status line is for ``port``/tcp (not e.g. 8000 when port is 80)."""
    key = f"{port}/tcp"
    for tok in line.split():
        if tok == key or tok.startswith(f"{key}("):
            return True
    return False


def _ufw_tcp_port_state(status: str, port: int) -> tuple[bool, bool]:
    """Parse ``ufw status`` for a TCP port.

    Works for default and numbered ``ufw status`` output.
    REJECT rules are treated like DENY for allow/deny logic.

    :param status: Raw output of ``sudo ufw status``
    :param port: TCP port (e.g. 80, 443)
    :return: (has_allow_rule, has_deny_or_reject_rule) for that port's tcp rules
    """
    has_allow = False
    has_deny = False
    for line in status.splitlines():
        if not _ufw_line_matches_tcp_port(line, port):
            continue
        u = line.upper()
        if "ALLOW" in u:
            has_allow = True
        if "DENY" in u or "REJECT" in u:
            has_deny = True
    return has_allow, has_deny


def _ufw_status_is_inactive(status: str) -> bool:
    for line in status.splitlines()[:5]:
        if "status:" in line.lower() and "inactive" in line.lower():
            return True
    return False


def _verify_instance_ufw(
    ufw_status: str,
    *,
    domain: str | None,
    expect_ssl_only_firewall: bool,
) -> tuple[list[str], bool]:
    """Interpret UFW for ``verify_instance``.

    :return: (issues, http_to_ip_likely_blocked). The second flag is True when 443 is allowed
        but 80 is not, so ``http://<ip>`` may fail even though the deployment is healthy.
    """
    issues: list[str] = []

    if _ufw_status_is_inactive(ufw_status):
        print("[WARN] Firewall: UFW is inactive (rules are not enforced)")
        return issues, False

    a80, d80 = _ufw_tcp_port_state(ufw_status, 80)
    a443, d443 = _ufw_tcp_port_state(ufw_status, 443)

    if d443 and not a443:
        issues.append("UFW: 443/tcp is denied/rejected without an allow rule")

    if domain is not None and not a443:
        issues.append("UFW: no allow rule for 443/tcp (required when verifying with --domain)")

    relaxed_80 = expect_ssl_only_firewall or domain is not None

    if not relaxed_80:
        if d80 and not a80:
            issues.append(
                "UFW: port 80 is denied/rejected without an allow rule "
                "(HTTP to the instance IP will fail)"
            )
        elif not a80 and not d80:
            issues.append(
                "UFW: no allow rule for port 80 (HTTP to the instance IP may be blocked by default deny)"
            )

    if a80 and d80:
        print("[WARN] Firewall: port 80 has both ALLOW and DENY/REJECT — confirm UFW rule order")

    http_to_ip_likely_blocked = bool(a443 and not a80)

    if not issues:
        if a443 and a80:
            print("[OK] Firewall: HTTP (80) and HTTPS (443) allowed in UFW")
        elif a443 and not a80 and relaxed_80:
            if d80:
                print("[OK] Firewall: HTTPS (443) allowed; HTTP (80) denied (SSL-only lockdown)")
            else:
                print(
                    "[OK] Firewall: HTTPS (443) allowed; no allow rule for HTTP (80) "
                    "(SSL-only or implicit deny — fine with --domain or --expect-ssl-only-firewall)"
                )
        elif a80 and not a443:
            print("[OK] Firewall: HTTP (80) allowed (no 443 allow — typical for IP-only HTTP)")
        elif not a80 and not a443:
            print("[WARN] Firewall: no explicit UFW allow rules for 80 or 443")
        else:
            print("[OK] Firewall: UFW allows the ports needed for this verify run")

    if issues:
        log_remote_output(ufw_status)

    return issues, http_to_ip_likely_blocked


def _ufw_delete_port_blocks(port: int) -> str:
    """:return: shell snippet to drop deny/reject rules for ``port``/tcp (best-effort)."""
    p = int(port)
    return (
        f"sudo ufw delete deny {p}/tcp 2>/dev/null || true && "
        f"sudo ufw delete reject {p}/tcp 2>/dev/null || true"
    )


def ensure_web_firewall(
    ip: str,
    ssh_user: str = "deploy",
    extra_port: int | None = None,
    provider=None,
    ssl_only: bool = False,
):
    """Ensure firewall allows HTTP (80), HTTPS (443), and an optional extra port.

    Updates both the OS-level UFW firewall and, when a provider is given,
    the cloud-level firewall (AWS security group, Vultr firewall group).

    Does not assume 80/443 are already allowed: clears conflicting UFW DENY rules,
    ensures cloud ingress for 80 and 443 when not in ssl-only mode, and before
    ssl-only lockdown opens 443 at the cloud then revokes 80.

    :param extra_port: Additional TCP port to open (e.g. custom outgoing_port)
    :param provider: Cloud provider instance for updating cloud-level firewall rules
    :param ssl_only: If True, block port 80 at firewall level for enhanced security
    """
    log("Checking firewall...")
    result = ssh(ip, "sudo ufw status", user=ssh_user)

    if ssl_only:
        a80, d80 = _ufw_tcp_port_state(result, 80)
        a443, d443 = _ufw_tcp_port_state(result, 443)
        a_extra, d_extra = (
            _ufw_tcp_port_state(result, extra_port)
            if extra_port is not None and extra_port not in (80, 443)
            else (False, False)
        )

        needs_80_lock = a80 or not d80
        needs_443 = d443 or not a443
        needs_extra = (
            extra_port is not None
            and extra_port not in (80, 443)
            and (d_extra or not a_extra)
        )

        if needs_80_lock or needs_443 or needs_extra:
            log("Configuring SSL-only firewall (blocking HTTP port 80)...")
            cmds = []
            if a80:
                cmds.append("sudo ufw delete allow 80/tcp")
            if needs_80_lock:
                cmds.append("sudo ufw deny 80/tcp")
            if d443:
                cmds.append(_ufw_delete_port_blocks(443))
            if not a443 or d443:
                cmds.append("sudo ufw allow 443/tcp")
            if extra_port is not None and extra_port not in (80, 443):
                if d_extra:
                    cmds.append(_ufw_delete_port_blocks(extra_port))
                if not a_extra or d_extra:
                    cmds.append(f"sudo ufw allow {extra_port}/tcp")
            cmds.append("sudo ufw reload")
            ssh_script(ip, " && ".join(cmds), user=ssh_user)
            log("SSL-only firewall configured")
        else:
            log("SSL-only firewall OK")
    else:
        a80, d80 = _ufw_tcp_port_state(result, 80)
        a443, d443 = _ufw_tcp_port_state(result, 443)
        a_extra, d_extra = (
            _ufw_tcp_port_state(result, extra_port)
            if extra_port is not None and extra_port not in (80, 443)
            else (False, False)
        )

        needs_80 = d80 or not a80
        needs_443 = d443 or not a443
        needs_extra = (
            extra_port is not None
            and extra_port not in (80, 443)
            and (d_extra or not a_extra)
        )

        if needs_80 or needs_443 or needs_extra:
            log("Opening web ports in firewall...")
            cmds = []
            if d80:
                cmds.append(_ufw_delete_port_blocks(80))
            if needs_80:
                cmds.append("sudo ufw allow 80/tcp")
            if d443:
                cmds.append(_ufw_delete_port_blocks(443))
            if needs_443:
                cmds.append("sudo ufw allow 443/tcp")
            if extra_port is not None and extra_port not in (80, 443):
                if d_extra:
                    cmds.append(_ufw_delete_port_blocks(extra_port))
                if not a_extra or d_extra:
                    cmds.append(f"sudo ufw allow {extra_port}/tcp")
            cmds.append("sudo ufw reload")
            ssh_script(ip, " && ".join(cmds), user=ssh_user)
            log("Firewall updated")
        else:
            log("Firewall OK")

    if provider is not None:
        if ssl_only:
            provider.open_firewall_port(443)
            provider.block_firewall_port(80)
        else:
            provider.ensure_standard_web_ports_open()
        if extra_port is not None and extra_port not in (80, 443):
            provider.open_firewall_port(extra_port)


def ensure_dns_matches(
    domain: str,
    expected_ip: str,
    provider_name: ProviderName = "digitalocean",
    aws_profile: str | None = None,
) -> bool:
    from deployvm.providers import get_provider

    p = get_provider(provider_name, aws_profile=aws_profile)

    # Check that the domain's registrar NS records point to this provider
    provider_ns = {ns.lower().rstrip(".") for ns in p.get_nameservers(domain)}
    actual_ns = resolve_dns_ns(domain)
    if actual_ns and actual_ns.isdisjoint(provider_ns):
        warn(
            f"Nameserver mismatch for '{domain}': registrar NS records point to {actual_ns}, "
            f"not {provider_name} ({provider_ns})"
        )
        warn(
            f"Update your domain registrar to use these nameservers: {sorted(provider_ns)}"
        )
        warn("DNS changes via this provider will have no effect until nameservers are updated")

    current_ip = resolve_dns_a(domain) or ""

    if current_ip == expected_ip:
        return False

    warn(
        f"DNS mismatch: '{domain}' points to '{current_ip or 'nothing'}', expected '{expected_ip}'"
    )
    profile_info = f" (profile: {aws_profile})" if aws_profile else ""
    log(f"Updating DNS via {provider_name}{profile_info}...")
    p.setup_dns(domain, expected_ip)
    log("DNS updated (may take a few minutes to propagate)")
    return True


def generate_nginx_server_block(
    server_name: str,
    port: int,
    static_dir: str | None = None,
    listen: str = "80",
    ssl_only: bool = False,
    letsencrypt_cert_name: str | None = None,
) -> str:
    """Generate nginx server block.

    :param static_dir: If provided, nginx serves static files and proxies non-static requests
    :param ssl_only: If True, only listen on HTTPS (443) and block HTTP entirely
    :param letsencrypt_cert_name: Primary name under /etc/letsencrypt/live/ for TLS directives
        on the HTTPS server (required when ssl_only and listen includes ssl)
    """
    proxy_block = (
        dedent("""
        proxy_pass http://127.0.0.1:{port};
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
    """)
        .strip()
        .format(port=port)
    )

    if static_dir:
        location_block = dedent(f"""
            location / {{
                root {static_dir};
                try_files $uri @backend;
            }}

            location @backend {{
                {proxy_block}
            }}
        """).strip()
    else:
        location_block = dedent(f"""
            location / {{
                {proxy_block}
            }}
        """).strip()

    if ssl_only:
        tls_opts = ""
        if letsencrypt_cert_name and "ssl" in listen:
            core = dedent(f"""
                ssl_certificate /etc/letsencrypt/live/{letsencrypt_cert_name}/fullchain.pem;
                ssl_certificate_key /etc/letsencrypt/live/{letsencrypt_cert_name}/privkey.pem;
                include /etc/letsencrypt/options-ssl-nginx.conf;
            """).strip()
            tls_opts = indent(core, "                ") + "\n"
        out = dedent(f"""
            # Block HTTP entirely when SSL-only mode is enabled
            server {{
                listen 80;
                server_name {server_name};
                return 444;  # Drop connection without response
            }}

            server {{
                listen {listen};
                server_name {server_name};
                __DEPLOYVM_TLS__

                {location_block}
            }}
        """).strip()
        if tls_opts:
            out = out.replace("                __DEPLOYVM_TLS__\n", tls_opts)
        else:
            out = out.replace("                __DEPLOYVM_TLS__\n", "")
        return out
    else:
        return dedent(f"""
            server {{
                listen {listen};
                server_name {server_name};

                {location_block}
            }}
        """).strip()


def setup_nginx_ip(
    ip: str,
    *,
    app_name: str = "app",
    port: int = 3000,
    outgoing_port: int = 80,
    static_dir: str | None = None,
    ssh_user: str = "deploy",
    provider=None,
    ssl_only: bool = False,
):
    """Setup nginx for IP-only access (no SSL).

    :param app_name: App name used as nginx config filename (default: default)
    :param port: Internal application port to proxy to
    :param outgoing_port: External port nginx listens on (default: 80)
    :param provider: Cloud provider instance for updating cloud-level firewall rules
    """
    ensure_web_firewall(ip, ssh_user=ssh_user, extra_port=outgoing_port, provider=provider, ssl_only=ssl_only)

    server_block = generate_nginx_server_block(
        "_", port, static_dir, listen=f"{outgoing_port} default_server", ssl_only=ssl_only
    )

    log(f"Setting up nginx for IP access on '{ip}' port {outgoing_port} (app: {app_name})...")
    install_nginx(ip, ssh_user)
    ensure_nginx_sites_enabled_included(ip, ssh_user)
    ssh_write_file(
        ip, f"/etc/nginx/sites-available/{app_name}", server_block, user=ssh_user
    )
    ssh_script(
        ip,
        f"sudo rm -f /etc/nginx/sites-enabled/default && "
        f"sudo ln -sf /etc/nginx/sites-available/{app_name} /etc/nginx/sites-enabled/{app_name} && "
        f"sudo nginx -t && sudo systemctl reload nginx",
        user=ssh_user,
    )

    verify_http(ip, port=outgoing_port)
    port_suffix = f":{outgoing_port}" if outgoing_port != 80 else ""
    log(f"Nginx configured! 'http://{ip}{port_suffix}'")


def setup_nginx_ssl(
    ip: str,
    domain: str,
    email: str,
    *,
    port: int = 3000,
    outgoing_port: int = 443,
    static_dir: str | None = None,
    skip_dns: bool = False,
    staging: bool = False,
    ssh_user: str = "deploy",
    provider_name: ProviderName = "digitalocean",
    aws_profile: str | None = None,
    provider=None,
    ssl_only: bool = False,
):
    """Setup nginx and SSL certificate.

    :param port: Internal application port to proxy to
    :param outgoing_port: External HTTPS port nginx listens on (default: 443).
        Certbot always validates via port 443; if a different port is given, nginx
        is configured to also listen on that port after the certificate is issued.
    :param provider: Cloud provider instance for updating cloud-level firewall rules
    """
    defer_ssl_lockdown = False
    if ssl_only:
        cert_check_cmd = f"test -d /etc/letsencrypt/live/{domain} && echo 'EXISTS' || echo 'MISSING'"
        cert_exists = ssh(ip, cert_check_cmd, user=ssh_user).strip()

        if cert_exists == 'MISSING':
            log("🔒 SSL lockdown requested but certificate missing. Using automatic two-phase deployment:")
            log("📋 Phase 1: Setting up SSL certificate with temporary HTTP access...")

            ensure_web_firewall(ip, ssh_user=ssh_user, extra_port=outgoing_port, provider=provider, ssl_only=False)
            _setup_ssl_certificate_phase(ip, domain, email, port, outgoing_port, static_dir, skip_dns, staging, ssh_user, provider_name, aws_profile)

            log("🔒 Phase 2: Applying SSL lockdown (blocking HTTP access)...")
            ensure_web_firewall(ip, ssh_user=ssh_user, extra_port=outgoing_port, provider=provider, ssl_only=True)
            _apply_ssl_lockdown_phase(ip, domain, port, static_dir, outgoing_port, ssh_user)

            log("✅ SSL lockdown deployment complete! HTTPS-only access enabled.")
            return

        log(
            "🔒 SSL lockdown requested; certificate already on disk. "
            "Keeping HTTP open until certbot finishes, then applying firewall and nginx lockdown."
        )
        defer_ssl_lockdown = True

    ensure_web_firewall(
        ip,
        ssh_user=ssh_user,
        extra_port=outgoing_port,
        provider=provider,
        ssl_only=False if defer_ssl_lockdown else ssl_only,
    )
    if not skip_dns:
        ensure_dns_matches(domain, ip, provider_name=provider_name, aws_profile=aws_profile)

    # Remove default site so it doesn't conflict with domain-based config
    ssh_script(
        ip,
        "sudo rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true",
        user=ssh_user,
    )

    nginx_ssl_only = False if defer_ssl_lockdown else ssl_only
    server_block = generate_nginx_server_block(
        f"{domain} www.{domain}",
        port,
        static_dir,
        ssl_only=nginx_ssl_only,
        letsencrypt_cert_name=None,
    )

    profile_info = f" (profile: {aws_profile})" if aws_profile else ""
    log(f"Setting up nginx for '{domain}' via {provider_name}{profile_info}...")
    install_nginx(ip, ssh_user)
    ensure_nginx_sites_enabled_included(ip, ssh_user)
    ssh_write_file(
        ip, f"/etc/nginx/sites-available/{domain}", server_block, user=ssh_user
    )
    ssh_script(
        ip,
        f"sudo ln -sf /etc/nginx/sites-available/{domain} /etc/nginx/sites-enabled/ && "
        f"sudo nginx -t && sudo systemctl reload nginx",
        user=ssh_user,
    )

    log("Verifying DNS...")
    auth_ns_ip = resolve_authoritative_ns_ip(domain)
    for i in range(DNS_VERIFY_RETRIES):
        # Check authoritative NS first (instant for Route53), then public resolver
        resolved = (auth_ns_ip and resolve_dns_a(domain, auth_ns_ip)) or resolve_dns_a(domain)
        if resolved == ip:
            log(f"DNS verified: '{domain}' -> '{ip}'")
            break
        warn(f"Waiting for DNS... ({i + 1}/{DNS_VERIFY_RETRIES})")
        time.sleep(DNS_VERIFY_DELAY)
    else:
        error("DNS verification timeout")

    if not ssl_only or defer_ssl_lockdown:
        verify_http(ip, domain=domain)

    log("Obtaining SSL certificate...")
    staging_flag = "--staging " if staging else ""
    ssl_script = dedent(f"""
        set -e
        sudo apt-get install -y certbot python3-certbot-nginx
        if [ -d "/etc/letsencrypt/live/{domain}" ]; then
            echo "Certificate exists, renewing if needed..."
            sudo certbot --nginx {staging_flag}-d {domain} -d www.{domain} \\
                --non-interactive --agree-tos --email {email} \\
                --redirect --keep-until-expiring
        else
            echo "Issuing new certificate..."
            sudo certbot --nginx {staging_flag}-d {domain} -d www.{domain} \\
                --non-interactive --agree-tos --email {email} --redirect
        fi
        sudo systemctl enable --now certbot.timer
    """).strip()
    ssh_script(ip, ssl_script, user=ssh_user)

    if defer_ssl_lockdown:
        ensure_web_firewall(ip, ssh_user=ssh_user, extra_port=outgoing_port, provider=provider, ssl_only=True)
        _apply_ssl_lockdown_phase(ip, domain, port, static_dir, outgoing_port, ssh_user)
        port_suffix = f":{outgoing_port}" if outgoing_port != 443 else ""
        log(f"SSL configured! http://{ip} and https://{domain}{port_suffix}")
        return

    # Certbot always configures 443. If a custom port is requested, add an
    # additional listen directive to the SSL server block.
    if outgoing_port != 443:
        log(f"Adding listen directive for custom SSL port {outgoing_port}...")
        add_listen_script = dedent(f"""
            set -e
            CONFIG="/etc/nginx/sites-available/{domain}"
            # Insert 'listen <port> ssl;' after the existing 'listen 443 ssl;' line
            sudo sed -i '/listen 443 ssl;/a\\    listen {outgoing_port} ssl;' "$CONFIG"
            sudo nginx -t && sudo systemctl reload nginx
        """).strip()
        ssh_script(ip, add_listen_script, user=ssh_user)

    # Ensure direct IP access still works alongside the domain SSL config.
    # Certbot's HTTP block only matches the domain, so IP requests need a catch-all.
    # Remove any prior catch-all configs first to avoid duplicate server_name _ conflicts.
    ssh_script(
        ip,
        "for f in $(grep -rl 'server_name _' /etc/nginx/sites-enabled/ 2>/dev/null);"
        " do sudo rm -f \"$f\"; done",
        user=ssh_user,
    )
    ip_block = generate_nginx_server_block("_", port, static_dir, listen="80", ssl_only=ssl_only)
    ssh_write_file(ip, "/etc/nginx/sites-available/ip-access", ip_block, user=ssh_user)
    ssh_script(
        ip,
        "sudo ln -sf /etc/nginx/sites-available/ip-access /etc/nginx/sites-enabled/ip-access"
        " && sudo nginx -t && sudo systemctl reload nginx",
        user=ssh_user,
    )

    port_suffix = f":{outgoing_port}" if outgoing_port != 443 else ""
    log(f"SSL configured! http://{ip} and https://{domain}{port_suffix}")


def probe_domain(ip: str, domain: str, port: int = 443) -> None:
    """Probe whether a deployed instance connects to a domain as configured by deployvm ssl.

    Checks DNS resolution, HTTP redirect, HTTPS connectivity, and SSL certificate validity.

    :param ip: Instance IP address
    :param domain: Domain name to probe
    :param port: HTTPS port to check (default: 443)
    """
    import socket
    import ssl
    from datetime import datetime, timezone

    print(f"Probing '{domain}' -> '{ip}' (port {port})...")
    print("-" * 40)
    issues = []

    # DNS
    dns_ip = resolve_dns_a(domain)
    if dns_ip == ip:
        print(f"[OK] DNS: '{domain}' -> '{ip}'")
    elif dns_ip:
        print(f"[FAIL] DNS: '{domain}' -> '{dns_ip}' (expected '{ip}')")
        issues.append(f"DNS mismatch: points to '{dns_ip}', expected '{ip}'")
    else:
        print(f"[FAIL] DNS: '{domain}' -> no A record found")
        issues.append("DNS: no A record found")

    # HTTP (should redirect to HTTPS after certbot --redirect)
    http_status, http_response = check_http_status(f"http://{domain}")
    if http_status in (301, 302):
        print(f"[OK] HTTP: redirects to HTTPS ({http_status})")
    elif http_status == 200:
        print(f"[WARN] HTTP: returns 200 (no redirect to HTTPS configured)")
    elif http_status:
        print(f"[WARN] HTTP: '{http_response}'")
    else:
        print(f"[FAIL] HTTP: '{http_response}'")
        issues.append("HTTP not reachable")

    # HTTPS connectivity
    https_url = f"https://{domain}" if port == 443 else f"https://{domain}:{port}"
    https_status, https_response = check_http_status(https_url)
    if https_status == 200:
        print(f"[OK] HTTPS: '{https_url}' responding (200)")
    elif https_status:
        print(f"[WARN] HTTPS: '{https_response}'")
    else:
        print(f"[FAIL] HTTPS: '{https_response}'")
        issues.append(f"HTTPS not reachable at '{https_url}'")

    # SSL certificate
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, port), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        not_after_str = cert.get("notAfter", "")
        if not_after_str:
            not_after = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            days_remaining = (not_after - datetime.now(timezone.utc)).days
            expiry_date = not_after.strftime("%Y-%m-%d")
            if days_remaining > 14:
                print(f"[OK] SSL cert: valid, expires in {days_remaining} days ({expiry_date})")
            elif days_remaining > 0:
                print(f"[WARN] SSL cert: expires soon in {days_remaining} days ({expiry_date})")
                issues.append(f"SSL certificate expires in {days_remaining} days")
            else:
                print(f"[FAIL] SSL cert: expired {-days_remaining} days ago ({expiry_date})")
                issues.append("SSL certificate expired")

        san_list = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
        apex = ".".join(domain.split(".")[-2:])
        wildcard = f"*.{apex}"
        if domain in san_list or wildcard in san_list:
            san_display = ", ".join(san_list[:3]) + ("..." if len(san_list) > 3 else "")
            print(f"[OK] SSL cert: covers '{domain}' (SAN: {san_display})")
        else:
            print(f"[WARN] SSL cert: SAN does not include '{domain}' ({san_list})")
            issues.append("SSL certificate SAN mismatch")

    except ssl.SSLCertVerificationError as e:
        print(f"[FAIL] SSL cert: verification failed — {e}")
        issues.append(f"SSL certificate invalid: {e}")
    except ConnectionRefusedError:
        print(f"[FAIL] SSL: connection refused on port {port}")
        issues.append(f"HTTPS port {port} not reachable")
    except Exception as e:
        print(f"[FAIL] SSL: {e}")
        issues.append(f"SSL check failed: {e}")

    print("-" * 40)
    if issues:
        print(f"Issues found ({len(issues)}):")
        for issue in issues:
            print(f"  - {issue}")
    else:
        print("All checks passed!")


def verify_instance(
    name: str,
    *,
    domain: str | None = None,
    ssh_user: str = "deploy",
    expect_ssl_only_firewall: bool = False,
):
    """Verify instance health: SSH, firewall, DNS, nginx, app.

    :param name: Instance name
    :param domain: Domain to check DNS for
    :param ssh_user: SSH user for connection
    :param expect_ssl_only_firewall: If True, do not require UFW to allow port 80 (HTTPS-only setups)
    """
    data = load_instance(name)
    ip = data["ip"]

    print(f"Verifying '{name}' ('{ip}')...")
    print("-" * 40)
    issues = []

    # SSH check
    try:
        uptime = ssh(ip, "uptime", user=ssh_user).strip()
        print(f"[OK] SSH: {remote_line_for_log(uptime)}")
    except Exception as e:
        print(f"[FAIL] SSH: {e}")
        issues.append("SSH connection failed")
        return

    ufw_status = ssh(ip, "sudo ufw status", user=ssh_user)
    fw_issues, http_ip_firewall_ssl = _verify_instance_ufw(
        ufw_status,
        domain=domain,
        expect_ssl_only_firewall=expect_ssl_only_firewall,
    )
    issues.extend(fw_issues)
    relax_http_ip = http_ip_firewall_ssl and (
        domain is not None or expect_ssl_only_firewall
    )

    nginx_status = ssh(
        ip, "systemctl is-active nginx 2>/dev/null || echo 'inactive'", user=ssh_user
    ).strip()
    if nginx_status == "active":
        print("[OK] Nginx: running")
    else:
        print(f"[FAIL] Nginx: '{nginx_status}'")
        issues.append("Nginx not running")

    if domain:
        dns_ip = resolve_dns_a(domain)
        if dns_ip == ip:
            print(f"[OK] DNS: '{domain}' -> '{ip}'")
        elif dns_ip:
            print(f"[FAIL] DNS: '{domain}' -> '{dns_ip}' (expected '{ip}')")
            issues.append(f"DNS mismatch: '{dns_ip}' != '{ip}'")
        else:
            print(f"[FAIL] DNS: '{domain}' -> no A record found")
            issues.append("DNS check failed")

    status_code, response_line = check_http_status(f"http://{ip}")
    if status_code and status_code in [200, 301, 302]:
        print("[OK] HTTP: responding")
    elif relax_http_ip:
        if status_code:
            print(f"[WARN] HTTP: instance IP returned '{response_line}' (HTTPS-only / blocked 80 is common)")
        else:
            print(
                "[WARN] HTTP: no response on instance IP (expected when only 443 is open or "
                "UFW denies port 80)"
            )
    elif status_code:
        print(f"[WARN] HTTP: '{response_line}'")
    else:
        print(f"[FAIL] HTTP: '{response_line}'")
        issues.append("HTTP not responding")

    if domain:
        status_code, response_line = check_http_status(f"https://{domain}")
        if status_code == 200:
            print(f"[OK] HTTPS: '{domain}' responding")
        elif status_code:
            print(f"[WARN] HTTPS: '{response_line}'")
        else:
            print(f"[FAIL] HTTPS: '{response_line}'")
            issues.append("HTTPS not responding")

    print("-" * 40)
    if issues:
        print(f"Issues found ({len(issues)}):")
        for issue in issues:
            print(f"  - {issue}")
    else:
        print("All checks passed!")


def _setup_ssl_certificate_phase(
    ip: str,
    domain: str,
    email: str,
    port: int,
    outgoing_port: int,
    static_dir: str | None,
    skip_dns: bool,
    staging: bool,
    ssh_user: str,
    provider_name: str,
    aws_profile: str | None,
):
    """Phase 1 of SSL lockdown: Setup SSL certificate with HTTP access allowed.
    
    This is extracted from the main setup_nginx_ssl function to handle
    the two-phase deployment for SSL lockdown mode.
    """
    if not skip_dns:
        ensure_dns_matches(domain, ip, provider_name=provider_name, aws_profile=aws_profile)

    # Remove default site so it doesn't conflict with domain-based config
    ssh_script(
        ip,
        "sudo rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true",
        user=ssh_user,
    )

    # Create normal SSL-ready nginx config (without SSL-only blocking)
    server_block = generate_nginx_server_block(
        f"{domain} www.{domain}", port, static_dir, ssl_only=False
    )

    log(f"Setting up nginx for '{domain}' (certificate provisioning phase)...")
    install_nginx(ip, ssh_user)
    ensure_nginx_sites_enabled_included(ip, ssh_user)
    ssh_write_file(
        ip, f"/etc/nginx/sites-available/{domain}", server_block, user=ssh_user
    )
    ssh_script(
        ip,
        f"sudo ln -sf /etc/nginx/sites-available/{domain} /etc/nginx/sites-enabled/ && "
        f"sudo nginx -t && sudo systemctl reload nginx",
        user=ssh_user,
    )

    log("Verifying DNS...")
    auth_ns_ip = resolve_authoritative_ns_ip(domain)
    for i in range(DNS_VERIFY_RETRIES):
        resolved = (auth_ns_ip and resolve_dns_a(domain, auth_ns_ip)) or resolve_dns_a(domain)
        if resolved == ip:
            log(f"DNS verified: '{domain}' -> '{ip}'")
            break
        warn(f"Waiting for DNS... ({i + 1}/{DNS_VERIFY_RETRIES})")
        time.sleep(DNS_VERIFY_DELAY)
    else:
        error("DNS verification timeout")

    # Verify HTTP connectivity before certificate issuance
    verify_http(ip, domain=domain)

    log("Obtaining SSL certificate...")
    staging_flag = "--staging " if staging else ""
    ssl_script = dedent(f"""
        set -e
        sudo apt-get install -y certbot python3-certbot-nginx
        if [ -d "/etc/letsencrypt/live/{domain}" ]; then
            echo "Certificate exists, renewing if needed..."
            sudo certbot --nginx {staging_flag}-d {domain} -d www.{domain} \\
                --non-interactive --agree-tos --email {email} \\
                --redirect --keep-until-expiring
        else
            echo "Issuing new certificate..."
            sudo certbot --nginx {staging_flag}-d {domain} -d www.{domain} \\
                --non-interactive --agree-tos --email {email} --redirect
        fi
        sudo systemctl enable --now certbot.timer
    """).strip()
    ssh_script(ip, ssl_script, user=ssh_user)

    # Handle custom SSL ports
    if outgoing_port != 443:
        log(f"Adding listen directive for custom SSL port {outgoing_port}...")
        add_listen_script = dedent(f"""
            set -e
            CONFIG="/etc/nginx/sites-available/{domain}"
            # Insert 'listen <port> ssl;' after the existing 'listen 443 ssl;' line
            sudo sed -i '/listen 443 ssl;/a\\    listen {outgoing_port} ssl;' "$CONFIG"
            sudo nginx -t && sudo systemctl reload nginx
        """).strip()
        ssh_script(ip, add_listen_script, user=ssh_user)


def _apply_ssl_lockdown_phase(
    ip: str,
    domain: str,
    port: int,
    static_dir: str | None,
    outgoing_port: int,
    ssh_user: str,
):
    """Phase 2 of SSL lockdown: Apply HTTP blocking to existing SSL setup.
    
    This regenerates the nginx configuration with SSL-only blocking
    and removes any HTTP access created by certbot.
    """
    log("Regenerating nginx configuration with SSL lockdown...")
    
    # Generate SSL-only server block (with HTTP blocking)
    server_block = generate_nginx_server_block(
        f"{domain} www.{domain}",
        port,
        static_dir,
        ssl_only=True,
        listen="443 ssl",
        letsencrypt_cert_name=domain,
    )
    
    # Write the new SSL-only configuration
    ssh_write_file(
        ip, f"/etc/nginx/sites-available/{domain}", server_block, user=ssh_user
    )
    
    # Handle custom SSL ports in SSL-only mode  
    if outgoing_port != 443:
        log(f"Adding custom SSL port {outgoing_port} to SSL-only configuration...")
        add_listen_script = dedent(f"""
            set -e
            CONFIG="/etc/nginx/sites-available/{domain}"
            # Add custom SSL port after 443 ssl
            sudo sed -i '/listen 443 ssl;/a\\    listen {outgoing_port} ssl;' "$CONFIG"
            sudo nginx -t && sudo systemctl reload nginx
        """).strip()
        ssh_script(ip, add_listen_script, user=ssh_user)
    
    # Reload nginx with SSL-only configuration
    ssh_script(
        ip,
        f"sudo nginx -t && sudo systemctl reload nginx",
        user=ssh_user,
    )
    
    # Setup IP access fallback with SSL-only blocking
    log("Configuring IP access fallback with SSL lockdown...")
    ssh_script(
        ip,
        "for f in $(grep -rl 'server_name _' /etc/nginx/sites-enabled/ 2>/dev/null);"
        " do sudo rm -f \"$f\"; done",
        user=ssh_user,
    )
    ip_block = generate_nginx_server_block("_", port, static_dir, listen="80", ssl_only=True)
    ssh_write_file(ip, "/etc/nginx/sites-available/ip-access", ip_block, user=ssh_user)
    ssh_script(
        ip,
        "sudo ln -sf /etc/nginx/sites-available/ip-access /etc/nginx/sites-enabled/ip-access"
        " && sudo nginx -t && sudo systemctl reload nginx",
        user=ssh_user,
    )
    
    log("SSL lockdown applied successfully - HTTP access blocked at nginx level")
