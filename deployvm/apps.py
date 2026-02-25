"""App deployment logic for Nuxt and uv Python applications."""

import hashlib
import json
import re
import subprocess
from pathlib import Path
from textwrap import dedent

from .server import (
    check_instance_auth,
    rsync,
    ssh,
    ssh_as_user,
    ssh_script,
    ssh_write_file,
)
from .utils import error, log, warn


def filter_aws_credentials_from_env(
    source_dir: str,
    provider_name: str,
    ip: str,
    remote_path: str,
    ssh_user: str,
) -> bool:
    """Filter AWS credentials from .env and upload filtered version.

    Removes AWS_PROFILE, AWS_ACCESS_KEY_ID, and AWS_SECRET_ACCESS_KEY
    since AWS EC2 instances use IAM roles instead. Ensures AWS_REGION
    is present for Bedrock and other AWS services.

    :param source_dir: Local source directory path
    :param provider_name: Cloud provider name
    :param ip: Remote instance IP
    :param remote_path: Remote path for filtered .env file
    :param ssh_user: SSH user for rsync
    :return: True if .env should be excluded from main rsync, False otherwise
    """
    env_path = Path(source_dir) / ".env"

    # Only filter for AWS deployments with .env file
    if provider_name != "aws" or not env_path.exists():
        return False

    log("Filtering AWS credentials from .env (EC2 instances use IAM roles)")

    lines = env_path.read_text().splitlines()
    aws_vars = ["AWS_PROFILE=", "AWS_ACCESS_KEY_ID=", "AWS_SECRET_ACCESS_KEY="]

    filtered_lines = []
    filtered_vars = []
    has_aws_region = False
    removing_profile = False

    for line in lines:
        stripped = line.strip()
        # Check if AWS_REGION is already present
        if stripped.startswith("AWS_REGION="):
            has_aws_region = True
            filtered_lines.append(line)
        elif any(stripped.startswith(var) for var in aws_vars):
            # Extract variable name for logging
            var_name = stripped.split("=")[0]
            filtered_vars.append(var_name)
            if var_name == "AWS_PROFILE":
                removing_profile = True
        else:
            filtered_lines.append(line)

    if filtered_vars:
        log(f"  Removed: {', '.join(filtered_vars)}")
    else:
        log("  No AWS credentials found in .env")

    # If we're removing AWS_PROFILE but AWS_REGION is missing, we need to add it
    if removing_profile and not has_aws_region:
        # Import here to avoid circular dependency
        from .providers import AWSProvider

        # Get region from AWS config (may come from profile)
        aws_config = AWSProvider.get_aws_config()
        region = aws_config.get("region_name")

        if region:
            filtered_lines.append(f"AWS_REGION={region}")
            log(f"  Added AWS_REGION={region} (from AWS profile configuration)")
        else:
            warn(
                "AWS_PROFILE removed but AWS_REGION not found!\n"
                "  Bedrock and other AWS services require AWS_REGION.\n"
                "  Please add AWS_REGION to your .env file."
            )

    # Upload filtered .env file directly (no temp file needed)
    filtered_content = "\n".join(filtered_lines) + "\n"

    # Remove any existing .env (could be a directory from failed previous run)
    ssh(ip, f"sudo rm -rf {remote_path}", user=ssh_user)

    ssh_write_file(ip, remote_path, filtered_content, user=ssh_user)

    return True  # Signal that .env should be excluded from main rsync


class BaseApp:
    """Base class for app deployment."""

    def __init__(self, instance_data: dict, provider_name: str):
        """Initialize app.

        :param instance_data: Instance data from .instance.json
        :param provider_name: Cloud provider name
        """
        self.instance = instance_data
        self.ip = instance_data["ip"]
        self.provider_name = provider_name
        self.ssh_user = "deploy"
        check_instance_auth(instance_data)

    def compute_source_hash(
        self, local_path: str, exclude: list[str] | None = None
    ) -> str:
        """Compute hash of local source directory."""
        source_path = Path(local_path)
        if exclude is None:
            exclude = [".git"]

        hasher = hashlib.md5()
        for f in sorted(source_path.rglob("*")):
            if f.is_file() and not any(ex in str(f) for ex in exclude):
                hasher.update(str(f.relative_to(source_path)).encode())
                hasher.update(f.read_bytes())
        return hasher.hexdigest()

    def select_app(self, app_type: str, app_name: str | None = None) -> dict:
        """Select app from instance data.

        :param app_type: App type (npm or uv)
        :param app_name: App name (if multiple apps exist)
        :return: App data dict
        """
        apps = [app for app in self.instance.get("apps", []) if app["type"] == app_type]

        if app_name is None:
            if len(apps) == 1:
                return apps[0]
            elif len(apps) > 1:
                app_names = ", ".join(app["name"] for app in apps)
                error(
                    f"Multiple {app_type} apps found: {app_names}. Use --app-name to specify."
                )
            else:
                # Fallback for old single-app instances
                return {"name": "app", "type": app_type}

        for app in apps:
            if app["name"] == app_name:
                return app

        error(f"App '{app_name}' not found in instance")


class NpmApp(BaseApp):
    """npm app deployment via PM2."""

    def __init__(
        self,
        instance_data: dict,
        provider_name: str,
        *,
        user: str,
        app_name: str = "npm",
        port: int = 3000,
        node_version: int = 20,
        start_script: str = ".output/server/index.mjs",
        build_command: str = "npm run build",
        dist_dir: str = ".output",
    ):
        super().__init__(instance_data, provider_name)
        self.user = user
        self.app_name = app_name
        self.port = port
        self.node_version = node_version
        self.start_script = start_script
        self.build_command = build_command
        self.dist_dir = dist_dir
        self.app_dir = f"/home/{user}/{app_name}"

    def detect_node_version(self, source: str) -> int | None:
        """Detect Node.js version from project files.

        :param source: Path to source directory
        :return: Major Node.js version number
        """
        import re

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

    def generate_pm2_config(self) -> str:
        """Generate PM2 ecosystem config.

        If start_script begins with 'npm ', it is treated as an npm command
        (e.g. 'npm run serve') and PM2 is configured to run npm with the
        remaining args. Otherwise start_script is used as a direct file path.
        """
        if self.start_script.startswith("npm "):
            npm_args = self.start_script[len("npm "):]
            script_line = f"script: 'npm',"
            args_line = f"args: '{npm_args}',"
        else:
            script_line = f"script: './{self.start_script}',"
            args_line = ""
        instances_line = "instances: 1,"
        exec_mode_line = "exec_mode: 'fork',"

        args_block = f"\n                {args_line}" if args_line else ""

        return dedent(f"""
            const fs = require('fs');
            const path = require('path');

            // Load .env file if it exists
            const envPath = path.join(__dirname, '.env');
            const envVars = {{}};
            if (fs.existsSync(envPath)) {{
              const content = fs.readFileSync(envPath, 'utf-8');
              content.split('\\n').forEach(line => {{
                const trimmed = line.trim();
                if (trimmed && !trimmed.startsWith('#')) {{
                  const [key, ...valueParts] = trimmed.split('=');
                  if (key && valueParts.length) {{
                    let value = valueParts.join('=').trim();
                    if ((value.startsWith('"') && value.endsWith('"')) ||
                        (value.startsWith("'") && value.endsWith("'"))) {{
                      value = value.slice(1, -1);
                    }}
                    envVars[key.trim()] = value;
                  }}
                }}
              }});
            }}

            module.exports = {{
              apps: [{{
                name: '{self.app_name}',
                {script_line}{args_block}
                cwd: '{self.app_dir}',
                {instances_line}
                {exec_mode_line}
                env: {{
                  NODE_ENV: 'production',
                  PORT: {self.port},
                  ...envVars
                }}
              }}]
            }};
        """).strip()

    def _fix_absolute_imports(self, source: str):
        """Replace file:/// absolute path imports with null stubs in dist dir.

        Nuxt devtools bakes absolute local machine paths into production builds
        when devtools.enabled=true. These imports fail on the server.
        """
        dist_path = Path(source) / self.dist_dir
        pattern = re.compile(r"import (\w+) from 'file:///[^']*';")
        for mjs_file in dist_path.rglob("*.mjs"):
            content = mjs_file.read_text()
            new_content = pattern.sub(r"const \1 = null;", content)
            if new_content != content:
                log(f"Fixed absolute path import in {mjs_file.relative_to(source)}")
                mjs_file.write_text(new_content)

    def sync(
        self,
        source: str,
        *,
        local_build: bool = True,
        force: bool = False,
    ):
        """Sync npm app to server.

        :param source: Local source directory
        :param local_build: Build locally instead of on server
        :param force: Force rebuild even if source unchanged
        """
        source = str(Path(source).resolve())

        if not Path(source).exists():
            error(f"Source directory not found: {source}")

        detected_version = self.detect_node_version(source)
        if detected_version:
            log(f"Detected Node.js version {detected_version} from project config")
            self.node_version = detected_version

        log(f"Deploying to {self.ip}...")

        log(f"Installing Node.js {self.node_version} and PM2...")
        node_script = dedent(f"""
            set -e
            if ! command -v node &> /dev/null; then
                curl -fsSL https://deb.nodesource.com/setup_{self.node_version}.x | sudo bash -
                sudo apt-get install -y nodejs
            fi
            node --version
            if ! command -v pm2 &> /dev/null; then
                sudo npm install -g pm2
            fi
            sudo mkdir -p {self.app_dir}
            sudo chown -R {self.user}:{self.user} {self.app_dir}
        """).strip()
        ssh_script(self.ip, node_script, user=self.ssh_user, show_output=True)

        log("Generating PM2 ecosystem config...")
        ecosystem_config = self.generate_pm2_config()
        ssh_write_file(
            self.ip,
            f"{self.app_dir}/ecosystem.config.cjs",
            ecosystem_config,
            user=self.ssh_user,
        )
        ssh(
            self.ip,
            f"sudo chown {self.user}:{self.user} {self.app_dir}/ecosystem.config.cjs",
            user=self.ssh_user,
        )

        npm_exclude = [
            "node_modules",
            ".git",
            self.dist_dir,
            "public/projects",
            "data/scripts/models",
            "json/projects",
        ]
        local_hash = self.compute_source_hash(source, npm_exclude)
        try:
            remote_hash = ssh(
                self.ip,
                f"cat {self.app_dir}/.source_hash 2>/dev/null || echo ''",
                user=self.ssh_user,
            ).strip()
        except Exception:
            remote_hash = ""

        if not force and local_hash == remote_hash and remote_hash:
            log("Source unchanged, restarting app...")
            restart_script = dedent(f"""
                if pm2 describe {self.app_name} > /dev/null 2>&1; then
                    pm2 reload {self.app_name}
                else
                    cd {self.app_dir} && pm2 start ecosystem.config.cjs && pm2 save
                fi
            """).strip()
            ssh_script(self.ip, restart_script, user=self.ssh_user)
            log("App restarted")
            return

        if local_build:
            log("Building locally...")
            subprocess.run(["npm", "install"], cwd=source, check=True)
            subprocess.run(self.build_command.split(), cwd=source, check=True)

            if not Path(source, self.dist_dir).exists():
                error(f"Build failed - no {self.dist_dir} directory")

            self._fix_absolute_imports(source)

        log("Uploading...")
        exclude = [
            "/node_modules",
            ".git",
            "ecosystem.config.cjs",
            ".source_hash",
            "public/projects",
            "data/scripts/models",
            "json/projects",
        ]
        if not local_build:
            exclude.append(self.dist_dir)
        rsync(source, self.ip, self.app_dir, exclude=exclude, user=self.ssh_user)

        if not local_build:
            log("Building on server...")
            build_script = dedent(f"""
                set -e
                cd {self.app_dir}
                export NODE_OPTIONS="--max-old-space-size=1024"
                su - {self.user} -c "cd {self.app_dir} && rm -rf package-lock.json && npm install && {self.build_command}"
            """).strip()
            ssh_script(self.ip, build_script, user=self.ssh_user, show_output=True)

        log("Starting app...")
        start_script = dedent(f"""
            set -e
            echo "{local_hash}" > {self.app_dir}/.source_hash
            sudo chown -R {self.user}:{self.user} {self.app_dir}
            if pm2 describe {self.app_name} > /dev/null 2>&1; then
                pm2 reload {self.app_name}
            else
                cd {self.app_dir} && pm2 start ecosystem.config.cjs && pm2 save
            fi
            sudo pm2 startup systemd -u {self.user} --hp /home/{self.user} 2>/dev/null || true
        """).strip()
        ssh_script(self.ip, start_script, user=self.ssh_user)
        log("npm app deployed!")

    def restart(self):
        """Restart PM2 app."""
        log(f"Restarting {self.app_name}...")
        ssh(self.ip, f"pm2 reload {self.app_name}", user=self.ssh_user)
        log("App restarted")

    def status(self):
        """Show PM2 status."""
        return ssh(self.ip, "pm2 list", user=self.ssh_user)

    def logs(self, lines: int = 50):
        """Show PM2 logs."""
        return ssh(
            self.ip,
            f"pm2 logs {self.app_name} --lines {lines} --nostream",
            user=self.ssh_user,
        )


def validate_uv_lockfile(source: str):
    """Validate that uv.lock is in sync with pyproject.toml.

    :param source: Path to source directory
    :raises SystemExit: If lockfile is out of sync
    """
    source_path = Path(source)
    lockfile = source_path / "uv.lock"

    # If no lockfile exists, uv sync will create one (no --frozen flag used)
    if not lockfile.exists():
        return

    # Check if lockfile is in sync using uv lock --check
    log("Validating uv.lock is in sync with pyproject.toml...")
    result = subprocess.run(
        ["uv", "lock", "--check"],
        cwd=source,
        capture_output=True,
        text=True
    )

    if result.returncode != 0:
        error(
            "uv.lock is out of sync with pyproject.toml!\n"
            f"  Location: {source}\n"
            f"  Error: {result.stderr.strip()}\n\n"
            "Fix this by running:\n"
            f"  cd {source}\n"
            "  uv lock\n\n"
            "Then redeploy."
        )

    log("✓ uv.lock is in sync")


class UVApp(BaseApp):
    """uv Python app deployment."""

    def __init__(
        self,
        instance_data: dict,
        provider_name: str,
        *,
        user: str,
        app_name: str = "uv",
        port: int = 8000,
        command: str | None = None,
    ):
        super().__init__(instance_data, provider_name)
        self.user = user
        self.app_name = app_name
        self.port = port
        self.command = command  # Only used by sync(), not needed for status/logs/restart
        self.app_dir = f"/home/{user}/{app_name}"

    def sync(self, source: str, *, force: bool = False) -> bool:
        """Sync uv Python app to server using supervisord.

        :param source: Local source directory
        :param force: Force rebuild even if source unchanged
        :return: True if full sync, False if source unchanged
        """
        if not self.command:
            error("Command is required for sync operation")

        source = str(Path(source).resolve())

        if not Path(source).exists():
            error(f"Source directory not found: {source}")

        if not (Path(source) / "pyproject.toml").exists():
            error(f"pyproject.toml not found in {source}")

        validate_uv_lockfile(source)

        log(f"Deploying uv app to {self.ip}...")

        log("Installing uv and supervisor...")
        setup_script = dedent(f"""
            set -e
            sudo apt-get update
            sudo apt-get install -y supervisor curl

            sudo mkdir -p /home/{self.user}/{self.app_name}
            sudo mkdir -p /var/log/{self.app_name}
            sudo chown -R {self.user}:{self.user} /home/{self.user}/{self.app_name}
            sudo chown -R {self.user}:{self.user} /var/log/{self.app_name}

            sudo su - {self.user} -c "curl -LsSf https://astral.sh/uv/install.sh | sh"
        """).strip()
        ssh_script(self.ip, setup_script, user=self.ssh_user, show_output=True)

        python_exclude = [".venv", "__pycache__", ".git", "*.pyc"]
        local_hash = self.compute_source_hash(source, python_exclude)
        try:
            remote_hash = ssh(
                self.ip,
                f"cat /home/{self.user}/{self.app_name}/.source_hash 2>/dev/null || echo ''",
                user=self.ssh_user,
            ).strip()
        except Exception:
            remote_hash = ""

        if not force and local_hash == remote_hash and remote_hash:
            log("Source unchanged, restarting app...")
            ssh_script(
                self.ip,
                f"sudo supervisorctl restart {self.app_name}",
                user=self.ssh_user,
            )
            log("App restarted")
            return False

        log("Uploading...")

        # Filter AWS credentials from .env for AWS deployments
        exclude_env = filter_aws_credentials_from_env(
            source,
            self.provider_name,
            self.ip,
            f"/home/{self.user}/{self.app_name}/.env",
            self.ssh_user,
        )

        exclude = [".venv", "__pycache__", ".git", "*.pyc", ".source_hash"]
        if exclude_env:
            exclude.append(".env")

        rsync(
            source,
            self.ip,
            f"/home/{self.user}/{self.app_name}",
            exclude=exclude,
            user=self.ssh_user,
        )

        log("Setting up Python environment...")
        venv_script = dedent(f"""
            set -e
            sudo chown -R {self.user}:{self.user} /home/{self.user}/{self.app_name}

            FROZEN=""
            if [ -f "/home/{self.user}/{self.app_name}/uv.lock" ]; then
                FROZEN="--frozen"
            fi

            sudo su - {self.user} -c "cd /home/{self.user}/{self.app_name} && ~/.local/bin/uv sync $FROZEN"
        """).strip()
        ssh_script(self.ip, venv_script, user=self.ssh_user)

        log("Configuring supervisord...")
        # Validate command starts with 'uv'
        if not self.command.strip().startswith("uv "):
            error(f"Command must start with 'uv': {self.command}")

        supervisor_config = dedent(f"""
            [program:{self.app_name}]
            directory=/home/{self.user}/{self.app_name}
            command={self.command}
            user={self.user}
            autostart=true
            autorestart=true
            stopasgroup=true
            killasgroup=true
            stderr_logfile=/var/log/{self.app_name}/error.log
            stdout_logfile=/var/log/{self.app_name}/access.log
            environment=PATH="/home/{self.user}/.local/bin:/usr/local/bin:/usr/bin:/bin"
        """).strip()
        ssh_write_file(
            self.ip,
            f"/etc/supervisor/conf.d/{self.app_name}.conf",
            supervisor_config,
            user=self.ssh_user,
        )

        hash_write_cmd = f'echo "{local_hash}" | sudo tee /home/{self.user}/{self.app_name}/.source_hash > /dev/null'

        ssh_script(
            self.ip,
            f"{hash_write_cmd} && "
            f"sudo chown {self.user}:{self.user} /home/{self.user}/{self.app_name}/.source_hash && "
            f"sudo supervisorctl reread && sudo supervisorctl update && sudo supervisorctl restart {self.app_name}",
            user=self.ssh_user,
        )
        log("uv app deployed!")
        return True

    def restart(self):
        """Restart supervisord app."""
        log(f"Restarting {self.app_name}...")
        ssh(self.ip, f"sudo supervisorctl restart {self.app_name}", user=self.ssh_user)
        log("App restarted")

    def status(self):
        """Show supervisord status."""
        return ssh(self.ip, "sudo supervisorctl status", user=self.ssh_user)

    def logs(self, lines: int = 50):
        """Show supervisord logs."""
        log(f"Last {lines} lines of {self.app_name} logs:")
        return ssh(
            self.ip,
            f"tail -n {lines} /var/log/{self.app_name}/access.log /var/log/{self.app_name}/error.log 2>/dev/null || echo 'No logs found'",
            user=self.ssh_user,
        )
