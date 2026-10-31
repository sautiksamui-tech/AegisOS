"""Secure Docker container launcher for AegisOS sandbox validation.

Strictly follows Section 7:
- Uses fixed argument template with argument array and shell=False.
- Accepts ONLY validated candidate workspace path, execution ID, fixed resource settings, fixed image identity.
- Explicitly rejects arbitrary docker flags, mounts, or socket injection.
- Candidate container NEVER receives /var/run/docker.sock, /run/docker.sock, \\.\\pipe\\docker_engine.
- Applies strict Linux container isolation:
  --network none
  --read-only root filesystem
  --cap-drop ALL
  --security-opt no-new-privileges
  --memory 1g
  --cpus 2.0
  --pids-limit 100
  --tmpfs /tmp:rw,noexec,nosuid,size=64m
"""

from pathlib import Path
import re
import subprocess
from typing import Any

FORBIDDEN_SOCKET_PATTERNS = [
    r"docker\.sock",
    r"docker_engine",
    r"docker\.pipe",
    r"/run/docker",
    r"/var/run/docker",
]

DEFAULT_IMAGE = "python:3.12-slim"


class SandboxSecurityViolation(Exception):
    """Raised when an attempt to bypass container sandbox or inject parameters is detected."""
    pass


def validate_workspace_path(path: Path) -> Path:
    resolved = path.resolve()
    if not resolved.exists() or not resolved.is_dir():
        raise SandboxSecurityViolation(f"Candidate workspace path does not exist or is not a directory: {path}")
    return resolved


def check_for_socket_injection(target_str: str) -> None:
    for pat in FORBIDDEN_SOCKET_PATTERNS:
        if re.search(pat, target_str, re.IGNORECASE):
            raise SandboxSecurityViolation(f"Docker socket injection attempt blocked: {target_str}")


class SecureDockerLauncher:
    def __init__(
        self,
        image_tag: str = DEFAULT_IMAGE,
        cpu_limit_millicores: int = 2000,
        memory_limit_bytes: int = 1073741824,
        pid_limit: int = 100,
    ):
        self.image_tag = image_tag
        self.cpu_limit_millicores = cpu_limit_millicores
        self.memory_limit_bytes = memory_limit_bytes
        self.pid_limit = pid_limit

    def build_container_args(
        self,
        candidate_workspace: Path,
        execution_id: str,
        control_file: Path | None = None,
        container_command: list[str] | None = None,
        custom_mount_attempt: str | None = None,
    ) -> list[str]:
        # 1. Launcher Injection Defense: reject any parameter attempting socket or arbitrary mount
        if custom_mount_attempt is not None:
            check_for_socket_injection(custom_mount_attempt)
            raise SandboxSecurityViolation(
                f"Launcher boundary rejection: arbitrary mounts are forbidden: {custom_mount_attempt}"
            )

        # 2. Validate workspace
        ws = validate_workspace_path(candidate_workspace)
        check_for_socket_injection(str(ws))

        # 3. Execution ID validation (alphanumeric and hyphens only)
        if not re.match(r"^[a-zA-Z0-9_\-]+$", execution_id):
            raise SandboxSecurityViolation(f"Invalid execution_id: {execution_id}")

        container_name = f"aegis_sandbox_{execution_id}"

        # 4. Construct fixed argument array
        # Format workspace host path for Docker on Windows
        ws_host_str = str(ws).replace("\\", "/")

        args = [
            "docker", "run",
            "--name", container_name,
            "--rm",
            "--network", "none",
            "--read-only",
            "--security-opt", "no-new-privileges",
            "--cap-drop", "ALL",
            f"--cpus={self.cpu_limit_millicores / 1000.0:.1f}",
            f"--memory={self.memory_limit_bytes}",
            f"--pids-limit={self.pid_limit}",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=64m",
            "-v", f"{ws_host_str}:/workspace:ro",
            "-w", "/workspace",
        ]

        # Explicit control file mount if provided
        if control_file is not None:
            ctrl = control_file.resolve()
            ctrl_str = str(ctrl).replace("\\", "/")
            check_for_socket_injection(ctrl_str)
            args.extend(["-v", f"{ctrl_str}:/workspace_control/control.txt:ro"])

        # Add fixed image identity
        args.append(self.image_tag)

        # Container command
        if container_command:
            args.extend(container_command)

        return args

    def run_container(
        self,
        candidate_workspace: Path,
        execution_id: str,
        control_file: Path | None = None,
        container_command: list[str] | None = None,
        timeout_seconds: int = 25,
    ) -> tuple[int, str]:
        args = self.build_container_args(
            candidate_workspace=candidate_workspace,
            execution_id=execution_id,
            control_file=control_file,
            container_command=container_command,
        )

        try:
            proc = subprocess.run(
                args,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                shell=False,
                timeout=timeout_seconds,
            )
            return proc.returncode, proc.stdout
        except subprocess.TimeoutExpired:
            # Cleanup container if needed
            subprocess.run(["docker", "rm", "-f", f"aegis_sandbox_{execution_id}"], shell=False, capture_output=True)
            return -1, f"Container execution timed out after {timeout_seconds} seconds"
        except Exception as e:
            return -1, str(e)
