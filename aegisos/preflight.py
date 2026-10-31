"""Stage 0: Environment Preflight Verification for AegisOS.

Checks:
- Windows OS
- PowerShell
- Python 3.12
- Node.js
- Git
- WSL 2
- Docker Linux containers
- Memory
- Ports 2375 and 2376 (ensuring no plaintext Docker daemon exposed)
- Workspace path
"""

import json
import os
import platform
import socket
import subprocess
import sys
from pathlib import Path


def check_port_listener(port: int, host: str = "127.0.0.1") -> bool:
    """Returns True if a listener is accepting connections on host:port, False otherwise."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        result = s.connect_ex((host, port))
        return result == 0


def run_cmd(cmd: list[str]) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            shell=False,
            timeout=10,
        )
        return proc.returncode, proc.stdout.strip()
    except Exception as e:
        return -1, str(e)


def run_preflight(workspace_dir: Path | None = None) -> dict:
    if workspace_dir is None:
        workspace_dir = Path.cwd().resolve()

    results = {
        "stage": "stage_0_preflight",
        "passed": False,
        "checks": {},
        "normalized_workspace": "/workspace",
        "host_workspace": str(workspace_dir).replace("\\", "/"),
    }

    # 1. OS check
    is_windows = platform.system().lower() == "windows"
    results["checks"]["os"] = {
        "expected": "Windows",
        "actual": platform.system(),
        "release": platform.release(),
        "version": platform.version(),
        "passed": is_windows,
    }

    # 2. PowerShell check
    ps_code, ps_out = run_cmd(["powershell.exe", "-NoProfile", "-Command", "$PSVersionTable.PSVersion.ToString()"])
    results["checks"]["powershell"] = {
        "version": ps_out if ps_code == 0 else "unavailable",
        "passed": ps_code == 0,
    }

    # 3. Python check (Host & Runtime)
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    is_py312 = sys.version_info.major == 3 and sys.version_info.minor == 12
    results["checks"]["python_host"] = {
        "version": py_ver,
        "executable": sys.executable,
        "is_312": is_py312,
        "passed": is_py312,
    }

    # 4. Node.js check
    node_code, node_out = run_cmd(["node", "--version"])
    results["checks"]["node"] = {
        "version": node_out if node_code == 0 else "unavailable",
        "passed": node_code == 0,
    }

    # 5. Git check
    git_code, git_out = run_cmd(["git", "--version"])
    results["checks"]["git"] = {
        "version": git_out if git_code == 0 else "unavailable",
        "passed": git_code == 0,
    }

    # 6. Docker Server & Linux Containers check
    docker_code, docker_info_out = run_cmd(["docker", "info", "--format", "{{json .}}"])
    docker_ok = False
    docker_details = {}
    if docker_code == 0:
        try:
            d_json = json.loads(docker_info_out)
            docker_ok = (d_json.get("OSType") == "linux")
            docker_details = {
                "server_version": d_json.get("ServerVersion", "unknown"),
                "ostype": d_json.get("OSType", "unknown"),
                "architecture": d_json.get("Architecture", "unknown"),
                "total_memory_bytes": d_json.get("MemTotal", d_json.get("TotalMemory", 0)),
                "kernel_version": d_json.get("KernelVersion", ""),
                "cpus": d_json.get("NCPU", 0),
            }
        except Exception as e:
            docker_details = {"error": str(e), "raw": docker_info_out[:200]}
    else:
        # Fallback to plain docker version
        v_code, v_out = run_cmd(["docker", "--version"])
        docker_details = {"raw": v_out, "code": docker_code}

    results["checks"]["docker"] = {
        "linux_containers": docker_ok,
        "details": docker_details,
        "passed": docker_ok,
    }

    # 7. WSL 2 check
    # From docker details, kernel version contains WSL2
    kernel_str = docker_details.get("kernel_version", "").lower()
    is_wsl2 = "wsl" in kernel_str or "microsoft" in kernel_str
    results["checks"]["wsl2"] = {
        "kernel": docker_details.get("kernel_version", "unknown"),
        "detected": is_wsl2,
        "passed": is_wsl2,
    }

    # 8. Memory check
    mem_bytes = docker_details.get("total_memory_bytes", 0)
    has_sufficient_mem = mem_bytes >= (4 * 1024 * 1024 * 1024)  # at least 4 GiB
    results["checks"]["memory"] = {
        "docker_memory_bytes": mem_bytes,
        "docker_memory_gib": round(mem_bytes / (1024**3), 2) if mem_bytes else 0,
        "passed": has_sufficient_mem,
    }

    # 9. Port 2375 and 2376 security check (Docker unencrypted daemon)
    port_2375_open = check_port_listener(2375)
    port_2376_open = check_port_listener(2376)
    ports_secure = (not port_2375_open) and (not port_2376_open)
    results["checks"]["docker_daemon_ports"] = {
        "port_2375_listener": port_2375_open,
        "port_2376_listener": port_2376_open,
        "secure": ports_secure,
        "passed": ports_secure,
    }

    # 10. Workspace check
    workspace_exists = workspace_dir.exists() and workspace_dir.is_dir()
    results["checks"]["workspace"] = {
        "path": str(workspace_dir),
        "exists": workspace_exists,
        "passed": workspace_exists,
    }

    all_passed = (
        results["checks"]["os"]["passed"]
        and results["checks"]["powershell"]["passed"]
        and results["checks"]["python_host"]["passed"]
        and results["checks"]["node"]["passed"]
        and results["checks"]["git"]["passed"]
        and results["checks"]["docker"]["passed"]
        and results["checks"]["wsl2"]["passed"]
        and results["checks"]["memory"]["passed"]
        and results["checks"]["docker_daemon_ports"]["passed"]
        and results["checks"]["workspace"]["passed"]
    )
    results["passed"] = all_passed
    return results


if __name__ == "__main__":
    res = run_preflight()
    print(json.dumps(res, indent=2))
    if not res["passed"]:
        sys.exit(1)
