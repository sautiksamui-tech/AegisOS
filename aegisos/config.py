"""Canonical experiment configuration for AegisOS benchmark and validation.

Strictly follows Section 4 of the AegisOS specification:
- Exact categories: Experiment definition, Workload identity, Fixed execution environment.
- Explicit exclusions: Hostname, timestamp, run/attempt ID, PIDs, host paths, host CPU/RAM, measured latency/throughput.
- Integer-only probabilities and numeric parameters (rejects floats).
- Canonical serialization: json.dumps(configuration, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
- SHA-256 hash computation.
"""

import hashlib
import json
from typing import Any
from aegisos.workload import get_deterministic_plans, serialize_canonical, compute_sha256


# Frozen Benchmark Parameters (Section 1)
SCHEMA_VERSION: str = "1.0.0"
RANDOM_SEED: int = 20261031
ARRIVAL_MODE: str = "open_loop"
ARRIVAL_INTERVAL_MS: int = 10
REQUEST_COUNT: int = 300
CONCURRENCY_LIMIT: int = 20
END_TO_END_DEADLINE_MS: int = 2000
POOL_SIZE: int = 5
CONNECTION_HOLD_DURATION_MS: int = 20
EXCEPTION_PROBABILITY_PER_MILLE: int = 100  # 10%
MAX_ATTEMPTS_PER_REQUEST: int = 3
WARMUP_COUNT: int = 30
MEASUREMENT_COUNT: int = 300
MAIN_MEASURED_ROUNDS: int = 3
RUN_LEVEL_SAFETY_CAP_SECONDS: int = 30

# Acceptance Thresholds (all integers)
ACCEPTANCE_THRESHOLDS = {
    "error_rate_max_per_mille": 10,  # Max 1.0% error rate
    "latency_p95_max_ms": 2000,
    "throughput_min_req_per_sec": 80,
    "max_pool_wait_events": 0,
    "max_pool_acquisition_timeouts": 0,
    "max_connection_leaks": 0,
}

# Fixed Execution Environment (Docker & Linux Container Isolation)
FIXED_EXECUTION_ENV = {
    "container_cpu_limit_millicores": 2000,
    "container_image_digest": "sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159",
    "container_memory_limit_bytes": 1073741824,  # 1 GiB
    "container_platform_and_architecture": "linux/amd64",
    "container_user_id": 1000,
    "docker_server_version": "29.8.0",
    "dropped_linux_capabilities": ["ALL"],
    "network_mode": "none",
    "no_new_privileges": True,
    "normalized_workspace_mount_destination": "/workspace",
    "pid_limit": 100,
    "python_runtime_version_inside_image": "3.12.13",
    "readonly_root_filesystem": True,
    "workspace_readonly": True,
    "writable_tmpfs_config": "/tmp:rw,noexec,nosuid,size=64m",
}


def build_canonical_configuration(
    seed: int = RANDOM_SEED,
    rounds: int = MAIN_MEASURED_ROUNDS,
) -> tuple[dict[str, Any], str]:
    """Constructs the canonical configuration dictionary and computes its SHA-256 hash.
    
    Rejects any floating point numbers.
    """
    plans = get_deterministic_plans(
        seed=seed,
        measurement_count=MEASUREMENT_COUNT,
        warmup_count=WARMUP_COUNT,
        interval_ms=ARRIVAL_INTERVAL_MS,
        max_attempts=MAX_ATTEMPTS_PER_REQUEST,
        prob_per_mille=EXCEPTION_PROBABILITY_PER_MILLE,
    )

    configuration = {
        "experiment_definition": {
            "acceptance_thresholds": ACCEPTANCE_THRESHOLDS,
            "arrival_interval_ms": ARRIVAL_INTERVAL_MS,
            "arrival_mode": ARRIVAL_MODE,
            "concurrency_limit": CONCURRENCY_LIMIT,
            "connection_hold_duration_ms": CONNECTION_HOLD_DURATION_MS,
            "end_to_end_deadline_ms": END_TO_END_DEADLINE_MS,
            "exception_probability_per_mille": EXCEPTION_PROBABILITY_PER_MILLE,
            "measurement_count": MEASUREMENT_COUNT,
            "number_of_rounds": rounds,
            "pool_size": POOL_SIZE,
            "random_seed": seed,
            "request_count": REQUEST_COUNT,
            "retry_limit": MAX_ATTEMPTS_PER_REQUEST,
            "run_level_safety_cap_seconds": RUN_LEVEL_SAFETY_CAP_SECONDS,
            "schema_version": SCHEMA_VERSION,
            "warmup_count": WARMUP_COUNT,
        },
        "fixed_execution_environment": FIXED_EXECUTION_ENV,
        "workload_identity": {
            "fault_injection_plan_sha256": plans["fault_plan_sha256"],
            "workload_schedule_sha256": plans["schedule_sha256"],
        },
    }

    # Verify no floats and serialize
    canonical_json_str = serialize_canonical(configuration)
    config_hash = compute_sha256(canonical_json_str)

    return configuration, config_hash


if __name__ == "__main__":
    cfg, cfg_hash = build_canonical_configuration()
    print("Configuration Hash:", cfg_hash)
    print("Canonical Config JSON length:", len(json.dumps(cfg)))
