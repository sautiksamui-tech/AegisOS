"""Deterministic open-loop workload schedule and fault injection plan generator for AegisOS.

Parameters:
- Random seed: 20261031
- Warmup requests: 30
- Measurement requests: 300
- Arrival interval: 10 ms
- Exception probability: 100 per 1,000 (10%)
- Max attempts per request: 3
"""

import hashlib
import json
import random
from typing import Any


def generate_workload_schedule(
    request_count: int = 300,
    interval_ms: int = 10,
) -> list[dict[str, int]]:
    """Generates open-loop scheduled arrival times: 0, 10, 20, ... (count-1)*interval ms."""
    return [
        {
            "request_index": i,
            "scheduled_arrival_ms": i * interval_ms,
        }
        for i in range(request_count)
    ]


def generate_fault_injection_plan(
    seed: int = 20261031,
    request_count: int = 300,
    max_attempts: int = 3,
    prob_per_mille: int = 100,
) -> dict[str, list[bool]]:
    """Generates a deterministic fault plan per request and attempt.
    
    True indicates an injected TransientProcessingError on that attempt.
    """
    rng = random.Random(seed)
    plan: dict[str, list[bool]] = {}
    for i in range(request_count):
        # Generate decision for attempts 1, 2, 3
        attempts = []
        for _ in range(max_attempts):
            # 100 in 1,000 chance
            val = rng.randint(1, 1000)
            attempts.append(val <= prob_per_mille)
        plan[str(i)] = attempts
    return plan


def serialize_canonical(obj: Any) -> str:
    """Serializes canonical object ensuring sort_keys, compact separators, no floats."""
    def check_no_floats(item: Any):
        if isinstance(item, float):
            raise TypeError(f"Floating-point value forbidden in canonical config/plan: {item}")
        if isinstance(item, dict):
            for k, v in item.items():
                check_no_floats(v)
        elif isinstance(item, (list, tuple)):
            for v in item:
                check_no_floats(v)

    check_no_floats(obj)
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def compute_sha256(canonical_str: str) -> str:
    return hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()


def get_deterministic_plans(
    seed: int = 20261031,
    measurement_count: int = 300,
    warmup_count: int = 30,
    interval_ms: int = 10,
    max_attempts: int = 3,
    prob_per_mille: int = 100,
) -> dict[str, Any]:
    # Workload schedule for measurement
    measured_schedule = generate_workload_schedule(measurement_count, interval_ms)
    schedule_canonical = serialize_canonical(measured_schedule)
    schedule_hash = compute_sha256(schedule_canonical)

    # Fault injection plan for measurement
    # Dedicated seeded generator for measurement
    measured_faults = generate_fault_injection_plan(seed, measurement_count, max_attempts, prob_per_mille)
    fault_canonical = serialize_canonical(measured_faults)
    fault_hash = compute_sha256(fault_canonical)

    # Warmup plans (using distinct seed or sequence)
    warmup_schedule = generate_workload_schedule(warmup_count, interval_ms)
    warmup_rng_seed = (seed + 999999) % (2**31)
    warmup_faults = generate_fault_injection_plan(warmup_rng_seed, warmup_count, max_attempts, prob_per_mille)

    return {
        "measured_schedule": measured_schedule,
        "schedule_sha256": schedule_hash,
        "measured_faults": measured_faults,
        "fault_plan_sha256": fault_hash,
        "warmup_schedule": warmup_schedule,
        "warmup_faults": warmup_faults,
    }


if __name__ == "__main__":
    plans = get_deterministic_plans()
    print("Schedule SHA-256:", plans["schedule_sha256"])
    print("Fault Plan SHA-256:", plans["fault_plan_sha256"])
    # Count expected faults in measurement
    fault_count = sum(sum(attempts) for attempts in plans["measured_faults"].values())
    print(f"Total potential faults planned across 300x3 attempts: {fault_count}")
