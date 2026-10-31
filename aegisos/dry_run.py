"""Stage 2: 4-Condition Dry-Run Gate for AegisOS.

Verifies:
1. Healthy:
   - Zero pool_wait_events
   - Zero pool_acquisition_timeouts
   - Error rate <= 1.0% (<= 10 per mille)
2. Vulnerable:
   - At least 1 pool_wait_event
   - Error rate > 1.0% (> 10 per mille)
   - Connection leaks detected
3. Patched:
   - Zero pool_wait_events
   - Zero pool_acquisition_timeouts
   - Error rate <= 1.0% (<= 10 per mille)
4. Negative Control:
   - At least 1 connection leak
   - Fails error rate / performance checks
"""

import importlib
import json
from pathlib import Path
import sys
from typing import Any
from aegisos.benchmark import run_benchmark_session
from aegisos.remediation.patch_manager import apply_implementation, get_current_condition
import demo.sample_app.payment_handler as payment_handler


def run_dry_run_condition(condition_name: str) -> dict[str, Any]:
    print(f"\n[DRY RUN] Switching implementation to: {condition_name}")
    apply_implementation(condition_name)
    importlib.reload(payment_handler)

    print(f"[DRY RUN] Running dry run (30 warmup + 300 measured requests)...")
    res = run_benchmark_session(rounds=1)
    measured = res["rounds"][0]

    pool = measured["pool_metrics"]
    print(f"[{condition_name}] Completed: {measured['completed_requests']}/{measured['total_requests']}")
    print(f"[{condition_name}] Error rate: {measured['error_rate']*100:.2f}% ({measured['error_rate_per_mille']} per-mille)")
    print(f"[{condition_name}] P95 Latency: {measured['p95_latency_ms']} ms | Throughput: {measured['throughput_req_per_sec']} req/s")
    print(f"[{condition_name}] Pool Wait Events: {pool['pool_wait_events']} | Timeouts: {pool['pool_acquisition_timeouts']} | Leaks: {pool['connection_leaks']}")

    # Validation criteria according to Section 6
    validation = {
        "condition": condition_name,
        "passed": False,
        "criteria": {},
    }

    if condition_name == "healthy":
        c1 = pool["pool_wait_events"] == 0
        c2 = pool["pool_acquisition_timeouts"] == 0
        c3 = measured["error_rate_per_mille"] <= 10  # <= 1.0%
        c4 = measured["total_requests"] == 300
        validation["criteria"] = {
            "zero_pool_wait_events": c1,
            "zero_pool_acquisition_timeouts": c2,
            "error_rate_le_1pct": c3,
            "complete_measurements": c4,
        }
        validation["passed"] = all([c1, c2, c3, c4])

    elif condition_name == "vulnerable":
        c1 = pool["pool_wait_events"] >= 1
        c2 = measured["error_rate_per_mille"] > 10  # > 1.0%
        c3 = pool["connection_leaks"] >= 1
        validation["criteria"] = {
            "has_pool_wait_events": c1,
            "error_rate_gt_1pct": c2,
            "connection_leaks_detected": c3,
        }
        validation["passed"] = all([c1, c2, c3])

    elif condition_name == "patched":
        c1 = pool["pool_wait_events"] == 0
        c2 = pool["pool_acquisition_timeouts"] == 0
        c3 = measured["error_rate_per_mille"] <= 10  # <= 1.0%
        c4 = pool["connection_leaks"] == 0
        validation["criteria"] = {
            "zero_pool_wait_events": c1,
            "zero_pool_acquisition_timeouts": c2,
            "error_rate_le_1pct": c3,
            "zero_connection_leaks": c4,
        }
        validation["passed"] = all([c1, c2, c3, c4])

    elif condition_name == "negative_control":
        c1 = pool["connection_leaks"] >= 1
        c2 = (pool["pool_wait_events"] >= 1) or (measured["error_rate_per_mille"] > 10)
        validation["criteria"] = {
            "connection_leaks_detected": c1,
            "lifecycle_or_performance_failure": c2,
        }
        validation["passed"] = all([c1, c2])

    return {
        "condition": condition_name,
        "benchmark_summary": {
            "total_requests": measured["total_requests"],
            "completed_requests": measured["completed_requests"],
            "failed_requests": measured["failed_requests"],
            "timed_out_requests": measured["timed_out_requests"],
            "error_rate": measured["error_rate"],
            "error_rate_per_mille": measured["error_rate_per_mille"],
            "wall_clock_duration_seconds": measured["wall_clock_duration_seconds"],
            "throughput_req_per_sec": measured["throughput_req_per_sec"],
            "p95_latency_ms": measured["p95_latency_ms"],
            "pool_metrics": pool,
        },
        "validation": validation,
        "raw_round": measured,
    }


def run_all_dry_runs() -> dict[str, Any]:
    print("==================================================")
    print("STARTING AEGISOS 4-CONDITION DRY-RUN GATE")
    print("==================================================")
    results = {}
    for cond in ["healthy", "vulnerable", "patched", "negative_control"]:
        results[cond] = run_dry_run_condition(cond)

    all_passed = all(r["validation"]["passed"] for r in results.values())
    summary = {
        "gate_passed": all_passed,
        "healthy_passed": results["healthy"]["validation"]["passed"],
        "vulnerable_passed": results["vulnerable"]["validation"]["passed"],
        "patched_passed": results["patched"]["validation"]["passed"],
        "negative_control_passed": results["negative_control"]["validation"]["passed"],
        "results": results,
    }

    # Reset implementation to vulnerable as baseline
    apply_implementation("vulnerable")

    print("\n==================================================")
    print(f"DRY-RUN GATE OVERALL STATUS: {'PASSED' if all_passed else 'FAILED'}")
    print("==================================================")
    return summary


if __name__ == "__main__":
    out = run_all_dry_runs()
    Path("runs/dry_run_summary.json").write_text(json.dumps(out, indent=2), encoding="utf-8")
