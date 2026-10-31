"""Open-loop workload generator and benchmark execution engine for AegisOS.

Strictly follows Section 1, 2, 3, and 6:
- 300 scheduled arrivals: 0 ms, 10 ms, ... 2990 ms (100 req/s, open-loop)
- 30 warm-up requests
- Maximum 20 actively dispatched requests
- Absolute deadline: scheduled_arrival_ms + 2000 ms (timeout origin at arrival)
- Queueing time counts toward deadline; queue delays tracked
- Timeout contributes exactly 2000 ms to latency distribution
- Nearest-rank p95 latency: x_{ceil(0.95 * n)}
- 30-second safety cap
- Precise pool metrics (wait events, acquisition timeouts, connection leaks)
"""

import concurrent.futures
import importlib
import math
import queue
import sys
import threading
import time
from typing import Any, Callable

from aegisos.pool import InstrumentedConnectionPool
from aegisos.workload import get_deterministic_plans
import demo.sample_app.payment_handler as payment_handler


class BenchmarkRun:
    def __init__(
        self,
        pool_size: int = 5,
        concurrency_limit: int = 20,
        arrival_interval_ms: int = 10,
        end_to_end_deadline_ms: int = 2000,
        connection_hold_duration_ms: int = 20,
        run_level_safety_cap_seconds: int = 30,
        retry_limit: int = 3,
    ):
        self.pool_size = pool_size
        self.concurrency_limit = concurrency_limit
        self.arrival_interval_ms = arrival_interval_ms
        self.end_to_end_deadline_ms = end_to_end_deadline_ms
        self.connection_hold_duration_ms = connection_hold_duration_ms
        self.safety_cap_seconds = run_level_safety_cap_seconds
        self.retry_limit = retry_limit

    def execute_workload(
        self,
        schedule: list[dict[str, int]],
        fault_plan: dict[str, list[bool]],
        is_warmup: bool = False,
    ) -> dict[str, Any]:
        """Executes an open-loop scheduled workload."""
        pool = InstrumentedConnectionPool(pool_size=self.pool_size)
        total_requests = len(schedule)
        results: list[dict[str, Any]] = [{} for _ in range(total_requests)]
        results_lock = threading.Lock()
        completed_event = threading.Event()
        remaining_count = total_requests

        request_queue: queue.Queue[dict[str, Any]] = queue.Queue()
        stop_workers = threading.Event()

        start_time = time.monotonic()

        def worker_loop():
            while not stop_workers.is_set():
                try:
                    item = request_queue.get(timeout=0.05)
                except queue.Empty:
                    continue

                req_idx = item["request_index"]
                sched_ms = item["scheduled_arrival_ms"]
                faults = item["faults"]

                # Current time check against absolute deadline
                now_ms = int((time.monotonic() - start_time) * 1000)
                deadline_ms = sched_ms + self.end_to_end_deadline_ms

                if now_ms >= deadline_ms:
                    # Request expired in queue before dispatch
                    res = {
                        "request_index": req_idx,
                        "request_id": f"req_{req_idx}",
                        "scheduled_arrival_ms": sched_ms,
                        "dispatch_time_ms": now_ms,
                        "queue_delay_ms": max(0, now_ms - sched_ms),
                        "completed": False,
                        "timed_out": True,
                        "timeout_reason": "queue_deadline_exceeded",
                        "attempts": 0,
                        "error": "Request timed out waiting in queue",
                        "latency_ms": 2000,
                    }
                else:
                    # Dispatch to execute
                    res = payment_handler.execute_payment_request(
                        pool=pool,
                        request_id=f"req_{req_idx}",
                        scheduled_arrival_ms=sched_ms,
                        start_time_monotonic=start_time,
                        deadline_ms=self.end_to_end_deadline_ms,
                        hold_duration_ms=self.connection_hold_duration_ms,
                        fault_plan_for_request=faults,
                        retry_limit=self.retry_limit,
                    )
                    res["request_index"] = req_idx

                with results_lock:
                    results[req_idx] = res
                    nonlocal remaining_count
                    remaining_count -= 1
                    if remaining_count == 0:
                        completed_event.set()

                request_queue.task_done()

        # Start worker threads up to concurrency limit
        workers = [
            threading.Thread(target=worker_loop, daemon=True)
            for _ in range(self.concurrency_limit)
        ]
        for w in workers:
            w.start()

        # Open-loop arrival dispatcher
        # Spawns requests according to exact scheduled arrival times
        def dispatcher():
            for item in schedule:
                req_idx = item["request_index"]
                sched_ms = item["scheduled_arrival_ms"]
                faults = fault_plan.get(str(req_idx), [False] * self.retry_limit)

                # Wait until scheduled arrival time
                target_monotonic = start_time + (sched_ms / 1000.0)
                now = time.monotonic()
                delay = target_monotonic - now
                if delay > 0:
                    time.sleep(delay)

                # Enqueue scheduled arrival
                request_queue.put({
                    "request_index": req_idx,
                    "scheduled_arrival_ms": sched_ms,
                    "faults": faults,
                })

        dispatcher_thread = threading.Thread(target=dispatcher, daemon=True)
        dispatcher_thread.start()

        # Wait for all requests to become terminal OR global safety cap
        completed_in_time = completed_event.wait(timeout=self.safety_cap_seconds)
        end_time = time.monotonic()
        wall_clock_duration = max(0.001, end_time - start_time)

        stop_workers.set()

        # Handle any incomplete requests if safety cap reached
        with results_lock:
            for i in range(total_requests):
                if not results[i]:
                    sched_ms = schedule[i]["scheduled_arrival_ms"]
                    results[i] = {
                        "request_index": i,
                        "request_id": f"req_{i}",
                        "scheduled_arrival_ms": sched_ms,
                        "dispatch_time_ms": int((end_time - start_time) * 1000),
                        "queue_delay_ms": max(0, int((end_time - start_time) * 1000) - sched_ms),
                        "completed": False,
                        "timed_out": True,
                        "timeout_reason": "global_run_cap",
                        "attempts": 0,
                        "error": "Benchmark reached global safety cap (30s)",
                        "latency_ms": 2000,
                    }

        # Metrics computation
        completed_requests = sum(1 for r in results if r.get("completed", False))
        timed_out_requests = sum(1 for r in results if r.get("timed_out", False))
        failed_requests = total_requests - completed_requests
        error_rate = failed_requests / total_requests

        # Latencies & nearest-rank p95
        latencies = [int(r["latency_ms"]) for r in results]
        sorted_latencies = sorted(latencies)
        # Nearest-rank p95 = x_{\lceil 0.95 * n \rceil}
        p95_rank = math.ceil(0.95 * total_requests)
        p95_latency = sorted_latencies[p95_rank - 1]

        throughput = completed_requests / wall_clock_duration
        pool_metrics = pool.get_metrics()

        return {
            "is_warmup": is_warmup,
            "total_requests": total_requests,
            "completed_requests": completed_requests,
            "failed_requests": failed_requests,
            "timed_out_requests": timed_out_requests,
            "error_rate": round(error_rate, 4),
            "error_rate_per_mille": int(round(error_rate * 1000)),
            "wall_clock_duration_seconds": round(wall_clock_duration, 4),
            "throughput_req_per_sec": round(throughput, 2),
            "p95_latency_ms": p95_latency,
            "min_latency_ms": sorted_latencies[0],
            "max_latency_ms": sorted_latencies[-1],
            "pool_metrics": pool_metrics,
            "requests": results,
        }


def run_benchmark_session(
    seed: int = 20261031,
    rounds: int = 1,  # 1 for dry run, 3 for main measured rounds
) -> dict[str, Any]:
    """Runs warmup followed by measured rounds."""
    plans = get_deterministic_plans(seed=seed)
    runner = BenchmarkRun()

    # 1. Warm-up run (30 requests)
    warmup_res = runner.execute_workload(
        schedule=plans["warmup_schedule"],
        fault_plan=plans["warmup_faults"],
        is_warmup=True,
    )

    # 2. Main measured rounds
    round_results = []
    for r in range(rounds):
        res = runner.execute_workload(
            schedule=plans["measured_schedule"],
            fault_plan=plans["measured_faults"],
            is_warmup=False,
        )
        res["round_index"] = r + 1
        round_results.append(res)

    return {
        "warmup": warmup_res,
        "rounds": round_results,
    }
