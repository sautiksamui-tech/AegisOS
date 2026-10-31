"""Payment processing handler for AegisOS sample application.

RESTRICTION (Section 5):
Only the function `process_payment_attempt` may be modified by the remediation engine.
All other definitions, imports, signatures, decorators, and policies MUST remain identical.
"""

import time
from typing import Any, Callable
from demo.sample_app.exceptions import (
    PaymentProcessingError,
    PaymentValidationError,
    TransientProcessingError,
)
from aegisos.pool import InstrumentedConnectionPool, Connection, PoolAcquisitionTimeoutError


def simulate_payment_db_operation(
    conn: Connection,
    hold_duration_ms: int,
    inject_fault: bool,
) -> dict[str, Any]:
    """Simulates payment database work holding the connection."""
    # Hold connection for specified duration (e.g. 20 ms)
    time.sleep(hold_duration_ms / 1000.0)

    if inject_fault:
        raise TransientProcessingError("Injected transient processing error on payment attempt")

    return {
        "status": "success",
        "connection_id": conn.conn_id,
        "processed_at": time.monotonic(),
    }


def process_payment_attempt(
    pool: InstrumentedConnectionPool,
    remaining_deadline_ms: int,
    operation_fn: Callable[[Connection], dict[str, Any]],
) -> dict[str, Any]:
    """Processes a single payment attempt against the connection pool.
    
    NEGATIVE CONTROL IMPLEMENTATION:
    Attempts cleanup for PaymentValidationError, but leaves TransientProcessingError unhandled and leaking.
    """
    conn = pool.acquire(timeout_ms=remaining_deadline_ms)
    try:
        return operation_fn(conn)
    except PaymentValidationError:
        pool.release(conn)
        raise
    else:
        pool.release(conn)

def execute_payment_request(
    pool: InstrumentedConnectionPool,
    request_id: str,
    scheduled_arrival_ms: int,
    start_time_monotonic: float,
    deadline_ms: int = 2000,
    hold_duration_ms: int = 20,
    fault_plan_for_request: list[bool] | None = None,
    retry_limit: int = 3,
) -> dict[str, Any]:
    """Orchestrates retry policy and request execution.
    
    This function remains OUTSIDE process_payment_attempt and must never be modified by patches.
    """
    dispatch_time_ms = int((time.monotonic() - start_time_monotonic) * 1000)
    queue_delay_ms = max(0, dispatch_time_ms - scheduled_arrival_ms)

    if fault_plan_for_request is None:
        fault_plan_for_request = [False] * retry_limit

    attempts_made = 0
    last_error: Exception | None = None

    for attempt_idx in range(1, retry_limit + 1):
        # Calculate remaining deadline from scheduled arrival
        now_ms = int((time.monotonic() - start_time_monotonic) * 1000)
        remaining_ms = (scheduled_arrival_ms + deadline_ms) - now_ms

        if remaining_ms <= 0:
            return {
                "request_id": request_id,
                "scheduled_arrival_ms": scheduled_arrival_ms,
                "dispatch_time_ms": dispatch_time_ms,
                "queue_delay_ms": queue_delay_ms,
                "completed": False,
                "timed_out": True,
                "timeout_reason": "request_deadline_exceeded",
                "attempts": attempts_made,
                "error": "Request deadline exceeded before attempt",
                "latency_ms": 2000,
            }

        attempts_made += 1
        inject_fault = fault_plan_for_request[attempt_idx - 1] if attempt_idx - 1 < len(fault_plan_for_request) else False

        try:
            result = process_payment_attempt(
                pool=pool,
                remaining_deadline_ms=remaining_ms,
                operation_fn=lambda c: simulate_payment_db_operation(c, hold_duration_ms, inject_fault),
            )
            # Success!
            end_time_ms = int((time.monotonic() - start_time_monotonic) * 1000)
            latency_ms = max(0, end_time_ms - scheduled_arrival_ms)
            return {
                "request_id": request_id,
                "scheduled_arrival_ms": scheduled_arrival_ms,
                "dispatch_time_ms": dispatch_time_ms,
                "queue_delay_ms": queue_delay_ms,
                "completed": True,
                "timed_out": False,
                "timeout_reason": None,
                "attempts": attempts_made,
                "latency_ms": latency_ms,
                "result": result,
            }
        except PoolAcquisitionTimeoutError as e:
            # Pool timeout
            end_time_ms = int((time.monotonic() - start_time_monotonic) * 1000)
            return {
                "request_id": request_id,
                "scheduled_arrival_ms": scheduled_arrival_ms,
                "dispatch_time_ms": dispatch_time_ms,
                "queue_delay_ms": queue_delay_ms,
                "completed": False,
                "timed_out": True,
                "timeout_reason": "pool_acquisition_timeout",
                "attempts": attempts_made,
                "error": str(e),
                "latency_ms": 2000,
            }
        except TransientProcessingError as e:
            last_error = e
            # Retry if attempts remain and deadline not expired
            continue
        except Exception as e:
            last_error = e
            break

    # Terminal failure (all attempts exhausted without success)
    end_time_ms = int((time.monotonic() - start_time_monotonic) * 1000)
    latency_ms = min(2000, max(0, end_time_ms - scheduled_arrival_ms))
    return {
        "request_id": request_id,
        "scheduled_arrival_ms": scheduled_arrival_ms,
        "dispatch_time_ms": dispatch_time_ms,
        "queue_delay_ms": queue_delay_ms,
        "completed": False,
        "timed_out": False,
        "timeout_reason": None,
        "attempts": attempts_made,
        "error": str(last_error) if last_error else "All attempts failed",
        "latency_ms": latency_ms,
    }
