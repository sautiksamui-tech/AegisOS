"""Patch management and implementation switching for AegisOS benchmark conditions.

Manages the four conditions:
1. Healthy
2. Vulnerable
3. Patched
4. Negative control
"""

from pathlib import Path
from aegisos.remediation.ast_checker import verify_patch_integrity

PAYMENT_HANDLER_PATH = Path("demo/sample_app/payment_handler.py")

# The exact implementations of process_payment_attempt for the 4 conditions:

FN_VULNERABLE = '''def process_payment_attempt(
    pool: InstrumentedConnectionPool,
    remaining_deadline_ms: int,
    operation_fn: Callable[[Connection], dict[str, Any]],
) -> dict[str, Any]:
    """Processes a single payment attempt against the connection pool.
    
    BASELINE (Vulnerable Implementation):
    Acquires a connection and executes the operation.
    Releases connection on normal completion, but leaks connection if operation_fn raises an exception!
    """
    conn = pool.acquire(timeout_ms=remaining_deadline_ms)
    result = operation_fn(conn)
    pool.release(conn)
    return result'''

FN_HEALTHY = '''def process_payment_attempt(
    pool: InstrumentedConnectionPool,
    remaining_deadline_ms: int,
    operation_fn: Callable[[Connection], dict[str, Any]],
) -> dict[str, Any]:
    """Processes a single payment attempt against the connection pool.
    
    HEALTHY IMPLEMENTATION:
    Guaranteed release using try...finally block.
    """
    conn = pool.acquire(timeout_ms=remaining_deadline_ms)
    try:
        return operation_fn(conn)
    finally:
        pool.release(conn)'''

FN_PATCHED = '''def process_payment_attempt(
    pool: InstrumentedConnectionPool,
    remaining_deadline_ms: int,
    operation_fn: Callable[[Connection], dict[str, Any]],
) -> dict[str, Any]:
    """Processes a single payment attempt against the connection pool.
    
    CORRECTLY PATCHED IMPLEMENTATION:
    Guaranteed cleanup in finally block ensuring connection is released on both success and failure.
    """
    conn = pool.acquire(timeout_ms=remaining_deadline_ms)
    try:
        return operation_fn(conn)
    finally:
        pool.release(conn)'''

FN_NEGATIVE_CONTROL = '''def process_payment_attempt(
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
        pool.release(conn)'''

IMPLEMENTATIONS = {
    "vulnerable": FN_VULNERABLE,
    "healthy": FN_HEALTHY,
    "patched": FN_PATCHED,
    "negative_control": FN_NEGATIVE_CONTROL,
}


def apply_implementation(condition: str, file_path: Path = PAYMENT_HANDLER_PATH) -> str:
    """Replaces process_payment_attempt in payment_handler.py with the specified condition's implementation."""
    if condition not in IMPLEMENTATIONS:
        raise ValueError(f"Unknown condition: {condition}. Must be one of {list(IMPLEMENTATIONS.keys())}")

    content = file_path.read_text(encoding="utf-8")
    fn_replacement = IMPLEMENTATIONS[condition]

    # Find start and end of def process_payment_attempt
    target_start = content.find("def process_payment_attempt(")
    if target_start == -1:
        raise ValueError("Could not find 'def process_payment_attempt(' in target file.")

    # Find the start of the next top-level function `def execute_payment_request`
    target_end = content.find("\ndef execute_payment_request(")
    if target_end == -1:
        raise ValueError("Could not find 'def execute_payment_request(' in target file.")

    new_content = content[:target_start] + fn_replacement + "\n\n" + content[target_end + 1:]
    file_path.write_text(new_content, encoding="utf-8")
    return new_content


def get_current_condition(file_path: Path = PAYMENT_HANDLER_PATH) -> str:
    content = file_path.read_text(encoding="utf-8")
    if "NEGATIVE CONTROL IMPLEMENTATION" in content:
        return "negative_control"
    if "CORRECTLY PATCHED IMPLEMENTATION" in content:
        return "patched"
    if "HEALTHY IMPLEMENTATION" in content:
        return "healthy"
    return "vulnerable"
