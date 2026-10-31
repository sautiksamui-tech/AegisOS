"""Database Connection Pool with precise instrumentation for AegisOS.

Strictly follows Section 3 of the AegisOS specification:
- Fixed pool size: 5 connections.
- Tracks:
  - checkout_attempts
  - successful_checkouts
  - successful_checkins
  - current_checked_out
  - peak_checked_out
  - pool_wait_events
  - pool_acquisition_timeouts
  - connection_leaks
- Defines pool_wait_event:
  A checkout attempt cannot receive a connection immediately because all 5 connections
  are already checked out and must wait.
- Bounded acquisition timeout based on remaining request deadline.
"""

import threading
import time
from typing import Any, Optional


class PoolAcquisitionTimeoutError(Exception):
    """Raised when connection cannot be acquired within the remaining deadline."""
    pass


class Connection:
    """Simulated database connection object."""
    def __init__(self, conn_id: int):
        self.conn_id = conn_id
        self.acquired_at: float = 0.0
        self.request_id: Optional[str] = None
        self.attempt: int = 1
        self.is_checked_out: bool = False

    def __repr__(self) -> str:
        return f"<Connection id={self.conn_id} checked_out={self.is_checked_out}>"


class InstrumentedConnectionPool:
    """Thread-safe connection pool with strict metrics tracking according to AegisOS Section 3."""

    def __init__(self, pool_size: int = 5):
        self.pool_size = pool_size
        self._lock = threading.Lock()
        self._cond = threading.Condition(self._lock)
        self._available_connections: list[Connection] = [Connection(i) for i in range(pool_size)]
        self._all_connections: list[Connection] = list(self._available_connections)

        # Metrics required by Section 3
        self.checkout_attempts: int = 0
        self.successful_checkouts: int = 0
        self.successful_checkins: int = 0
        self.current_checked_out: int = 0
        self.peak_checked_out: int = 0
        self.pool_wait_events: int = 0
        self.pool_acquisition_timeouts: int = 0
        self.connection_leaks: int = 0

    def acquire(
        self,
        timeout_ms: int = 2000,
        request_id: Optional[str] = None,
        attempt: int = 1,
    ) -> Connection:
        """Acquires a connection from the pool.
        
        If no connection is immediately available, records a pool_wait_event and waits up to timeout_ms.
        Raises PoolAcquisitionTimeoutError if acquisition deadline expires.
        """
        start_time = time.monotonic()
        timeout_sec = max(0.0, timeout_ms / 1000.0)

        with self._cond:
            self.checkout_attempts += 1

            # Check if all connections are currently checked out
            if len(self._available_connections) == 0:
                self.pool_wait_events += 1

            # Wait while pool is exhausted and timeout hasn't elapsed
            while len(self._available_connections) == 0:
                elapsed = time.monotonic() - start_time
                remaining = timeout_sec - elapsed
                if remaining <= 0:
                    self.pool_acquisition_timeouts += 1
                    raise PoolAcquisitionTimeoutError(
                        f"Pool exhausted: failed to acquire connection within {timeout_ms} ms (remaining: {remaining:.3f}s)"
                    )
                self._cond.wait(timeout=remaining)

            # Connection is available!
            conn = self._available_connections.pop()
            conn.is_checked_out = True
            conn.acquired_at = time.monotonic()
            conn.request_id = request_id
            conn.attempt = attempt

            self.successful_checkouts += 1
            self.current_checked_out = len(self._all_connections) - len(self._available_connections)
            if self.current_checked_out > self.peak_checked_out:
                self.peak_checked_out = self.current_checked_out

            return conn

    def release(self, conn: Connection) -> None:
        """Returns a connection to the pool."""
        with self._cond:
            if not conn.is_checked_out:
                # Double release guard
                return
            conn.is_checked_out = False
            conn.request_id = None
            self._available_connections.append(conn)
            self.successful_checkins += 1
            self.current_checked_out = len(self._all_connections) - len(self._available_connections)
            self._cond.notify()

    def record_leak(self, count: int = 1) -> None:
        with self._lock:
            self.connection_leaks += count

    def get_metrics(self) -> dict[str, int | bool]:
        """Returns snapshot of connection pool metrics."""
        with self._lock:
            computed_leaks = max(0, self.successful_checkouts - self.successful_checkins)
            total_leaks = max(self.connection_leaks, computed_leaks)
            return {
                "checkout_attempts": self.checkout_attempts,
                "successful_checkouts": self.successful_checkouts,
                "successful_checkins": self.successful_checkins,
                "current_checked_out": self.current_checked_out,
                "peak_checked_out": self.peak_checked_out,
                "pool_wait_events": self.pool_wait_events,
                "pool_acquisition_timeouts": self.pool_acquisition_timeouts,
                "connection_leaks": total_leaks,
                "pool_exhausted": self.pool_wait_events > 0,
            }
