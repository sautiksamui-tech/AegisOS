# AegisOS — Live Demonstration Runbook & Evidence Verification

This runbook guides evaluators and judges through the verification of **AegisOS**: an autonomous remediation and security benchmarking platform demonstrating genuine failure reproduction, strict AST patch containment, Docker container sandbox isolation, and an independently computed validation verdict.

---

## Architecture & Verification Overview

AegisOS demonstrates:
1. **One Genuine Failure:** Database connection pool starvation (leaking all 5 connections on unhandled `TransientProcessingError` paths).
2. **One Correct Fix:** Guaranteed cleanup via `try...finally: pool.release(conn)` strictly contained to `demo/sample_app/payment_handler.py :: process_payment_attempt`.
3. **One Ineffective Negative Control:** Cleanup applied only to `PaymentValidationError`, leaving `TransientProcessingError` unhandled and leaking.
4. **A Measured Difference:** Statistically proven across 300-request open-loop workloads with 0.67% error rate on patched vs 86.33% error rate on vulnerable and 98.33% error rate on negative control.
5. **Rigorous Container Sandbox:** Validated using both positive (loopback TCP, mounted control read) and negative (external egress probe blocked, host canary inaccessible) controls under `--network none` and read-only filesystems.

---

## Step-by-Step Demonstration

### 1. Environment Preflight (Stage 0)
Run the automated preflight check:
```powershell
.\.venv\Scripts\python.exe -m aegisos.preflight
```
**Verification Points:**
- Windows 11 host with PowerShell 5.1+.
- Python 3.12 runtime.
- Docker Server with Linux container subsystem (WSL 2).
- Security Ports 2375 and 2376 verified disabled (no plaintext daemon exposed).

---

### 2. Run the 4-Condition Benchmark Dry Run (Stage 2)
Execute the dry-run feasibility gate covering Healthy, Vulnerable, Patched, and Negative Control implementations:
```powershell
.\.venv\Scripts\python.exe -m aegisos.dry_run
```
**Verification Points:**
- **Healthy Reference:** 298/300 completed, 0.67% error rate, 0 pool wait events, 0 leaks.
- **Vulnerable Baseline:** 41/300 completed, 86.33% error rate, 271 pool wait events, 5 connection leaks (exhausting the pool in ~0.45s).
- **Correctly Patched:** 298/300 completed, 0.67% error rate, 0 pool wait events, 0 leaks.
- **Negative Control:** 5/300 completed, 98.33% error rate, 295 pool wait events, 5 connection leaks.
- **Overall Status:** `PASSED`.

---

### 3. Verify AST Patch Integrity (Stage 3)
Inspect patch boundaries and run AST checks:
```powershell
.\.venv\Scripts\python.exe -m aegisos.remediation.verifier
.\.venv\Scripts\pytest.exe tests/aegis/test_ast_checker.py
```
**Verification Points:**
- Only `demo/sample_app/payment_handler.py` may change.
- Only the function `process_payment_attempt` is modified.
- Function signature, decorators, module-level variables, retry logic, fault injection, and hold duration are 100% untouched.
- Patch digests recorded and verified.

---

### 4. Verify Docker Sandbox Controls (Stage 4)
Run the container sandbox verification suite:
```powershell
.\.venv\Scripts\python.exe -m aegisos.sandbox.verifier
```
**Verification Points:**
- **Network Positive Control:** In-container loopback server (`127.0.0.1:45678`) succeeds.
- **Network Negative Control:** External probe to `8.8.8.8:53` fails under `--network none`.
- **Host-File Positive Control:** Read explicitly mounted control file succeeds.
- **Host-File Negative Control:** Attempt to read host canary file (`aegis_canary_*.txt`) outside workspace fails.
- **Docker Socket Isolation:** Sockets absent; launcher injection attempts rejected at boundary.

---

### 5. Launch the Minimal Status Page (Stage 5)
Start the FastAPI server:
```powershell
.\.venv\Scripts\uvicorn.exe aegisos.backend.app:app --host 127.0.0.1 --port 8000
```
Open **[http://127.0.0.1:8000](http://127.0.0.1:8000)** in your browser:
- Polls `/api/status` every 2 seconds.
- Displays the `VERIFIED` status badge.
- Shows incident status, root cause, and remediation summary.
- Displays SecOps approval status with one-click approval button.
- Shows benchmark metric comparison and container sandbox security status cards.
- Allows browsing the latest benchmark raw JSON.

---

### 6. Execute the Acceptance Orchestrator & Audit Evidence (Stage 6)
To run or re-validate the entire end-to-end acceptance suite:
```powershell
.\.venv\Scripts\python.exe -m aegisos.orchestration.runner
```
Inspect the official generated report:
- `VALIDATION_REPORT.md`
- Run directory: `runs/acceptance/<run_id>/`
- Progress log: `runs/acceptance/<run_id>/progress.jsonl`
- Validated state: `runs/acceptance/<run_id>/state.json`
- Sealed manifest: `runs/acceptance/<run_id>/manifest.json`
