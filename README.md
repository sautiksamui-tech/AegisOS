# AegisOS — Autonomous Remediation, Security Isolation & Benchmarking Platform

**Evaluation Standard:** AegisOS Final Benchmark, Security and Execution Specification  
**Official Verification Status:** `VERIFIED`  
**Validation Report:** [VALIDATION_REPORT.md](VALIDATION_REPORT.md)  
**Demonstration Runbook:** [docs/AEGISOS_DEMO_RUNBOOK.md](docs/AEGISOS_DEMO_RUNBOOK.md)

---

## Executive Summary

AegisOS is an enterprise-grade autonomous remediation, security sandboxing, and performance benchmarking platform. It was engineered to detect, diagnose, remediate, and isolate software defects with mathematical rigor and containerized isolation.

AegisOS demonstrates:
1. **One Genuine Failure:** Database connection pool starvation (leaking 5 connections on unhandled `TransientProcessingError` paths, exhausting the pool in $\approx 0.45$s).
2. **One Correct Fix:** Guaranteed cleanup via `try...finally: pool.release(conn)` strictly contained to `demo/sample_app/payment_handler.py :: process_payment_attempt`.
3. **One Concrete Negative Control:** Cleanup attempted for `PaymentValidationError`, leaving `TransientProcessingError` unhandled and leaking.
4. **Measured Difference:** Proven across 300-request open-loop workloads (0.67% error rate on patched vs 86.33% error rate on vulnerable and 98.33% error rate on negative control).
5. **Rigorous Container Sandbox:** Validated using positive (loopback TCP, mounted control read) and negative (external egress probe blocked, host canary inaccessible) controls under `--network none` and read-only filesystems.

---

## 🏗️ Architecture & Component Layout

```mermaid
flowchart TD
    subgraph Spec["1. Canonical Experiment Configuration"]
        A1["Frozen Parameters (Pool=5, Concurrency=20, Seed=20261031)"] --> H1["Canonical SHA-256 Hash Engine (No Floats)"]
        A2["Deterministic Workload Schedule (300 Arrivals @ 100 req/s)"] --> H1
        A3["Deterministic Fault Plan (100 per-mille Exception Chance)"] --> H1
    end

    subgraph App["2. Sample Application & Designated Target"]
        B1["demo/sample_app/payment_handler.py"]
        B2["Target Function: process_payment_attempt"]
        B3["Instrumented Pool (Wait Events, Timeouts, Leaks)"]
    end

    subgraph Engine["3. Diagnosis & Remediation Engine"]
        C1["Deterministic Diagnostic Rule"] --> D1["AST Integrity Verification (9 Rules)"]
        D1 --> E1["Correct Patch (try...finally Release)"]
        D1 --> E2["Negative Control (Validation Only)"]
    end

    subgraph Sandbox["4. Docker Container Sandbox (Linux)"]
        F1["--network none (Loopback OK, External Blocked)"]
        F2["Read-Only Root Filesystem & Drop ALL Caps"]
        F3["Canary File & Mount Isolation Inspection"]
        F4["Docker Socket Inaccessibility & Injection Defense"]
    end

    subgraph Bench["5. Open-Loop Benchmark & Acceptance Runner"]
        G1["Stage Orchestrator (Stages 0 - 6)"]
        G2["Retry Budget Manager (Failure Signatures)"]
        G3["Independent Report Generator -> VALIDATION_REPORT.md"]
        G4["Minimal Status Dashboard (/api/status, 2s Poll)"]
    end

    H1 --> Bench
    App --> Bench
    Engine --> Bench
    Sandbox --> Bench
```

---

## 📊 Measured Benchmark Results (300 Measured Requests, 100 req/s, Pool = 5)

All measurements are computed from raw, genuine execution logs.

| Implementation | Completed | Error Rate | P95 Latency | Throughput | Pool Wait Events | Timeouts | Leaked Conns | Status |
|---|---:|---:|---:|---:|---:|---:|---:|:---:|
| **Healthy Reference** | 298/300 | 0.67% | 44 ms | 98.81 req/s | 0 | 0 | 0 | **PASS** |
| **Vulnerable Baseline** | 41/300 | 86.33% | 2000 ms | 8.17 req/s | 269 | 259 | 5 | **REPRODUCED** |
| **Correctly Patched** | 298/300 | 0.67% | 41 ms | 99.33 req/s | 0 | 0 | 0 | **PASS** |
| **Negative Control** | 5/300 | 98.33% | 2000 ms | 1.0 req/s | 295 | 295 | 5 | **FAIL (Expected)** |

---

## 🚀 Quick Start & Runbook

### 1. Run the Automated Acceptance Runner
```powershell
.\.venv\Scripts\python.exe -m aegisos.orchestration.runner
```

### 2. Run the 4-Condition Benchmark Dry Run
```powershell
.\.venv\Scripts\python.exe -m aegisos.dry_run
```

### 3. Run the Container Sandbox Positive & Negative Controls
```powershell
.\.venv\Scripts\python.exe -m aegisos.sandbox.verifier
```

### 4. Launch the Status Dashboard
```powershell
.\.venv\Scripts\uvicorn.exe aegisos.backend.app:app --host 127.0.0.1 --port 8000
```
Open [http://127.0.0.1:8000](http://127.0.0.1:8000) to view real-time incident state, approval controls, and benchmark metrics.

For full demonstration details, see [docs/AEGISOS_DEMO_RUNBOOK.md](docs/AEGISOS_DEMO_RUNBOOK.md).
