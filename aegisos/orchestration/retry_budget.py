"""Retry budget and failure signature tracker for AegisOS.

Strictly follows Section 8:
- Normalizes failure signatures:
  - test identifier / command
  - exception or exit category
  - stable normalized error message (strips timestamps, temp paths, UUIDs)
  - failure location
- Persists retry counts across runs.
- Max 3 attempts per signature.
- If 3 failed: stops retrying, creates docs/BLOCKER_REPORT.md with command, test id,
  normalized signature, original error, attempt history, and identified remaining blocker.
"""

import json
from pathlib import Path
import re
from typing import Any

MAX_RETRIES_PER_SIGNATURE = 3


def normalize_error_message(msg: str) -> str:
    """Strips timestamps, temporary paths, hex memory addresses, and UUIDs."""
    # Replace UUIDs
    msg = re.sub(r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}", "<UUID>", msg, flags=re.IGNORECASE)
    # Replace hex addresses
    msg = re.sub(r"0x[0-9a-fA-F]+", "<HEX>", msg)
    # Replace ISO timestamps
    msg = re.sub(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?", "<TIMESTAMP>", msg)
    # Replace file paths
    msg = re.sub(r"[A-Za-z]:\\[\w\\\.-]+", "<HOST_PATH>", msg)
    msg = re.sub(r"/tmp/[\w\.-]+", "<TMP_PATH>", msg)
    # Strip whitespace
    return " ".join(msg.strip().split())


class RetryBudgetManager:
    def __init__(self, persistence_file: Path):
        self.persistence_file = persistence_file
        self.state: dict[str, Any] = self._load()

    def _load(self) -> dict[str, Any]:
        if self.persistence_file.exists():
            try:
                return json.loads(self.persistence_file.read_text(encoding="utf-8"))
            except Exception:
                pass
        return {"signatures": {}}

    def _save(self) -> None:
        self.persistence_file.parent.mkdir(parents=True, exist_ok=True)
        # Atomic write
        tmp_file = self.persistence_file.with_suffix(".tmp")
        tmp_file.write_text(json.dumps(self.state, indent=2), encoding="utf-8")
        tmp_file.replace(self.persistence_file)

    def compute_signature(
        self,
        command_or_test_id: str,
        category: str,
        raw_error: str,
        location: str = "unknown",
    ) -> str:
        norm_msg = normalize_error_message(raw_error)
        return f"{command_or_test_id}::{category}::{location}::{norm_msg}"

    def record_attempt(
        self,
        command_or_test_id: str,
        category: str,
        raw_error: str,
        location: str = "unknown",
    ) -> tuple[int, bool]:
        """Records an attempt for the given signature.
        
        Returns (attempt_count, is_budget_exhausted).
        """
        sig = self.compute_signature(command_or_test_id, category, raw_error, location)
        signatures = self.state.setdefault("signatures", {})

        sig_data = signatures.setdefault(sig, {
            "command_or_test_id": command_or_test_id,
            "category": category,
            "normalized_error": normalize_error_message(raw_error),
            "raw_error_latest": raw_error,
            "location": location,
            "attempts": 0,
            "history": [],
        })

        sig_data["attempts"] += 1
        sig_data["raw_error_latest"] = raw_error
        sig_data["history"].append({
            "attempt": sig_data["attempts"],
            "raw_error": raw_error[:500],
        })

        self._save()

        attempts = sig_data["attempts"]
        is_exhausted = attempts >= MAX_RETRIES_PER_SIGNATURE

        if is_exhausted:
            self._generate_blocker_report(sig, sig_data)

        return attempts, is_exhausted

    def _generate_blocker_report(self, signature: str, sig_data: dict[str, Any]) -> None:
        docs_dir = Path("docs")
        docs_dir.mkdir(parents=True, exist_ok=True)
        report_file = docs_dir / "BLOCKER_REPORT.md"

        content = f"""# AegisOS — Blocker Report

**Status:** STOPPED (Failure-signature retry budget exhausted)
**Attempts Exceeded:** {sig_data['attempts']} / {MAX_RETRIES_PER_SIGNATURE}

## Failure Signature
`{signature}`

## Details
- **Command / Test Identifier:** `{sig_data['command_or_test_id']}`
- **Category:** `{sig_data['category']}`
- **Location:** `{sig_data['location']}`
- **Normalized Error Message:**
  ```text
  {sig_data['normalized_error']}
  ```

## Raw Error Output
```text
{sig_data['raw_error_latest']}
```

## Attempt History
"""
        for h in sig_data["history"]:
            content += f"- **Attempt {h['attempt']}:** `{h['raw_error']}`\n"

        content += """
## Identified Remaining Blocker
The execution failed 3 times with the exact same failure signature. In accordance with Section 8 of the AegisOS specification, further automatic retries are halted. Manual intervention or environmental remediation is required before re-executing.
"""
        report_file.write_text(content, encoding="utf-8")
