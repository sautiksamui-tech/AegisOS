"""Stage 3: Deterministic Diagnosis and Remediation Engine for AegisOS.

Strictly follows Section 5:
- Deterministic diagnosis rule: detects unhandled exception path in process_payment_attempt
  where connection release is bypassed on TransientProcessingError.
- Enforces patch restrictions:
  - Only demo/sample_app/payment_handler.py may change.
  - Only process_payment_attempt may change.
  - AST equivalence verified for all other definitions.
- Applies patch template with guaranteed `try...finally` release.
- Generates concrete negative control (incomplete release on PaymentValidationError only).
- Validates patch digests and AST integrity for both.
"""

import ast
import json
from pathlib import Path
from typing import Any

from aegisos.remediation.ast_checker import verify_patch_integrity, compute_patch_digest
from aegisos.remediation.patch_manager import (
    FN_VULNERABLE,
    FN_PATCHED,
    FN_NEGATIVE_CONTROL,
    PAYMENT_HANDLER_PATH,
    apply_implementation,
    get_current_condition,
)


def diagnose_code(source_code: str) -> dict[str, Any]:
    """Deterministic diagnostic rule: analyzes AST of payment_handler.py to detect connection leak."""
    tree = ast.parse(source_code)
    fn_node = None
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "process_payment_attempt":
            fn_node = node
            break

    if not fn_node:
        return {
            "vulnerability_detected": False,
            "error": "Function process_payment_attempt not found",
        }

    # Inspect statements inside process_payment_attempt
    has_try_finally = False
    has_acquire = False
    has_release = False

    for stmt in fn_node.body:
        if isinstance(stmt, ast.Try) and stmt.finalbody:
            has_try_finally = True
        # Check call expressions
        for child in ast.walk(stmt):
            if isinstance(child, ast.Call) and hasattr(child.func, "attr"):
                if child.func.attr == "acquire":
                    has_acquire = True
                elif child.func.attr == "release":
                    has_release = True

    is_vulnerable = has_acquire and has_release and (not has_try_finally)

    return {
        "vulnerability_detected": is_vulnerable,
        "rule_id": "AEGIS-RULE-001-CONNECTION-LEAK-ON-EXCEPTION",
        "description": "Connection acquired without guaranteed try...finally cleanup. TransientProcessingError leaks connection.",
        "target_file": str(PAYMENT_HANDLER_PATH).replace("\\", "/"),
        "target_function": "process_payment_attempt",
        "remediation_strategy": "Wrap operation in try...finally block ensuring pool.release(conn) is executed unconditionally.",
    }


def run_stage_3_verification() -> dict[str, Any]:
    # Ensure baseline vulnerable file is on disk
    apply_implementation("vulnerable")
    vulnerable_content = PAYMENT_HANDLER_PATH.read_text(encoding="utf-8")

    # 1. Run deterministic diagnostic rule
    diagnosis = diagnose_code(vulnerable_content)
    assert diagnosis["vulnerability_detected"] is True, "Diagnosis rule failed to detect leak in baseline"

    # 2. Verify Correct Patch AST and Integrity
    temp_patched = PAYMENT_HANDLER_PATH.parent / "payment_handler_patched_temp.py"
    target_start = vulnerable_content.find("def process_payment_attempt(")
    target_end = vulnerable_content.find("\ndef execute_payment_request(")
    patched_content = vulnerable_content[:target_start] + FN_PATCHED + "\n\n" + vulnerable_content[target_end + 1:]
    temp_patched.write_text(patched_content, encoding="utf-8")

    patch_verification = verify_patch_integrity(
        original_path=PAYMENT_HANDLER_PATH,
        candidate_path=temp_patched,
        relative_target_path=str(PAYMENT_HANDLER_PATH),
    )
    temp_patched.unlink()

    # 3. Verify Negative Control AST and Integrity
    temp_neg = PAYMENT_HANDLER_PATH.parent / "payment_handler_neg_temp.py"
    neg_content = vulnerable_content[:target_start] + FN_NEGATIVE_CONTROL + "\n\n" + vulnerable_content[target_end + 1:]
    temp_neg.write_text(neg_content, encoding="utf-8")

    neg_verification = verify_patch_integrity(
        original_path=PAYMENT_HANDLER_PATH,
        candidate_path=temp_neg,
        relative_target_path=str(PAYMENT_HANDLER_PATH),
    )
    temp_neg.unlink()

    result = {
        "stage": "stage_3_diagnosis_and_remediation",
        "passed": True,
        "diagnosis": diagnosis,
        "correct_patch": {
            "patch_digest": patch_verification["patch_digest"],
            "status": patch_verification["status"],
            "rules_passed": patch_verification["verified_rules"],
        },
        "negative_control": {
            "patch_digest": neg_verification["patch_digest"],
            "status": neg_verification["status"],
            "rules_passed": neg_verification["verified_rules"],
        },
    }
    return result


if __name__ == "__main__":
    out = run_stage_3_verification()
    print(json.dumps(out, indent=2))
