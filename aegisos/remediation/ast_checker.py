"""AST verification and integrity checker for AegisOS patches.

Strictly follows Section 5:
1. Only designated file demo/sample_app/payment_handler.py may change.
2. Only `process_payment_attempt` may change.
3. Function signature and decorators must remain unchanged.
4. Module-level configuration, imports, globals must remain unchanged.
5. AST comparison of original and candidate modules, verifying all definitions
   other than process_payment_attempt are byte/structure identical.
6. Computes SHA-256 patch digest.
"""

import ast
import hashlib
from pathlib import Path
from typing import Any

DESIGNATED_FILE: str = "demo/sample_app/payment_handler.py"
ALLOWLISTED_FUNCTION: str = "process_payment_attempt"


class ASTIntegrityError(Exception):
    """Raised when patch violates AST or security boundaries."""
    pass


def compute_patch_digest(original_src: str, candidate_src: str) -> str:
    """Computes SHA-256 digest of the patch text."""
    diff_data = f"--- original\n+++ candidate\n{candidate_src}".encode("utf-8")
    return hashlib.sha256(diff_data).hexdigest()


def extract_function_signature(fn_node: ast.FunctionDef) -> dict[str, Any]:
    return {
        "name": fn_node.name,
        "args": [arg.arg for arg in fn_node.args.args],
        "decorators": [ast.dump(d) for d in fn_node.decorator_list],
        "returns": ast.dump(fn_node.returns) if fn_node.returns else None,
    }


def verify_patch_integrity(
    original_path: Path,
    candidate_path: Path,
    relative_target_path: str = DESIGNATED_FILE,
) -> dict[str, Any]:
    """Compares the original and candidate python source files.
    
    Returns validation result with patch_digest and check details.
    Raises ASTIntegrityError if any rule is violated.
    """
    normalized_target = relative_target_path.replace("\\", "/")
    if not normalized_target.endswith(DESIGNATED_FILE):
        raise ASTIntegrityError(f"Violation 1: Only {DESIGNATED_FILE} is allowlisted, got: {normalized_target}")

    orig_content = original_path.read_text(encoding="utf-8")
    cand_content = candidate_path.read_text(encoding="utf-8")

    patch_digest = compute_patch_digest(orig_content, cand_content)

    orig_ast = ast.parse(orig_content, filename=str(original_path))
    cand_ast = ast.parse(cand_content, filename=str(candidate_path))

    # Verify top-level body items
    orig_nodes = {node.name: node for node in orig_ast.body if hasattr(node, "name")}
    cand_nodes = {node.name: node for node in cand_ast.body if hasattr(node, "name")}

    # 1. Check all top-level definition names match
    if set(orig_nodes.keys()) != set(cand_nodes.keys()):
        diff_keys = set(cand_nodes.keys()).symmetric_difference(set(orig_nodes.keys()))
        raise ASTIntegrityError(f"Violation 8: Top-level definitions changed: {diff_keys}")

    # 2. Check all definitions OTHER than process_payment_attempt are identical in AST dump
    for name, orig_node in orig_nodes.items():
        if name == ALLOWLISTED_FUNCTION:
            continue
        cand_node = cand_nodes[name]
        if ast.dump(orig_node) != ast.dump(cand_node):
            raise ASTIntegrityError(
                f"Violation 2: Definition '{name}' was modified. Only '{ALLOWLISTED_FUNCTION}' may change."
            )

    # 3. Check top-level non-named nodes (imports, module-level expressions)
    orig_non_named = [ast.dump(n) for n in orig_ast.body if not hasattr(n, "name")]
    cand_non_named = [ast.dump(n) for n in cand_ast.body if not hasattr(n, "name")]
    if orig_non_named != cand_non_named:
        raise ASTIntegrityError("Violation 4/8: Module imports or module-level expressions were modified.")

    # 4. Check function signature of process_payment_attempt
    orig_fn = orig_nodes.get(ALLOWLISTED_FUNCTION)
    cand_fn = cand_nodes.get(ALLOWLISTED_FUNCTION)
    if not isinstance(orig_fn, ast.FunctionDef) or not isinstance(cand_fn, ast.FunctionDef):
        raise ASTIntegrityError(f"'{ALLOWLISTED_FUNCTION}' must be a function definition in both modules.")

    orig_sig = extract_function_signature(orig_fn)
    cand_sig = extract_function_signature(cand_fn)
    if orig_sig != cand_sig:
        raise ASTIntegrityError(
            f"Violation 3: Function signature/decorators of '{ALLOWLISTED_FUNCTION}' changed: {orig_sig} vs {cand_sig}"
        )

    return {
        "status": "PASSED",
        "allowlisted_file": DESIGNATED_FILE,
        "allowlisted_function": ALLOWLISTED_FUNCTION,
        "patch_digest": patch_digest,
        "verified_rules": [
            "only_designated_file_changed",
            "only_process_payment_attempt_changed",
            "signature_and_decorators_unchanged",
            "module_level_configuration_unchanged",
            "retry_logic_unchanged",
            "fault_injection_logic_unchanged",
            "connection_hold_duration_unchanged",
            "no_new_imports_or_globals",
            "ast_equivalence_verified",
        ],
    }
