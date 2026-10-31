"""Tests for AST validation and patch boundaries."""

from pathlib import Path
import tempfile
import pytest
from aegisos.remediation.ast_checker import verify_patch_integrity, ASTIntegrityError
from aegisos.remediation.patch_manager import FN_VULNERABLE, FN_PATCHED, FN_NEGATIVE_CONTROL, PAYMENT_HANDLER_PATH


def test_ast_integrity_valid_patch():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        orig_file = tmp_path / "payment_handler.py"
        cand_file = tmp_path / "payment_handler_cand.py"

        content = PAYMENT_HANDLER_PATH.read_text(encoding="utf-8")
        orig_file.write_text(content, encoding="utf-8")

        # Create candidate with FN_PATCHED
        target_start = content.find("def process_payment_attempt(")
        target_end = content.find("\ndef execute_payment_request(")
        cand_content = content[:target_start] + FN_PATCHED + "\n\n" + content[target_end + 1:]
        cand_file.write_text(cand_content, encoding="utf-8")

        result = verify_patch_integrity(orig_file, cand_file, "demo/sample_app/payment_handler.py")
        assert result["status"] == "PASSED"
        assert len(result["patch_digest"]) == 64


def test_ast_integrity_negative_control():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        orig_file = tmp_path / "payment_handler.py"
        cand_file = tmp_path / "payment_handler_cand.py"

        content = PAYMENT_HANDLER_PATH.read_text(encoding="utf-8")
        orig_file.write_text(content, encoding="utf-8")

        # Create candidate with FN_NEGATIVE_CONTROL
        target_start = content.find("def process_payment_attempt(")
        target_end = content.find("\ndef execute_payment_request(")
        cand_content = content[:target_start] + FN_NEGATIVE_CONTROL + "\n\n" + content[target_end + 1:]
        cand_file.write_text(cand_content, encoding="utf-8")

        result = verify_patch_integrity(orig_file, cand_file, "demo/sample_app/payment_handler.py")
        assert result["status"] == "PASSED"
        assert len(result["patch_digest"]) == 64


def test_ast_integrity_rejects_illegal_modifications():
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        orig_file = tmp_path / "payment_handler.py"
        cand_file = tmp_path / "payment_handler_cand.py"

        content = PAYMENT_HANDLER_PATH.read_text(encoding="utf-8")
        orig_file.write_text(content, encoding="utf-8")

        # 1. Rejecting modifications to execute_payment_request
        bad_content = content + "\nILLEGAL_GLOBAL = 123\n"
        cand_file.write_text(bad_content, encoding="utf-8")
        with pytest.raises(ASTIntegrityError):
            verify_patch_integrity(orig_file, cand_file, "demo/sample_app/payment_handler.py")

        # 2. Rejecting unauthorized target file
        with pytest.raises(ASTIntegrityError):
            verify_patch_integrity(orig_file, orig_file, "demo/sample_app/other_file.py")
