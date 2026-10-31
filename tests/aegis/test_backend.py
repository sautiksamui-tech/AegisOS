"""Tests for AegisOS backend status endpoints and approval enforcement."""

import anyio
import httpx
import pytest
from aegisos.backend.app import app, approval_state


@pytest.fixture
def anyio_backend():
    return "asyncio"


@pytest.mark.anyio
async def test_get_dashboard():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/")
        assert response.status_code == 200
        assert "AegisOS" in response.text


@pytest.mark.anyio
async def test_get_status():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/status")
        assert response.status_code == 200
        data = response.json()
        assert "validation_outcome" in data
        assert "incident_state" in data
        assert "sandbox_isolation" in data


@pytest.mark.anyio
async def test_backend_approval_enforcement():
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        # 1. Reset approval
        await client.post("/api/reset-approval")
        assert approval_state.is_approved is False

        # 2. Attempt validation without approval -> MUST be 403 Forbidden
        unapproved_resp = await client.post("/api/run-validation")
        assert unapproved_resp.status_code == 403
        assert "VALIDATION_REJECTED" in unapproved_resp.json()["detail"]

        # 3. Grant approval
        approve_resp = await client.post(
            "/api/approve",
            json={"approver": "SecOps Lead", "token": "AEGIS-APPROVE-SEC-2026"},
        )
        assert approve_resp.status_code == 200
        assert approval_state.is_approved is True

        # 4. Attempt validation with approval -> MUST be 200 OK
        approved_resp = await client.post("/api/run-validation")
        assert approved_resp.status_code == 200
        assert approved_resp.json()["status"] == "VALIDATION_AUTHORIZED"
