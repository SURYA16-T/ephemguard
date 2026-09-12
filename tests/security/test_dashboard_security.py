import pytest
import json
import os
import shutil
import asyncio
from aiohttp import web
from ephemguard.dashboard.server import DashboardServer

@pytest.fixture
def temp_workspace(tmp_path):
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    yield str(workspace)
    if workspace.exists():
        shutil.rmtree(workspace)

@pytest.fixture
def dashboard(temp_workspace):
    server = DashboardServer(workspace=temp_workspace, port=0)
    return server

@pytest.fixture
def get_client(aiohttp_client, dashboard):
    async def _get_client():
        app = web.Application(middlewares=[dashboard.security_middleware])
        app.router.add_post("/api/decide", dashboard.post_decision)
        return await aiohttp_client(app)
    return _get_client

@pytest.mark.asyncio
async def test_api_decide_invalid_uuid(get_client):
    cli = await get_client()
    resp = await cli.post('/api/decide', json={"id": "../../../etc/passwd", "approved": True})
    assert resp.status == 400
    data = await resp.json()
    assert "Invalid request ID format" in data["error"]

@pytest.mark.asyncio
async def test_api_decide_valid_uuid(get_client, dashboard):
    cli = await get_client()
    valid_uuid = "123e4567-e89b-12d3-a456-426614174000"
    resp = await cli.post('/api/decide', json={"id": valid_uuid, "approved": True})
    assert resp.status == 200
    
    decision_file = os.path.join(dashboard.decisions_dir, f"{valid_uuid}.json")
    assert os.path.exists(decision_file)
    with open(decision_file, "r") as f:
        data = json.load(f)
        assert data["id"] == valid_uuid
        assert data["approved"] is True

@pytest.mark.asyncio
async def test_cors_origin_check(get_client):
    cli = await get_client()
    resp = await cli.post('/api/decide', 
                          headers={"Origin": "http://evil-site.com"}, 
                          json={"id": "123e4567-e89b-12d3-a456-426614174000", "approved": True})
    assert resp.status == 403
    data = await resp.json()
    assert "Invalid Origin" in data["error"]
    
@pytest.mark.asyncio
async def test_csrf_fetch_check(get_client):
    cli = await get_client()
    resp = await cli.post('/api/decide', 
                          headers={"Sec-Fetch-Site": "cross-site"}, 
                          json={"id": "123e4567-e89b-12d3-a456-426614174000", "approved": True})
    assert resp.status == 403
    data = await resp.json()
    assert "Cross-site requests forbidden" in data["error"]
