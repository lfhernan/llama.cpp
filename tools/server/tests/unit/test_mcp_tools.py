#!/usr/bin/env python
"""
Test MCP client integration with llama-server.

Tests the /mcp/servers endpoint, tool discovery via GET /tools,
and tool invocation via POST /tools, using a mock MCP server.
"""

import pytest
import json
import threading
import time
import sys
import requests
from pathlib import Path
from http.server import HTTPServer, BaseHTTPRequestHandler

from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from utils import ServerProcess

MCP_MOCK_PORT = 19876
SERVER_PORT = 18080


class MockMCPHandler(BaseHTTPRequestHandler):
    """Minimal MCP server that responds to initialize, tools/list, and tools/call."""

    session_initialized = False

    def log_message(self, format, *args):
        pass

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)
        try:
            req = json.loads(body)
        except json.JSONDecodeError:
            self._send_json(500, {"error": "invalid JSON"})
            return

        method = req.get("method", "")
        params = req.get("params", {})
        req_id = req.get("id", 0)

        if method == "initialize":
            MockMCPHandler.session_initialized = True
            self._send_json(200, {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {"listChanged": True}
                    },
                    "serverInfo": {
                        "name": "test-mcp-server",
                        "version": "0.1.0"
                    }
                }
            })

        elif method == "tools/list":
            self._send_json(200, {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": [
                        {
                            "name": "test_echo",
                            "description": "Echo back the input message",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "message": {
                                        "type": "string",
                                        "description": "Message to echo"
                                    }
                                },
                                "required": ["message"]
                            }
                        },
                        {
                            "name": "test_add",
                            "description": "Add two numbers together",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "a": {"type": "number", "description": "First number"},
                                    "b": {"type": "number", "description": "Second number"}
                                },
                                "required": ["a", "b"]
                            }
                        }
                    ]
                }
            })

        elif method == "tools/call":
            tool_name = params.get("name", "")
            arguments = params.get("arguments", {})

            if tool_name == "test_echo":
                msg = arguments.get("message", "no message")
                self._send_json(200, {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {"type": "text", "text": f"echo: {msg}"}
                        ]
                    }
                })
            elif tool_name == "test_add":
                a = arguments.get("a", 0)
                b = arguments.get("b", 0)
                self._send_json(200, {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [
                            {"type": "text", "text": str(a + b)}
                        ]
                    }
                })
            else:
                self._send_json(200, {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32601,
                        "message": f"Unknown tool: {tool_name}"
                    }
                })
        else:
            self._send_json(200, {
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {}
            })

    def _send_json(self, status, data):
        body = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class MockMCPAuthHandler(BaseHTTPRequestHandler):
    """MCP server that requires OAuth (returns 401 on initialize)."""

    def log_message(self, format, *args):
        pass

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(content_length)
        self.send_response(401)
        self.send_header("Content-Type", "application/json")
        body = json.dumps({"error": "authentication required"}).encode("utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture(scope="module")
def mcp_mock_server():
    httpd = HTTPServer(("127.0.0.1", MCP_MOCK_PORT), MockMCPHandler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield httpd
    httpd.shutdown()


@pytest.fixture(scope="module")
def mcp_auth_mock_server():
    httpd = HTTPServer(("127.0.0.1", MCP_MOCK_PORT + 1), MockMCPAuthHandler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    yield httpd
    httpd.shutdown()


@pytest.fixture(scope="module")
def mcp_config_file(tmp_path_factory, mcp_mock_server):
    config_dir = tmp_path_factory.mktemp("mcp_config")
    config_file = config_dir / "mcp_servers.json"
    config = {
        "servers": [
            {
                "id": "test-mock",
                "url": f"http://127.0.0.1:{MCP_MOCK_PORT}",
                "scopes": []
            }
        ]
    }
    config_file.write_text(json.dumps(config))
    return str(config_file)


@pytest.fixture(scope="module")
def llama_server_with_mcp(mcp_config_file):
    server = ServerProcess()
    server.server_port = SERVER_PORT
    server.model_hf_repo = "ggml-org/models"
    server.model_hf_file = "tinyllamas/stories260K.gguf"
    server.model_alias = "mcp-test"
    server.n_ctx = 2048
    server.n_batch = 1024
    server.offline = False
    yield server
    if server.process:
        server.process.terminate()
        server.process.wait(timeout=10)


def test_mcp_servers_status(mcp_mock_server, mcp_config_file):
    """Test that GET /mcp/servers returns configured servers."""
    server = ServerProcess()
    server.server_port = SERVER_PORT
    server.model_hf_repo = None
    server.model_hf_file = None
    server.model_alias = None
    server.models_max = 0
    server.no_models_autoload = True
    server.mcp_config_file = mcp_config_file

    base_url = f"http://127.0.0.1:{SERVER_PORT}"
    server.start(timeout_seconds=120)
    try:
        resp = requests.get(f"{base_url}/mcp/servers", timeout=10)
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
        data = resp.json()
        assert isinstance(data, list), "Expected list of server statuses"
        assert len(data) >= 1, "Expected at least one MCP server"
        server_entry = data[0]
        assert server_entry["id"] == "test-mock"
    finally:
        server.process.terminate()
        server.process.wait(timeout=10)


def test_mcp_tools_appear_in_list(mcp_mock_server, mcp_config_file):
    """Test that MCP tools show up in GET /tools alongside built-in tools."""
    server = ServerProcess()
    server.server_port = SERVER_PORT + 1
    server.model_hf_repo = None
    server.model_hf_file = None
    server.model_alias = None
    server.models_max = 0
    server.no_models_autoload = True
    server.mcp_config_file = mcp_config_file
    server.tools = "all"

    base_url = f"http://127.0.0.1:{SERVER_PORT + 1}"
    server.start(timeout_seconds=120)
    try:
        resp = requests.get(f"{base_url}/tools", timeout=10)
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
        tools = resp.json()
        tool_names = [t.get("tool", "") for t in tools]
        mcp_tools = [n for n in tool_names if n.startswith("mcp:")]
        assert len(mcp_tools) >= 2, f"Expected at least 2 MCP tools, got: {mcp_tools}"
        assert "mcp:test-mock:test_echo" in tool_names
        assert "mcp:test-mock:test_add" in tool_names
    finally:
        server.process.terminate()
        server.process.wait(timeout=10)


def test_mcp_tool_invoke_echo(mcp_mock_server, mcp_config_file):
    """Test invoking an MCP tool via POST /tools."""
    server = ServerProcess()
    server.server_port = SERVER_PORT + 2
    server.model_hf_repo = None
    server.model_hf_file = None
    server.model_alias = None
    server.models_max = 0
    server.no_models_autoload = True
    server.mcp_config_file = mcp_config_file
    server.tools = "all"

    base_url = f"http://127.0.0.1:{SERVER_PORT + 2}"
    server.start(timeout_seconds=120)
    try:
        resp = requests.post(
            f"{base_url}/tools",
            json={
                "tool": "mcp:test-mock:test_echo",
                "params": {"message": "hello world"}
            },
            timeout=30
        )
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
        result = resp.json()
        assert "plain_text_response" in result or "result" in result, f"Unexpected response: {result}"
        text = result.get("plain_text_response", result.get("result", ""))
        assert "hello world" in str(text), f"Expected 'hello world' in response, got: {text}"
    finally:
        server.process.terminate()
        server.process.wait(timeout=10)


def test_mcp_tool_invoke_add(mcp_mock_server, mcp_config_file):
    """Test invoking the add MCP tool."""
    server = ServerProcess()
    server.server_port = SERVER_PORT + 3
    server.model_hf_repo = None
    server.model_hf_file = None
    server.model_alias = None
    server.models_max = 0
    server.no_models_autoload = True
    server.mcp_config_file = mcp_config_file
    server.tools = "all"

    base_url = f"http://127.0.0.1:{SERVER_PORT + 3}"
    server.start(timeout_seconds=120)
    try:
        resp = requests.post(
            f"{base_url}/tools",
            json={
                "tool": "mcp:test-mock:test_add",
                "params": {"a": 17, "b": 25}
            },
            timeout=30
        )
        assert resp.status_code == 200, f"Expected 200, got {resp.status_code}: {resp.text}"
        result = resp.json()
        text = result.get("plain_text_response", result.get("result", ""))
        assert "42" in str(text), f"Expected '42' in response, got: {text}"
    finally:
        server.process.terminate()
        server.process.wait(timeout=10)


def test_mcp_server_needs_auth(mcp_auth_mock_server, tmp_path):
    """Test that MCP server requiring auth shows needs_auth state."""
    config_file = str(tmp_path / "mcp_auth.json")
    config = {
        "servers": [
            {
                "id": "auth-required",
                "url": f"http://127.0.0.1:{MCP_MOCK_PORT + 1}",
                "scopes": []
            }
        ]
    }
    Path(config_file).write_text(json.dumps(config))

    server = ServerProcess()
    server.server_port = SERVER_PORT + 4
    server.model_hf_repo = None
    server.model_hf_file = None
    server.model_alias = None
    server.models_max = 0
    server.no_models_autoload = True
    server.mcp_config_file = config_file
    server.tools = "all"

    base_url = f"http://127.0.0.1:{SERVER_PORT + 4}"
    server.start(timeout_seconds=120)
    try:
        resp = requests.get(f"{base_url}/mcp/servers", timeout=10)
        assert resp.status_code == 200
        data = resp.json()
        auth_server = next((s for s in data if s["id"] == "auth-required"), None)
        assert auth_server is not None, "auth-required server not found"
        assert auth_server["state"] in ("needs_auth", "error"), f"Expected needs_auth or error, got {auth_server['state']}"
    finally:
        server.process.terminate()
        server.process.wait(timeout=10)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
