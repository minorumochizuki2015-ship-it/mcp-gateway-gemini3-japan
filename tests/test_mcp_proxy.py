"""Tests for mcp_proxy.py — MCP transparent security proxy."""

from __future__ import annotations

import io
import json
import os
import signal
import subprocess
import sys
import textwrap
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# Add src to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from mcp_gateway.mcp_proxy import (
    CircuitBreaker,
    check_security,
    client_to_server,
    drain_stderr,
    make_blocked_response,
    read_message,
    redact_args,
    server_to_client,
    write_message,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_bytes_stream(lines: list[str]) -> io.BytesIO:
    """Build a BytesIO from newline-delimited JSON strings."""
    data = "\n".join(lines) + "\n"
    return io.BytesIO(data.encode("utf-8"))


def _json_line(obj: dict) -> str:
    return json.dumps(obj, separators=(",", ":"))


# ---------------------------------------------------------------------------
# Framing: read_message / write_message
# ---------------------------------------------------------------------------

class TestReadMessage:
    def test_basic_read(self) -> None:
        msg = {"jsonrpc": "2.0", "id": 1, "method": "initialize"}
        stream = _make_bytes_stream([json.dumps(msg)])
        result = read_message(stream)
        assert result == msg

    def test_eof_returns_none(self) -> None:
        stream = io.BytesIO(b"")
        assert read_message(stream) is None

    def test_skips_blank_lines(self) -> None:
        msg = {"jsonrpc": "2.0", "id": 1}
        stream = _make_bytes_stream(["", "", json.dumps(msg), ""])
        result = read_message(stream)
        assert result == msg

    def test_skips_non_json_lines(self) -> None:
        msg = {"jsonrpc": "2.0", "id": 2}
        stream = _make_bytes_stream(["this is not json", json.dumps(msg)])
        result = read_message(stream)
        assert result == msg

    def test_large_payload(self) -> None:
        big = {"data": "x" * 100_000}
        stream = _make_bytes_stream([json.dumps(big)])
        result = read_message(stream)
        assert result is not None
        assert len(result["data"]) == 100_000


class TestWriteMessage:
    def test_basic_write(self) -> None:
        stream = io.BytesIO()
        lock = threading.Lock()
        msg = {"jsonrpc": "2.0", "id": 1, "result": {}}
        write_message(stream, msg, lock)
        written = stream.getvalue()
        assert written.endswith(b"\n")
        parsed = json.loads(written.strip())
        assert parsed == msg

    def test_thread_safety(self) -> None:
        """Multiple threads writing should not corrupt output."""
        stream = io.BytesIO()
        lock = threading.Lock()
        results: list[bool] = []

        def writer(n: int) -> None:
            try:
                for i in range(50):
                    write_message(stream, {"id": n * 100 + i}, lock)
                results.append(True)
            except Exception:
                results.append(False)

        threads = [threading.Thread(target=writer, args=(t,)) for t in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert all(results)
        lines = stream.getvalue().strip().split(b"\n")
        assert len(lines) == 200  # 4 threads * 50 messages
        for line in lines:
            json.loads(line)  # all must be valid JSON

    def test_roundtrip(self) -> None:
        msg = {"jsonrpc": "2.0", "id": 42, "result": {"content": [{"type": "text", "text": "hello"}]}}
        buf = io.BytesIO()
        lock = threading.Lock()
        write_message(buf, msg, lock)
        buf.seek(0)
        result = read_message(buf)
        assert result == msg


# ---------------------------------------------------------------------------
# Redaction
# ---------------------------------------------------------------------------

class TestRedaction:
    def test_redacts_secret(self) -> None:
        text = 'secret="my-super-secret-value"'
        result = redact_args(text)
        assert "my-super-secret-value" not in result
        assert "[REDACTED]" in result

    def test_redacts_api_key(self) -> None:
        text = '{"api_key": "AKIA1234567890"}'
        result = redact_args(text)
        assert "AKIA1234567890" not in result

    def test_redacts_token(self) -> None:
        text = 'token: ghp_abcdef123456'
        result = redact_args(text)
        assert "ghp_abcdef123456" not in result

    def test_does_not_redact_normal(self) -> None:
        text = '{"path": "/tmp/test.txt", "name": "foo"}'
        result = redact_args(text)
        assert result == text

    def test_redacts_password(self) -> None:
        text = 'password=hunter2'
        result = redact_args(text)
        assert "hunter2" not in result


# ---------------------------------------------------------------------------
# Circuit Breaker
# ---------------------------------------------------------------------------

class TestCircuitBreaker:
    def test_starts_closed(self) -> None:
        cb = CircuitBreaker()
        assert cb.state == "CLOSED"

    def test_opens_after_threshold(self) -> None:
        cb = CircuitBreaker()
        for _ in range(3):
            cb.record_failure()
        assert cb.state == "OPEN"

    def test_success_resets(self) -> None:
        cb = CircuitBreaker()
        cb.record_failure()
        cb.record_failure()
        cb.record_success()
        assert cb.state == "CLOSED"

    def test_half_open_after_recovery(self) -> None:
        cb = CircuitBreaker()
        cb.RECOVERY_SECONDS = 0.1  # shorten for test
        for _ in range(3):
            cb.record_failure()
        assert cb.state == "OPEN"
        time.sleep(0.15)
        assert cb.state == "HALF-OPEN"


# ---------------------------------------------------------------------------
# Security check (mocked gateway)
# ---------------------------------------------------------------------------

class _MockGatewayHandler(BaseHTTPRequestHandler):
    """Simple HTTP handler simulating /api/mcp/intercept."""

    response_data: dict[str, Any] = {"allowed": True, "reason": "ok"}

    def do_POST(self) -> None:
        content_len = int(self.headers.get("Content-Length", 0))
        body = json.loads(self.rfile.read(content_len))
        # Block requests containing "malicious" in method
        if "malicious" in body.get("method", ""):
            resp = {"allowed": False, "reason": "blocked by test"}
        else:
            resp = self.__class__.response_data
        payload = json.dumps(resp).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, format: str, *args: Any) -> None:
        pass  # suppress output


@pytest.fixture()
def mock_gateway():
    """Start a local HTTP server simulating the gateway."""
    server = HTTPServer(("127.0.0.1", 0), _MockGatewayHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


class TestCheckSecurity:
    def test_allowed(self, mock_gateway: str) -> None:
        cb = CircuitBreaker()
        allowed, reason = check_security("read_file", {"path": "/tmp"}, mock_gateway, 5.0, cb, False)
        assert allowed is True

    def test_blocked(self, mock_gateway: str) -> None:
        cb = CircuitBreaker()
        allowed, reason = check_security("malicious_tool", {}, mock_gateway, 5.0, cb, False)
        assert allowed is False
        assert "blocked" in reason

    def test_timeout_fail_open(self) -> None:
        cb = CircuitBreaker()
        # Use a non-routable address to force timeout
        allowed, reason = check_security(
            "read_file", {}, "http://192.0.2.1:9999", 0.5, cb, fail_closed=False
        )
        assert allowed is True
        assert "unreachable" in reason.lower() or "fail-open" in reason.lower()

    def test_timeout_fail_closed(self) -> None:
        cb = CircuitBreaker()
        allowed, reason = check_security(
            "read_file", {}, "http://192.0.2.1:9999", 0.5, cb, fail_closed=True
        )
        assert allowed is False

    def test_circuit_breaker_open_fail_open(self) -> None:
        cb = CircuitBreaker()
        for _ in range(3):
            cb.record_failure()
        allowed, reason = check_security("read_file", {}, "http://unused", 5, cb, False)
        assert allowed is True
        assert "circuit" in reason.lower()

    def test_circuit_breaker_open_fail_closed(self) -> None:
        cb = CircuitBreaker()
        for _ in range(3):
            cb.record_failure()
        allowed, reason = check_security("read_file", {}, "http://unused", 5, cb, True)
        assert allowed is False
        assert "circuit" in reason.lower()


# ---------------------------------------------------------------------------
# Blocked response
# ---------------------------------------------------------------------------

class TestMakeBlockedResponse:
    def test_structure(self) -> None:
        resp = make_blocked_response(42, "test reason")
        assert resp["jsonrpc"] == "2.0"
        assert resp["id"] == 42
        assert resp["result"]["isError"] is True
        assert "BLOCKED" in resp["result"]["content"][0]["text"]
        assert "test reason" in resp["result"]["content"][0]["text"]

    def test_preserves_string_id(self) -> None:
        resp = make_blocked_response("abc-123", "reason")
        assert resp["id"] == "abc-123"


# ---------------------------------------------------------------------------
# Thread functions (unit)
# ---------------------------------------------------------------------------

class TestServerToClient:
    def test_forwards_messages(self) -> None:
        msgs = [
            {"jsonrpc": "2.0", "id": 1, "result": {}},
            {"jsonrpc": "2.0", "id": 2, "result": {"data": "x"}},
        ]
        server_out = _make_bytes_stream([json.dumps(m) for m in msgs])
        client_out = io.BytesIO()
        lock = threading.Lock()
        event = threading.Event()

        server_to_client(server_out, client_out, lock, event)

        lines = client_out.getvalue().strip().split(b"\n")
        assert len(lines) == 2
        assert json.loads(lines[0]) == msgs[0]
        assert json.loads(lines[1]) == msgs[1]


class TestDrainStderr:
    def test_forwards_stderr(self) -> None:
        server_stderr = io.BytesIO(b"warning: something\nerror: bad\n")
        event = threading.Event()

        with patch("sys.stderr") as mock_stderr:
            mock_stderr.buffer = io.BytesIO()
            drain_stderr(server_stderr, event)
            output = mock_stderr.buffer.getvalue()
            assert b"warning: something" in output
            assert b"error: bad" in output


# ---------------------------------------------------------------------------
# Integration: subprocess proxy (echo server)
# ---------------------------------------------------------------------------

_ECHO_SERVER = textwrap.dedent("""\
    import sys, json, time
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except json.JSONDecodeError:
            continue
        # Echo back with result (only for requests with id)
        if "id" in msg:
            resp = {"jsonrpc": "2.0", "id": msg["id"], "result": {"echo": msg}}
            sys.stdout.write(json.dumps(resp) + "\\n")
            sys.stdout.flush()
        # For notifications, just acknowledge on stderr
        else:
            sys.stderr.write("echo-server: notification received\\n")
            sys.stderr.flush()
    sys.stderr.write("echo-server: done\\n")
    sys.stderr.flush()
""")


class TestIntegration:
    @pytest.fixture()
    def echo_server_script(self, tmp_path) -> str:
        script = tmp_path / "echo_server.py"
        script.write_text(_ECHO_SERVER)
        return str(script)

    def test_passthrough(self, echo_server_script: str, mock_gateway: str) -> None:
        """Non tools/call messages pass through transparently."""
        input_msg = {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m", "mcp_gateway.mcp_proxy",
                "--gateway-url", mock_gateway,
                "--", sys.executable, echo_server_script,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=os.path.join(os.path.dirname(__file__), "..", "src"),
        )
        assert proc.stdin is not None and proc.stdout is not None
        proc.stdin.write(json.dumps(input_msg).encode() + b"\n")
        proc.stdin.flush()
        time.sleep(0.5)  # let message propagate through proxy + echo server
        proc.stdin.close()
        proc.wait(timeout=10)
        stdout = proc.stdout.read()
        lines = [l for l in stdout.strip().split(b"\n") if l]
        assert len(lines) >= 1
        resp = json.loads(lines[0])
        assert resp["id"] == 1
        assert resp["result"]["echo"]["method"] == "initialize"

    def test_tools_call_allowed(self, echo_server_script: str, mock_gateway: str) -> None:
        """tools/call with allowed tool passes through."""
        input_msg = {
            "jsonrpc": "2.0", "id": 2,
            "method": "tools/call",
            "params": {"name": "read_file", "arguments": {"path": "/tmp/test"}},
        }
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m", "mcp_gateway.mcp_proxy",
                "--gateway-url", mock_gateway,
                "--", sys.executable, echo_server_script,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=os.path.join(os.path.dirname(__file__), "..", "src"),
        )
        assert proc.stdin is not None and proc.stdout is not None
        proc.stdin.write(json.dumps(input_msg).encode() + b"\n")
        proc.stdin.flush()
        time.sleep(0.5)
        proc.stdin.close()
        proc.wait(timeout=10)
        stdout = proc.stdout.read()
        lines = [l for l in stdout.strip().split(b"\n") if l]
        assert len(lines) >= 1
        resp = json.loads(lines[0])
        assert resp["id"] == 2
        assert resp["result"]["echo"]["method"] == "tools/call"

    def test_tools_call_blocked(self, echo_server_script: str, mock_gateway: str) -> None:
        """tools/call with blocked tool returns error without forwarding."""
        input_msg = {
            "jsonrpc": "2.0", "id": 3,
            "method": "tools/call",
            "params": {"name": "malicious_tool", "arguments": {}},
        }
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m", "mcp_gateway.mcp_proxy",
                "--gateway-url", mock_gateway,
                "--", sys.executable, echo_server_script,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=os.path.join(os.path.dirname(__file__), "..", "src"),
        )
        assert proc.stdin is not None and proc.stdout is not None
        proc.stdin.write(json.dumps(input_msg).encode() + b"\n")
        proc.stdin.flush()
        time.sleep(0.5)
        proc.stdin.close()
        proc.wait(timeout=10)
        stdout = proc.stdout.read()
        lines = [l for l in stdout.strip().split(b"\n") if l]
        assert len(lines) >= 1
        resp = json.loads(lines[0])
        assert resp["id"] == 3
        assert resp["result"]["isError"] is True
        assert "BLOCKED" in resp["result"]["content"][0]["text"]

    def test_notification_forwarding(self, echo_server_script: str, mock_gateway: str) -> None:
        """Notifications (no id) are forwarded without security check."""
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m", "mcp_gateway.mcp_proxy",
                "--gateway-url", mock_gateway,
                "--", sys.executable, echo_server_script,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=os.path.join(os.path.dirname(__file__), "..", "src"),
        )
        assert proc.stdin is not None and proc.stdout is not None
        notification = {"jsonrpc": "2.0", "method": "notifications/initialized"}
        regular = {"jsonrpc": "2.0", "id": 1, "method": "test"}
        proc.stdin.write(json.dumps(notification).encode() + b"\n")
        proc.stdin.flush()
        time.sleep(0.3)
        proc.stdin.write(json.dumps(regular).encode() + b"\n")
        proc.stdin.flush()
        time.sleep(0.5)
        proc.stdin.close()
        proc.wait(timeout=10)
        stdout = proc.stdout.read()
        lines = [l for l in stdout.strip().split(b"\n") if l]
        found_regular = any(
            json.loads(l).get("id") == 1 for l in lines
        )
        assert found_regular

    def test_server_exit_code(self, tmp_path) -> None:
        """Proxy returns server's exit code."""
        script = tmp_path / "exit42.py"
        script.write_text("import sys; sys.exit(42)")
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m", "mcp_gateway.mcp_proxy",
                "--gateway-url", "http://127.0.0.1:9999",
                "--", sys.executable, str(script),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=os.path.join(os.path.dirname(__file__), "..", "src"),
        )
        _, _ = proc.communicate(timeout=10)
        assert proc.returncode == 42

    def test_concurrent_calls(self, echo_server_script: str, mock_gateway: str) -> None:
        """Multiple tools/call requests are handled correctly."""
        proc = subprocess.Popen(
            [
                sys.executable,
                "-m", "mcp_gateway.mcp_proxy",
                "--gateway-url", mock_gateway,
                "--", sys.executable, echo_server_script,
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=os.path.join(os.path.dirname(__file__), "..", "src"),
        )
        assert proc.stdin is not None and proc.stdout is not None
        for i in range(5):
            msg = {
                "jsonrpc": "2.0", "id": i,
                "method": "tools/call",
                "params": {"name": f"tool_{i}", "arguments": {"idx": i}},
            }
            proc.stdin.write(json.dumps(msg).encode() + b"\n")
            proc.stdin.flush()
            time.sleep(0.2)
        time.sleep(0.5)
        proc.stdin.close()
        proc.wait(timeout=15)
        stdout = proc.stdout.read()
        lines = [l for l in stdout.strip().split(b"\n") if l]
        ids = {json.loads(l)["id"] for l in lines}
        assert ids == {0, 1, 2, 3, 4}
