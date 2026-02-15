#!/usr/bin/env python3
"""MCP Transparent Proxy — full-duplex, model-agnostic.

Sits between an MCP client (Claude Code) and an MCP server (e.g. filesystem),
intercepting ``tools/call`` requests via the Gateway security API.

Architecture (3 threads):
  Thread 1 (client→server): reads stdin, checks security, forwards or blocks
  Thread 2 (server→client): reads server stdout, forwards to client stdout
  Thread 3 (stderr drain) : reads server stderr, forwards to parent stderr

MCP stdio transport = newline-delimited JSON (one JSON object per line).

Usage::

    python mcp_proxy.py [--gateway-url URL] [--timeout 5] [--fail-closed] \\
        -- npx -y @modelcontextprotocol/server-filesystem .
"""

from __future__ import annotations

import atexit
import hashlib
import json
import logging
import os
import re
import signal
import subprocess
import sys
import threading
import time
from typing import IO, Any
from urllib.error import URLError
from urllib.request import Request, urlopen

# ---------------------------------------------------------------------------
# Logging (all output goes to stderr; stdout is MCP-only)
# ---------------------------------------------------------------------------
logging.basicConfig(
    stream=sys.stderr,
    level=logging.DEBUG if os.environ.get("MCP_PROXY_DEBUG") else logging.INFO,
    format="[mcp-proxy] %(levelname)s %(message)s",
)
log = logging.getLogger("mcp-proxy")

# ---------------------------------------------------------------------------
# Redaction (Audit 1 F7)
# ---------------------------------------------------------------------------
_REDACT_RE = re.compile(
    r"(secret|key|token|password|credential|auth)([\"']?\s*[:=]\s*[\"']?)"
    r"([^\s\"',}{]{4,})",
    re.IGNORECASE,
)


def redact_args(text: str) -> str:
    """Replace sensitive-looking values with [REDACTED]."""
    return _REDACT_RE.sub(r"\1\2[REDACTED]", text)


# ---------------------------------------------------------------------------
# MCP framing: newline-delimited JSON (Audit 2 H1)
# ---------------------------------------------------------------------------


def read_message(stream: IO[bytes]) -> dict[str, Any] | None:
    """Read one newline-delimited JSON message. Returns None on EOF."""
    while True:
        line = stream.readline()
        if not line:
            return None  # EOF
        line = line.strip()
        if not line:
            continue  # skip blank lines
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            log.warning(
                "non-JSON line skipped: %s",
                redact_args(line.decode("utf-8", errors="replace")[:200]),
            )
            continue


def write_message(stream: IO[bytes], msg: dict[str, Any], lock: threading.Lock) -> None:
    """Write one newline-delimited JSON message (thread-safe)."""
    data = (
        json.dumps(msg, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        + b"\n"
    )
    with lock:
        stream.write(data)
        stream.flush()


# ---------------------------------------------------------------------------
# Circuit Breaker (Audit 1 F5, Audit 2 L2)
# ---------------------------------------------------------------------------


class CircuitBreaker:
    """Simple circuit breaker for gateway communication."""

    THRESHOLD = 3
    RECOVERY_SECONDS = 60.0

    def __init__(self) -> None:
        self._failures = 0
        self._opened_at: float | None = None
        self._lock = threading.Lock()

    @property
    def state(self) -> str:
        with self._lock:
            if self._failures < self.THRESHOLD:
                return "CLOSED"
            elapsed = time.monotonic() - (self._opened_at or 0)
            if elapsed >= self.RECOVERY_SECONDS:
                return "HALF-OPEN"
            return "OPEN"

    def record_success(self) -> None:
        with self._lock:
            self._failures = 0
            self._opened_at = None

    def record_failure(self) -> None:
        with self._lock:
            self._failures += 1
            if self._failures >= self.THRESHOLD:
                self._opened_at = time.monotonic()


# ---------------------------------------------------------------------------
# Security check via Gateway API
# ---------------------------------------------------------------------------


def check_security(
    tool_name: str,
    arguments: dict[str, Any],
    gateway_url: str,
    timeout: float,
    circuit: CircuitBreaker,
    fail_closed: bool,
) -> tuple[bool, str]:
    """Ask the Gateway whether a tool call is allowed.

    Returns (allowed: bool, reason: str).
    """
    state = circuit.state
    if state == "OPEN":
        if fail_closed:
            return False, "circuit-breaker OPEN (fail-closed)"
        return True, "circuit-breaker OPEN (fail-open)"

    url = f"{gateway_url.rstrip('/')}/api/mcp/intercept"
    body = json.dumps(
        {
            "method": f"tools/{tool_name}",
            "params": arguments,
        }
    ).encode("utf-8")

    req = Request(url, data=body, headers={"Content-Type": "application/json"})
    try:
        with urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read())
        circuit.record_success()
        allowed = data.get("allowed", True)
        reason = data.get("reason", "")
        return allowed, reason
    except (URLError, OSError, json.JSONDecodeError, KeyError) as exc:
        circuit.record_failure()
        log.warning("gateway error: %s", exc)
        if fail_closed:
            return False, f"gateway unreachable (fail-closed): {exc}"
        return True, f"gateway unreachable (fail-open): {exc}"


# ---------------------------------------------------------------------------
# Blocked response (MCP-compliant)
# ---------------------------------------------------------------------------


def make_blocked_response(request_id: Any, reason: str) -> dict[str, Any]:
    """Build a JSON-RPC result that signals an error to the MCP client."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "result": {
            "content": [
                {"type": "text", "text": f"[MCP Gateway] BLOCKED: {reason}"},
            ],
            "isError": True,
        },
    }


# ---------------------------------------------------------------------------
# Threads
# ---------------------------------------------------------------------------


def client_to_server(
    client_in: IO[bytes],
    server_in: IO[bytes],
    client_out: IO[bytes],
    server_in_lock: threading.Lock,
    client_out_lock: threading.Lock,
    gateway_url: str,
    timeout: float,
    circuit: CircuitBreaker,
    fail_closed: bool,
    shutdown_event: threading.Event,
) -> None:
    """Thread 1: read from client stdin, check security, forward or block."""
    try:
        while not shutdown_event.is_set():
            msg = read_message(client_in)
            if msg is None:
                log.debug("client stdin EOF")
                break

            method = msg.get("method", "")

            # Only intercept tools/call
            if method == "tools/call":
                params = msg.get("params", {})
                tool_name = params.get("name", "")
                arguments = params.get("arguments", {})

                args_hash = hashlib.sha256(
                    json.dumps(arguments, sort_keys=True).encode()
                ).hexdigest()[:16]
                log.info(
                    "intercept tools/call: %s (args_hash=%s)",
                    tool_name,
                    args_hash,
                )

                allowed, reason = check_security(
                    tool_name, arguments, gateway_url, timeout, circuit, fail_closed
                )

                if not allowed:
                    log.warning(
                        "BLOCKED: %s reason=%s args=%s",
                        tool_name,
                        reason,
                        redact_args(json.dumps(arguments)[:500]),
                    )
                    resp = make_blocked_response(msg.get("id"), reason)
                    write_message(client_out, resp, client_out_lock)
                    continue
                else:
                    log.debug("ALLOWED: %s reason=%s", tool_name, reason)

            # Forward to server
            data = (
                json.dumps(msg, separators=(",", ":"), ensure_ascii=False).encode(
                    "utf-8"
                )
                + b"\n"
            )
            with server_in_lock:
                server_in.write(data)
                server_in.flush()
    except (BrokenPipeError, OSError):
        log.debug("client_to_server pipe closed")
    finally:
        # Close server stdin to signal EOF (Audit 2 H3)
        try:
            server_in.close()
        except OSError:
            pass
        shutdown_event.set()


def server_to_client(
    server_out: IO[bytes],
    client_out: IO[bytes],
    client_out_lock: threading.Lock,
    shutdown_event: threading.Event,
) -> None:
    """Thread 2: read from server stdout, forward to client stdout."""
    try:
        while not shutdown_event.is_set():
            msg = read_message(server_out)
            if msg is None:
                log.debug("server stdout EOF")
                break
            write_message(client_out, msg, client_out_lock)
    except (BrokenPipeError, OSError):
        log.debug("server_to_client pipe closed")
    finally:
        shutdown_event.set()


def drain_stderr(server_stderr: IO[bytes], shutdown_event: threading.Event) -> None:
    """Thread 3: drain server stderr to parent stderr (Audit 2 H2)."""
    try:
        while not shutdown_event.is_set():
            line = server_stderr.readline()
            if not line:
                break
            sys.stderr.buffer.write(line)
            sys.stderr.buffer.flush()
    except (BrokenPipeError, OSError):
        pass


# ---------------------------------------------------------------------------
# Main proxy loop
# ---------------------------------------------------------------------------


def run_proxy(
    server_cmd: list[str],
    gateway_url: str,
    timeout: float = 5.0,
    fail_closed: bool = False,
) -> int:
    """Launch the MCP server and proxy traffic through the Gateway.

    Returns the server's exit code (or 1 on error).
    """
    log.info("starting MCP server: %s", server_cmd)
    log.info(
        "gateway: %s (timeout=%ss, fail_closed=%s)", gateway_url, timeout, fail_closed
    )

    proc = subprocess.Popen(
        server_cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )

    # atexit: ensure child is terminated (Audit 2 H3)
    def _cleanup() -> None:
        if proc.poll() is None:
            log.debug("atexit: terminating server")
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()

    atexit.register(_cleanup)

    # SIGTERM handler (Audit 2 H3)
    def _sigterm(signum: int, frame: Any) -> None:
        log.info("SIGTERM received, shutting down")
        if proc.poll() is None:
            proc.terminate()
        sys.exit(0)

    signal.signal(signal.SIGTERM, _sigterm)

    circuit = CircuitBreaker()
    shutdown_event = threading.Event()
    server_in_lock = threading.Lock()
    client_out_lock = threading.Lock()

    assert proc.stdin is not None
    assert proc.stdout is not None
    assert proc.stderr is not None

    t1 = threading.Thread(
        target=client_to_server,
        args=(
            sys.stdin.buffer,
            proc.stdin,
            sys.stdout.buffer,
            server_in_lock,
            client_out_lock,
            gateway_url,
            timeout,
            circuit,
            fail_closed,
            shutdown_event,
        ),
        daemon=True,
        name="client_to_server",
    )
    t2 = threading.Thread(
        target=server_to_client,
        args=(proc.stdout, sys.stdout.buffer, client_out_lock, shutdown_event),
        daemon=True,
        name="server_to_client",
    )
    t3 = threading.Thread(
        target=drain_stderr,
        args=(proc.stderr, shutdown_event),
        daemon=True,
        name="drain_stderr",
    )

    t1.start()
    t2.start()
    t3.start()

    # Wait for child process to exit
    exit_code = proc.wait()
    shutdown_event.set()
    log.info("server exited with code %d", exit_code)

    # Give threads time to flush
    for t in (t1, t2, t3):
        t.join(timeout=2.0)

    return exit_code


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main() -> None:
    """Parse args and run the proxy."""
    import argparse

    parser = argparse.ArgumentParser(
        description="MCP transparent security proxy",
        usage="%(prog)s [OPTIONS] -- SERVER_CMD [ARGS...]",
    )
    parser.add_argument(
        "--gateway-url",
        default=os.environ.get("MCP_GATEWAY_URL", "http://127.0.0.1:4100"),
        help="Gateway API base URL (default: $MCP_GATEWAY_URL or http://127.0.0.1:4100)",
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=float(os.environ.get("MCP_PROXY_TIMEOUT", "5")),
        help="HTTP timeout for gateway calls in seconds (default: 5)",
    )
    parser.add_argument(
        "--fail-closed",
        action="store_true",
        default=os.environ.get("MCP_PROXY_FAIL_CLOSED", "").lower()
        in ("1", "true", "yes"),
        help="Block all calls when gateway is unreachable (default: fail-open)",
    )

    # Everything after -- is the server command
    if "--" in sys.argv:
        sep_idx = sys.argv.index("--")
        our_args = sys.argv[1:sep_idx]
        server_cmd = sys.argv[sep_idx + 1 :]
    else:
        our_args = sys.argv[1:]
        server_cmd = []

    args = parser.parse_args(our_args)

    if not server_cmd:
        parser.error("no server command provided (use -- CMD [ARGS...])")

    exit_code = run_proxy(
        server_cmd=server_cmd,
        gateway_url=args.gateway_url,
        timeout=args.timeout,
        fail_closed=args.fail_closed,
    )
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
