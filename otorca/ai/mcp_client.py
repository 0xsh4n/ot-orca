"""Minimal Model Context Protocol (MCP) client.

Lets OT-ORCA publish a scan result to an MCP server (e.g. a corporate LLM
gateway or an agent runtime) or call an MCP tool for enrichment. This is a
pragmatic stdio JSON-RPC 2.0 client covering ``initialize``, ``tools/list`` and
``tools/call`` — enough to hand a findings bundle to an MCP-exposed model or
threat-intel tool. It shells out to the server command the operator configures.

MCP is transport-agnostic; here we use the common stdio transport so the tool
works with locally launched servers without extra dependencies.
"""

from __future__ import annotations

import json
import subprocess
import threading
from typing import Any, Optional

from .base import AIBackendError


class MCPStdioClient:
    def __init__(self, command: list[str], timeout: int = 60):
        self.command = command
        self.timeout = timeout
        self._proc: Optional[subprocess.Popen] = None
        self._id = 0
        self._lock = threading.Lock()

    def __enter__(self) -> "MCPStdioClient":
        self.start()
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    def start(self) -> None:
        try:
            self._proc = subprocess.Popen(
                self.command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, text=True, bufsize=1)
        except FileNotFoundError as exc:
            raise AIBackendError(
                f"MCP server command not found: {self.command[0]}") from exc
        self._rpc("initialize", {
            "protocolVersion": "2024-11-05",
            "capabilities": {},
            "clientInfo": {"name": "OT-ORCA", "version": "1.0.0"},
        })
        self._notify("notifications/initialized", {})

    def close(self) -> None:
        if self._proc and self._proc.poll() is None:
            try:
                self._proc.terminate()
            except Exception:
                pass

    def _next_id(self) -> int:
        with self._lock:
            self._id += 1
            return self._id

    def _send(self, obj: dict) -> None:
        assert self._proc and self._proc.stdin
        self._proc.stdin.write(json.dumps(obj) + "\n")
        self._proc.stdin.flush()

    def _notify(self, method: str, params: dict) -> None:
        self._send({"jsonrpc": "2.0", "method": method, "params": params})

    def _rpc(self, method: str, params: dict) -> Any:
        if not self._proc or not self._proc.stdout:
            raise AIBackendError("MCP client not started")
        rid = self._next_id()
        self._send({"jsonrpc": "2.0", "id": rid, "method": method,
                    "params": params})
        # Read lines until we get the matching response id.
        while True:
            line = self._proc.stdout.readline()
            if not line:
                err = (self._proc.stderr.read() if self._proc.stderr else "")
                raise AIBackendError(f"MCP server closed the stream. {err[:200]}")
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except json.JSONDecodeError:
                continue
            if msg.get("id") == rid:
                if "error" in msg:
                    raise AIBackendError(f"MCP error: {msg['error']}")
                return msg.get("result")

    def list_tools(self) -> list[dict]:
        res = self._rpc("tools/list", {})
        return (res or {}).get("tools", [])

    def call_tool(self, name: str, arguments: dict) -> Any:
        return self._rpc("tools/call", {"name": name, "arguments": arguments})
