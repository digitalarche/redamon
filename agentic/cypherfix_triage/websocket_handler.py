"""WebSocket handler for the triage agent."""

import asyncio
import json
import logging
import uuid
from fastapi import WebSocket, WebSocketDisconnect

from .orchestrator import TriageOrchestrator
from .state import TriageState

logger = logging.getLogger(__name__)


class TriageStreamingCallback:
    """Streams triage events to the frontend via WebSocket."""

    def __init__(self, websocket: WebSocket):
        self.ws = websocket

    async def on_phase(self, phase: str, description: str, progress: int = 0):
        await self._send("triage_phase", {
            "phase": phase, "description": description, "progress": progress,
        })

    async def on_finding(self, finding: dict):
        await self._send("triage_finding", finding)

    async def on_thinking(self, thought: str):
        await self._send("thinking", {"thought": thought})

    async def on_thinking_chunk(self, chunk: str):
        await self._send("thinking_chunk", {"chunk": chunk})

    async def on_tool_start(self, tool_name: str, tool_args: dict):
        display_args = {
            k: v[:200] if isinstance(v, str) and len(v) > 200 else v
            for k, v in tool_args.items()
        }
        await self._send("tool_start", {"tool_name": tool_name, "tool_args": display_args})

    async def on_tool_complete(self, tool_name: str, success: bool, output_summary: str):
        await self._send("tool_complete", {
            "tool_name": tool_name, "success": success,
            "output_summary": output_summary[:500],
        })

    async def on_complete(self, total: int, by_severity: dict, by_type: dict, summary: str):
        await self._send("triage_complete", {
            "total_remediations": total,
            "by_severity": by_severity,
            "by_type": by_type,
            "summary": summary,
        })

    async def on_error(self, message: str, recoverable: bool = True):
        await self._send("error", {"message": message, "recoverable": recoverable})

    async def _send(self, msg_type: str, payload: dict):
        try:
            await self.ws.send_json({"type": msg_type, "payload": payload})
        except Exception:
            pass


async def handle_triage_websocket(websocket: WebSocket):
    """Main WebSocket handler for triage agent connections.

    STRIDE S4: same-origin + fail-closed ws-ticket gate BEFORE accept(). Identity
    is bound from the verified ticket claims, never the self-asserted init frame.
    """
    import sys as _sys
    from pathlib import Path as _Path
    _agentic = str(_Path(__file__).resolve().parents[1])
    if _agentic not in _sys.path:
        _sys.path.insert(0, _agentic)
    from ws_ticket import authorize_ws, cors_allowlist

    _origin = websocket.headers.get("origin")
    _host = websocket.headers.get("host")
    _ticket = websocket.query_params.get("ticket")
    _ok, _claims, _reason = authorize_ws(_origin, _host, _ticket, cors_allowlist())
    if not _ok:
        logger.warning("Rejected /ws/cypherfix-triage: %s (origin=%r)", _reason, _origin)
        await websocket.close(code=1008)
        return

    await websocket.accept()
    callback = TriageStreamingCallback(websocket)

    state: TriageState | None = None
    orchestrator: TriageOrchestrator | None = None
    triage_task: asyncio.Task | None = None

    try:
        while True:
            raw = await websocket.receive_text()
            msg = json.loads(raw)
            msg_type = msg.get("type", "")

            if msg_type == "ping":
                await websocket.send_json({"type": "pong"})

            elif msg_type == "init":
                # Identity is bound from the VERIFIED ticket claims (S4), not the
                # self-asserted init frame.
                state: TriageState = {
                    "user_id": str(_claims["sub"]),
                    "project_id": str(_claims["pid"]),
                    "session_id": str(_claims["sid"]),
                    "settings": {},
                    "raw_data": {},
                    "analysis_result": None,
                    "status": "initializing",
                    "current_phase": "",
                    "error": None,
                }
                await websocket.send_json({
                    "type": "connected", "session_id": state["session_id"],
                })

            elif msg_type == "start_triage":
                if not state:
                    await callback.on_error("Not initialized. Send init first.", recoverable=True)
                    continue

                orchestrator = TriageOrchestrator(
                    user_id=state["user_id"],
                    project_id=state["project_id"],
                    callback=callback,
                )

                async def run_triage():
                    try:
                        await orchestrator.run(state)
                    except Exception as e:
                        logger.exception("Triage failed")
                        await callback.on_error(str(e), recoverable=False)

                triage_task = asyncio.create_task(run_triage())

            elif msg_type == "stop":
                if triage_task and not triage_task.done():
                    triage_task.cancel()
                    await websocket.send_json({"type": "stopped"})

    except WebSocketDisconnect:
        logger.info("Triage WebSocket disconnected")
    except Exception as e:
        logger.exception(f"Triage WebSocket error: {e}")
    finally:
        if triage_task and not triage_task.done():
            triage_task.cancel()
        if orchestrator:
            await orchestrator.cleanup()
