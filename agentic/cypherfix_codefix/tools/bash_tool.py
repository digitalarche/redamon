"""Bash tool: runs build/test commands in the isolated CodeFix sandbox (T6/E10).

A cloned repo is untrusted external input (poisoned postinstall scripts,
prompt-injected build steps). Running its build commands inside the agent
container would expose INTERNAL_API_KEY, the Neo4j/Postgres creds, every per-user
LLM key, and the GitHub token. So this tool does NOT execute locally: it forwards
the command to an ephemeral, secret-free, network-isolated sandbox via the webapp
passthrough. The sandbox is the security boundary; there is no local blocklist to
bypass because nothing runs here.
"""

from .. import sandbox_client


async def github_bash(state, command: str, timeout: int = 120000) -> str:
    """Run a shell command in the job's build sandbox (not the agent container)."""
    if not getattr(state, "job_id", ""):
        return "Error: build sandbox is not available for this session; cannot run commands."

    # Tool contract passes timeout in milliseconds; the sandbox takes seconds.
    timeout_seconds = max(1, min(int(timeout / 1000), 600))

    result = await sandbox_client.run_bash(state.job_id, command, timeout_seconds)
    output = result.get("output", "")
    exit_code = result.get("exit_code", 0)

    if exit_code not in (0, None):
        output += f"\n\n[Exit code: {exit_code}]"
    return output or "[no output]"
