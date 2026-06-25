"""Unit tests for the recon-start pre-flight guardrail path.

The orchestrator's pre-flight (api.py /recon/start) fetches the project from the
webapp to run the deterministic hard guardrail + RoE time-window check. Before the
5.1.0 fix it called the client-supplied ``localhost:3000`` (unreachable from the
orchestrator container -> check silently skipped). It now uses the orchestrator's
own ``_trusted_webapp_base()`` (``http://webapp:3000``), reachable after V1 put the
orchestrator on a shared network with the webapp. These tests pin both the
guardrail decision logic and the URL helper.

Run (pytest available in CI / dev): python -m pytest tests/test_guardrail_webapp_base.py -q
"""
import api
from hard_guardrail import is_hard_blocked


def test_gov_domain_is_hard_blocked():
    blocked, reason = is_hard_blocked("whitehouse.gov")
    assert blocked is True
    assert reason  # non-empty human-readable reason


def test_exact_listed_domain_is_hard_blocked():
    blocked, _ = is_hard_blocked("un.org")
    assert blocked is True


def test_normal_domain_is_allowed():
    blocked, _ = is_hard_blocked("example.com")
    assert blocked is False


def test_trusted_webapp_base_defaults_to_docker_dns(monkeypatch):
    # No env set -> the orchestrator must NOT fall back to localhost (the old bug);
    # it defaults to the webapp's docker DNS name.
    monkeypatch.delenv("WEBAPP_API_URL", raising=False)
    assert api._trusted_webapp_base() == "http://webapp:3000"


def test_trusted_webapp_base_honours_env_and_strips_slash(monkeypatch):
    monkeypatch.setenv("WEBAPP_API_URL", "http://webapp:3000/")
    assert api._trusted_webapp_base() == "http://webapp:3000"


def test_trusted_webapp_base_is_never_localhost(monkeypatch):
    # Regression guard: the pre-flight target must never resolve to the
    # orchestrator's own loopback (which silently disabled the guardrail/RoE).
    monkeypatch.delenv("WEBAPP_API_URL", raising=False)
    assert "localhost" not in api._trusted_webapp_base()
    assert "127.0.0.1" not in api._trusted_webapp_base()


# --- V2: spawned-container webapp URL is server-controlled, never client input ---

def test_spawned_webapp_url_defaults_to_host_published_localhost(monkeypatch):
    # Spawned scan containers run on the HOST network and must reach the webapp
    # via the host-published port, not the `webapp` DNS name.
    monkeypatch.delenv("SPAWNED_WEBAPP_API_URL", raising=False)
    assert api._spawned_webapp_url() == "http://localhost:3000"


def test_spawned_webapp_url_honours_env_and_strips_slash(monkeypatch):
    monkeypatch.setenv("SPAWNED_WEBAPP_API_URL", "http://localhost:3000/")
    assert api._spawned_webapp_url() == "http://localhost:3000"


def test_spawned_webapp_url_ignores_any_request_value(monkeypatch):
    # V2 invariant: the value the orchestrator forwards to spawned containers
    # (which carries INTERNAL_API_KEY) comes only from server-side env, so an
    # attacker-supplied request.webapp_api_url can never redirect that key.
    monkeypatch.setenv("SPAWNED_WEBAPP_API_URL", "http://localhost:3000")
    attacker = "http://attacker.example"
    assert attacker not in api._spawned_webapp_url()
    # The two webapp URLs are intentionally different (bridge DNS vs host port).
    monkeypatch.setenv("WEBAPP_API_URL", "http://webapp:3000")
    assert api._spawned_webapp_url() != api._trusted_webapp_base()
