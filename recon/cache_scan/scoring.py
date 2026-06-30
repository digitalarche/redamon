"""
Cache Poisoning Scanner — Confidence scoring (Phase 5 of the native engine).

Cache poisoning results are high-noise; analysts distrust raw differential output.
This module turns a confirmation record into a confidence score + tier so only
trustworthy findings reach the graph. Inspired by the HCache validation model and
CacheX persistence logic described in the design doc.

Tiers (per the design doc):
  Confirmed  0.95-0.99  benign canary persists on a CLEAN request, cache hit
                        explicit or strongly evidenced, repetition succeeds.
  Strong     0.80-0.94  poisoned behaviour persists on a clean request, but the
                        cache hit is only inferred from stable behaviour.
  Tentative  0.50-0.79  only differential behaviour observed, no clean-request
                        persistence.
  Rejected   <0.50      change did not survive clean validation, or unstable.
"""


def score_finding(confirmation: dict) -> tuple[float, str]:
    """Map a confirmation record to (confidence, tier).

    Expected confirmation keys (from confirm.py):
      reflected_in_baseline (bool)  - payload changed the immediate response
      persisted_on_clean (bool)     - canary returned on a clean (no-payload) request
      cache_hit_on_clean (bool)     - that clean response was an explicit cache HIT
      repeated_ok (bool)            - second clean request also returned the canary
      stable (bool)                 - responses were stable across repeats
    """
    reflected = confirmation.get("reflected_in_baseline", False)
    persisted = confirmation.get("persisted_on_clean", False)
    cache_hit = confirmation.get("cache_hit_on_clean", False)
    repeated = confirmation.get("repeated_ok", False)
    stable = confirmation.get("stable", True)

    # Did a *reflected* canary (not just a behavioural diff) survive to the clean
    # request? That is the strongest proof and the only thing allowed to reach
    # "Confirmed". A differential-only (non-reflective) persistence is real but
    # inherently more coincidence-prone, so it is capped at "Strong".
    reflected_persist = confirmation.get("persisted_reflected")
    if reflected_persist is None:  # legacy record shape (pre-differential)
        reflected_persist = reflected and persisted

    # Rejected: nothing survived clean validation, or unstable noise.
    if not persisted:
        if reflected:
            return 0.40, "Rejected"   # reflected but not cached -> not WCP
        return 0.10, "Rejected"

    # Persisted on a clean request -> at minimum Strong.
    if persisted and cache_hit and repeated and stable:
        return (0.97, "Confirmed") if reflected_persist else (0.90, "Strong")
    if persisted and cache_hit and stable:
        return 0.90, "Strong"
    if persisted and stable:
        # persisted but cache-hit only inferred
        return 0.82, "Strong"
    if persisted:
        return 0.65, "Tentative"

    return 0.30, "Rejected"


def severity_for_impact(impact: str) -> tuple[str, float]:
    """Map an impact class to (severity, cvss_score). Lowercase severity per schema."""
    impact = (impact or "").lower()
    table = {
        "stored_xss": ("critical", 9.3),
        "open_redirect": ("high", 7.4),
        "deception": ("high", 7.5),       # private data exposure via cache
        "dos": ("high", 7.5),             # CPDoS
        "reflected": ("medium", 5.3),
        "unknown": ("medium", 5.0),
    }
    return table.get(impact, ("medium", 5.0))


def passes_min_confidence(confidence: float, settings: dict) -> bool:
    threshold = float(settings.get("WEB_CACHE_POISON_MIN_CONFIDENCE", 0.8))
    return confidence >= threshold
