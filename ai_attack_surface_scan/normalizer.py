"""Shared spine piece 3 — the findings normalizer (§6.3, §7).

Every tool has its own native parser; all parsers emit the SAME Finding shape,
which this module maps onto the existing `Vulnerability` label using the fields
the schema reserves for this lap (ai_owasp_llm_id, ai_asr, ai_trials, ...).
Zero new node labels. Findings link to the attacked Endpoint via
HAS_VULNERABILITY (fallback BaseURL -> Subdomain -> Domain), exactly like the
MCP static findings already produced by ai_surface_recon.
"""
from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass, field
from urllib.parse import urlparse

logger = logging.getLogger("ai-attack-surface")


@dataclass
class Finding:
    """The unified finding shape every tool adapter emits (§7)."""
    source: str                      # garak / pyrit / giskard / promptfoo / skeleton
    chip: str                        # prompt-injection / jailbreak / ...
    name: str
    baseurl: str
    path: str = "/"
    severity: str = "medium"
    description: str = ""
    ai_owasp_llm_id: str | None = None      # LLM01..LLM10
    ai_atlas_technique: str | None = None    # MITRE ATLAS AML.T*
    ai_asr: float = 0.0                       # attack success rate over trials
    ai_trials: int = 0
    ai_oracle_kind: str = "none"             # regex/contains/judge_llm/length/latency
    ai_payload_class: str = ""               # e.g. garak-promptinject
    ai_transcript_ref: str | None = None
    ai_probe_pack_version: str | None = None
    evidence: str | None = None
    extra: dict = field(default_factory=dict)

    @property
    def vuln_type(self) -> str:
        return f"ai_attack_{self.chip.replace('-', '_')}"


def finding_id(finding: Finding) -> str:
    """Deterministic id so dedup keys on OWASP-LLM id + target + payload class
    (§6.3): re-running the same tool against the same target updates rather than
    duplicates. Mirrors ai_surface_recon's aisr_<sha16> convention."""
    key = "|".join([
        finding.source,
        finding.ai_owasp_llm_id or finding.chip,
        finding.ai_payload_class or finding.chip,
        finding.baseurl or "",
        finding.path or "/",
    ])
    digest = hashlib.sha256(key.encode("utf-8")).hexdigest()[:16]
    return f"aiatk_{digest}"


def _target_url(finding: Finding) -> str:
    base = (finding.baseurl or "").rstrip("/")
    path = finding.path or "/"
    if path and not path.startswith("/"):
        path = "/" + path
    return f"{base}{path}"


def _props(finding: Finding, vid: str, user_id: str, project_id: str) -> dict:
    return {
        "id": vid,
        "user_id": user_id,
        "project_id": project_id,
        "source": finding.source,
        "type": finding.vuln_type,
        # The attacked URL, stored on the finding so custom (off-graph) targets
        # still display a target even when no Endpoint node exists to link to.
        "ai_target_url": _target_url(finding),
        "name": finding.name,
        "severity": (finding.severity or "medium").lower(),
        "description": finding.description or finding.name,
        "evidence": finding.evidence,
        "ai_owasp_llm_id": finding.ai_owasp_llm_id,
        "ai_atlas_technique": finding.ai_atlas_technique,
        "ai_asr": float(finding.ai_asr),
        "ai_trials": int(finding.ai_trials),
        "ai_oracle_kind": finding.ai_oracle_kind,
        "ai_payload_class": finding.ai_payload_class,
        "ai_transcript_ref": finding.ai_transcript_ref,
        "ai_probe_pack_version": finding.ai_probe_pack_version,
    }


def write_finding(session, finding: Finding, user_id: str, project_id: str) -> bool:
    """MERGE the Vulnerability and link it to the attacked Endpoint.

    Returns True if it linked to a specific Endpoint, False if it fell back to a
    coarser parent (BaseURL/Subdomain/Domain) or could not link at all.
    """
    vid = finding_id(finding)
    props = _props(finding, vid, user_id, project_id)

    session.run(
        """
        MERGE (v:Vulnerability {id: $id})
        ON CREATE SET v.first_seen = datetime()
        SET v += $props, v.updated_at = datetime()
        """,
        id=vid, props=props,
    )

    base_url = finding.baseurl
    path = finding.path or "/"
    host = urlparse(base_url).hostname or "" if base_url else ""

    linked = session.run(
        """
        MATCH (v:Vulnerability {id: $id})
        OPTIONAL MATCH (e:Endpoint {baseurl: $baseurl, user_id: $uid, project_id: $pid})
          WHERE e.path = $path
        // Prefer the AI-typed endpoint over a bare sibling on the same path.
        WITH v, e ORDER BY (CASE WHEN e.ai_interface_type IS NOT NULL THEN 0 ELSE 1 END) LIMIT 1
        FOREACH (_ IN CASE WHEN e IS NOT NULL THEN [1] ELSE [] END |
            MERGE (e)-[:HAS_VULNERABILITY]->(v))
        RETURN e IS NOT NULL AS linked
        """,
        id=vid, baseurl=base_url, path=path, uid=user_id, pid=project_id,
    ).single()

    if linked and linked.get("linked"):
        return True

    # Fallback: attach to the coarsest existing parent so the finding never orphans.
    session.run(
        """
        MATCH (v:Vulnerability {id: $id})
        OPTIONAL MATCH (b:BaseURL {url: $baseurl, user_id: $uid, project_id: $pid})
        OPTIONAL MATCH (s:Subdomain {name: $host, user_id: $uid, project_id: $pid})
        OPTIONAL MATCH (d:Domain {name: $host, user_id: $uid, project_id: $pid})
        WITH v, coalesce(b, s, d) AS parent
        FOREACH (_ IN CASE WHEN parent IS NOT NULL THEN [1] ELSE [] END |
            MERGE (parent)-[:HAS_VULNERABILITY]->(v))
        """,
        id=vid, baseurl=base_url, host=host, uid=user_id, pid=project_id,
    )
    return False


def make_dummy_finding(target, tool: str, run_id: str) -> Finding:
    """Step 2 skeleton: a hardcoded dummy finding per target, proving the
    graph-in / findings-out loop without any real attack tool."""
    return Finding(
        source=tool,
        chip="prompt-injection",
        name="AI Attack Surface skeleton dummy finding",
        baseurl=target.baseurl,
        path=target.path,
        severity="info",
        description=(
            "Placeholder finding emitted by the AI Attack Surface skeleton "
            "(no tool ran). Proves graph read -> normalize -> Vulnerability write."
        ),
        ai_owasp_llm_id="LLM01",
        ai_payload_class=f"{tool}-skeleton-dummy",
        ai_oracle_kind="none",
        ai_asr=0.0,
        ai_trials=0,
        ai_probe_pack_version=f"skeleton/{run_id or 'dev'}",
        evidence=f"interface={target.ai_interface_type} model={target.ai_model_family_guess}",
    )
