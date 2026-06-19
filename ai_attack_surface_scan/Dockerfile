# =============================================================================
# RedAmon AI Attack Surface Scanner — Python Container
# =============================================================================
# One image, PER-TOOL VIRTUALENVS. The attack tools' dependencies conflict and
# cannot share one environment (garak needs datasets<4.0; pyrit needs >=4.8.0;
# promptfoo is Node.js). So the shared spine (neo4j driver + main/target_loader/
# safety/normalizer) runs in the BASE interpreter, and each tool gets its own
# venv. Each adapter invokes its tool via that venv's interpreter as a subprocess.
# =============================================================================

FROM python:3.12-slim

LABEL maintainer="RedAmon Project"
LABEL description="AI Attack Surface deterministic offensive scanner for RedAmon"

WORKDIR /app

# Build tools some tool wheels need at install time. (Kept in the image; a future
# optimization could strip build-essential after the venvs are built to slim it.)
RUN apt-get update && apt-get install -y --no-install-recommends git build-essential \
    && rm -rf /var/lib/apt/lists/*

# --- Base (shared spine): just the Neo4j driver ---
COPY ai_attack_surface_scan/requirements.txt /tmp/base-requirements.txt
RUN pip install --no-cache-dir -r /tmp/base-requirements.txt

# --- Per-tool venvs (isolated, conflicting deps) ---
COPY ai_attack_surface_scan/adapters/garak/requirements.txt /tmp/garak-requirements.txt
RUN python -m venv /opt/venv-garak \
    && /opt/venv-garak/bin/pip install --no-cache-dir -U pip \
    && /opt/venv-garak/bin/pip install --no-cache-dir -r /tmp/garak-requirements.txt

COPY ai_attack_surface_scan/adapters/pyrit/requirements.txt /tmp/pyrit-requirements.txt
RUN python -m venv /opt/venv-pyrit \
    && /opt/venv-pyrit/bin/pip install --no-cache-dir -U pip \
    && /opt/venv-pyrit/bin/pip install --no-cache-dir -r /tmp/pyrit-requirements.txt

# Copy the scanner (spine + adapters). The runner scripts are invoked by their
# tool's venv; the spine runs in the base interpreter.
COPY ai_attack_surface_scan/ ./ai_attack_surface_scan/

RUN mkdir -p ai_attack_surface_scan/output

# Per-tool interpreter paths (adapters default to these; overridable for dev).
ENV GARAK_PYTHON=/opt/venv-garak/bin/python
ENV PYRIT_PYTHON=/opt/venv-pyrit/bin/python
ENV PYTHONPATH=/app/ai_attack_surface_scan
ENV PYTHONUNBUFFERED=1

CMD ["python", "ai_attack_surface_scan/main.py"]
