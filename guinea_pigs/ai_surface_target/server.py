"""
AI Surface Recon — Guinea Pig HTTP target.

Listens on every port + path the lap-1 catalog cares about, returns
deterministic responses that fire each detection. No LLM, no model
weights, no GPU — just a Python aiohttp process producing surface signals.

Layout:
    16 per-port listeners (one aiohttp app per AI product port)
    +  1 header showroom on port 9100 (20 framework variants)
    +  1 title  showroom on port 9101 (18 product variants)
    = 18 ports bound to 0.0.0.0

The recon container reaches this via `network_mode: host` → 127.0.0.1:*.
"""
from __future__ import annotations

import asyncio
import logging
import signal
import sys

from aiohttp import web

from ai_signals import (
    ENDPOINT_AI_CLASSIFIER_PORT,
    HEADER_SHOWROOM_PORT,
    HEADER_VARIANTS,
    JS_RECON_AI_SDK_FIXTURES,
    JS_RECON_AI_SDK_PORT,
    PORT_LISTENERS,
    RESOURCE_ENUM_AI_PATHS,
    RESOURCE_ENUM_AI_RAG_PATHS,
    TITLE_SHOWROOM_PORT,
    TITLE_VARIANTS,
)


# Port for the jsluice URL-verification end-to-end target. Independent of the
# AI surface ports above so the AI lap-1 catalog tests stay untouched.
JSLUICE_TARGET_PORT = 9102


# ---------------------------------------------------------------------------
# Logging — concise, single-line per request
# ---------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("guinea-pig")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _html(title: str, body: str = "") -> str:
    return (
        "<!DOCTYPE html><html><head>"
        f"<title>{title}</title>"
        "<meta charset='utf-8'></head><body>"
        f"<h1>{title}</h1><pre>{body}</pre>"
        "<p>RedAmon AI surface guinea pig — deterministic stub.</p>"
        "</body></html>"
    )


def _empty_favicon() -> web.Response:
    # Tiny PNG-style placeholder so httpx -favicon doesn't 404.
    # Hash is irrelevant for lap-1 (catalog is empty); Phase 15 will use a
    # known mmh3 hash here.
    return web.Response(body=b"\x00", content_type="image/x-icon")


# ---------------------------------------------------------------------------
# Per-product port handler factory
# ---------------------------------------------------------------------------

def make_port_app(descriptor: dict) -> web.Application:
    app = web.Application()
    app["descriptor"] = descriptor

    @web.middleware
    async def server_header_mw(request: web.Request, handler) -> web.Response:
        response = await handler(request)
        response.headers["Server"] = descriptor.get("server_header", "ai-test-target")
        return response

    app.middlewares.append(server_header_mw)

    async def root(request: web.Request) -> web.Response:
        body = (
            f"product       = {descriptor['name']}\n"
            f"port          = {descriptor['port']}\n"
            f"server_banner = {descriptor.get('server_header', '')}\n"
        )
        return web.Response(
            text=_html(descriptor.get("html_title", descriptor["name"]), body),
            content_type="text/html",
        )

    async def favicon(_request: web.Request) -> web.Response:
        return _empty_favicon()

    async def healthz(_request: web.Request) -> web.Response:
        return web.Response(text="ok", content_type="text/plain")

    app.router.add_get("/", root)
    app.router.add_get("/favicon.ico", favicon)
    app.router.add_get("/healthz", healthz)
    return app


# ---------------------------------------------------------------------------
# Header showroom (port 9100) — emit AI headers per /header/<framework>
# ---------------------------------------------------------------------------

def make_header_showroom_app() -> web.Application:
    app = web.Application()

    async def index(_request: web.Request) -> web.Response:
        links = "\n".join(
            f"  <li><a href='/header/{k}'>/header/{k}</a> &mdash; "
            f"{', '.join(v['headers'].keys())} → {v['expected_framework']}/{v['expected_category']}</li>"
            for k, v in HEADER_VARIANTS.items()
        )
        body = _html(
            "AI Header Showroom",
            f"GET /header/&lt;framework&gt; returns response carrying that AI header.\n\n<ul>\n{links}\n</ul>",
        )
        return web.Response(text=body, content_type="text/html")

    async def emit(request: web.Request) -> web.Response:
        framework = request.match_info["framework"]
        info = HEADER_VARIANTS.get(framework)
        if not info:
            return web.Response(
                text=f"unknown framework: {framework}",
                status=404,
                content_type="text/plain",
            )
        body = _html(
            f"AI Header: {framework}",
            "\n".join(f"{k}: {v}" for k, v in info["headers"].items()),
        )
        response = web.Response(text=body, content_type="text/html")
        for h_name, h_value in info["headers"].items():
            response.headers[h_name] = h_value
        response.headers["Server"] = "ai-test-target/header-showroom"
        return response

    async def favicon(_r: web.Request) -> web.Response:
        return _empty_favicon()

    async def healthz(_r: web.Request) -> web.Response:
        return web.Response(text="ok", content_type="text/plain")

    app.router.add_get("/", index)
    app.router.add_get("/header/{framework}", emit)
    app.router.add_get("/favicon.ico", favicon)
    app.router.add_get("/healthz", healthz)
    return app


# ---------------------------------------------------------------------------
# Title showroom (port 9101) — emit AI titles per /title/<product>
# ---------------------------------------------------------------------------

def make_title_showroom_app() -> web.Application:
    app = web.Application()

    async def index(_request: web.Request) -> web.Response:
        links = "\n".join(
            f"  <li><a href='/title/{k}'>/title/{k}</a> &mdash; "
            f"&lt;title&gt;{v['title']}&lt;/title&gt; → {v['expected_product']}</li>"
            for k, v in TITLE_VARIANTS.items()
        )
        body = _html(
            "AI Title Showroom",
            f"GET /title/&lt;product&gt; returns HTML with the matching &lt;title&gt;.\n\n<ul>\n{links}\n</ul>",
        )
        return web.Response(text=body, content_type="text/html")

    async def emit(request: web.Request) -> web.Response:
        product = request.match_info["product"]
        info = TITLE_VARIANTS.get(product)
        if not info:
            return web.Response(
                text=f"unknown product: {product}",
                status=404,
                content_type="text/plain",
            )
        body = _html(info["title"], f"product = {product}")
        response = web.Response(text=body, content_type="text/html")
        response.headers["Server"] = "ai-test-target/title-showroom"
        return response

    async def favicon(_r: web.Request) -> web.Response:
        return _empty_favicon()

    async def healthz(_r: web.Request) -> web.Response:
        return web.Response(text="ok", content_type="text/plain")

    app.router.add_get("/", index)
    app.router.add_get("/title/{product}", emit)
    app.router.add_get("/favicon.ico", favicon)
    app.router.add_get("/healthz", healthz)
    return app


# ---------------------------------------------------------------------------
# jsluice URL-verification target (port 9102)
#
# Serves a tiny HTML entry point that links to an application JS file. The JS
# file embeds a deliberately mixed bag of URL strings that exercise every
# branch of the jsluice deny-list + httpx verifier:
#
#   live  + .json  → /api/v1/users.json   (proves B1: .json survives .js rule)
#   live  + path   → /api/products
#   live  + 403    → /admin                (proves accept_status default 403)
#   dead  + 404    → /api/deprecated       (proves fail-closed for dead URL)
#   noise + lib    → /node_modules/...     (deny-list drops before httpx)
#   noise + lib    → /rxjs/static-5.10     (deny-list drops before httpx)
#   noise + asset  → /assets/logo.png      (deny-list drops before httpx)
#
# Noise paths are intentionally NOT served — if the deny-list ever stops
# filtering them, httpx would 404 the path and they still wouldn't reach the
# graph. The deny-list is the guard we care about.
# ---------------------------------------------------------------------------

JSLUICE_APP_JS = b"""
// Mixed-signal JS for end-to-end jsluice verification testing.
// Each fetch / string literal below should exercise a specific branch of the
// jsluice deny-list + httpx verifier.

const USERS_API = '/api/v1/users.json';      // live + .json (B1 regression)
fetch('/api/products');                       // live + path
fetch('/admin');                              // live + 403 (accept_status)
fetch('/api/deprecated');                    // dead + 404 (fail-closed)

// Noise that the deny-list MUST drop before httpx ever probes it.
const LIB    = '/node_modules/lodash/index.js';
const BUNDLE = '/rxjs/static-5.10';
const LOGO   = '/assets/logo.png';

export { USERS_API, LIB, BUNDLE, LOGO };
"""


def make_endpoint_ai_classifier_app() -> web.Application:
    """Lap-2 — resource_enum AI classifier showroom.

    Serves an HTML index linking to every catalogued AI path. Each link
    carries query-string params (some prompt-injectable, some control) so
    Katana picks them up as Endpoint + Parameter nodes. The resource_enum
    AI classifier then tags each endpoint with `ai_interface_type` /
    `is_ai_rag_ingest` and each prompt-named param with
    `is_ai_prompt_injectable=true`.

    Every linked URL serves a trivial 200 OK — the goal is discovery, not
    realism. The classifier reads from the graph, not from the response.
    """
    app = web.Application()

    all_entries = RESOURCE_ENUM_AI_PATHS + RESOURCE_ENUM_AI_RAG_PATHS

    def _qs(entry: dict) -> str:
        params = entry.get("prompt_params", []) + entry.get("control_params", [])
        return "&".join(f"{p}=demo" for p in params)

    async def index(_request: web.Request) -> web.Response:
        rows = []
        for entry in RESOURCE_ENUM_AI_PATHS:
            params = entry.get("prompt_params", []) + entry.get("control_params", [])
            href = entry["path"] + (("?" + _qs(entry)) if params else "")
            rows.append(
                f"  <li><a href='{href}'>{entry['path']}</a> &mdash; "
                f"<code>{entry['enum']}</code>"
                + (f" (params: {', '.join(params)})" if params else "")
                + "</li>"
            )
        rag_rows = []
        for entry in RESOURCE_ENUM_AI_RAG_PATHS:
            params = entry.get("prompt_params", []) + entry.get("control_params", [])
            href = entry["path"] + (("?" + _qs(entry)) if params else "")
            rag_rows.append(
                f"  <li><a href='{href}'>{entry['path']}</a> &mdash; RAG"
                + (f" (params: {', '.join(params)})" if params else "")
                + "</li>"
            )
        body = (
            "<!DOCTYPE html><html><head>"
            "<title>RedAmon Endpoint AI Classifier Showroom</title>"
            "</head><body>"
            "<h1>Endpoint AI Classifier Showroom</h1>"
            "<p>Katana discovers these links. The resource_enum AI classifier "
            "stamps <code>Endpoint.ai_interface_type</code> and "
            "<code>is_ai_rag_ingest</code> based on path; "
            "<code>Parameter.is_ai_prompt_injectable=true</code> on the prompt-named params.</p>"
            f"<h2>AI Interface Type paths ({len(RESOURCE_ENUM_AI_PATHS)})</h2>"
            "<ul>\n" + "\n".join(rows) + "\n</ul>"
            f"<h2>RAG ingestion / retrieval paths ({len(RESOURCE_ENUM_AI_RAG_PATHS)})</h2>"
            "<ul>\n" + "\n".join(rag_rows) + "\n</ul>"
            "</body></html>"
        )
        return web.Response(text=body, content_type="text/html")

    async def catch_all(request: web.Request) -> web.Response:
        # Echo the path and parsed query string. 200 OK is enough — the
        # classifier reads from the graph, not from the response body.
        path = request.path
        return web.Response(
            text=f"OK — guinea pig endpoint: {path}\nquery: {dict(request.query)}\n",
            content_type="text/plain",
        )

    async def favicon(_r: web.Request) -> web.Response:
        return _empty_favicon()

    async def healthz(_r: web.Request) -> web.Response:
        return web.Response(text="ok", content_type="text/plain")

    app.router.add_get("/", index)
    app.router.add_get("/favicon.ico", favicon)
    app.router.add_get("/healthz", healthz)
    # Register every catalogued path as a no-op 200 OK.
    seen: set[str] = set()
    for entry in all_entries:
        p = entry["path"]
        if p in seen:
            continue
        seen.add(p)
        app.router.add_get(p, catch_all)
    return app


# ---------------------------------------------------------------------------
# Lap-3 (Phase 6) — js_recon AI SDK showroom (port 9104)
#
# Serves an HTML index that links to every fixture JS file via <script>
# tags. Katana follows the script tags; js_recon downloads each .js, runs
# match_ai_sdk() against the content, and writes JsReconFinding nodes with
# finding_type ai-sdk-*. The mixin then enriches matching Secret nodes
# with ai_provider.
#
# Each fixture is engineered to exercise one or more detection branches:
#   - SDK imports (single + sub-path + multi-vendor)
#   - constructor-context key literals (suppresses prefix duplicate)
#   - prefix-anchored key literals (for SDK-less fetch calls)
#   - dangerouslyAllowBrowser opt-in (bareword + terser !0 + JSON form)
#   - Gemini disambiguation BOTH WAYS (with and without context)
#   - frontend product markers (Open WebUI, Gradio, Flowise, SillyTavern)
#   - provider base URLs (OpenAI, Anthropic, Groq, OpenRouter, etc.)
#   - Bearer + x-api-key header literals
#   - env-var hydration leak (NEXT_PUBLIC_*)
#   - negative cases (jQuery, Stripe) for false-positive regression
# ---------------------------------------------------------------------------

def make_js_recon_ai_sdk_app() -> web.Application:
    app = web.Application()

    # Index of {filename: bytes} so the JS handler is O(1) per request.
    fixtures_by_name = {f["filename"]: f for f in JS_RECON_AI_SDK_FIXTURES}

    async def index(_request: web.Request) -> web.Response:
        # Generate <script> tags so Katana picks up every JS file as a JS
        # discovery edge. Also list them in a human-readable table.
        script_tags = "\n".join(
            f"  <script src='/static/{f['filename']}'></script>"
            for f in JS_RECON_AI_SDK_FIXTURES
        )
        rows = []
        for f in JS_RECON_AI_SDK_FIXTURES:
            expected = ", ".join(
                f"{e['category']}" + (f"({e.get('sdk_name', '?')})"
                                       if 'sdk_name' in e else "")
                for e in f["expected_findings"]
            ) or "(none — negative case)"
            rows.append(
                f"  <tr>"
                f"<td><a href='/static/{f['filename']}'><code>{f['filename']}</code></a></td>"
                f"<td>{f['description']}</td>"
                f"<td><code>{expected}</code></td>"
                f"</tr>"
            )
        body = (
            "<!DOCTYPE html><html><head>"
            "<title>RedAmon JS Recon AI SDK Showroom</title>"
            "<meta charset='utf-8'>"
            "<style>table{border-collapse:collapse;font-family:monospace;}"
            "th,td{border:1px solid #444;padding:6px;text-align:left;vertical-align:top;}"
            "code{background:#eee;padding:1px 4px;}</style>"
            f"{script_tags}\n"
            "</head><body>"
            "<h1>JS Recon AI SDK Showroom (Phase 6)</h1>"
            f"<p>Serves {len(JS_RECON_AI_SDK_FIXTURES)} fixture JS files that "
            "exercise every detection branch in <code>match_ai_sdk()</code>. "
            "Katana follows the <code>&lt;script&gt;</code> tags above; "
            "js_recon downloads each file and the catalogue emits "
            "JsReconFinding nodes with finding_type <code>ai-sdk-*</code>.</p>"
            "<table>"
            "<thead><tr><th>Fixture</th><th>Purpose</th>"
            "<th>Expected match_ai_sdk findings</th></tr></thead>"
            "<tbody>" + "\n".join(rows) + "</tbody></table>"
            "</body></html>"
        )
        return web.Response(text=body, content_type="text/html")

    async def serve_js(request: web.Request) -> web.Response:
        filename = request.match_info["filename"]
        fixture = fixtures_by_name.get(filename)
        if not fixture:
            return web.Response(text=f"unknown fixture: {filename}",
                                status=404, content_type="text/plain")
        # NB: served as application/javascript so httpx/katana treat it as
        # JS and js_recon downloads it. The content itself is what the AI
        # SDK detection catalogue scans.
        return web.Response(text=fixture["content"],
                            content_type="application/javascript")

    async def favicon(_r: web.Request) -> web.Response:
        return _empty_favicon()

    async def healthz(_r: web.Request) -> web.Response:
        return web.Response(text="ok", content_type="text/plain")

    app.router.add_get("/", index)
    app.router.add_get("/static/{filename}", serve_js)
    app.router.add_get("/favicon.ico", favicon)
    app.router.add_get("/healthz", healthz)
    return app


def make_jsluice_target_app() -> web.Application:
    app = web.Application()

    async def index(_r: web.Request) -> web.Response:
        body = (
            "<!DOCTYPE html><html><head>"
            "<title>RedAmon jsluice verifier target</title>"
            "<script src='/static/app.js'></script>"
            "</head><body><h1>jsluice target</h1>"
            "<p>Katana follows the script tag; jsluice extracts the URLs.</p>"
            "</body></html>"
        )
        return web.Response(text=body, content_type="text/html")

    async def app_js(_r: web.Request) -> web.Response:
        return web.Response(body=JSLUICE_APP_JS, content_type="application/javascript")

    async def users_json(_r: web.Request) -> web.Response:
        return web.json_response({"users": []})

    async def products(_r: web.Request) -> web.Response:
        return web.json_response({"products": []})

    async def admin(_r: web.Request) -> web.Response:
        return web.Response(text="forbidden", status=403)

    async def deprecated(_r: web.Request) -> web.Response:
        return web.Response(text="gone", status=404)

    async def favicon(_r: web.Request) -> web.Response:
        return _empty_favicon()

    async def healthz(_r: web.Request) -> web.Response:
        return web.Response(text="ok", content_type="text/plain")

    app.router.add_get("/", index)
    app.router.add_get("/static/app.js", app_js)
    app.router.add_get("/api/v1/users.json", users_json)
    app.router.add_get("/api/products", products)
    app.router.add_get("/admin", admin)
    app.router.add_get("/api/deprecated", deprecated)
    app.router.add_get("/favicon.ico", favicon)
    app.router.add_get("/healthz", healthz)
    return app


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------

async def _start_site(app: web.Application, port: int, label: str) -> web.AppRunner:
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", port)
    await site.start()
    log.info(f"+ listening :{port:<5d}  {label}")
    return runner


async def main() -> None:
    runners: list[web.AppRunner] = []

    log.info("=" * 60)
    log.info("RedAmon AI surface guinea pig starting")
    log.info("=" * 60)

    # 1. Per-product ports
    for descriptor in PORT_LISTENERS:
        app = make_port_app(descriptor)
        runner = await _start_site(
            app,
            descriptor["port"],
            f"{descriptor['name']:<22s}  banner={descriptor.get('server_header', '')!r}",
        )
        runners.append(runner)

    # 2. Header showroom
    runners.append(
        await _start_site(
            make_header_showroom_app(),
            HEADER_SHOWROOM_PORT,
            f"header showroom — {len(HEADER_VARIANTS)} variants on /header/<framework>",
        )
    )

    # 3. Title showroom
    runners.append(
        await _start_site(
            make_title_showroom_app(),
            TITLE_SHOWROOM_PORT,
            f"title  showroom — {len(TITLE_VARIANTS)} variants on /title/<product>",
        )
    )

    # 4. jsluice URL-verification target (additive — does not affect AI surface tests)
    runners.append(
        await _start_site(
            make_jsluice_target_app(),
            JSLUICE_TARGET_PORT,
            "jsluice verifier target — /static/app.js with mixed live/dead/noise URLs",
        )
    )

    # 5. Lap-2 — resource_enum AI classifier showroom
    runners.append(
        await _start_site(
            make_endpoint_ai_classifier_app(),
            ENDPOINT_AI_CLASSIFIER_PORT,
            f"endpoint-ai-classifier showroom — "
            f"{len(RESOURCE_ENUM_AI_PATHS)} interface-type paths + "
            f"{len(RESOURCE_ENUM_AI_RAG_PATHS)} RAG paths",
        )
    )

    # 6. Lap-3 (Phase 6) — js_recon AI SDK showroom
    runners.append(
        await _start_site(
            make_js_recon_ai_sdk_app(),
            JS_RECON_AI_SDK_PORT,
            f"js-recon-ai-sdk showroom — {len(JS_RECON_AI_SDK_FIXTURES)} "
            f"fixture JS files exercising match_ai_sdk() across all 5 channels",
        )
    )

    log.info("=" * 60)
    log.info(f"Ready. {len(runners)} ports bound. Ctrl-C / SIGTERM to stop.")
    log.info("=" * 60)

    # Block until cancelled / signal
    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, stop.set)
        except (NotImplementedError, RuntimeError):
            # No signal support (e.g. on Windows) — fall back to forever loop
            pass
    await stop.wait()

    log.info("Shutting down…")
    for runner in runners:
        await runner.cleanup()
    log.info("Bye.")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        sys.exit(0)
