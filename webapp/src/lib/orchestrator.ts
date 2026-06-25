/**
 * Server-side fetch wrapper for all calls to the recon orchestrator.
 *
 * The orchestrator requires `X-Orchestrator-Key` on every route except `/health`
 * (V1-auth). This helper injects that header so the webapp's server-side API
 * routes are accepted, while a compromised recon container (which does not hold
 * ORCHESTRATOR_API_KEY) cannot drive the orchestration API even though it can
 * reach 127.0.0.1:8010 over host networking.
 *
 * Pass the full URL (callers keep their existing `${RECON_ORCHESTRATOR_URL}/...`
 * templates); only the function name changes from `fetch` to `orchestratorFetch`.
 * Server-side only — never import this into client components.
 */
export function orchestratorFetch(url: string | URL, init: RequestInit = {}): Promise<Response> {
  return fetch(url, {
    ...init,
    headers: {
      ...(init.headers || {}),
      'X-Orchestrator-Key': process.env.ORCHESTRATOR_API_KEY || 'changeme',
    },
  })
}
