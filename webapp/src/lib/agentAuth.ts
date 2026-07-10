// D3: attach the internal API key when the webapp proxies to the agent's
// guarded endpoints (/llm/*, /guardrail/check-target, /roe/parse, /models,
// /llm-provider/test). Without it those endpoints now return 401 once the
// secret is set. An empty value is harmless before the secret exists — the
// agent guard fails open until INTERNAL_API_KEY/SCANNER_API_KEY is present.
export function internalKeyHeaders(
  base: Record<string, string> = {},
): Record<string, string> {
  return { ...base, 'x-internal-key': process.env.INTERNAL_API_KEY || '' }
}
