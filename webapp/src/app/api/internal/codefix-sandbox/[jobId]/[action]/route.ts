import { NextRequest, NextResponse } from 'next/server'
import { isInternalRequest } from '@/lib/session'
import { orchestratorFetch } from '@/lib/orchestrator'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'

// Internal passthrough so the AGENT can drive the CodeFix build sandbox (T6/E10)
// without ever reaching the privileged orchestrator directly: only the webapp
// holds ORCHESTRATOR_API_KEY. The agent authenticates here with X-Internal-Key;
// this route re-issues the request to the orchestrator with the orchestrator key.
const ALLOWED_ACTIONS = new Set(['start', 'exec', 'stop'])

interface RouteParams {
  params: Promise<{ jobId: string; action: string }>
}

export async function POST(request: NextRequest, { params }: RouteParams) {
  if (!isInternalRequest(request)) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  const { jobId, action } = await params
  if (!ALLOWED_ACTIONS.has(action)) {
    return NextResponse.json({ error: 'Unknown action' }, { status: 404 })
  }

  // Only the exec action carries a body ({ command, timeout }); forward it as-is.
  const body = action === 'exec' ? await request.text() : undefined

  try {
    const response = await orchestratorFetch(
      `${RECON_ORCHESTRATOR_URL}/codefix-sandbox/${encodeURIComponent(jobId)}/${action}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body,
      },
    )
    const data = await response.json().catch(() => ({}))
    return NextResponse.json(data, { status: response.status })
  } catch (err) {
    return NextResponse.json(
      { error: `CodeFix sandbox passthrough failed: ${err instanceof Error ? err.message : String(err)}` },
      { status: 502 },
    )
  }
}
