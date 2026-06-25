import { NextRequest, NextResponse } from 'next/server'
import { orchestratorFetch } from '@/lib/orchestrator'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'

interface RouteParams {
  params: Promise<{ projectId: string; runId: string }>
}

// POST /api/ai-attack-surface/{projectId}/{runId}/stop
export async function POST(_request: NextRequest, { params }: RouteParams) {
  const { projectId, runId } = await params
  try {
    const response = await orchestratorFetch(
      `${RECON_ORCHESTRATOR_URL}/ai-attack-surface/${projectId}/${runId}/stop`,
      { method: 'POST', headers: { 'Content-Type': 'application/json' } },
    )
    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}))
      return NextResponse.json(
        { error: errorData.detail || 'Failed to stop AI Gauntlet scan' },
        { status: response.status },
      )
    }
    return NextResponse.json(await response.json())
  } catch (error) {
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Internal server error' },
      { status: 500 },
    )
  }
}
