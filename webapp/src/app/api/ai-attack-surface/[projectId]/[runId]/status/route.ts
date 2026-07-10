import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import { orchestratorFetch } from '@/lib/orchestrator'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'

interface RouteParams {
  params: Promise<{ projectId: string; runId: string }>
}

// GET /api/ai-attack-surface/{projectId}/{runId}/status
export async function GET(_request: NextRequest, { params }: RouteParams) {
  const { projectId, runId } = await params
  const __denied = await guardProject(projectId)
  if (__denied) return __denied
  try {
    const response = await orchestratorFetch(
      `${RECON_ORCHESTRATOR_URL}/ai-attack-surface/${projectId}/${runId}/status`,
      { headers: { 'Content-Type': 'application/json' }, cache: 'no-store' },
    )
    if (!response.ok) {
      return NextResponse.json(
        { project_id: projectId, run_id: runId, status: 'idle' },
        { status: 200 },
      )
    }
    return NextResponse.json(await response.json())
  } catch {
    return NextResponse.json({ project_id: projectId, run_id: runId, status: 'idle' })
  }
}
