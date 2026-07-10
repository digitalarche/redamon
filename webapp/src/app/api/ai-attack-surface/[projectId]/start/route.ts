import { NextRequest, NextResponse } from 'next/server'
import { guardProject } from '@/lib/access'
import prisma from '@/lib/prisma'
import { orchestratorFetch } from '@/lib/orchestrator'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'
const WEBAPP_URL = process.env.WEBAPP_URL || 'http://localhost:3000'

interface RouteParams {
  params: Promise<{ projectId: string }>
}

// POST /api/ai-attack-surface/{projectId}/start
// Launch one AI Attack Surface tool against the selected AI nodes.
export async function POST(request: NextRequest, { params }: RouteParams) {
  try {
    const { projectId } = await params
    const __denied = await guardProject(projectId)
    if (__denied) return __denied
    const body = await request.json()

    const project = await prisma.project.findUnique({
      where: { id: projectId },
      select: { id: true, userId: true },
    })
    if (!project) {
      return NextResponse.json({ error: 'Project not found' }, { status: 404 })
    }

    const response = await orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/ai-attack-surface/${projectId}/start`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        project_id: projectId,
        user_id: project.userId,
        webapp_api_url: WEBAPP_URL,
        tool: body.tool || 'garak',
        targets: body.targets || [],
        bounds: body.bounds || {},
        roe_confirmed: body.roe_confirmed ?? false,
        dry_run: body.dry_run ?? false,
        probes: body.probes || [],
        strategies: body.strategies || [],
        objective: body.objective || '',
        target_model: body.target_model || '',
        target_purpose: body.target_purpose || '',
        api_key: body.api_key || '',
        auth_header: body.auth_header || '',
        auth_scheme: body.auth_scheme || '',
      }),
    })

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}))
      return NextResponse.json(
        { error: errorData.detail || 'Failed to start AI Gauntlet scan' },
        { status: response.status },
      )
    }

    return NextResponse.json(await response.json())
  } catch (error) {
    console.error('Error starting AI Attack Surface scan:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Internal server error' },
      { status: 500 },
    )
  }
}
