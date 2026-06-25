import { NextRequest, NextResponse } from 'next/server'
import { orchestratorFetch } from '@/lib/orchestrator'

const RECON_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://recon-orchestrator:8010'

async function fetchStatus(url: string) {
  try {
    const res = await orchestratorFetch(url, { cache: 'no-store' })
    if (!res.ok) return null
    return await res.json()
  } catch {
    return null
  }
}

export async function GET(request: NextRequest) {
  const projectId = request.nextUrl.searchParams.get('projectId')
  if (!projectId) {
    return NextResponse.json({ error: 'projectId is required' }, { status: 400 })
  }

  const [recon, gvm, githubHunt] = await Promise.all([
    fetchStatus(`${RECON_URL}/recon/${projectId}/status`),
    fetchStatus(`${RECON_URL}/gvm/${projectId}/status`),
    fetchStatus(`${RECON_URL}/github-hunt/${projectId}/status`),
  ])

  return NextResponse.json({ recon, gvm, githubHunt })
}
