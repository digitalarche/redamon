import { NextResponse } from 'next/server'
import { orchestratorFetch } from '@/lib/orchestrator'

const RECON_ORCHESTRATOR_URL = process.env.RECON_ORCHESTRATOR_URL || 'http://localhost:8010'
const AGENT_API_URL = process.env.AGENT_API_URL || 'http://localhost:8090'

// GET /api/projects/defaults - Get default project settings from recon + agent backends
export async function GET() {
  try {
    // Fetch from both backends in parallel
    const [reconResult, agentResult] = await Promise.allSettled([
      orchestratorFetch(`${RECON_ORCHESTRATOR_URL}/defaults`, {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' },
        cache: 'no-store',
      }),
      fetch(`${AGENT_API_URL}/defaults`, {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' },
        cache: 'no-store',
      }),
    ])

    // Recon defaults are required
    if (reconResult.status === 'rejected' || !reconResult.value.ok) {
      const error = reconResult.status === 'rejected'
        ? reconResult.reason
        : await reconResult.value.text()
      console.error('Failed to fetch defaults from recon orchestrator:', error)
      return NextResponse.json(
        { error: 'Failed to fetch defaults from recon backend' },
        { status: 503 }
      )
    }

    const reconDefaults = await reconResult.value.json()

    // Agent defaults are optional - merge if available, otherwise frontend uses Prisma defaults
    let agentDefaults = {}
    if (agentResult.status === 'fulfilled' && agentResult.value.ok) {
      agentDefaults = await agentResult.value.json()
    } else {
      console.warn('Agent API defaults unavailable, using recon/Prisma defaults for agent settings')
    }

    // Merge: recon defaults + agent defaults (agent overrides any overlapping keys)
    const merged = { ...reconDefaults, ...agentDefaults }
    return NextResponse.json(merged)
  } catch (error) {
    console.error('Failed to fetch defaults:', error)
    return NextResponse.json(
      { error: 'Failed to connect to backend services' },
      { status: 503 }
    )
  }
}
