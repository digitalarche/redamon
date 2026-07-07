import { NextRequest, NextResponse } from 'next/server'
import { getSession } from '@/lib/session'
import { createWsTicket } from '@/lib/auth'

// POST /api/agent/ws-ticket
//
// STRIDE S6: mints a short-lived ticket the browser includes in the /ws/agent
// init frame so the agent can authenticate the WebSocket. The user identity is
// taken from the verified JWT COOKIE (getSession), never from the request body
// or the spoofable x-user-id header — an internal-key caller (e.g. a compromised
// scanner, S3) has no cookie and therefore cannot mint a ticket for any user.
// projectId/sessionId are caller-scoped context and are bound into the ticket.
export async function POST(request: NextRequest) {
  const session = await getSession()
  if (!session) {
    return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
  }

  const body = await request.json().catch(() => ({}))
  const projectId = String(body.projectId ?? body.project_id ?? '')
  const sessionId = String(body.sessionId ?? body.session_id ?? '')
  if (!projectId || !sessionId) {
    return NextResponse.json(
      { error: 'projectId and sessionId are required' },
      { status: 400 }
    )
  }

  // Null when AGENT_WS_TICKET_SECRET is unset (dev) — the agent fails open.
  const ticket = await createWsTicket(session.userId, projectId, sessionId)
  return NextResponse.json({ ticket })
}
