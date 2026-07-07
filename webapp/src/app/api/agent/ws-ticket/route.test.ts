/**
 * Unit tests for POST /api/agent/ws-ticket — STRIDE S6.
 *
 * The ticket identity MUST come from the verified session cookie, never the
 * request body, so a caller cannot mint a ticket for another user. session +
 * auth are mocked.
 *
 * Run: npx vitest run "src/app/api/agent/ws-ticket/route.test.ts"
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const mockGetSession = vi.fn()
const mockCreateWsTicket = vi.fn()

vi.mock('@/lib/session', () => ({
  getSession: (...a: unknown[]) => mockGetSession(...a),
}))
vi.mock('@/lib/auth', () => ({
  createWsTicket: (...a: unknown[]) => mockCreateWsTicket(...a),
}))

import { POST } from './route'

function req(body: unknown): NextRequest {
  return new NextRequest('http://x/api/agent/ws-ticket', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
}

beforeEach(() => {
  mockGetSession.mockReset()
  mockCreateWsTicket.mockReset().mockResolvedValue('signed.ticket.value')
})

describe('POST /api/agent/ws-ticket — S6', () => {
  test('no session → 401, no ticket minted', async () => {
    mockGetSession.mockResolvedValue(null)
    const res = await POST(req({ projectId: 'p', sessionId: 's' }))
    expect(res.status).toBe(401)
    expect(mockCreateWsTicket).not.toHaveBeenCalled()
  })

  test('missing projectId/sessionId → 400', async () => {
    mockGetSession.mockResolvedValue({ userId: 'u1', role: 'user' })
    expect((await POST(req({ projectId: 'p' }))).status).toBe(400)
    expect((await POST(req({ sessionId: 's' }))).status).toBe(400)
  })

  test('identity is bound to the SESSION, never the body', async () => {
    mockGetSession.mockResolvedValue({ userId: 'real-user', role: 'user' })
    // Attacker tries to smuggle a different userId in the body.
    const res = await POST(req({ userId: 'victim', projectId: 'p', sessionId: 's' }))
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ ticket: 'signed.ticket.value' })
    // createWsTicket called with the session user, not "victim".
    expect(mockCreateWsTicket).toHaveBeenCalledWith('real-user', 'p', 's')
  })

  test('null ticket (secret unset) is passed through for agent fail-open', async () => {
    mockGetSession.mockResolvedValue({ userId: 'u1', role: 'user' })
    mockCreateWsTicket.mockResolvedValue(null)
    const res = await POST(req({ projectId: 'p', sessionId: 's' }))
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ ticket: null })
  })
})
