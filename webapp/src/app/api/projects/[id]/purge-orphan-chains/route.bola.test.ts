/**
 * BOLA exploit-repro — POST /api/projects/[id]/purge-orphan-chains.
 *
 * This route stops another project's agent tasks and DETACH-DELETEs its graph
 * nodes. Before the fix it had NO ownership check. Fix: requireProjectAccess before
 * any conversation lookup / Neo4j session.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const mockConversationFindMany = vi.fn()
const mockGetGraphSession = vi.fn()
const mockRequireEff = vi.fn()
const mockRequireProjectAccess = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: { conversation: { findMany: (...a: unknown[]) => mockConversationFindMany(...a) } },
}))
vi.mock('../../../graph/neo4j', () => ({ getGraphSession: () => mockGetGraphSession() }))
vi.mock('@/lib/access', () => ({
  requireEffectiveUser: () => mockRequireEff(),
  requireProjectAccess: (...a: unknown[]) => mockRequireProjectAccess(...a),
}))

import { POST } from './route'

const NOT_FOUND = NextResponse.json({ error: 'Not found' }, { status: 404 })
const params = (id: string) => ({ params: Promise.resolve({ id }) })

beforeEach(() => {
  vi.clearAllMocks()
  mockConversationFindMany.mockResolvedValue([])
  mockGetGraphSession.mockReturnValue({ run: vi.fn().mockResolvedValue({ records: [] }), close: vi.fn() })
})

describe('POST purge-orphan-chains — BOLA', () => {
  test('EXPLOIT: cross-user purge → 404, no conversation read, no Neo4j session', async () => {
    mockRequireEff.mockResolvedValue({ userId: 'attacker' })
    mockRequireProjectAccess.mockResolvedValue(NOT_FOUND)
    const res = await POST(new NextRequest('http://x/api/projects/victimProj/purge-orphan-chains', { method: 'POST' }), params('victimProj'))
    expect(res.status).toBe(404)
    expect(mockConversationFindMany).not.toHaveBeenCalled()
    expect(mockGetGraphSession).not.toHaveBeenCalled()
  })

  test('owner → guard passes, proceeds', async () => {
    mockRequireEff.mockResolvedValue({ userId: 'victim' })
    mockRequireProjectAccess.mockResolvedValue({ project: { id: 'victimProj', userId: 'victim' } })
    await POST(new NextRequest('http://x/api/projects/victimProj/purge-orphan-chains', { method: 'POST' }), params('victimProj'))
    expect(mockConversationFindMany).toHaveBeenCalled()
  })
})
