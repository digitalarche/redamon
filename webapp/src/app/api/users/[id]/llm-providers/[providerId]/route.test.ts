/**
 * STRIDE I1 (single-item closure) — GET/DELETE
 * /api/users/[id]/llm-providers/[providerId] ownership + unmask gating (wiring).
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const mockFindFirst = vi.fn()
const mockDelete = vi.fn()
const mockRequireUserAccess = vi.fn()
const mockIsInternal = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    userLlmProvider: {
      findFirst: (...a: unknown[]) => mockFindFirst(...a),
      delete: (...a: unknown[]) => mockDelete(...a),
    },
  },
}))
vi.mock('@/lib/session', () => ({
  requireUserAccess: (...a: unknown[]) => mockRequireUserAccess(...a),
  isInternalRequest: (...a: unknown[]) => mockIsInternal(...a),
}))

import { GET, DELETE } from './route'

const SECRET = 'sk-PROVIDERSECRET1234'
const PROVIDER = { id: 'p1', userId: 'victim', apiKey: SECRET, awsAccessKeyId: '', awsSecretKey: '', awsBearerToken: '' }
const FORBIDDEN = NextResponse.json({ error: 'Forbidden' }, { status: 403 })
function get(url: string): NextRequest { return new NextRequest(url) }
function del(): NextRequest { return new NextRequest('http://x/api/users/victim/llm-providers/p1', { method: 'DELETE' }) }
const params = (id: string, providerId: string) => ({ params: Promise.resolve({ id, providerId }) })

beforeEach(() => {
  mockFindFirst.mockReset().mockResolvedValue(PROVIDER)
  mockDelete.mockReset().mockResolvedValue({})
  mockRequireUserAccess.mockReset()
  mockIsInternal.mockReset()
})

describe('GET provider — I1', () => {
  test('EXPLOIT: guard denies (cross-user) → 403, no secret, no DB read', async () => {
    mockRequireUserAccess.mockResolvedValue(FORBIDDEN)
    const res = await GET(get('http://x/api/users/victim/llm-providers/p1?internal=true'), params('victim', 'p1'))
    expect(res.status).toBe(403)
    expect(await res.text()).not.toContain(SECRET)
    expect(mockFindFirst).not.toHaveBeenCalled()
  })

  test('owner, no internal-key header → 200 masked (never cleartext for browser)', async () => {
    mockRequireUserAccess.mockResolvedValue(null)
    mockIsInternal.mockReturnValue(false)
    const res = await GET(get('http://x/api/users/victim/llm-providers/p1?internal=true'), params('victim', 'p1'))
    expect(res.status).toBe(200)
    expect(await res.text()).not.toContain(SECRET)
  })

  test('internal-key header → 200 unmasked', async () => {
    mockRequireUserAccess.mockResolvedValue(null)
    mockIsInternal.mockReturnValue(true)
    const res = await GET(get('http://x/api/users/victim/llm-providers/p1'), params('victim', 'p1'))
    expect(res.status).toBe(200)
    expect(await res.text()).toContain(SECRET)
  })
})

describe('DELETE provider — ownership', () => {
  test('EXPLOIT: guard denies (cross-user) → 403, no write', async () => {
    mockRequireUserAccess.mockResolvedValue(FORBIDDEN)
    const res = await DELETE(del(), params('victim', 'p1'))
    expect(res.status).toBe(403)
    expect(mockDelete).not.toHaveBeenCalled()
  })

  test('owner delete → 200', async () => {
    mockRequireUserAccess.mockResolvedValue(null)
    mockIsInternal.mockReturnValue(false)
    const res = await DELETE(del(), params('victim', 'p1'))
    expect(res.status).toBe(200)
    expect(mockDelete).toHaveBeenCalled()
  })
})
