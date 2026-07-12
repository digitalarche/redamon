/**
 * Import-community caps repro — POST /api/users/[id]/attack-skills/import-community.
 *
 * Same class of bug as the chat-skills importer: bulk import bypassed the
 * content-size (50KB), per-user-count (20), and description-length (500) caps
 * the manual POST path enforces.
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const mockRequireUserAccess = vi.fn()
const mockFindMany = vi.fn()
const mockCreate = vi.fn()
const mockFetch = vi.fn()

vi.mock('@/lib/session', () => ({
  requireUserAccess: (...a: unknown[]) => mockRequireUserAccess(...a),
}))
vi.mock('@/lib/prisma', () => ({
  default: {
    userAttackSkill: {
      findMany: (...a: unknown[]) => mockFindMany(...a),
      create: (...a: unknown[]) => mockCreate(...a),
    },
  },
}))

import { POST } from './route'

const params = (id: string) => ({ params: Promise.resolve({ id }) })
function post(): NextRequest {
  return new NextRequest('http://x/api/users/u1/attack-skills/import-community', { method: 'POST' })
}

function wireFetch(catalog: Array<{ id: string; name: string }>, content: Record<string, unknown>) {
  mockFetch.mockImplementation((url: string) => {
    if (/\/community-skills$/.test(url)) {
      return Promise.resolve({ ok: true, json: async () => ({ skills: catalog }) })
    }
    const id = decodeURIComponent(url.split('/').pop() as string)
    return Promise.resolve({ ok: true, json: async () => content[id] ?? {} })
  })
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.stubGlobal('fetch', mockFetch)
  mockRequireUserAccess.mockResolvedValue(null)
  mockCreate.mockResolvedValue({})
})

describe('POST attack-skills/import-community — caps', () => {
  test('skips content over the 50KB cap', async () => {
    mockFindMany.mockResolvedValue([])
    wireFetch(
      [{ id: 'big', name: 'Big' }, { id: 'ok', name: 'Ok' }],
      { big: { content: 'X'.repeat(51 * 1024) }, ok: { content: 'small' } },
    )
    const body = await (await POST(post(), params('u1'))).json()
    expect(body.imported).toBe(1)
    expect(mockCreate).toHaveBeenCalledTimes(1)
  })

  test('stops at the per-user ceiling (20)', async () => {
    mockFindMany.mockResolvedValue(Array.from({ length: 20 }, (_, i) => ({ name: `e-${i}` })))
    wireFetch([{ id: 'a', name: 'A' }, { id: 'b', name: 'B' }], { a: { content: 'x' }, b: { content: 'y' } })
    const body = await (await POST(post(), params('u1'))).json()
    expect(body.imported).toBe(0)
    expect(mockCreate).not.toHaveBeenCalled()
  })

  test('truncates description to 500 chars', async () => {
    mockFindMany.mockResolvedValue([])
    wireFetch([{ id: 'a', name: 'A' }], { a: { description: 'D'.repeat(600), content: 'ok' } })
    await POST(post(), params('u1'))
    expect(mockCreate.mock.calls[0][0].data.description).toHaveLength(500)
  })

  test('rejects a cross-user caller', async () => {
    mockRequireUserAccess.mockResolvedValue(NextResponse.json({ error: 'forbidden' }, { status: 403 }))
    const res = await POST(post(), params('u1'))
    expect(res.status).toBe(403)
    expect(mockCreate).not.toHaveBeenCalled()
  })
})
