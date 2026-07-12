/**
 * Import-community caps repro — POST /api/users/[id]/chat-skills/import-community.
 *
 * The bug: bulk community import wrote skills straight to the DB, bypassing the
 * content-size, per-user-count, and description-length caps the manual POST
 * path enforces. Fix: mirror those caps in the import loop.
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
    userChatSkill: {
      findMany: (...a: unknown[]) => mockFindMany(...a),
      create: (...a: unknown[]) => mockCreate(...a),
    },
  },
}))

import { POST } from './route'

const params = (id: string) => ({ params: Promise.resolve({ id }) })
function post(): NextRequest {
  return new NextRequest('http://x/api/users/u1/chat-skills/import-community', { method: 'POST' })
}

// catalog: 2 skills; content per id supplied by the test.
function wireFetch(catalog: Array<{ id: string; name: string }>, content: Record<string, unknown>) {
  mockFetch.mockImplementation((url: string) => {
    if (/\/skills$/.test(url)) {
      return Promise.resolve({ ok: true, json: async () => ({ skills: catalog }) })
    }
    const id = decodeURIComponent(url.split('/').pop() as string)
    return Promise.resolve({ ok: true, json: async () => content[id] ?? {} })
  })
}

beforeEach(() => {
  vi.clearAllMocks()
  vi.stubGlobal('fetch', mockFetch)
  mockRequireUserAccess.mockResolvedValue(null) // allowed
  mockCreate.mockResolvedValue({})
})

describe('POST chat-skills/import-community — caps', () => {
  test('skips a skill whose content exceeds the 50KB cap', async () => {
    mockFindMany.mockResolvedValue([])
    wireFetch(
      [{ id: 'big', name: 'Big' }, { id: 'ok', name: 'Ok' }],
      {
        big: { name: 'Big', description: 'd', content: 'X'.repeat(51 * 1024) },
        ok: { name: 'Ok', description: 'd', content: 'small' },
      },
    )
    const res = await POST(post(), params('u1'))
    const body = await res.json()
    expect(body.imported).toBe(1) // only 'ok'
    expect(body.skipped).toBe(1) // 'big'
    expect(mockCreate).toHaveBeenCalledTimes(1)
    expect(mockCreate.mock.calls[0][0].data.name).toBe('Ok')
  })

  test('stops importing once the per-user ceiling (50) is reached', async () => {
    // 50 existing skills -> already at the cap, nothing new may be created.
    mockFindMany.mockResolvedValue(
      Array.from({ length: 50 }, (_, i) => ({ name: `existing-${i}` })),
    )
    wireFetch(
      [{ id: 'a', name: 'A' }, { id: 'b', name: 'B' }],
      { a: { content: 'x' }, b: { content: 'y' } },
    )
    const res = await POST(post(), params('u1'))
    const body = await res.json()
    expect(body.imported).toBe(0)
    expect(body.skipped).toBe(2)
    expect(mockCreate).not.toHaveBeenCalled()
  })

  test('truncates an over-long description to 500 chars', async () => {
    mockFindMany.mockResolvedValue([])
    wireFetch(
      [{ id: 'a', name: 'A' }],
      { a: { name: 'A', description: 'D'.repeat(600), content: 'ok' } },
    )
    await POST(post(), params('u1'))
    expect(mockCreate).toHaveBeenCalledTimes(1)
    expect(mockCreate.mock.calls[0][0].data.description).toHaveLength(500)
  })

  test('rejects a cross-user caller (ownership guard)', async () => {
    mockRequireUserAccess.mockResolvedValue(NextResponse.json({ error: 'forbidden' }, { status: 403 }))
    const res = await POST(post(), params('u1'))
    expect(res.status).toBe(403)
    expect(mockFetch).not.toHaveBeenCalled()
    expect(mockCreate).not.toHaveBeenCalled()
  })
})
