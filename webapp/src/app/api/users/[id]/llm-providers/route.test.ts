/**
 * Unit tests for GET/POST /api/users/[id]/llm-providers — STRIDE I1.
 *
 * I1: any logged-in user could read ANOTHER user's UNMASKED provider secrets by
 * appending `?internal=true`. The fix gates unmasked rows on a valid
 * `X-Internal-Key` header (the agent) and forces browser/JWT callers to own the
 * account (or be admin), always masked. prisma + session are mocked so the
 * handler runs with no DB and no cookies.
 *
 * Run: npx vitest run "src/app/api/users/[id]/llm-providers/route.test.ts"
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest } from 'next/server'

const mockFindMany = vi.fn()
const mockCreate = vi.fn()
const mockGetSession = vi.fn()
const mockIsInternal = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    userLlmProvider: {
      findMany: (...args: unknown[]) => mockFindMany(...args),
      create: (...args: unknown[]) => mockCreate(...args),
    },
  },
}))

vi.mock('@/lib/session', () => ({
  getSession: (...args: unknown[]) => mockGetSession(...args),
  isInternalRequest: (...args: unknown[]) => mockIsInternal(...args),
}))

import { GET, POST } from './route'

const SECRET = 'sk-SECRETKEY123456'
const PROVIDER = {
  id: 'p1',
  userId: 'victim',
  providerType: 'openai',
  name: 'OpenAI',
  apiKey: SECRET,
  awsAccessKeyId: 'AKIAEXAMPLE12345',
  awsSecretKey: 'awssecretvalue999',
  awsBearerToken: 'bearer-secret-888',
}

function req(url: string): NextRequest {
  return new NextRequest(url)
}
const params = (id: string) => ({ params: Promise.resolve({ id }) })

beforeEach(() => {
  mockFindMany.mockReset().mockResolvedValue([PROVIDER])
  mockCreate.mockReset().mockResolvedValue({ ...PROVIDER })
  mockGetSession.mockReset()
  mockIsInternal.mockReset()
})

function postReq(id: string, body: unknown): NextRequest {
  return new NextRequest(`http://x/api/users/${id}/llm-providers`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(body),
  })
}
const NEW_PROVIDER = { providerType: 'openai', name: 'mine', apiKey: 'k' }

describe('GET /api/users/[id]/llm-providers — I1', () => {
  test('internal-key caller with ?internal=true → UNMASKED secrets', async () => {
    mockIsInternal.mockReturnValue(true)
    const res = await GET(req('http://x/api/users/victim/llm-providers?internal=true'), params('victim'))
    const text = await res.text()
    expect(res.status).toBe(200)
    expect(text).toContain(SECRET) // agent path still works
  })

  test('internal-key caller WITHOUT ?internal=true → masked', async () => {
    mockIsInternal.mockReturnValue(true)
    const res = await GET(req('http://x/api/users/victim/llm-providers'), params('victim'))
    const text = await res.text()
    expect(text).not.toContain(SECRET)
  })

  test('EXPLOIT: browser user requests ANOTHER user with ?internal=true → 403, no secrets', async () => {
    mockIsInternal.mockReturnValue(false)
    mockGetSession.mockResolvedValue({ userId: 'attacker', role: 'user' })
    const res = await GET(req('http://x/api/users/victim/llm-providers?internal=true'), params('victim'))
    const text = await res.text()
    expect(res.status).toBe(403)
    expect(text).not.toContain(SECRET)
  })

  test('browser user requests OWN id → 200 masked, never the raw secret', async () => {
    mockIsInternal.mockReturnValue(false)
    mockGetSession.mockResolvedValue({ userId: 'victim', role: 'user' })
    const res = await GET(req('http://x/api/users/victim/llm-providers?internal=true'), params('victim'))
    const text = await res.text()
    expect(res.status).toBe(200)
    expect(text).not.toContain(SECRET) // browser NEVER gets unmasked
    expect(text).toContain('3456') // masked tail present
  })

  test('admin requests another user → 200 masked', async () => {
    mockIsInternal.mockReturnValue(false)
    mockGetSession.mockResolvedValue({ userId: 'admin1', role: 'admin' })
    const res = await GET(req('http://x/api/users/victim/llm-providers'), params('victim'))
    expect(res.status).toBe(200)
    expect(await res.text()).not.toContain(SECRET)
  })

  test('no session, no internal key → 401', async () => {
    mockIsInternal.mockReturnValue(false)
    mockGetSession.mockResolvedValue(null)
    const res = await GET(req('http://x/api/users/victim/llm-providers'), params('victim'))
    expect(res.status).toBe(401)
    expect(mockFindMany).not.toHaveBeenCalled()
  })
})

describe('POST /api/users/[id]/llm-providers — I1 ownership', () => {
  test('EXPLOIT: user creates a provider under ANOTHER user id → 403, no write', async () => {
    mockIsInternal.mockReturnValue(false)
    mockGetSession.mockResolvedValue({ userId: 'attacker', role: 'user' })
    const res = await POST(postReq('victim', NEW_PROVIDER), params('victim'))
    expect(res.status).toBe(403)
    expect(mockCreate).not.toHaveBeenCalled()
  })

  test('owner creates their own provider → 201', async () => {
    mockIsInternal.mockReturnValue(false)
    mockGetSession.mockResolvedValue({ userId: 'victim', role: 'user' })
    const res = await POST(postReq('victim', NEW_PROVIDER), params('victim'))
    expect(res.status).toBe(201)
    expect(mockCreate).toHaveBeenCalled()
  })

  test('internal-key caller may create for any user → 201', async () => {
    mockIsInternal.mockReturnValue(true)
    const res = await POST(postReq('anyuser', NEW_PROVIDER), params('anyuser'))
    expect(res.status).toBe(201)
    expect(mockCreate).toHaveBeenCalled()
  })

  test('no session, no key → 401, no write', async () => {
    mockIsInternal.mockReturnValue(false)
    mockGetSession.mockResolvedValue(null)
    const res = await POST(postReq('victim', NEW_PROVIDER), params('victim'))
    expect(res.status).toBe(401)
    expect(mockCreate).not.toHaveBeenCalled()
  })
})
