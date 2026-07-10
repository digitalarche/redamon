/**
 * Unit tests for the admin-only act-as (impersonation) endpoint.
 *
 * Run: npx vitest run src/app/api/auth/act-as/route.test.ts
 *
 * @vitest-environment node
 */

import { describe, test, expect, vi, beforeEach } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

vi.stubEnv('AUTH_SECRET', 'c'.repeat(64))

const mockRequireAdmin = vi.fn()
vi.mock('@/lib/session', () => ({
  requireAdmin: () => mockRequireAdmin(),
}))

const mockUserFindUnique = vi.fn()
vi.mock('@/lib/prisma', () => ({
  default: { user: { findUnique: (a: unknown) => mockUserFindUnique(a) } },
}))

import { POST, DELETE } from './route'

function req(body?: unknown): NextRequest {
  return new NextRequest('http://localhost:3000/api/auth/act-as', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: body === undefined ? undefined : JSON.stringify(body),
  })
}

beforeEach(() => {
  vi.clearAllMocks()
})

describe('POST /api/auth/act-as', () => {
  test('non-admin -> passes through requireAdmin 403', async () => {
    mockRequireAdmin.mockResolvedValue(NextResponse.json({ error: 'Forbidden' }, { status: 403 }))
    const res = await POST(req({ targetUserId: 'user-X' }))
    expect(res.status).toBe(403)
  })

  test('admin acting as an existing user -> sets httpOnly act-as cookie', async () => {
    mockRequireAdmin.mockResolvedValue({ userId: 'admin-1', role: 'admin' })
    mockUserFindUnique.mockResolvedValue({ id: 'user-X' })
    const res = await POST(req({ targetUserId: 'user-X' }))
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ actingAs: 'user-X' })
    const setCookie = res.headers.get('set-cookie') || ''
    expect(setCookie).toContain('redamon-act-as=')
    expect(setCookie).toMatch(/HttpOnly/i)
  })

  test('admin acting as a nonexistent user -> 404', async () => {
    mockRequireAdmin.mockResolvedValue({ userId: 'admin-1', role: 'admin' })
    mockUserFindUnique.mockResolvedValue(null)
    const res = await POST(req({ targetUserId: 'ghost' }))
    expect(res.status).toBe(404)
  })

  test('missing targetUserId -> 400', async () => {
    mockRequireAdmin.mockResolvedValue({ userId: 'admin-1', role: 'admin' })
    const res = await POST(req({}))
    expect(res.status).toBe(400)
  })

  test('acting as self -> clears the cookie (stop simulating)', async () => {
    mockRequireAdmin.mockResolvedValue({ userId: 'admin-1', role: 'admin' })
    const res = await POST(req({ targetUserId: 'admin-1' }))
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ actingAs: null })
    expect(res.headers.get('set-cookie') || '').toMatch(/Max-Age=0/i)
  })
})

describe('DELETE /api/auth/act-as', () => {
  test('non-admin -> 403', async () => {
    mockRequireAdmin.mockResolvedValue(NextResponse.json({ error: 'Forbidden' }, { status: 403 }))
    const res = await DELETE()
    expect(res.status).toBe(403)
  })

  test('admin -> clears the cookie', async () => {
    mockRequireAdmin.mockResolvedValue({ userId: 'admin-1', role: 'admin' })
    const res = await DELETE()
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ actingAs: null })
    expect(res.headers.get('set-cookie') || '').toMatch(/Max-Age=0/i)
  })
})
