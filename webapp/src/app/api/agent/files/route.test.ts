/**
 * agent/files download proxy — the projectId is OPTIONAL:
 *  - with projectId: enforce project ownership (guardProject)
 *  - without projectId: legacy /tmp in-chat download must still work (no 400 from
 *    the project guard)  <- regression for the scripted-guard over-block bug
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, vi } from 'vitest'
import { NextRequest, NextResponse } from 'next/server'

const mockGuardProject = vi.fn()
vi.mock('@/lib/access', () => ({ guardProject: (...a: unknown[]) => mockGuardProject(...a) }))

import { GET } from './route'

let fetchCalls: string[]
const NOT_FOUND = NextResponse.json({ error: 'Not found' }, { status: 404 })

beforeEach(() => {
  fetchCalls = []
  mockGuardProject.mockReset()
  vi.stubGlobal('fetch', vi.fn(async (url: unknown) => {
    fetchCalls.push(String(url))
    return { ok: true, arrayBuffer: async () => new ArrayBuffer(3), headers: new Headers() } as unknown as Response
  }))
})

describe('GET /api/agent/files', () => {
  test('LEGACY: no projectId + valid path → guard skipped, proxies to /files', async () => {
    const res = await GET(new NextRequest('http://x/api/agent/files?path=/tmp/out.txt'))
    expect(res.status).toBe(200)
    expect(mockGuardProject).not.toHaveBeenCalled()
    expect(fetchCalls.some(u => u.includes('/files?path='))).toBe(true)
  })

  test('with projectId, owner → guard passes, proxies to workspace/download', async () => {
    mockGuardProject.mockResolvedValue(null)
    const res = await GET(new NextRequest('http://x/api/agent/files?projectId=p1&path=/a'))
    expect(res.status).toBe(200)
    expect(mockGuardProject).toHaveBeenCalledWith('p1')
    expect(fetchCalls.some(u => u.includes('/workspace/download?projectId=p1'))).toBe(true)
  })

  test('EXPLOIT: with projectId, cross-user → 404, no proxy', async () => {
    mockGuardProject.mockResolvedValue(NOT_FOUND)
    const res = await GET(new NextRequest('http://x/api/agent/files?projectId=victimProj&path=/a'))
    expect(res.status).toBe(404)
    expect(fetchCalls).toHaveLength(0)
  })
})
