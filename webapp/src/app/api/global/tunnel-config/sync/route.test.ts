/**
 * Unit tests for the tunnel-config sync trigger route.
 *
 * The worker calls POST /api/global/tunnel-config/sync (unauthenticated) on boot;
 * the webapp reads the saved tunnel config from the DB and PUSHES it to the
 * worker's tunnel-manager. The worker never pulls secrets itself (see V8 + the
 * 5.1.0 tunnel fix). prisma and global fetch are mocked so the handler runs with
 * no DB and no network.
 *
 * Run: npx vitest run "src/app/api/global/tunnel-config/sync/route.test.ts"
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'

const mockFindFirst = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    userSettings: {
      findFirst: (...args: unknown[]) => mockFindFirst(...args),
    },
  },
}))

import { POST } from './route'

const WORKER_URL = 'http://kali-sandbox:8015/tunnel/configure'

beforeEach(() => {
  mockFindFirst.mockReset()
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('POST /api/global/tunnel-config/sync', () => {
  test('no saved config: pushes an EMPTY config to the worker, reports configured:false', async () => {
    mockFindFirst.mockResolvedValue(null)
    const fetchSpy = vi.fn().mockResolvedValue(new Response(null, { status: 200 }))
    vi.stubGlobal('fetch', fetchSpy)

    const res = await POST()
    expect(await res.json()).toEqual({ ok: true, configured: false })

    expect(fetchSpy).toHaveBeenCalledTimes(1)
    const [url, opts] = fetchSpy.mock.calls[0] as [string, RequestInit]
    expect(url).toBe(WORKER_URL)
    expect(opts.method).toBe('POST')
    expect(JSON.parse(opts.body as string)).toEqual({
      ngrokAuthtoken: '',
      chiselServerUrl: '',
      chiselAuth: '',
    })
  })

  test('saved config: PUSHES the stored values to the worker, reports configured:true', async () => {
    mockFindFirst.mockResolvedValue({
      ngrokAuthtoken: 'tok',
      chiselServerUrl: 'http://chisel.example',
      chiselAuth: 'pw',
    })
    const fetchSpy = vi.fn().mockResolvedValue(new Response(null, { status: 200 }))
    vi.stubGlobal('fetch', fetchSpy)

    const res = await POST()
    expect(await res.json()).toEqual({ ok: true, configured: true })

    const [, opts] = fetchSpy.mock.calls[0] as [string, RequestInit]
    expect(JSON.parse(opts.body as string)).toEqual({
      ngrokAuthtoken: 'tok',
      chiselServerUrl: 'http://chisel.example',
      chiselAuth: 'pw',
    })
  })

  test('worker push failure is swallowed: returns ok:false, HTTP 200, no throw', async () => {
    mockFindFirst.mockResolvedValue(null)
    vi.spyOn(console, 'error').mockImplementation(() => {})
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('connect ECONNREFUSED')))

    const res = await POST()
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ ok: false })
  })

  test('SECURITY: the HTTP response never contains the secret values', async () => {
    mockFindFirst.mockResolvedValue({
      ngrokAuthtoken: 'SUPER_SECRET_TOKEN',
      chiselServerUrl: 'http://x',
      chiselAuth: 'SECRET_AUTH',
    })
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(null, { status: 200 })))

    const res = await POST()
    const text = await res.text()
    expect(text).not.toContain('SUPER_SECRET_TOKEN')
    expect(text).not.toContain('SECRET_AUTH')
  })
})
