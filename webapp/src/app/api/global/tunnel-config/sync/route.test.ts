/**
 * Unit tests for the tunnel-config sync trigger route (STRIDE I19).
 *
 * On worker boot this route must FORCE tunnels down (clear tunnelsEnabled + push
 * an empty/stop config) so a restart never silently re-exposes internal
 * listeners to the internet. It presents TUNNEL_AUTH_TOKEN when set. prisma +
 * global fetch are mocked.
 *
 * Run: npx vitest run "src/app/api/global/tunnel-config/sync/route.test.ts"
 *
 * @vitest-environment node
 */
import { describe, test, expect, beforeEach, afterEach, vi } from 'vitest'

const mockUpdateMany = vi.fn()

vi.mock('@/lib/prisma', () => ({
  default: {
    userSettings: {
      updateMany: (...args: unknown[]) => mockUpdateMany(...args),
    },
  },
}))

import { POST } from './route'

const WORKER_URL = 'http://kali-sandbox:8015/tunnel/configure'

beforeEach(() => {
  mockUpdateMany.mockReset().mockResolvedValue({ count: 0 })
  delete process.env.TUNNEL_AUTH_TOKEN
})

afterEach(() => {
  vi.unstubAllGlobals()
  vi.restoreAllMocks()
})

describe('POST /api/global/tunnel-config/sync — I19', () => {
  test('forces tunnels down: clears tunnelsEnabled and pushes an EMPTY config', async () => {
    const fetchSpy = vi.fn().mockResolvedValue(new Response(null, { status: 200 }))
    vi.stubGlobal('fetch', fetchSpy)

    const res = await POST()
    expect(await res.json()).toEqual({ ok: true, configured: false })

    // Disabled every enabled row.
    expect(mockUpdateMany).toHaveBeenCalledWith({
      where: { tunnelsEnabled: true },
      data: { tunnelsEnabled: false },
    })

    // Pushed a stop (empty) config — never re-activates on boot.
    const [url, opts] = fetchSpy.mock.calls[0] as [string, RequestInit]
    expect(url).toBe(WORKER_URL)
    expect(JSON.parse(opts.body as string)).toEqual({
      ngrokAuthtoken: '',
      chiselServerUrl: '',
      chiselAuth: '',
    })
  })

  test('presents the TUNNEL_AUTH_TOKEN when set', async () => {
    process.env.TUNNEL_AUTH_TOKEN = 'tok-123'
    const fetchSpy = vi.fn().mockResolvedValue(new Response(null, { status: 200 }))
    vi.stubGlobal('fetch', fetchSpy)

    await POST()
    const [, opts] = fetchSpy.mock.calls[0] as [string, RequestInit]
    expect((opts.headers as Record<string, string>)['Authorization']).toBe('Bearer tok-123')
  })

  test('omits the auth header when the token is unset (dev fail-open)', async () => {
    const fetchSpy = vi.fn().mockResolvedValue(new Response(null, { status: 200 }))
    vi.stubGlobal('fetch', fetchSpy)

    await POST()
    const [, opts] = fetchSpy.mock.calls[0] as [string, RequestInit]
    expect((opts.headers as Record<string, string>)['Authorization']).toBeUndefined()
  })

  test('worker push failure is swallowed: returns ok:false, HTTP 200', async () => {
    vi.spyOn(console, 'error').mockImplementation(() => {})
    vi.stubGlobal('fetch', vi.fn().mockRejectedValue(new Error('connect ECONNREFUSED')))

    const res = await POST()
    expect(res.status).toBe(200)
    expect(await res.json()).toEqual({ ok: false })
  })
})
