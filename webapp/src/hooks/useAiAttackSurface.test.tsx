/**
 * Launch-flow tests for useAiAttackSurface (fetch + EventSource mocked).
 */
import { describe, test, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act, cleanup } from '@testing-library/react'
import { useAiAttackSurface } from './useAiAttackSurface'

afterEach(cleanup)

class MockEventSource {
  static instances: MockEventSource[] = []
  url: string
  onerror: (() => void) | null = null
  onopen: (() => void) | null = null
  listeners: Record<string, (ev: MessageEvent) => void> = {}
  closed = false
  constructor(url: string) {
    this.url = url
    MockEventSource.instances.push(this)
  }
  addEventListener(type: string, cb: (ev: MessageEvent) => void) {
    this.listeners[type] = cb
  }
  emit(type: string, data: unknown) {
    this.listeners[type]?.({ data: JSON.stringify(data) } as MessageEvent)
  }
  close() {
    this.closed = true
  }
}

function routedFetch(routes: Record<string, unknown>) {
  return vi.fn(async (url: string) => {
    const key = Object.keys(routes).find((k) => url.includes(k))
    const payload = key ? routes[key] : {}
    return { ok: true, json: async () => payload } as Response
  })
}

beforeEach(() => {
  MockEventSource.instances = []
  vi.stubGlobal('EventSource', MockEventSource as unknown as typeof EventSource)
  vi.useFakeTimers()
})

afterEach(() => {
  vi.useRealTimers()
  vi.unstubAllGlobals()
})

describe('useAiAttackSurface', () => {
  test('loadTargets populates targets', async () => {
    vi.stubGlobal('fetch', routedFetch({ '/targets': { targets: [{ baseUrl: 'http://h', path: '/c' }] } }))
    const { result } = renderHook(() => useAiAttackSurface('p1'))
    await act(async () => { await result.current.loadTargets() })
    expect(result.current.targets).toHaveLength(1)
  })

  test('launch posts to start, opens SSE, and records phase from log events', async () => {
    vi.stubGlobal('fetch', routedFetch({
      '/start': { run_id: 'r1', status: 'running', tool: 'garak' },
      '/status': { run_id: 'r1', status: 'running' },
    }))
    const { result } = renderHook(() => useAiAttackSurface('p1'))

    await act(async () => {
      await result.current.launch({
        tool: 'garak', targets: [{ baseurl: 'http://h', path: '/c' }],
        bounds: { trials: 1 }, roe_confirmed: true, probes: ['dan'],
      })
    })

    expect(result.current.run?.run_id).toBe('r1')
    // SSE opened against the run's log stream
    const es = MockEventSource.instances[0]
    expect(es.url).toContain('/api/ai-attack-surface/p1/r1/logs')

    // A phase-start log event advances the tracked phase
    act(() => { es.emit('log', { log: '[Phase 2] Target loading', phase: 'Target loading', phaseNumber: 2, isPhaseStart: true, level: 'info' }) })
    expect(result.current.phase).toEqual({ name: 'Target loading', num: 2 })
    expect(result.current.logs).toHaveLength(1)
  })

  test('reconnects to an in-flight run on mount (stateful across refresh)', async () => {
    vi.stubGlobal('fetch', routedFetch({
      '/all': { runs: [{ run_id: 'r9', status: 'running', tool: 'pyrit' }] },
      '/status': { run_id: 'r9', status: 'running' },
    }))
    const { result } = renderHook(() => useAiAttackSurface('p1'))
    // the mount effect fires reconnect() -> /all -> finds the running run
    await act(async () => { await vi.advanceTimersByTimeAsync(0) })

    expect(result.current.run?.run_id).toBe('r9')          // status restored
    const es = MockEventSource.instances.find((e) => e.url.includes('/r9/logs'))
    expect(es).toBeTruthy()                                  // log stream re-attached
    // live logs resume after reconnect
    act(() => { es!.emit('log', { log: 'resumed', level: 'info' }) })
    expect(result.current.logs.map((l) => l.log)).toContain('resumed')
  })

  test('does NOT reconnect when there is no active run', async () => {
    vi.stubGlobal('fetch', routedFetch({ '/all': { runs: [{ run_id: 'old', status: 'completed' }] } }))
    const { result } = renderHook(() => useAiAttackSurface('p1'))
    await act(async () => { await vi.advanceTimersByTimeAsync(0) })
    expect(result.current.run).toBeNull()
    expect(MockEventSource.instances).toHaveLength(0)
  })

  test('stream onopen resets logs so a full-history replay does not duplicate', async () => {
    vi.stubGlobal('fetch', routedFetch({
      '/all': { runs: [{ run_id: 'r9', status: 'running', tool: 'garak' }] },
      '/status': { run_id: 'r9', status: 'running' },
    }))
    const { result } = renderHook(() => useAiAttackSurface('p1'))
    await act(async () => { await vi.advanceTimersByTimeAsync(0) })
    const es = MockEventSource.instances.find((e) => e.url.includes('/r9/logs'))!
    act(() => { es.emit('log', { log: 'stale', level: 'info' }) })   // pre-replay line
    expect(result.current.logs).toHaveLength(1)
    // server (re)opens the stream and replays from the start -> client resets
    act(() => { es.onopen?.() })
    expect(result.current.logs).toHaveLength(0)
    act(() => { es.emit('log', { log: 'fresh', level: 'info' }) })
    expect(result.current.logs.map((l) => l.log)).toEqual(['fresh'])
  })

  test('completion stops the stream and loads findings', async () => {
    vi.stubGlobal('fetch', routedFetch({
      '/start': { run_id: 'r1', status: 'running' },
      '/status': { run_id: 'r1', status: 'completed' },
      '/findings': { findings: [{ id: 'aiatk_1', source: 'garak' }] },
    }))
    const { result } = renderHook(() => useAiAttackSurface('p1'))
    await act(async () => {
      await result.current.launch({ tool: 'garak', targets: [], bounds: {}, roe_confirmed: true })
    })
    // advance to trigger the 3s status poll -> sees completed -> loads findings.
    // advanceTimersByTimeAsync flushes the async fetch chain, so assert directly
    // (waitFor would hang under fake timers).
    await act(async () => { await vi.advanceTimersByTimeAsync(3500) })
    expect(result.current.findings).toHaveLength(1)
    expect(MockEventSource.instances[0].closed).toBe(true)
  })
})
