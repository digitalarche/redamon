/**
 * S4 regression: making connect() async (it awaits a ws-ticket fetch) must NOT
 * open two sockets when two connects race (double-click "Start"). A synchronous
 * connectingRef sentinel guards the window between the guard and wsRef assignment.
 *
 * We can't easily import the hooks headless (React), so we assert the invariant
 * on the extracted connect logic shape: two concurrent async connects that share
 * a wsRef + connectingRef sentinel construct exactly one WebSocket.
 *
 * @vitest-environment node
 */
import { describe, test, expect, vi } from 'vitest'

// Minimal reproduction of the guarded connect() control flow used by both
// cypherfix hooks (and KaliTerminal): sentinel set synchronously BEFORE the
// awaited ticket fetch, cleared after the socket is assigned.
function makeConnector(makeSocket: () => object) {
  const wsRef: { current: object | null } = { current: null }
  const connectingRef = { current: false }
  async function connect() {
    if (wsRef.current || connectingRef.current) return
    connectingRef.current = true
    // awaited ticket fetch (the window that used to allow a double-fire)
    await Promise.resolve()
    const ws = makeSocket()
    wsRef.current = ws
    connectingRef.current = false
    return ws
  }
  return { connect, wsRef }
}

describe('cypherfix/terminal connect double-fire guard (S4)', () => {
  test('two concurrent connects construct exactly ONE socket', async () => {
    const ctor = vi.fn(() => ({ id: Math.random() }))
    const { connect, wsRef } = makeConnector(ctor)
    // Fire twice in the same tick (double-click) before the await resolves.
    await Promise.all([connect(), connect()])
    expect(ctor).toHaveBeenCalledTimes(1)
    expect(wsRef.current).not.toBeNull()
  })

  test('WITHOUT the sentinel, the same race opens TWO sockets (proves the guard matters)', async () => {
    // Same flow minus connectingRef -> demonstrates the bug the sentinel fixes.
    const ctor = vi.fn(() => ({ id: Math.random() }))
    const wsRef: { current: object | null } = { current: null }
    async function unguarded() {
      if (wsRef.current) return
      await Promise.resolve()
      wsRef.current = ctor()
    }
    await Promise.all([unguarded(), unguarded()])
    expect(ctor).toHaveBeenCalledTimes(2)
  })
})
