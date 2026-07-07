/**
 * STRIDE S7 — session ids must be CSPRNG-generated, high-entropy, unguessable.
 *
 * Run: npx vitest run "src/hooks/useSession.test.tsx"
 */
import { describe, test, expect } from 'vitest'
import { renderHook, act } from '@testing-library/react'
import { useSession } from './useSession'

const FORMAT = /^session_[0-9a-f]{32}$/ // 128-bit hex

describe('useSession — S7', () => {
  test('generates a 128-bit hex id, not the old 8-char Math.random form', () => {
    const { result } = renderHook(() => useSession())
    expect(result.current.sessionId).toMatch(FORMAT)
  })

  test('resetSession yields a different, well-formed id', () => {
    const { result } = renderHook(() => useSession())
    const first = result.current.sessionId
    let next = ''
    act(() => {
      next = result.current.resetSession()
    })
    expect(next).toMatch(FORMAT)
    expect(next).not.toBe(first)
  })

  test('ids are unique across many generations (no predictable stream)', () => {
    const seen = new Set<string>()
    for (let i = 0; i < 200; i++) {
      const { result } = renderHook(() => useSession())
      seen.add(result.current.sessionId)
    }
    // With 128 bits of entropy, 200 draws must all be distinct.
    expect(seen.size).toBe(200)
  })
})
