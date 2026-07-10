/**
 * Unit tests for the act-as impersonation token.
 *
 * Run: npx vitest run src/lib/auth.actAs.test.ts
 *
 * @vitest-environment node
 */

import { describe, test, expect, vi } from 'vitest'

vi.stubEnv('AUTH_SECRET', 'b'.repeat(64))

import { createActAsToken, verifyActAsToken, createToken } from './auth'

describe('act-as token', () => {
  test('round-trips sub (admin) + act (target)', async () => {
    const t = await createActAsToken('admin-1', 'user-X')
    expect(await verifyActAsToken(t)).toEqual({ sub: 'admin-1', act: 'user-X' })
  })

  test('rejects a tampered token', async () => {
    const t = await createActAsToken('admin-1', 'user-X')
    expect(await verifyActAsToken(t.slice(0, -3) + 'zzz')).toBeNull()
  })

  test('rejects a login token (has role, no act claim) -> non-substitutable', async () => {
    const login = await createToken('admin-1', 'admin')
    expect(await verifyActAsToken(login)).toBeNull()
  })

  test('rejects garbage', async () => {
    expect(await verifyActAsToken('not-a-jwt')).toBeNull()
  })
})
