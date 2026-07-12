import { describe, test, expect } from 'vitest'
import { maskSecret, maskMcpServersForApi, restoreMaskedToken } from './mask'
import { MASK_PREFIX, type MCPServer } from '@/lib/mcp/schema'

function srv(overrides: Record<string, unknown>): MCPServer {
  return {
    id: 's1',
    name: 's1',
    transport: 'stdio',
    command: 'node',
    args: [],
    headers: {},
    env: {},
    ...overrides,
  } as unknown as MCPServer
}

describe('maskSecret', () => {
  test('masks a long value showing only last 4', () => {
    expect(maskSecret('supersecretkey1234')).toBe('••••••••1234')
  })
  test('fully masks short values and returns empty for empty', () => {
    expect(maskSecret('abcd')).toBe('••••')
    expect(maskSecret('')).toBe('')
  })
})

describe('maskMcpServersForApi', () => {
  test('masks auth token, header values, and env values but keeps keys', () => {
    const input = srv({
      auth: { token: 'realtoken1234' },
      headers: { 'X-Api-Key': 'headersecret9999', 'Content-Type': 'application/json' },
      env: { OPENAI_API_KEY: 'sk-realenvsecret' },
    })
    const [out] = maskMcpServersForApi([input])
    expect(out.auth?.token?.startsWith(MASK_PREFIX)).toBe(true)
    expect(out.auth?.token).not.toContain('realtoken')
    expect(out.headers['X-Api-Key'].startsWith(MASK_PREFIX)).toBe(true)
    expect(out.headers['Content-Type'].startsWith(MASK_PREFIX)).toBe(true) // all header values masked
    expect((out as { env: Record<string, string> }).env.OPENAI_API_KEY.startsWith(MASK_PREFIX)).toBe(true)
    expect(Object.keys(out.headers)).toEqual(['X-Api-Key', 'Content-Type']) // keys preserved
  })

  test('does not mutate the input server', () => {
    const input = srv({ auth: { token: 'realtoken1234' } })
    maskMcpServersForApi([input])
    expect(input.auth?.token).toBe('realtoken1234')
  })
})

describe('restoreMaskedToken (round-trip)', () => {
  const existing = srv({
    auth: { token: 'realtoken1234' },
    headers: { 'X-Api-Key': 'headersecret9999' },
    env: { OPENAI_API_KEY: 'sk-realenvsecret' },
  })

  test('restores masked token/headers/env from the existing record', () => {
    const masked = maskMcpServersForApi([existing])[0]
    const restored = restoreMaskedToken(masked, existing)
    expect(restored.auth?.token).toBe('realtoken1234')
    expect(restored.headers['X-Api-Key']).toBe('headersecret9999')
    expect((restored as { env: Record<string, string> }).env.OPENAI_API_KEY).toBe('sk-realenvsecret')
  })

  test('drops masked values with no saved counterpart (never persists the mask)', () => {
    const masked = maskMcpServersForApi([existing])[0]
    const restored = restoreMaskedToken(masked, undefined)
    expect(restored.auth?.token).toBeUndefined()
    expect(restored.headers['X-Api-Key']).toBeUndefined()
    expect((restored as { env: Record<string, string> }).env.OPENAI_API_KEY).toBeUndefined()
  })

  test('leaves freshly-entered (non-masked) values untouched', () => {
    const incoming = srv({
      auth: { token: 'brandnewtoken' },
      headers: { 'Content-Type': 'application/json' },
      env: { NEW: 'value' },
    })
    const restored = restoreMaskedToken(incoming, existing)
    expect(restored.auth?.token).toBe('brandnewtoken')
    expect(restored.headers['Content-Type']).toBe('application/json')
    expect((restored as { env: Record<string, string> }).env.NEW).toBe('value')
  })
})
