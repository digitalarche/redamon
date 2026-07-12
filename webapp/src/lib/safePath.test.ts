import { describe, test, expect } from 'vitest'
import path from 'path'
import { safeBasename, safeJoinWithin } from './safePath'

describe('safeBasename', () => {
  test('accepts a plain filename', () => {
    expect(safeBasename('report_123.html')).toBe('report_123.html')
    expect(safeBasename('a-b_c.2.html')).toBe('a-b_c.2.html')
  })

  test('rejects path traversal', () => {
    expect(safeBasename('../../../app/evil.html')).toBeNull()
    expect(safeBasename('..')).toBeNull()
    expect(safeBasename('.')).toBeNull()
    expect(safeBasename('foo/../bar')).toBeNull()
  })

  test('rejects any path separator (posix and windows)', () => {
    expect(safeBasename('a/b.html')).toBeNull()
    expect(safeBasename('a\\b.html')).toBeNull()
    expect(safeBasename('/etc/passwd')).toBeNull()
    expect(safeBasename('C:\\Windows\\evil')).toBeNull()
  })

  test('rejects dotfiles, empty, NUL byte, and non-strings', () => {
    expect(safeBasename('.env')).toBeNull()
    expect(safeBasename('.git')).toBeNull()
    expect(safeBasename('')).toBeNull()
    expect(safeBasename('a\0b')).toBeNull()
    expect(safeBasename(undefined)).toBeNull()
    expect(safeBasename(null)).toBeNull()
    expect(safeBasename(123)).toBeNull()
  })
})

describe('safeJoinWithin', () => {
  const base = '/data/reports'

  test('joins a safe name directly within base', () => {
    expect(safeJoinWithin(base, 'r.html')).toBe(path.resolve(base, 'r.html'))
  })

  test('rejects names that would escape base', () => {
    expect(safeJoinWithin(base, '../evil')).toBeNull()
    expect(safeJoinWithin(base, '/etc/passwd')).toBeNull()
    expect(safeJoinWithin(base, 'a/b')).toBeNull()
    expect(safeJoinWithin(base, '..')).toBeNull()
  })
})
