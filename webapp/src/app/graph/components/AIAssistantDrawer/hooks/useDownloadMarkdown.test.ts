/**
 * Unit tests for the Markdown session-export header.
 *
 * Run: npx vitest run src/app/graph/components/AIAssistantDrawer/hooks/useDownloadMarkdown.test.ts
 *
 * Focus: the XBEN-evaluation fields added to the "# AI Agent Session Report"
 * header -- Session id, Wall time (first-to-last timestamp), and Tokens
 * (summed across root thinking deltas + fireteam member cumulative totals,
 * matching the on-screen DrawerHeader). downloadStreaming is mocked so the test
 * captures the emitted Markdown without touching browser file APIs.
 */

import { describe, test, expect, vi, beforeEach } from 'vitest'
import { renderHook } from '@testing-library/react'
import type { ChatItem } from '../types'

// Capture whatever the hook streams to disk.
let captured = ''
vi.mock('../../../utils/exportHelpers', () => ({
  downloadStreaming: async (
    _filename: string,
    _mime: string,
    makeChunks: () => AsyncGenerator<string>,
  ) => {
    captured = ''
    for await (const chunk of makeChunks()) captured += chunk
    return true
  },
}))

import { useDownloadMarkdown } from './useDownloadMarkdown'

function run(chatItems: ChatItem[], sessionId = 'session_abc123def456') {
  const { result } = renderHook(() =>
    useDownloadMarkdown({
      chatItems,
      currentPhase: 'exploitation',
      iterationCount: 18,
      modelName: 'deepseek-v4-pro',
      todoList: [],
      sessionId,
    }),
  )
  return result.current.handleDownloadMarkdown()
}

// Minimal ChatItem factories. Only the fields the header math reads are set;
// cast keeps the test focused on header behaviour rather than full item shape.
function userMsg(atMs: number): ChatItem {
  return { type: 'message', id: `m${atMs}`, role: 'user', content: 'go', timestamp: new Date(atMs) } as unknown as ChatItem
}
function assistantMsg(atMs: number): ChatItem {
  return { type: 'message', id: `a${atMs}`, role: 'assistant', content: 'done', timestamp: new Date(atMs) } as unknown as ChatItem
}
function thinking(atMs: number, inTok: number, outTok: number): ChatItem {
  return { type: 'thinking', id: `t${atMs}`, timestamp: new Date(atMs), thought: 'x', input_tokens: inTok, output_tokens: outTok } as unknown as ChatItem
}
function fireteam(atMs: number, members: Array<{ input_tokens_used: number; output_tokens_used: number }>): ChatItem {
  const fullMembers = members.map((m, i) => ({
    name: `member-${i}`,
    member_id: `mem-${i}`,
    status: 'success',
    ...m,
  }))
  return { type: 'fireteam', id: `f${atMs}`, timestamp: new Date(atMs), status: 'success', members: fullMembers } as unknown as ChatItem
}

beforeEach(() => { captured = '' })

describe('useDownloadMarkdown header', () => {
  test('sums tokens across thinking deltas and fireteam members', async () => {
    await run([
      userMsg(0),
      thinking(1000, 700_000, 90_000),
      fireteam(2000, [
        { input_tokens_used: 30_000, output_tokens_used: 6_000 },
        { input_tokens_used: 8_000, output_tokens_used: 2_000 },
      ]),
      assistantMsg(1_960_000),
    ])
    // 700k + 30k + 8k = 738,000 ; 90k + 6k + 2k = 98,000 ; total 836,000
    expect(captured).toContain('**Tokens:** in 738,000 · out 98,000 · total 836,000')
  })

  test('wall time is last-minus-first timestamp, both pretty and seconds', async () => {
    await run([userMsg(0), thinking(500_000, 1, 1), assistantMsg(1_960_000)])
    expect(captured).toContain('**Wall time:** 32m 40s (1960s)')
  })

  test('includes the full session id for log correlation', async () => {
    await run([userMsg(0), assistantMsg(5000)], 'session_203c6e074e8ba3e0')
    expect(captured).toContain('**Session:** session_203c6e074e8ba3e0')
  })

  test('omits Tokens line when no token data is present', async () => {
    await run([userMsg(0), assistantMsg(5000)])
    expect(captured).not.toContain('**Tokens:**')
    // wall time still present (2 timestamps exist)
    expect(captured).toContain('**Wall time:** 5s (5s)')
  })

  test('sub-minute wall time renders without a minute part', async () => {
    await run([userMsg(0), assistantMsg(89_000)])
    expect(captured).toContain('**Wall time:** 1m 29s (89s)')
  })

  test('empty session produces no output at all', async () => {
    await run([])
    expect(captured).toBe('')
  })

  test('header order: Date, Session, Phase, Step, Model, Wall time, Tokens', async () => {
    await run([userMsg(0), thinking(1000, 10, 5), assistantMsg(60_000)])
    const idx = (s: string) => captured.indexOf(s)
    expect(idx('**Date:**')).toBeGreaterThanOrEqual(0)
    expect(idx('**Date:**')).toBeLessThan(idx('**Session:**'))
    expect(idx('**Session:**')).toBeLessThan(idx('**Phase:**'))
    expect(idx('**Phase:**')).toBeLessThan(idx('**Step:**'))
    expect(idx('**Step:**')).toBeLessThan(idx('**Model:**'))
    expect(idx('**Model:**')).toBeLessThan(idx('**Wall time:**'))
    expect(idx('**Wall time:**')).toBeLessThan(idx('**Tokens:**'))
  })
})
