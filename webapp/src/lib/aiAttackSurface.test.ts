/**
 * Invariants for the AI Attack Surface shared vocabulary.
 * @vitest-environment node
 */
import { describe, test, expect } from 'vitest'
import { existsSync, readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import {
  ALL_CARDS, ATTACK_CHIPS, FUTURE_CARDS, GARAK_CARD, PYRIT_CARD, GISKARD_CARD,
  PROMPTFOO_CARD, resolveAuth, splitUrl,
  type ChipKey,
} from './aiAttackSurface'

const CHIP_KEYS = Object.keys(ATTACK_CHIPS) as ChipKey[]

describe('ATTACK_CHIPS', () => {
  test('has 11 chips, each fully specified', () => {
    expect(CHIP_KEYS).toHaveLength(11)
    for (const k of CHIP_KEYS) {
      const c = ATTACK_CHIPS[k]
      expect(c.label).toBeTruthy()
      expect(c.color).toMatch(/^#[0-9a-f]{6}$/i)
      expect(c.owasp).toBeTruthy()
      expect(c.definition).toBeTruthy()
    }
  })
})

describe('cards', () => {
  test('every card chip is a known chip key', () => {
    for (const card of ALL_CARDS) {
      for (const chip of card.chips) {
        expect(CHIP_KEYS).toContain(chip)
      }
    }
  })

  test('garak probes map to known chip keys', () => {
    for (const p of GARAK_CARD.probes) {
      expect(CHIP_KEYS).toContain(p.chip)
      expect(p.id).toBeTruthy()
    }
  })

  test('garak + pyrit + giskard + promptfoo all available; no future cards', () => {
    expect(GARAK_CARD.available).toBe(true)
    expect(PYRIT_CARD.available).toBe(true)
    expect(GISKARD_CARD.available).toBe(true)
    expect(PROMPTFOO_CARD.available).toBe(true)
    expect(FUTURE_CARDS).toHaveLength(0)
    expect(ALL_CARDS).toHaveLength(4)
    expect(ALL_CARDS[0]).toBe(GARAK_CARD)
    expect(PYRIT_CARD.probes.map((p) => p.id)).toEqual(['crescendo', 'skeleton_key', 'tap', 'many_shot'])
    // giskard probes are the scan detector tags (extended in Tier-1)
    expect(GISKARD_CARD.probes.map((p) => p.id)).toEqual(
      ['prompt_injection', 'information_disclosure', 'hallucination', 'harmfulness', 'stereotypes', 'sycophancy', 'output_formatting'])
    // promptfoo probes are the verified single-turn dataset plugins
    expect(PROMPTFOO_CARD.probes.map((p) => p.id)).toEqual(['pliny', 'beavertails', 'harmbench'])
    // promptfoo also exposes local-only mutation strategies
    expect(PROMPTFOO_CARD.strategies?.map((s) => s.id)).toEqual(['basic', 'base64', 'rot13', 'leetspeak', 'morse', 'piglatin'])
  })

  test('garak probe catalog still offers the documented MVP families', () => {
    // The catalog has since been expanded well beyond the MVP; assert the MVP
    // families remain offered (subset) rather than pinning the full list.
    const ids = new Set(GARAK_CARD.probes.map((p) => p.id))
    for (const mvp of ['dan', 'encoding', 'leakreplay', 'promptinject']) {
      expect(ids.has(mvp)).toBe(true)
    }
  })

  test('garak catalog excludes inactive-by-default + no-op families that abort the run', () => {
    const ids = GARAK_CARD.probes.map((p) => p.id)
    expect(ids).toHaveLength(33)                 // full v0.15.1 minus the 7 below
    expect(new Set(ids).size).toBe(ids.length)   // unique
    expect(ids).not.toContain('test')            // no-op smoke probe
    // These garak families have ZERO active sub-probes by default, so selecting
    // one makes garak abort the WHOLE run. They must never appear in the catalog.
    for (const dead of ['doctor', 'donotanswer', 'fitd', 'goat', 'propile', 'smuggling', 'av_spam_scanning']) {
      expect(ids, `${dead} is inactive-by-default and must be removed`).not.toContain(dead)
    }
  })

  test('only the four MVP families default to checked', () => {
    const on = GARAK_CARD.probes.filter((p) => p.default).map((p) => p.id).sort()
    expect(on).toEqual(['dan', 'encoding', 'leakreplay', 'promptinject'])
  })

  test('every probe across every card has a non-empty description', () => {
    for (const card of ALL_CARDS) {
      for (const p of card.probes) {
        expect(p.description).toBeTruthy()
      }
    }
  })

  test('garak probes that need a non-chat / white-box target are flagged requires', () => {
    const byId = new Map(GARAK_CARD.probes.map((p) => [p.id, p]))
    for (const id of ['audio', 'visual_jailbreak', 'glitch', 'fileformats', 'agent_breaker']) {
      expect(byId.get(id)?.requires, `${id} must be flagged incompatible`).toBeTruthy()
    }
  })

  test('GPU-heavy probes carry a warning (shown as a hover alert in the UI)', () => {
    const byId = new Map(GARAK_CARD.probes.map((p) => [p.id, p]))
    for (const id of ['divergence', 'tap', 'realtoxicityprompts', 'atkgen']) {
      expect(byId.get(id)?.warning, `${id} must carry a GPU warning`).toBeTruthy()
    }
    // a normal fast probe has none
    expect(byId.get('dan')?.warning).toBeFalsy()
  })

  test('no default-selected probe is flagged incompatible (defaults must be runnable)', () => {
    for (const card of ALL_CARDS) {
      for (const p of card.probes) {
        if (p.default) expect(p.requires, `${card.id}/${p.id}`).toBeFalsy()
      }
    }
  })

  test('card ids are unique', () => {
    const ids = ALL_CARDS.map((c) => c.id)
    expect(new Set(ids).size).toBe(ids.length)
  })

  // Filter-bar invariant: filtering hides any card whose `chips` does not include
  // the active chip. If a probe used a chip absent from its card's `chips`, the
  // card would vanish when filtering by that chip even though it has a match.
  test('every probe chip is declared in its card chips', () => {
    for (const card of ALL_CARDS) {
      for (const p of card.probes) {
        expect(card.chips).toContain(p.chip)
      }
    }
  })
})

// Regression: the frontend probe catalog and the backend owasp_map must agree.
// Every garak family selectable in the UI must be classified by the backend with
// the SAME chip, else a finding's chip in the graph diverges from the UI vocab
// (or falls back to the LLM01 default). Parses the Python source so drift in
// either file fails the build.
describe('frontend ↔ backend owasp_map consistency', () => {
  const owaspMapPath = resolve(process.cwd(),
    '../ai_attack_surface_scan/adapters/garak/owasp_map.py')
  const hasBackend = existsSync(owaspMapPath)

  const parseBackendMap = (): Record<string, { owasp: string; chip: string; oracle: string }> => {
    const src = readFileSync(owaspMapPath, 'utf8')
    // Only the PROBE_FAMILY_MAP dict body, to avoid catching the _DEFAULT tuple.
    // Anchor on the dict assignment (not an earlier comment mention) and slice up
    // to the `_DEFAULT =` assignment that follows it.
    const mapStart = src.indexOf('PROBE_FAMILY_MAP: dict')
    const body = src.slice(mapStart, src.indexOf('_DEFAULT =', mapStart))
    const re = /"([a-z_]+)":\s*\(\s*"([^"]+)"\s*,\s*"([^"]+)"\s*,\s*"([^"]+)"\s*\)/g
    const out: Record<string, { owasp: string; chip: string; oracle: string }> = {}
    let m: RegExpExecArray | null
    while ((m = re.exec(body)) !== null) out[m[1]] = { owasp: m[2], chip: m[3], oracle: m[4] }
    return out
  }

  test.skipIf(!hasBackend)('every garak UI family is mapped with a matching chip', () => {
    const backend = parseBackendMap()
    expect(Object.keys(backend).length).toBeGreaterThan(0)
    for (const p of GARAK_CARD.probes) {
      const entry = backend[p.id]
      expect(entry, `family "${p.id}" missing from PROBE_FAMILY_MAP`).toBeTruthy()
      expect(entry.chip, `chip mismatch for "${p.id}"`).toBe(p.chip)
    }
  })

  test.skipIf(!hasBackend)('every backend chip is a known frontend chip key', () => {
    const backend = parseBackendMap()
    for (const [fam, entry] of Object.entries(backend)) {
      expect(CHIP_KEYS, `backend family "${fam}" uses unknown chip "${entry.chip}"`)
        .toContain(entry.chip as ChipKey)
    }
  })
})

describe('resolveAuth (shared, reused by all tools)', () => {
  test('none -> no header', () => {
    expect(resolveAuth({ mode: 'none' })).toEqual({ api_key: '', auth_header: '', auth_scheme: '' })
  })
  test('bearer -> Authorization + Bearer scheme', () => {
    expect(resolveAuth({ mode: 'bearer', bearerToken: 'sk-1' }))
      .toEqual({ api_key: 'sk-1', auth_header: 'Authorization', auth_scheme: 'Bearer' })
  })
  test('custom -> named header, no scheme', () => {
    expect(resolveAuth({ mode: 'custom', headerName: 'x-api-key', headerValue: 'k' }))
      .toEqual({ api_key: 'k', auth_header: 'x-api-key', auth_scheme: '' })
  })
})

describe('splitUrl (custom target parsing)', () => {
  test('splits host and path+query', () => {
    expect(splitUrl('https://api.example.com:8443/v1/chat/completions?x=1'))
      .toEqual({ baseUrl: 'https://api.example.com:8443', path: '/v1/chat/completions?x=1' })
  })
  test('bare host -> root path', () => {
    expect(splitUrl('http://h:11434')).toEqual({ baseUrl: 'http://h:11434', path: '/' })
  })
  test('garbage -> null', () => {
    expect(splitUrl('not a url')).toBeNull()
  })
})
