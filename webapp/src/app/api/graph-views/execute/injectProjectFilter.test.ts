/**
 * Unit tests for injectProjectFilter.
 *
 * Run: npx vitest run src/app/api/graph-views/execute/injectProjectFilter.test.ts
 */

import { describe, test, expect } from 'vitest'
import { injectProjectFilter, findUnscopedNodePattern } from './injectProjectFilter'

describe('injectProjectFilter', () => {
  test('injects project_id into bare node pattern', () => {
    const input = 'MATCH (d:Domain) RETURN d'
    const result = injectProjectFilter(input)
    expect(result).toBe('MATCH (d:Domain {project_id: $projectId}) RETURN d')
  })

  test('injects project_id into node with existing properties', () => {
    const input = 'MATCH (d:Domain {name: "example.com"}) RETURN d'
    const result = injectProjectFilter(input)
    expect(result).toBe('MATCH (d:Domain {project_id: $projectId, name: "example.com"}) RETURN d')
  })

  test('injects into multiple nodes', () => {
    const input = 'MATCH (d:Domain)-[:HAS_SUBDOMAIN]->(s:Subdomain) RETURN d, s'
    const result = injectProjectFilter(input)
    expect(result).toContain('(d:Domain {project_id: $projectId})')
    expect(result).toContain('(s:Subdomain {project_id: $projectId})')
  })

  test('skips CVE nodes (global label)', () => {
    const input = 'MATCH (t:Technology)-[:HAS_KNOWN_CVE]->(c:CVE) RETURN t, c'
    const result = injectProjectFilter(input)
    expect(result).toContain('(t:Technology {project_id: $projectId})')
    expect(result).toContain('(c:CVE)')
    expect(result).not.toContain('(c:CVE {project_id')
  })

  test('skips MitreData nodes (global label)', () => {
    const input = 'MATCH (c:CVE)-[:HAS_CWE]->(m:MitreData) RETURN c, m'
    const result = injectProjectFilter(input)
    expect(result).toContain('(c:CVE)')
    expect(result).toContain('(m:MitreData)')
    expect(result).not.toContain('(m:MitreData {project_id')
  })

  test('skips Capec nodes (global label)', () => {
    const input = 'MATCH (m:MitreData)-[:HAS_CAPEC]->(cap:Capec) RETURN m, cap'
    const result = injectProjectFilter(input)
    expect(result).not.toContain('(cap:Capec {project_id')
  })

  test('skips ExploitGvm nodes (global label)', () => {
    const input = 'MATCH (e:ExploitGvm) RETURN e'
    const result = injectProjectFilter(input)
    expect(result).toBe('MATCH (e:ExploitGvm) RETURN e')
  })

  test('preserves existing props on global labels', () => {
    const input = 'MATCH (c:CVE {severity: "CRITICAL"}) RETURN c'
    const result = injectProjectFilter(input)
    expect(result).toBe('MATCH (c:CVE {severity: "CRITICAL"}) RETURN c')
  })

  test('handles complex query with mixed labels', () => {
    const input = `
      MATCH (d:Domain)-[:HAS_SUBDOMAIN]->(s:Subdomain)-[:RESOLVES_TO]->(ip:IP)
      MATCH (ip)-[:HAS_PORT]->(p:Port)
      MATCH (t:Technology {name: "nginx"})-[:HAS_KNOWN_CVE]->(c:CVE)
      RETURN d, s, ip, p, t, c
    `
    const result = injectProjectFilter(input)
    expect(result).toContain('(d:Domain {project_id: $projectId})')
    expect(result).toContain('(s:Subdomain {project_id: $projectId})')
    expect(result).toContain('(ip:IP {project_id: $projectId})')
    expect(result).toContain('(p:Port {project_id: $projectId})')
    expect(result).toContain('(t:Technology {project_id: $projectId, name: "nginx"})')
    expect(result).toContain('(c:CVE)')
    expect(result).not.toContain('(c:CVE {project_id')
  })

  test('handles empty braces', () => {
    const input = 'MATCH (d:Domain {}) RETURN d'
    const result = injectProjectFilter(input)
    expect(result).toBe('MATCH (d:Domain {project_id: $projectId}) RETURN d')
  })

  test('handles query with LIMIT', () => {
    const input = 'MATCH (v:Vulnerability {severity: "critical"}) RETURN v LIMIT 50'
    const result = injectProjectFilter(input)
    expect(result).toContain('(v:Vulnerability {project_id: $projectId, severity: "critical"})')
    expect(result).toContain('LIMIT 50')
  })
})

describe('injectProjectFilter — cross-tenant node patterns (regression)', () => {
  test('scopes an UNLABELED variable node (the leak vector)', () => {
    // Previously (n) got no project_id and could read across tenants.
    expect(injectProjectFilter('MATCH (n) RETURN n')).toBe(
      'MATCH (n {project_id: $projectId}) RETURN n'
    )
  })

  test('scopes an unlabeled variable node with existing props', () => {
    expect(injectProjectFilter('MATCH (n {name: "x"}) RETURN n')).toBe(
      'MATCH (n {project_id: $projectId, name: "x"}) RETURN n'
    )
  })

  test('scopes a label-only node (no variable)', () => {
    expect(injectProjectFilter('MATCH (:Host) RETURN 1')).toBe(
      'MATCH (:Host {project_id: $projectId}) RETURN 1'
    )
  })

  test('scopes an anonymous node in a relationship path', () => {
    const out = injectProjectFilter('MATCH (a:Host)-[:R]->() RETURN a')
    expect(out).toContain('(a:Host {project_id: $projectId})')
    expect(out).toContain('({project_id: $projectId})')
  })

  test('does NOT double-inject an already-scoped node', () => {
    const input = 'MATCH (n:Host {project_id: $projectId}) RETURN n'
    expect(injectProjectFilter(input)).toBe(input)
  })

  test('does NOT mangle a function call like count(n)', () => {
    const input = 'MATCH (n:Host) RETURN count(n)'
    const out = injectProjectFilter(input)
    expect(out).toContain('(n:Host {project_id: $projectId})')
    expect(out).toContain('count(n)')
    expect(out).not.toContain('count(n {')
  })

  test('does NOT mangle a parenthesized WHERE expression', () => {
    const input = 'MATCH (n:Host) WHERE (n.port > 1000) RETURN n'
    const out = injectProjectFilter(input)
    expect(out).toContain('(n.port > 1000)')
  })
})

describe('findUnscopedNodePattern', () => {
  test('flags a raw unlabeled variable node before injection', () => {
    expect(findUnscopedNodePattern('MATCH (n) RETURN n')).toBe('n')
  })

  test('flags a raw labeled node before injection', () => {
    expect(findUnscopedNodePattern('MATCH (h:Host) RETURN h')).toBe('h:Host')
  })

  test('returns null once injectProjectFilter has scoped the query', () => {
    const cases = [
      'MATCH (n) RETURN n',
      'MATCH (h:Host)-[:R]->(s:Svc) RETURN h, s',
      'MATCH (h:Host)-[:R]->() RETURN h',
      'MATCH (:Host) RETURN 1',
      'MATCH (t:Technology)-[:HAS_KNOWN_CVE]->(c:CVE) RETURN t, c',
      'MATCH (n:Host) RETURN count(n)',
    ]
    for (const q of cases) {
      expect(findUnscopedNodePattern(injectProjectFilter(q))).toBeNull()
    }
  })

  test('exempts global reference labels', () => {
    expect(findUnscopedNodePattern('MATCH (c:CVE) RETURN c')).toBeNull()
  })

  test('does not flag anonymous waypoint nodes (no var, no label)', () => {
    expect(findUnscopedNodePattern('MATCH (h:Host {project_id: $projectId})-[:R]->() RETURN h')).toBeNull()
  })
})
