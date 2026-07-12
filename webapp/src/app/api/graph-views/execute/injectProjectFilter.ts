/**
 * Inject a project_id tenant filter into every node pattern of a Cypher query.
 *
 * The earlier version only rewrote `(var:Label ...)` patterns, so an
 * unlabeled or anonymous node pattern (`(n)`, `()`, `MATCH (n) RETURN n`)
 * slipped through with NO project_id predicate and could read across tenants.
 * This version scopes labeled, unlabeled, and anonymous node patterns alike,
 * skips the global reference labels, and never touches function-call parens.
 *
 * Extracted as a standalone function for testability.
 */

// Global node types that exist across all projects (no project_id property).
// These are enrichment/reference data from public databases (NVD, MITRE, CAPEC).
const GLOBAL_LABELS = new Set(['CVE', 'MitreData', 'Capec', 'ExploitGvm'])

const FILTER_PROP = 'project_id: $projectId'

// A node pattern is a `(...)` group with no nested parens that is NOT preceded
// by a word char or `$` -> that excludes function calls like `count(n)` /
// `id(x)` and parameter refs, matching only true node positions and groupings.
function nodePatternRegex(): RegExp {
  return /(?<![\w$])\(([^()]*)\)/g
}

// Interior grammar of a node pattern: optional variable, optional :Label(s)
// (including label-expression separators), optional {props}. A parenthesized
// expression such as `(a.x > 1)` fails this grammar and is left untouched.
const INTERIOR = /^(\w+)?\s*((?::[\w|&!]+)*)\s*(\{[\s\S]*\})?$/

function labelsFrom(labelStr: string): string[] {
  return labelStr.split(/[:|&!]+/).map(s => s.trim()).filter(Boolean)
}

interface ParsedNode {
  varName: string
  labelStr: string
  labels: string[]
  props?: string // includes the surrounding braces
}

/** Parse a node-pattern interior, or return null if it is not one. */
function parseInterior(interior: string): ParsedNode | null {
  const m = INTERIOR.exec(interior.trim())
  if (!m) return null
  const labelStr = m[2] || ''
  return {
    varName: m[1] || '',
    labelStr,
    labels: labelsFrom(labelStr),
    props: m[3],
  }
}

export function injectProjectFilter(cypher: string): string {
  return cypher.replace(nodePatternRegex(), (match, interior) => {
    const node = parseInterior(interior)
    if (!node) return match // parenthesized expression / function arg, leave as-is
    if (node.labels.some(l => GLOBAL_LABELS.has(l))) return match // global reference data
    if (node.props && /\bproject_id\b/.test(node.props)) return match // already scoped

    const head = `${node.varName}${node.labelStr}`
    if (node.props != null) {
      const inner = node.props.slice(1, -1).trim()
      const body = inner ? `${FILTER_PROP}, ${inner}` : FILTER_PROP
      return head ? `(${head} {${body}})` : `({${body}})`
    }
    return head ? `(${head} {${FILTER_PROP}})` : `({${FILTER_PROP}})`
  })
}

/**
 * Safety net. After injection, scan for any node pattern that still carries a
 * variable or a non-global label but lacks a project_id predicate. Returns the
 * first offending interior, or null when the query is fully tenant-scoped.
 */
export function findUnscopedNodePattern(cypher: string): string | null {
  const re = nodePatternRegex()
  let m: RegExpExecArray | null
  while ((m = re.exec(cypher)) !== null) {
    const node = parseInterior(m[1])
    if (!node) continue // not a node pattern
    if (node.labels.some(l => GLOBAL_LABELS.has(l))) continue // global reference data, exempt
    const scoped = !!node.props && /\bproject_id\b/.test(node.props)
    if (!scoped && (node.varName || node.labels.length > 0)) {
      return m[1].trim() || '(anonymous)'
    }
  }
  return null
}
