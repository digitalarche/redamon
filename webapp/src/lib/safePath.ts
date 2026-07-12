import path from 'path'

/**
 * Return a safe basename for an untrusted filename, or `null` if the input is
 * not a plain, single-segment filename.
 *
 * Rejects: empty input, anything containing a path separator (`/` or `\`),
 * `.`/`..`, a leading dot (dotfiles), or a NUL byte. Because any input that
 * still contains a directory component is rejected outright (rather than
 * silently stripped), a caller can trust that a non-null result names a file
 * directly inside the intended directory.
 */
export function safeBasename(name: unknown): string | null {
  if (typeof name !== 'string' || name.length === 0) return null
  if (name.includes('\0')) return null
  // Reject if the value carries any directory component under either OS
  // separator (path.basename only strips the platform separator).
  if (name.includes('/') || name.includes('\\')) return null
  const base = path.basename(name)
  if (base !== name) return null
  if (base === '.' || base === '..') return null
  if (base.startsWith('.')) return null
  return base
}

/**
 * Join an untrusted filename onto a trusted base directory, guaranteeing the
 * result stays directly inside `baseDir`. Returns `null` if the filename is
 * unsafe (see {@link safeBasename}) or if, after resolution, the path would
 * escape `baseDir`.
 */
export function safeJoinWithin(baseDir: string, untrustedName: unknown): string | null {
  const base = safeBasename(untrustedName)
  if (base === null) return null
  const resolvedBase = path.resolve(baseDir)
  const joined = path.join(resolvedBase, base)
  const resolvedJoined = path.resolve(joined)
  // Defense in depth: the resolved path must equal baseDir/base exactly.
  if (resolvedJoined !== path.join(resolvedBase, base)) return null
  if (resolvedJoined !== resolvedBase && !resolvedJoined.startsWith(resolvedBase + path.sep)) return null
  return resolvedJoined
}
