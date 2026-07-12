/**
 * Pure helpers for masking/restoring the secret-bearing fields of an MCP
 * server (auth token, custom header values, stdio env values) in API
 * responses. Extracted from the route handler so they can be unit-tested
 * without pulling in server-only dependencies (prisma, next/server).
 */
import { MASK_PREFIX, type MCPServer } from '@/lib/mcp/schema'

/** Mask a secret showing only the last 4 characters. */
export function maskSecret(value: string): string {
  if (!value) return ''
  if (value.length <= 4) return '••••'
  return '••••••••' + value.slice(-4)
}

function maskRecord(rec: Record<string, string> | undefined): Record<string, string> | undefined {
  if (!rec || Object.keys(rec).length === 0) return rec
  return Object.fromEntries(Object.entries(rec).map(([k, v]) => [k, maskSecret(String(v))]))
}

/** Replace secret-bearing values (auth token, custom headers, stdio env) with
 *  masked placeholders so an API response never returns them in cleartext. */
export function maskMcpServersForApi(servers: MCPServer[]): MCPServer[] {
  return servers.map(srv => {
    const next: MCPServer = { ...srv }
    if (srv.auth && srv.auth.token) {
      next.auth = { ...srv.auth, token: maskSecret(srv.auth.token) }
    }
    const maskedHeaders = maskRecord(srv.headers as Record<string, string> | undefined)
    if (maskedHeaders !== srv.headers) next.headers = maskedHeaders
    const inEnv = (srv as { env?: Record<string, string> }).env
    const maskedEnv = maskRecord(inEnv)
    if (maskedEnv !== inEnv) (next as { env?: Record<string, string> }).env = maskedEnv
    return next
  })
}

/** Restore masked values in a key/value record from the existing DB record.
 *  A masked value with no saved counterpart is dropped (never persisted). */
function restoreMaskedRecord(
  incoming: Record<string, string> | undefined,
  existing: Record<string, string> | undefined,
): Record<string, string> | undefined {
  if (!incoming) return incoming
  const out: Record<string, string> = {}
  for (const [k, v] of Object.entries(incoming)) {
    if (typeof v === 'string' && v.startsWith(MASK_PREFIX)) {
      if (existing && typeof existing[k] === 'string') out[k] = existing[k]
      // else: masked with no saved value -> drop the key rather than persist the mask
    } else {
      out[k] = v
    }
  }
  return out
}

/** When the user submits a server carrying masked placeholders (••••) for its
 *  token / headers / env, preserve the existing literals from the DB rather
 *  than writing the placeholder back. */
export function restoreMaskedToken(incoming: MCPServer, existing: MCPServer | undefined): MCPServer {
  let out: MCPServer = incoming

  if (out.auth && out.auth.token && out.auth.token.startsWith(MASK_PREFIX)) {
    if (existing?.auth?.token) {
      out = { ...out, auth: { ...out.auth, token: existing.auth.token } }
    } else {
      // Masked sent for a server with no prior token — strip the placeholder so
      // the schema's at-least-one validator triggers.
      out = { ...out, auth: { ...out.auth, token: undefined } }
    }
  }

  const restoredHeaders = restoreMaskedRecord(
    out.headers as Record<string, string> | undefined,
    existing?.headers as Record<string, string> | undefined,
  )
  if (restoredHeaders !== out.headers) out = { ...out, headers: restoredHeaders as MCPServer['headers'] }

  const inEnv = (out as { env?: Record<string, string> }).env
  const restoredEnv = restoreMaskedRecord(
    inEnv,
    (existing as { env?: Record<string, string> } | undefined)?.env,
  )
  if (restoredEnv !== inEnv) out = { ...out, env: restoredEnv } as MCPServer

  return out
}
