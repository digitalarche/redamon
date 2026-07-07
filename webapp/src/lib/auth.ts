import { SignJWT, jwtVerify } from 'jose'
import bcrypt from 'bcryptjs'

export const AUTH_COOKIE_NAME = 'redamon-auth'
const BCRYPT_ROUNDS = 12
const TOKEN_EXPIRY = '7d'

function getSecret() {
  const secret = process.env.AUTH_SECRET
  if (!secret || secret === 'changeme') {
    throw new Error('AUTH_SECRET environment variable is not set')
  }
  return new TextEncoder().encode(secret)
}

export async function hashPassword(plain: string): Promise<string> {
  return bcrypt.hash(plain, BCRYPT_ROUNDS)
}

export async function verifyPassword(plain: string, hash: string): Promise<boolean> {
  if (!hash) return false
  return bcrypt.compare(plain, hash)
}

export async function createToken(userId: string, role: string): Promise<string> {
  return new SignJWT({ sub: userId, role })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(TOKEN_EXPIRY)
    .sign(getSecret())
}

export async function verifyToken(token: string): Promise<{ sub: string; role: string } | null> {
  try {
    const { payload } = await jwtVerify(token, getSecret())
    if (!payload.sub || !payload.role) return null
    return { sub: payload.sub, role: payload.role as string }
  } catch {
    return null
  }
}

// --- Agent WebSocket ticket (STRIDE S6) ---------------------------------------
// Short-lived HS256 ticket that binds an authenticated operator identity to a
// (projectId, sessionId) so the agent can verify the /ws/agent init frame. Signed
// with a DEDICATED secret (never AUTH_SECRET) so an agent-side compromise cannot
// forge login cookies. Returns null when the secret is unset — the agent then
// fails open (dev), so the WS still connects.
const WS_TICKET_EXPIRY = '60s'

function getWsTicketSecret(): Uint8Array | null {
  const secret = process.env.AGENT_WS_TICKET_SECRET
  if (!secret || secret === 'changeme') return null
  return new TextEncoder().encode(secret)
}

export async function createWsTicket(
  userId: string,
  projectId: string,
  sessionId: string
): Promise<string | null> {
  const key = getWsTicketSecret()
  if (!key) return null
  return new SignJWT({ sub: userId, pid: projectId, sid: sessionId })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(WS_TICKET_EXPIRY)
    .sign(key)
}
