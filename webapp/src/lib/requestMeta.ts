// R5: extract the client source IP for auth audit events.
//
// IP-trust caveat: X-Forwarded-For is authoritative ONLY behind a trusted proxy
// (the public posture, where nginx overwrites it with the real peer). In the
// LOCAL posture there is no nginx and a client can forge X-Forwarded-For, so we
// record the IP as best-effort/unverified rather than attribution-grade. Set
// TRUST_PROXY=1 (public/behind-nginx deploy) to mark it trusted.
import type { NextRequest } from 'next/server'

export interface ClientMeta {
  ip: string | null
  ipTrusted: boolean
  userAgent: string | null
}

function behindTrustedProxy(): boolean {
  const on = (v: string | undefined) => v === '1' || v === 'true'
  return on(process.env.TRUST_PROXY) || on(process.env.DEPLOY_BEHIND_PROXY)
}

export function getClientMeta(request: NextRequest): ClientMeta {
  const trusted = behindTrustedProxy()
  const userAgent = request.headers.get('user-agent')
  const xff = request.headers.get('x-forwarded-for')
  if (xff) {
    return { ip: xff.split(',')[0].trim() || null, ipTrusted: trusted, userAgent }
  }
  const real = request.headers.get('x-real-ip')
  if (real) return { ip: real.trim() || null, ipTrusted: trusted, userAgent }
  return { ip: null, ipTrusted: false, userAgent }
}
