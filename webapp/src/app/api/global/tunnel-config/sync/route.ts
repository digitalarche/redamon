import { NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

// POST /api/global/tunnel-config/sync
//
// Public trigger the kali-sandbox worker calls on boot.
//
// STRIDE I19: a worker (re)boot must NEVER silently re-activate tunnels — that
// would re-expose internal listeners to the internet and break the LAN-only
// premise. So on boot we FORCE tunnels down: clear the `tunnelsEnabled` flag and
// push an empty (stop) config to the tunnel-manager. The operator must
// deliberately re-enable tunnels from Global Settings, which is the only
// activation path. Because this only ever DISABLES, it stays safe to expose
// without auth (an unauthenticated caller can at most turn tunnels off).
export async function POST() {
  try {
    // Reflect reality in the UI: tunnels are down after a restart.
    await prisma.userSettings.updateMany({
      where: { tunnelsEnabled: true },
      data: { tunnelsEnabled: false },
    })

    const headers: Record<string, string> = { 'Content-Type': 'application/json' }
    const token = process.env.TUNNEL_AUTH_TOKEN
    if (token) headers['Authorization'] = `Bearer ${token}`

    await fetch('http://kali-sandbox:8015/tunnel/configure', {
      method: 'POST',
      headers,
      body: JSON.stringify({ ngrokAuthtoken: '', chiselServerUrl: '', chiselAuth: '' }),
    })

    return NextResponse.json({ ok: true, configured: false })
  } catch (error) {
    console.error('Tunnel config sync failed:', error)
    // Return 200 so the worker's best-effort boot trigger does not retry-spam.
    return NextResponse.json({ ok: false })
  }
}
