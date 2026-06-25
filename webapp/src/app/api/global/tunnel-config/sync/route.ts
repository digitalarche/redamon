import { NextResponse } from 'next/server'
import prisma from '@/lib/prisma'

// POST /api/global/tunnel-config/sync
//
// Public trigger (no secrets in or out). The kali-sandbox worker calls this on
// boot to ask the webapp to PUSH the saved tunnel config to the worker's
// tunnel-manager (kali-sandbox:8015). Credentials never leave the server via a
// worker-initiated authenticated pull; they ride the same webapp -> worker push
// channel used when tunnel settings are saved. This keeps the worker free of
// secrets (least privilege) while still auto-restoring tunnels after a worker
// restart.
//
// Worst case for an unauthenticated caller on the internal network is a
// redundant re-push of the already-saved config to the worker: no data is
// disclosed, no state changes. Hence it is safe to expose without the internal
// key (see PUBLIC_PATHS in middleware.ts).
export async function POST() {
  try {
    const settings = await prisma.userSettings.findFirst({
      where: {
        OR: [
          { ngrokAuthtoken: { not: '' } },
          { chiselServerUrl: { not: '' } },
        ],
      },
      select: {
        ngrokAuthtoken: true,
        chiselServerUrl: true,
        chiselAuth: true,
      },
    })

    const config = settings ?? {
      ngrokAuthtoken: '',
      chiselServerUrl: '',
      chiselAuth: '',
    }

    await fetch('http://kali-sandbox:8015/tunnel/configure', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(config),
    })

    return NextResponse.json({ ok: true, configured: !!settings })
  } catch (error) {
    console.error('Tunnel config sync failed:', error)
    // Return 200 so the worker's best-effort boot trigger does not retry-spam.
    return NextResponse.json({ ok: false })
  }
}
