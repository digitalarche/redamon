import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requireAdmin } from '@/lib/session'
import { createActAsToken, ACT_AS_COOKIE_NAME } from '@/lib/auth'

// Impersonation ("switch user") is an ADMIN-only, server-authorized act. The
// client can no longer decide "which user am I" via a localStorage value: the
// effective user is derived server-side from this signed httpOnly cookie, and it
// is only ever consulted when the caller's real role (login JWT) is admin.

const COOKIE_OPTS = {
  httpOnly: true,
  sameSite: 'lax' as const,
  secure: false,
  path: '/',
  maxAge: 12 * 60 * 60, // 12h
}

// POST /api/auth/act-as  { targetUserId }  -> begin simulating targetUserId.
// Acting as self clears the cookie (equivalent to "stop simulating").
export async function POST(request: NextRequest) {
  const admin = await requireAdmin()
  if (admin instanceof NextResponse) return admin

  const body = await request.json().catch(() => ({}))
  const targetUserId = body?.targetUserId
  if (!targetUserId || typeof targetUserId !== 'string') {
    return NextResponse.json({ error: 'targetUserId is required' }, { status: 400 })
  }

  if (targetUserId === admin.userId) {
    const res = NextResponse.json({ actingAs: null })
    res.cookies.set(ACT_AS_COOKIE_NAME, '', { ...COOKIE_OPTS, maxAge: 0 })
    return res
  }

  const target = await prisma.user.findUnique({
    where: { id: targetUserId },
    select: { id: true },
  })
  if (!target) {
    return NextResponse.json({ error: 'User not found' }, { status: 404 })
  }

  const token = await createActAsToken(admin.userId, targetUserId)
  const res = NextResponse.json({ actingAs: targetUserId })
  res.cookies.set(ACT_AS_COOKIE_NAME, token, COOKIE_OPTS)
  return res
}

// DELETE /api/auth/act-as -> stop simulating (back to the admin's own data).
export async function DELETE() {
  const admin = await requireAdmin()
  if (admin instanceof NextResponse) return admin

  const res = NextResponse.json({ actingAs: null })
  res.cookies.set(ACT_AS_COOKIE_NAME, '', { ...COOKIE_OPTS, maxAge: 0 })
  return res
}
