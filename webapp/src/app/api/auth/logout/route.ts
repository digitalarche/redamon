import { NextResponse } from 'next/server'
import { AUTH_COOKIE_NAME, ACT_AS_COOKIE_NAME } from '@/lib/auth'

export async function POST() {
  const response = NextResponse.json({ ok: true })
  const expire = {
    httpOnly: true,
    sameSite: 'lax' as const,
    secure: false,
    path: '/',
    maxAge: 0,
  }
  response.cookies.set(AUTH_COOKIE_NAME, '', expire)
  // Also clear any admin impersonation so it can't silently resume on next login.
  response.cookies.set(ACT_AS_COOKIE_NAME, '', expire)
  return response
}
