import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { verifyPassword, createToken, AUTH_COOKIE_NAME } from '@/lib/auth'
import { writeAudit } from '@/lib/audit'
import { getClientMeta } from '@/lib/requestMeta'
import { checkLockout, recordFailure, clearAttempts } from '@/lib/loginThrottle'

export async function POST(request: NextRequest) {
  try {
    const { email, password } = await request.json()
    const meta = getClientMeta(request)

    if (!email || !password) {
      return NextResponse.json(
        { error: 'Email and password are required' },
        { status: 400 }
      )
    }

    // S11: reject if this account or source IP is currently locked out.
    const lock = checkLockout(String(email), meta.ip)
    if (lock.locked) {
      await writeAudit({
        action: 'auth.login.lockout', targetType: 'user',
        after: { email: String(email), ip: meta.ip, ipTrusted: meta.ipTrusted, retryAfter: lock.retryAfterSeconds },
      })
      return NextResponse.json(
        { error: 'Too many failed attempts. Try again later.' },
        { status: 429, headers: { 'Retry-After': String(lock.retryAfterSeconds) } }
      )
    }

    const user = await prisma.user.findUnique({
      where: { email },
      select: { id: true, name: true, email: true, password: true, role: true },
    })

    if (!user || !user.password) {
      // R5: log the failure. Record ONLY the attempted email + source IP; never
      // the password or hash. S11: increment the lockout counter.
      recordFailure(String(email), meta.ip)
      await writeAudit({
        action: 'auth.login.failure', targetType: 'user',
        after: { email: String(email), ip: meta.ip, ipTrusted: meta.ipTrusted, userAgent: meta.userAgent },
      })
      return NextResponse.json(
        { error: 'Invalid email or password' },
        { status: 401 }
      )
    }

    const valid = await verifyPassword(password, user.password)
    if (!valid) {
      recordFailure(String(email), meta.ip)
      await writeAudit({
        action: 'auth.login.failure', targetType: 'user', targetId: user.id,
        after: { email: String(email), ip: meta.ip, ipTrusted: meta.ipTrusted, userAgent: meta.userAgent },
      })
      return NextResponse.json(
        { error: 'Invalid email or password' },
        { status: 401 }
      )
    }

    // S11: successful login clears the failure counters for this email + IP.
    clearAttempts(String(email), meta.ip)
    await writeAudit({
      actorId: user.id, action: 'auth.login.success', targetType: 'user', targetId: user.id,
      after: { ip: meta.ip, ipTrusted: meta.ipTrusted, userAgent: meta.userAgent },
    })

    const token = await createToken(user.id, user.role)

    const response = NextResponse.json({
      id: user.id,
      name: user.name,
      email: user.email,
      role: user.role,
    })

    response.cookies.set(AUTH_COOKIE_NAME, token, {
      httpOnly: true,
      sameSite: 'lax',
      secure: false,
      path: '/',
      maxAge: 7 * 24 * 60 * 60, // 7 days
    })

    return response
  } catch (error) {
    console.error('Login error:', error)
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    )
  }
}
