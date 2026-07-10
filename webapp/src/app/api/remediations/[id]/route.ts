import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { isInternalRequest } from '@/lib/session'
import { requireEffectiveUser, requireProjectScopedResource } from '@/lib/access'

interface RouteParams {
  params: Promise<{ id: string }>
}

// A remediation is owned via its parent project. Cypherfix uses X-Internal-Key
// (carve-out); browser callers must own the remediation's project.
async function guardRemediation(request: NextRequest, id: string): Promise<NextResponse | null> {
  if (isInternalRequest(request)) return null
  const eff = await requireEffectiveUser()
  if (eff instanceof NextResponse) return eff
  const guard = await requireProjectScopedResource(eff, async () => {
    const r = await prisma.remediation.findUnique({ where: { id }, select: { projectId: true } })
    return r?.projectId
  })
  return guard instanceof NextResponse ? guard : null
}

// GET /api/remediations/[id] - Get single remediation
export async function GET(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params

    const denied = await guardRemediation(request, id)
    if (denied) return denied

    const remediation = await prisma.remediation.findUnique({
      where: { id },
    })

    if (!remediation) {
      return NextResponse.json(
        { error: 'Remediation not found' },
        { status: 404 }
      )
    }

    return NextResponse.json(remediation)
  } catch (error) {
    console.error('Failed to fetch remediation:', error)
    return NextResponse.json(
      { error: 'Failed to fetch remediation' },
      { status: 500 }
    )
  }
}

// PUT /api/remediations/[id] - Update remediation
export async function PUT(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params

    const denied = await guardRemediation(request, id)
    if (denied) return denied

    const body = await request.json()

    const { projectId, createdAt, updatedAt, project, ...updateData } = body

    const remediation = await prisma.remediation.update({
      where: { id },
      data: updateData,
    })

    return NextResponse.json(remediation)
  } catch (error: unknown) {
    console.error('Failed to update remediation:', error)

    if (error && typeof error === 'object' && 'code' in error && error.code === 'P2025') {
      return NextResponse.json(
        { error: 'Remediation not found' },
        { status: 404 }
      )
    }

    return NextResponse.json(
      { error: 'Failed to update remediation' },
      { status: 500 }
    )
  }
}

// DELETE /api/remediations/[id] - Delete remediation
export async function DELETE(request: NextRequest, { params }: RouteParams) {
  try {
    const { id } = await params

    const denied = await guardRemediation(request, id)
    if (denied) return denied

    await prisma.remediation.delete({
      where: { id },
    })

    return NextResponse.json({ success: true })
  } catch (error: unknown) {
    console.error('Failed to delete remediation:', error)

    if (error && typeof error === 'object' && 'code' in error && error.code === 'P2025') {
      return NextResponse.json(
        { error: 'Remediation not found' },
        { status: 404 }
      )
    }

    return NextResponse.json(
      { error: 'Failed to delete remediation' },
      { status: 500 }
    )
  }
}
