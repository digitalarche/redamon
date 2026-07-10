import { NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { requireEffectiveUser } from '@/lib/access'

/** GET /api/reports — List the effective user's reports (scoped by project owner). */
export async function GET() {
  try {
    const eff = await requireEffectiveUser()
    if (eff instanceof NextResponse) return eff

    const reports = await prisma.report.findMany({
      where: { project: { userId: eff.userId } },
      orderBy: { createdAt: 'desc' },
      select: {
        id: true,
        projectId: true,
        title: true,
        filename: true,
        fileSize: true,
        format: true,
        metrics: true,
        hasNarratives: true,
        createdAt: true,
        project: {
          select: {
            id: true,
            name: true,
            targetDomain: true,
          },
        },
      },
    })
    return NextResponse.json(reports)
  } catch (error) {
    console.error('List all reports failed:', error)
    return NextResponse.json(
      { error: error instanceof Error ? error.message : 'Failed to list reports' },
      { status: 500 }
    )
  }
}
