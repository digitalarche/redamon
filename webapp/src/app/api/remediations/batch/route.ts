import { NextRequest, NextResponse } from 'next/server'
import prisma from '@/lib/prisma'
import { isInternalRequest } from '@/lib/session'
import { requireEffectiveUser, requireProjectAccess } from '@/lib/access'

// POST /api/remediations/batch - Batch create remediations (triage agent via
// X-Internal-Key carve-out; browser callers must own the project).
export async function POST(request: NextRequest) {
  try {
    const body = await request.json()
    const { projectId, remediations } = body

    if (!projectId || !Array.isArray(remediations) || remediations.length === 0) {
      return NextResponse.json(
        { error: 'projectId and non-empty remediations array are required' },
        { status: 400 }
      )
    }

    if (!isInternalRequest(request)) {
      const eff = await requireEffectiveUser()
      if (eff instanceof NextResponse) return eff
      const access = await requireProjectAccess(eff, projectId)
      if (access instanceof NextResponse) return access
    }

    // Delete existing pending remediations for this project (re-triage replaces them)
    await prisma.remediation.deleteMany({
      where: { projectId, status: 'pending' },
    })

    // Batch create all new remediations
    const created = await prisma.$transaction(
      remediations.map((rem: Record<string, unknown>) =>
        prisma.remediation.create({
          data: {
            projectId,
            title: rem.title as string,
            description: rem.description as string,
            severity: (rem.severity as string) || 'medium',
            priority: (rem.priority as number) || 0,
            category: (rem.category as string) || 'vulnerability',
            remediationType: (rem.remediationType as string) || 'code_fix',
            affectedAssets: rem.affectedAssets || [],
            cvssScore: rem.cvssScore as number | undefined,
            cveIds: (rem.cveIds as string[]) || [],
            cweIds: (rem.cweIds as string[]) || [],
            capecIds: (rem.capecIds as string[]) || [],
            evidence: (rem.evidence as string) || '',
            attackChainPath: (rem.attackChainPath as string) || '',
            exploitAvailable: (rem.exploitAvailable as boolean) || false,
            cisaKev: (rem.cisaKev as boolean) || false,
            solution: (rem.solution as string) || '',
            fixComplexity: (rem.fixComplexity as string) || 'medium',
            estimatedFiles: (rem.estimatedFiles as number) || 0,
            targetRepo: (rem.targetRepo as string) || '',
            targetBranch: (rem.targetBranch as string) || 'main',
          },
        })
      )
    )

    return NextResponse.json(created, { status: 201 })
  } catch (error) {
    console.error('Failed to batch create remediations:', error)
    return NextResponse.json(
      { error: 'Failed to batch create remediations' },
      { status: 500 }
    )
  }
}
