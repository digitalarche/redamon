/**
 * Remove the two-user BOLA E2E fixtures. Deleting the users cascades to their
 * projects/conversations/etc. (onDelete: Cascade).
 *
 * Run: docker compose exec -T webapp node scripts/e2e-bola-cleanup.mjs
 */
import { PrismaClient } from '@prisma/client'
const prisma = new PrismaClient()
try {
  const { count } = await prisma.user.deleteMany({
    where: { email: { in: ['bola-a@e2e.local', 'bola-b@e2e.local', 'bola-admin@e2e.local'] } },
  })
  console.log(`CLEANED=${count}`)
} catch (err) {
  console.error('CLEANUP_ERROR:', err.message)
  process.exit(1)
} finally {
  await prisma.$disconnect()
}
