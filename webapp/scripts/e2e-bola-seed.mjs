/**
 * Seed fixtures for the two-user BOLA E2E (tests/test_e2e_bola_live.sh).
 * Creates two standard users (A, B) + one admin, and a project owned by each of
 * A and B. Idempotent (upsert by email). Prints KEY=VALUE lines for the shell.
 *
 * Run: docker compose exec -T webapp node scripts/e2e-bola-seed.mjs
 */
import { PrismaClient } from '@prisma/client'
import bcrypt from 'bcryptjs'

const PW = 'e2epass123'
const prisma = new PrismaClient()

async function upsertUser(email, name, role) {
  const hash = await bcrypt.hash(PW, 12)
  return prisma.user.upsert({
    where: { email },
    update: { password: hash, role, name },
    create: { email, name, password: hash, role },
  })
}

async function upsertProject(userId, name) {
  const existing = await prisma.project.findFirst({ where: { userId, name } })
  if (existing) return existing
  return prisma.project.create({
    data: { userId, name, targetDomain: 'e2e-bola.local', ipMode: true },
  })
}

try {
  const a = await upsertUser('bola-a@e2e.local', 'BOLA A', 'standard')
  const b = await upsertUser('bola-b@e2e.local', 'BOLA B', 'standard')
  const admin = await upsertUser('bola-admin@e2e.local', 'BOLA Admin', 'admin')
  const pa = await upsertProject(a.id, 'e2e-bola-A')
  const pb = await upsertProject(b.id, 'e2e-bola-B')

  // A conversation, a remediation and a preset owned by B (to test the
  // conversations/remediations/presets guards + carve-out routes cross-user).
  const CONV_B_SESSION = 'e2e-bola-sess-B'
  await prisma.conversation.upsert({
    where: { sessionId: CONV_B_SESSION },
    update: {},
    create: { userId: b.id, projectId: pb.id, sessionId: CONV_B_SESSION },
  })
  const remB = (await prisma.remediation.findFirst({ where: { projectId: pb.id, title: 'e2e-bola-rem' } }))
    || (await prisma.remediation.create({ data: { projectId: pb.id, title: 'e2e-bola-rem', description: 'x' } }))
  const presetB = (await prisma.userProjectPreset.findFirst({ where: { userId: b.id, name: 'e2e-bola-preset' } }))
    || (await prisma.userProjectPreset.create({ data: { userId: b.id, name: 'e2e-bola-preset', settings: {} } }))

  console.log(`A_ID=${a.id}`)
  console.log(`B_ID=${b.id}`)
  console.log(`ADMIN_ID=${admin.id}`)
  console.log(`PA_ID=${pa.id}`)
  console.log(`PB_ID=${pb.id}`)
  console.log(`CONV_B_SESSION=${CONV_B_SESSION}`)
  console.log(`REM_B_ID=${remB.id}`)
  console.log(`PRESET_B_ID=${presetB.id}`)
} catch (err) {
  console.error('SEED_ERROR:', err.message)
  process.exit(1)
} finally {
  await prisma.$disconnect()
}
