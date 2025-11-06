import crypto from "crypto";
import bcrypt from "bcryptjs";
import {
  createUser,
  getUserByEmail,
  closeDatabase,
} from "../db.js";

const seedUsers = [
  {
    fullName: "Customer Portal User",
    email: "customer@example.com",
    phone: "+15555550100",
    password: "Customer123!",
    role: "customer",
  },
  {
    fullName: "Employee Portal User",
    email: "employee@example.com",
    phone: "+15555550200",
    password: "Employee123!",
    role: "employee",
  },
];

async function ensureUser(seed) {
  const existing = await getUserByEmail(seed.email);
  if (existing) {
    console.log(`[seed] User already exists: ${seed.email}`);
    return;
  }

  const passwordHash = await bcrypt.hash(seed.password, 12);
  await createUser({
    id: crypto.randomUUID(),
    fullName: seed.fullName,
    email: seed.email,
    phone: seed.phone,
    role: seed.role,
    passwordHash,
    createdAt: new Date().toISOString(),
  });
  console.log(`[seed] Created user: ${seed.email} (${seed.role})`);
}

async function run() {
  try {
    for (const seed of seedUsers) {
      await ensureUser(seed);
    }
    console.log("[seed] Completed user seeding.");
  } catch (error) {
    console.error("[seed] Failed:", error);
    process.exitCode = 1;
  } finally {
    await closeDatabase();
  }
}

run();
