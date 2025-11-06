// src/api/handlers.ts
import { http, HttpResponse } from "msw";
import type { AuthResponse, User, Beneficiary, Payment, Transaction } from "./types";
import { v4 as uuid } from "uuid";
import bcrypt from "bcryptjs";

// --------------------- Fake in-memory DB ---------------------
const db = {
  users: new Map<string, { user: User; passwordHash: string }>(),
  sessions: new Map<string, string>(),             // token -> userId
  beneficiaries: new Map<string, Beneficiary[]>(), // userId -> list
  payments: new Map<string, Payment[]>(),          // userId -> list
};

// helper: extract logged-in user id from Authorization header
function getUserId(req: Request): string | null {
  const auth = req.headers.get("authorization");
  const token = auth?.replace("Bearer ", "");
  const userId = token ? db.sessions.get(token) : undefined;
  return userId ?? null;
}

// ===================== AUTH =====================
const authHandlers = [
  // Register
  http.post("/auth/register", async ({ request }) => {
    const body = (await request.json()) as any;
    const { fullName, email, passwordHash, phone } = body || {};

    if (!fullName || !email || !passwordHash) {
      return HttpResponse.json({ message: "Invalid payload" }, { status: 422 });
    }

    const exists = [...db.users.values()].some(
      r => r.user.email.toLowerCase() === String(email).toLowerCase()
    );
    if (exists) {
      return HttpResponse.json({ message: "Email already in use" }, { status: 409 });
    }

    const user: User = { id: uuid(), fullName, email, phone };
    db.users.set(user.id, { user, passwordHash });

    const token = uuid();
    db.sessions.set(token, user.id);

    const res: AuthResponse = { user, token };
    return HttpResponse.json(res, { status: 201 });
  }),

  // Login (checks password, reuses stable token)
  http.post("/auth/login", async ({ request }) => {
    const { email, password } = (await request.json()) as any;

    const record = [...db.users.values()].find(
      r => r.user.email.toLowerCase() === String(email).toLowerCase()
    );
    if (!record) {
      return HttpResponse.json({ message: "Invalid credentials" }, { status: 401 });
    }

    const ok = await bcrypt.compare(String(password ?? ""), record.passwordHash);
    if (!ok) {
      return HttpResponse.json({ message: "Invalid credentials" }, { status: 401 });
    }

    let token = [...db.sessions.entries()].find(([, uid]) => uid === record.user.id)?.[0];
    if (!token) {
      token = uuid();
      db.sessions.set(token, record.user.id);
    }

    const res: AuthResponse = { user: record.user, token };
    return HttpResponse.json(res, { status: 200 });
  }),

  // Who am I
  http.get("/me", ({ request }) => {
    const userId = getUserId(request);
    if (!userId) return HttpResponse.json({ message: "Unauthorized" }, { status: 401 });
    return HttpResponse.json(db.users.get(userId)?.user ?? null);
  }),

  // Change password (accepts hashed pw from client for coursework only)
  http.post("/auth/change-password", async ({ request }) => {
    const userId = getUserId(request);
    if (!userId) return HttpResponse.json({ message: "Unauthorized" }, { status: 401 });

    const { passwordHash } = (await request.json()) as any;
    if (!passwordHash) {
      return HttpResponse.json({ message: "Missing passwordHash" }, { status: 422 });
    }

    const rec = db.users.get(userId);
    if (rec) db.users.set(userId, { ...rec, passwordHash });
    return HttpResponse.json({ ok: true });
  }),
]; // ← this closes authHandlers properly

// ================= BENEFICIARIES =================
const beneficiaryHandlers = [
  http.get("/beneficiaries", ({ request }) => {
    const userId = getUserId(request);
    if (!userId) return HttpResponse.json({ message: "Unauthorized" }, { status: 401 });
    return HttpResponse.json(db.beneficiaries.get(userId) ?? []);
  }),

  http.post("/beneficiaries", async ({ request }) => {
    const userId = getUserId(request);
    if (!userId) return HttpResponse.json({ message: "Unauthorized" }, { status: 401 });

    const body = (await request.json()) as Partial<Beneficiary>;
    const list = db.beneficiaries.get(userId) ?? [];

    const item: Beneficiary = {
      id: uuid(),
      name: body.name ?? "Unknown",
      bank: body.bank ?? "Unknown Bank",
      accountNumber: body.accountNumber ?? "0000000000",
      swift: body.swift ?? "",
      currency: body.currency ?? "USD",
    };

    list.push(item);
    db.beneficiaries.set(userId, list);
    return HttpResponse.json(item, { status: 201 });
  }),

  http.delete("/beneficiaries/:id", ({ request, params }) => {
    const userId = getUserId(request);
    if (!userId) return HttpResponse.json({ message: "Unauthorized" }, { status: 401 });

    const list = db.beneficiaries.get(userId) ?? [];
    db.beneficiaries.set(userId, list.filter(b => b.id !== params.id));
    return HttpResponse.json({ ok: true });
  }),
];

// =================== PAYMENTS / TX ===============
const paymentHandlers = [
  http.post("/payments", async ({ request }) => {
    const userId = getUserId(request);
    if (!userId) return HttpResponse.json({ message: "Unauthorized" }, { status: 401 });

    const body = (await request.json()) as Partial<Payment>;
    if (!body.beneficiaryId) {
      return HttpResponse.json({ message: "Missing beneficiaryId" }, { status: 422 });
    }

    const pay: Payment = {
      id: uuid(),
      beneficiaryId: body.beneficiaryId,
      amount: Number(body.amount ?? 0),
      currency: body.currency ?? "USD",
      reference: body.reference ?? "",
      createdAt: new Date().toISOString(),
    };

    const arr = db.payments.get(userId) ?? [];
    arr.unshift(pay);
    db.payments.set(userId, arr);

    return HttpResponse.json(pay, { status: 201 });
  }),

  http.get("/transactions", ({ request }) => {
    const userId = getUserId(request);
    if (!userId) return HttpResponse.json({ message: "Unauthorized" }, { status: 401 });

    const pays = db.payments.get(userId) ?? [];
    const bens = db.beneficiaries.get(userId) ?? [];

    const tx: Transaction[] = pays.map(p => ({
      ...p,
      beneficiaryName: bens.find(b => b.id === p.beneficiaryId)?.name ?? "Unknown",
    }));

    return HttpResponse.json(tx);
  }),
];

// --------------------- Export all handlers ---------------------
export const handlers = [
  ...authHandlers,
  ...beneficiaryHandlers,
  ...paymentHandlers,
];