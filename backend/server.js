import fs from "fs";
import path from "path";
import https from "https";
import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import bcrypt from "bcryptjs";
import crypto from "crypto";

const asyncHandler = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

import {
  getUserByEmail,
  getUserById,
  updateUserPassword,
  replaceSession,
  getSession,
  updateSessionCsrf,
  listBeneficiaries,
  addBeneficiary,
  getBeneficiaryById,
  removeBeneficiary,
  listPayments,
  addPayment,
  removePaymentsForBeneficiary,
  listAllPayments,
  getBeneficiariesByIds,
  getUsersByIds,
} from "./db.js";

const app = express();

/* ---------- Security middleware ---------- */
// Helmet gives a basic layer of security headers.
app.use(
  helmet({
    contentSecurityPolicy: false,
    hsts: false,
  })
);
// Limit JSON body size to avoid some joker uploading a movie as “user data”
app.use(express.json({ limit: "50kb" }));

/* ---------- CORS (dev allowlist) ---------- */
// This only allows requests from your local dev origin.
// If anyone else tries to talk to the server, it quietly ignores them.
app.use((req, res, next) => {
  const devOrigin = "https://localhost:5173";
  const origin = req.headers.origin || devOrigin;

  if (origin === devOrigin) {
    res.header("Access-Control-Allow-Origin", origin);
    res.header("Vary", "Origin"); // cache control for multiple origins
    res.header("Access-Control-Allow-Credentials", "true");
    res.header(
      "Access-Control-Allow-Headers",
      "Content-Type, Authorization, X-CSRF-Token, X-Request-Time, X-Requested-With"
    );
    res.header("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS");
    res.header("Access-Control-Expose-Headers", "X-CSRF-Token");
  }

  // Handle preflight OPTIONS requests without drama
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

/* ---------- Rate limits ---------- */
// Prevent brute force login spamming.
// 20 attempts per 10 minutes, which is generous enough unless you’re a bot.
const loginLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
});

/* ---------- Regex allowlists ---------- */
// Because letting users type whatever they want ends badly.
const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const nameRe = /^[A-Za-z .'-]{2,60}$/;
const pwRe = /^[A-Za-z0-9!@#$%^&*()_+\-=\[\]{};':",.<>/?]{8,64}$/;
const acctRe = /^[0-9]{8,18}$/;
const bankRe = /^[A-Za-z0-9' .,&-]{2,60}$/;
const currencyRe = /^(USD|EUR|GBP|ZAR|JPY|AUD|CAD|CHF|CNY)$/;
const swiftRe = /^[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?$/;
const referenceRe = /^[A-Za-z0-9 .,'#&\-]{1,40}$/;
const amountRe = /^(?!0(?:\.0{1,2})?$)\d{1,9}(?:\.\d{2})?$/;

/* ---------- Helpers ---------- */
// Creates a new session for a user and kills any previous one.
async function createSession(userId) {
  const token = crypto.randomUUID();
  const csrfToken = crypto.randomBytes(24).toString("hex");
  await replaceSession({ token, userId, csrfToken, createdAt: Date.now() });
  return { token, csrfToken };
}

// Checks if the request has a valid Bearer token and session.
const authed = asyncHandler(async (req, res, next) => {
  const token = String(req.headers.authorization || "").replace("Bearer ", "");
  const session = await getSession(token);
  if (!session) {
    return res.status(401).json({ code: "NO_TOKEN", message: "Unauthorized" });
  }

  req.userId = session.userId;
  req.session = { ...session };
  req.authToken = token;

  // Send current CSRF token with each response
  res.setHeader("X-CSRF-Token", session.csrfToken);
  next();
});

// Confirms CSRF token matches, then rotates it.
const requireCsrf = asyncHandler(async (req, res, next) => {
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) return next();
  if (!req.session) {
    return res.status(401).json({ code: "NO_SESSION", message: "Session not found" });
  }

  const incoming = req.headers["x-csrf-token"];
  if (typeof incoming !== "string" || incoming !== req.session.csrfToken) {
    return res.status(403).json({ code: "CSRF_INVALID", message: "Security validation failed" });
  }

  req.session.csrfToken = crypto.randomBytes(24).toString("hex");
  await updateSessionCsrf(req.authToken, req.session.csrfToken);
  res.setHeader("X-CSRF-Token", req.session.csrfToken);
  next();
});

// Login with rate limiting
app.post(
  "/auth/login",
  loginLimiter,
  asyncHandler(async (req, res) => {
    const { email, password } = req.body || {};
    if (!emailRe.test(email || "") || !pwRe.test(password || "")) {
      return res.status(400).json({ code: "BAD_INPUT", message: "Invalid credentials format" });
    }

    const record = await getUserByEmail(email);
    if (!record || !(await bcrypt.compare(String(password), record.passwordHash))) {
      return res.status(401).json({ code: "UNAUTHORIZED", message: "Invalid email or password" });
    }

    const session = await createSession(record.id);
    res
      .set("X-CSRF-Token", session.csrfToken)
      .json({
        user: {
          id: record.id,
          fullName: record.fullName,
          email: record.email,
          phone: record.phone,
          createdAt: record.createdAt,
          role: record.role ?? "customer",
        },
        token: session.token,
        csrfToken: session.csrfToken,
      });
  })
);

// Password change with old password check
app.post(
  "/auth/change-password",
  authed,
  requireCsrf,
  asyncHandler(async (req, res) => {
    const { oldPassword, newPassword } = req.body || {};
    if (!pwRe.test(newPassword || "")) {
      return res.status(422).json({ code: "BAD_INPUT", message: "Weak password" });
    }

    const record = await getUserById(req.userId);
    if (!record) return res.status(404).json({ code: "NOT_FOUND", message: "User not found" });

    const ok = await bcrypt.compare(String(oldPassword || ""), record.passwordHash);
    if (!ok) return res.status(401).json({ code: "UNAUTHORIZED", message: "Current password incorrect" });

    const newHash = await bcrypt.hash(String(newPassword), 12);
    await updateUserPassword(req.userId, newHash);

    return res.json({ ok: true, message: "Password updated" });
  })
);

/* ---------- User and Data Routes ---------- */
// Return user profile
app.get(
  "/me",
  authed,
  asyncHandler(async (req, res) => {
    const record = await getUserById(req.userId);
    if (!record) return res.json(null);
    const { passwordHash, ...user } = record;
    res.json(user);
  })
);

// List user’s beneficiaries
app.get(
  "/beneficiaries",
  authed,
  asyncHandler(async (req, res) => {
    const actor = await getUserById(req.userId);
    if (!actor) {
      return res.status(404).json({ code: "NOT_FOUND", message: "User not found" });
    }
    if ((actor.role ?? "customer") !== "customer") {
      return res
        .status(403)
        .json({ code: "FORBIDDEN", message: "Employees cannot access beneficiaries" });
    }

    const list = (await listBeneficiaries(req.userId)).map(({ userId, ...ben }) => ben);
    res.json(list);
  })
);

// Add a new beneficiary with validation & dedupe
app.post(
  "/beneficiaries",
  authed,
  requireCsrf,
  asyncHandler(async (req, res) => {
    const actor = await getUserById(req.userId);
    if (!actor) {
      return res.status(404).json({ code: "NOT_FOUND", message: "User not found" });
    }
    if ((actor.role ?? "customer") !== "customer") {
      return res
        .status(403)
        .json({ code: "FORBIDDEN", message: "Employees cannot add beneficiaries" });
    }

    const { name, bank, accountNumber, swift, currency } = req.body || {};

    const trimmedName = typeof name === "string" ? name.trim() : "";
    const trimmedBank = typeof bank === "string" ? bank.trim() : "";
    const trimmedAccount = typeof accountNumber === "string" ? accountNumber.trim() : "";
    const trimmedSwift = typeof swift === "string" ? swift.trim().toUpperCase() : "";
    const currencyCode = typeof currency === "string" ? currency.trim().toUpperCase() : "USD";

    if (!nameRe.test(trimmedName) || !acctRe.test(trimmedAccount)) {
      return res.status(422).json({ code: "BAD_INPUT", message: "Invalid beneficiary details" });
    }

    if (trimmedBank && !bankRe.test(trimmedBank)) {
      return res.status(422).json({ code: "BAD_INPUT", message: "Invalid bank name" });
    }

    if (trimmedSwift && !swiftRe.test(trimmedSwift)) {
      return res.status(422).json({ code: "BAD_INPUT", message: "Invalid SWIFT code" });
    }

    if (currencyCode && !currencyRe.test(currencyCode)) {
      return res.status(422).json({ code: "BAD_INPUT", message: "Invalid currency" });
    }

    const list = await listBeneficiaries(req.userId);
    const normalizedName = trimmedName.toLowerCase();
    const normalizedBank = trimmedBank.toLowerCase();
    const duplicate = list.some((ben) => {
      const sameAccount = ben.accountNumber === trimmedAccount;
      const sameIdentity =
        ben.name.toLowerCase() === normalizedName &&
        ben.bank.toLowerCase() === (normalizedBank || "unknown bank");
      return sameAccount || sameIdentity;
    });
    if (duplicate) {
      return res.status(409).json({ code: "BENEFICIARY_EXISTS", message: "Beneficiary already exists" });
    }

    const item = {
      id: crypto.randomUUID(),
      name: trimmedName,
      bank: trimmedBank || "Unknown Bank",
      accountNumber: trimmedAccount,
      swift: trimmedSwift,
      currency: currencyCode || "USD",
      createdAt: new Date().toISOString(),
    };
    await addBeneficiary({ ...item, userId: req.userId });
    res.status(201).json(item);
  })
);

// Delete beneficiary and related payments
app.delete(
  "/beneficiaries/:id",
  authed,
  requireCsrf,
  asyncHandler(async (req, res) => {
    const actor = await getUserById(req.userId);
    if (!actor) {
      return res.status(404).json({ code: "NOT_FOUND", message: "User not found" });
    }
    if ((actor.role ?? "customer") !== "customer") {
      return res
        .status(403)
        .json({ code: "FORBIDDEN", message: "Employees cannot remove beneficiaries" });
    }

    const { id } = req.params;
    if (!id || typeof id !== "string") {
      return res.status(400).json({ code: "BAD_INPUT", message: "Beneficiary id required" });
    }

    const removed = await removeBeneficiary(req.userId, id);
    if (!removed) {
      return res.status(404).json({ code: "BENEFICIARY_NOT_FOUND", message: "Beneficiary not found" });
    }

    await removePaymentsForBeneficiary(req.userId, id);

    res.status(204).send();
  })
);

// Create a payment with full validation
app.post(
  "/payments",
  authed,
  requireCsrf,
  asyncHandler(async (req, res) => {
    const actor = await getUserById(req.userId);
    if (!actor) {
      return res.status(404).json({ code: "NOT_FOUND", message: "User not found" });
    }
    if ((actor.role ?? "customer") !== "customer") {
      return res
        .status(403)
        .json({ code: "FORBIDDEN", message: "Employees cannot create payments" });
    }

    const { beneficiaryId, amount, currency, reference } = req.body || {};

    const trimmedBeneficiaryId = typeof beneficiaryId === "string" ? beneficiaryId.trim() : "";
    const amountStr = typeof amount === "number" ? amount.toFixed(2) : String(amount ?? "").trim();
    const currencyCode = typeof currency === "string" ? currency.trim().toUpperCase() : "USD";
    const referenceStr = typeof reference === "string" ? reference.trim() : "";

    if (!trimmedBeneficiaryId) {
      return res.status(422).json({ code: "BAD_INPUT", message: "Beneficiary is required" });
    }

    if (!amountRe.test(amountStr)) {
      return res.status(422).json({ code: "BAD_INPUT", message: "Invalid amount format" });
    }

    const amountValue = Number(amountStr);
    if (!Number.isFinite(amountValue) || amountValue <= 0 || amountValue > 999999999.99) {
      return res.status(422).json({ code: "BAD_INPUT", message: "Amount out of range" });
    }

    if (currencyCode && !currencyRe.test(currencyCode)) {
      return res.status(422).json({ code: "BAD_INPUT", message: "Invalid currency code" });
    }

    if (referenceStr && !referenceRe.test(referenceStr)) {
      return res.status(422).json({ code: "BAD_INPUT", message: "Invalid reference" });
    }

    const beneficiary = await getBeneficiaryById(req.userId, trimmedBeneficiaryId);
    if (!beneficiary) {
      return res.status(404).json({ code: "BENEFICIARY_NOT_FOUND", message: "Beneficiary not found" });
    }

    const pay = {
      id: crypto.randomUUID(),
      beneficiaryId: trimmedBeneficiaryId,
      amount: amountValue,
      currency: currencyCode || "USD",
      reference: referenceStr,
      createdAt: new Date().toISOString(),
    };
    await addPayment({ ...pay, userId: req.userId });
    res.status(201).json(pay);
  })
);

// Transaction history
app.get(
  "/transactions",
  authed,
  asyncHandler(async (req, res) => {
    const actor = await getUserById(req.userId);
    if (!actor) {
      return res.status(404).json({ code: "NOT_FOUND", message: "User not found" });
    }

    if ((actor.role ?? "customer") === "employee") {
      const payments = await listAllPayments();
      if (payments.length === 0) {
        return res.json([]);
      }

      const beneficiaryIds = payments.map((p) => p.beneficiaryId).filter(Boolean);
      const userIds = payments.map((p) => p.userId);

      const [beneficiaries, users] = await Promise.all([
        getBeneficiariesByIds(beneficiaryIds),
        getUsersByIds(userIds),
      ]);

      const benMap = new Map(beneficiaries.map((ben) => [ben.id, ben]));
      const userMap = new Map(users.map((user) => [user.id, user]));

      const tx = payments.map(({ userId, ...p }) => {
        const owner = userMap.get(userId);
        const ben = benMap.get(p.beneficiaryId);
        return {
          ...p,
          customerId: userId,
          customerName: owner?.fullName ?? "Unknown Customer",
          customerEmail: owner?.email ?? "unknown",
          beneficiaryName: ben?.name ?? "Unknown",
          beneficiaryBank: ben?.bank ?? "Unknown Bank",
        };
      });

      return res.json(tx);
    }

    const pays = await listPayments(req.userId);
    const bens = await listBeneficiaries(req.userId);
    const nameById = new Map(bens.map((ben) => [ben.id, ben.name]));
    const tx = pays.map(({ userId, ...p }) => ({
      ...p,
      beneficiaryName: nameById.get(p.beneficiaryId) || "Unknown",
    }));
    res.json(tx);
  })
);

/* ---------- Error handler ---------- */
// Universal catch-all. Logs and returns a very polite 500.
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ code: "SERVER_ERROR", message: "Something went wrong" });
});

/* ---------- HTTPS bootstrap ---------- */
// Loads your local cert/key for HTTPS dev server.
// If you lose the cert folder, the server cries.
const key = fs.readFileSync(path.join(".cert", "key.pem"));
const cert = fs.readFileSync(path.join(".cert", "cert.pem"));
https.createServer({ key, cert }, app).listen(3001, () => {
  console.log("API running on https://localhost:3001");
});
