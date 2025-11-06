import fs from "fs";
import path from "path";
import https from "https";
import express from "express";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import bcrypt from "bcryptjs";
import crypto from "crypto";

const app = express();

/* ---------- Security middleware ---------- */
app.use(helmet({
  contentSecurityPolicy: false, // keep CSP off for localhost; use real headers in prod
  hsts: false                   // avoid sticky HTTPS on localhost
}));
app.use(express.json({ limit: "50kb" }));

// CORS allowlist: your Vite dev origin
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "https://localhost:5173");
  res.header("Access-Control-Allow-Credentials", "true");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.header("Access-Control-Allow-Methods", "GET,POST,DELETE,OPTIONS");
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});

// Login brute-force limiter
const loginLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false
});

/* ---------- In-memory “DB” ---------- */
const users = new Map();         // id -> { user, passwordHash }
const sessions = new Map();      // token -> userId
const beneficiaries = new Map(); // userId -> Beneficiary[]
const payments = new Map();      // userId -> Payment[]

/* ---------- Regex allowlists ---------- */
const emailRe = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const nameRe  = /^[A-Za-z .'-]{2,60}$/;
const pwRe    = /^[A-Za-z0-9!@#$%^&*()_+\-=\[\]{};':",.<>/?]{8,64}$/;
const acctRe  = /^[0-9]{8,18}$/;

/* ---------- Helpers ---------- */
function issueToken(userId) {
  let token = [...sessions.entries()].find(([, uid]) => uid === userId)?.[0];
  if (!token) {
    token = crypto.randomUUID();
    sessions.set(token, userId);
  }
  return token;
}
function authed(req, res, next) {
  const token = String(req.headers.authorization || "").replace("Bearer ", "");
  const uid = sessions.get(token);
  if (!uid) return res.status(401).json({ code: "NO_TOKEN", message: "Unauthorized" });
  req.userId = uid;
  next();
}

/* ---------- Routes ---------- */
app.post("/auth/register", async (req, res) => {
  const { fullName, email, password, phone } = req.body || {};
  if (!nameRe.test(fullName || "") || !emailRe.test(email || "") || !pwRe.test(password || "")) {
    return res.status(422).json({ code: "BAD_INPUT", message: "Invalid registration data" });
  }
  const exists = [...users.values()].some(r => r.user.email.toLowerCase() === String(email).toLowerCase());
  if (exists) return res.status(409).json({ code: "EMAIL_IN_USE", message: "Email already in use" });

  const id = crypto.randomUUID();
  const passwordHash = await bcrypt.hash(String(password), 12);
  const user = { id, fullName, email, phone: phone || "" };
  users.set(id, { user, passwordHash });

  const token = issueToken(id);
  res.status(201).json({ user, token });
});

app.post("/auth/login", loginLimiter, async (req, res) => {
  const { email, password } = req.body || {};
  if (!emailRe.test(email || "") || !pwRe.test(password || "")) {
    return res.status(400).json({ code: "BAD_INPUT", message: "Invalid credentials format" });
  }
  const record = [...users.values()].find(r => r.user.email.toLowerCase() === String(email).toLowerCase());
  if (!record || !(await bcrypt.compare(String(password), record.passwordHash))) {
    return res.status(401).json({ code: "UNAUTHORIZED", message: "Invalid email or password" });
  }
  const token = issueToken([...users.entries()].find(([, v]) => v === record)[0]);
  res.json({ user: record.user, token });
});

app.get("/me", authed, (req, res) => {
  res.json(users.get(req.userId)?.user ?? null);
});

app.get("/beneficiaries", authed, (req, res) => {
  res.json(beneficiaries.get(req.userId) ?? []);
});

app.post("/beneficiaries", authed, (req, res) => {
  const { name, bank, accountNumber, swift, currency } = req.body || {};
  if (!nameRe.test(name || "") || !acctRe.test(accountNumber || "")) {
    return res.status(422).json({ code: "BAD_INPUT", message: "Invalid beneficiary" });
  }
  const list = beneficiaries.get(req.userId) ?? [];
  const item = {
    id: crypto.randomUUID(),
    name,
    bank: bank || "Unknown Bank",
    accountNumber,
    swift: swift || "",
    currency: currency || "USD"
  };
  beneficiaries.set(req.userId, [...list, item]);
  res.status(201).json(item);
});

app.post("/payments", authed, (req, res) => {
  const { beneficiaryId, amount, currency, reference } = req.body || {};
  if (!beneficiaryId || isNaN(Number(amount))) {
    return res.status(422).json({ code: "BAD_INPUT", message: "Invalid payment" });
  }
  const arr = payments.get(req.userId) ?? [];
  const pay = {
    id: crypto.randomUUID(),
    beneficiaryId,
    amount: Number(amount),
    currency: currency || "USD",
    reference: reference || "",
    createdAt: new Date().toISOString()
  };
  payments.set(req.userId, [pay, ...arr]);
  res.status(201).json(pay);
});

app.get("/transactions", authed, (req, res) => {
  const pays = payments.get(req.userId) ?? [];
  const bens = beneficiaries.get(req.userId) ?? [];
  const tx = pays.map(p => ({ ...p, beneficiaryName: bens.find(b => b.id === p.beneficiaryId)?.name || "Unknown" }));
  res.json(tx);
});

/* ---------- Error handler ---------- */
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ code: "SERVER_ERROR", message: "Something went wrong" });
});

/* ---------- HTTPS bootstrap ---------- */
const key = fs.readFileSync(path.join(".cert", "key.pem"));
const cert = fs.readFileSync(path.join(".cert", "cert.pem"));
https.createServer({ key, cert }, app).listen(3001, () => {
  console.log("API running on https://localhost:3001");
});

// Change password (server-side hashing, verifies old password)
app.post("/auth/change-password", authed, async (req, res) => {
  const { oldPassword, newPassword } = req.body || {};
  if (!pwRe.test(newPassword || "")) {
    return res.status(422).json({ code: "BAD_INPUT", message: "Weak password" });
  }

  const record = users.get(req.userId);
  if (!record) return res.status(404).json({ code: "NOT_FOUND", message: "User not found" });

  const ok = await bcrypt.compare(String(oldPassword || ""), record.passwordHash);
  if (!ok) return res.status(401).json({ code: "UNAUTHORIZED", message: "Current password incorrect" });

  const newHash = await bcrypt.hash(String(newPassword), 12);
  users.set(req.userId, { ...record, passwordHash: newHash });

  return res.json({ ok: true, message: "Password updated" });
});