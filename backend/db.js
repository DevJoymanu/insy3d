import "dotenv/config";
import { MongoClient } from "mongodb";

const connectionString =
  process.env.MONGODB_URI ||
  "mongodb+srv://hamyhamzah_db_user:Hamy1243@paymentscluster.deynebw.mongodb.net/?appName=paymentsCluster";
const databaseName = process.env.MONGODB_DB || "payments_portal";

const client = new MongoClient(connectionString, {
  serverSelectionTimeoutMS: 5000,
});

let collectionsPromise;

async function initialize() {
  const connectedClient = await client.connect();
  const db = connectedClient.db(databaseName);

  const users = db.collection("users");
  const sessions = db.collection("sessions");
  const beneficiaries = db.collection("beneficiaries");
  const payments = db.collection("payments");

  await Promise.all([
    users.createIndex({ emailLower: 1 }, { unique: true }),
    sessions.createIndex({ token: 1 }, { unique: true }),
    sessions.createIndex({ userId: 1 }),
    beneficiaries.createIndex({ userId: 1, createdAt: 1 }),
    payments.createIndex({ userId: 1, createdAt: -1 }),
    payments.createIndex({ beneficiaryId: 1 }),
  ]);

  return { users, sessions, beneficiaries, payments };
}

function getCollections() {
  if (!collectionsPromise) {
    collectionsPromise = initialize();
  }
  return collectionsPromise;
}

function stripMongoFields(document, extra = []) {
  if (!document) return null;
  const cloned = { ...document };
  delete cloned._id;
  for (const key of extra) {
    delete cloned[key];
  }
  return cloned;
}

function normalizeUser(document) {
  const sanitized = stripMongoFields(document, ["emailLower"]);
  if (!sanitized) return null;
  return {
    ...sanitized,
    role: typeof sanitized.role === "string" ? sanitized.role : "customer",
  };
}

export async function createUser(record) {
  const { users } = await getCollections();
  const payload = {
    ...record,
    role: typeof record.role === "string" ? record.role : "customer",
    emailLower: record.email.toLowerCase(),
    createdAt: record.createdAt ?? new Date().toISOString(),
  };
  await users.insertOne(payload);
}

export async function getUserByEmail(email) {
  const { users } = await getCollections();
  const doc = await users.findOne({ emailLower: email.toLowerCase() });
  return normalizeUser(doc);
}

export async function getUserById(id) {
  const { users } = await getCollections();
  const doc = await users.findOne({ id });
  return normalizeUser(doc);
}

export async function updateUserPassword(id, passwordHash) {
  const { users } = await getCollections();
  const { modifiedCount } = await users.updateOne({ id }, { $set: { passwordHash } });
  return modifiedCount > 0;
}

export async function replaceSession({ token, userId, csrfToken, createdAt }) {
  const { sessions } = await getCollections();
  await sessions.deleteMany({ userId });
  await sessions.insertOne({
    token,
    userId,
    csrfToken,
    createdAt: createdAt ?? Date.now(),
  });
}

export async function getSession(token) {
  const { sessions } = await getCollections();
  const doc = await sessions.findOne({ token });
  return stripMongoFields(doc);
}

export async function updateSessionCsrf(token, csrfToken) {
  const { sessions } = await getCollections();
  await sessions.updateOne({ token }, { $set: { csrfToken } });
}

export async function listBeneficiaries(userId) {
  const { beneficiaries } = await getCollections();
  const cursor = beneficiaries.find({ userId }).sort({ createdAt: 1, id: 1 });
  const docs = await cursor.toArray();
  return docs.map((doc) => stripMongoFields(doc));
}

export async function getBeneficiaryById(userId, id) {
  const { beneficiaries } = await getCollections();
  const doc = await beneficiaries.findOne({ userId, id });
  return stripMongoFields(doc);
}

export async function addBeneficiary(record) {
  const { beneficiaries } = await getCollections();
  await beneficiaries.insertOne({
    ...record,
    createdAt: record.createdAt ?? new Date().toISOString(),
  });
}

export async function removeBeneficiary(userId, id) {
  const { beneficiaries } = await getCollections();
  const { deletedCount } = await beneficiaries.deleteOne({ userId, id });
  return deletedCount > 0;
}

export async function listPayments(userId) {
  const { payments } = await getCollections();
  const cursor = payments.find({ userId }).sort({ createdAt: -1, id: -1 });
  const docs = await cursor.toArray();
  return docs.map((doc) => stripMongoFields(doc));
}

export async function addPayment(record) {
  const { payments } = await getCollections();
  await payments.insertOne({
    ...record,
    createdAt: record.createdAt ?? new Date().toISOString(),
  });
}

export async function removePaymentsForBeneficiary(userId, beneficiaryId) {
  const { payments } = await getCollections();
  await payments.deleteMany({ userId, beneficiaryId });
}

export async function listAllPayments() {
  const { payments } = await getCollections();
  const cursor = payments.find({}).sort({ createdAt: -1, id: -1 });
  const docs = await cursor.toArray();
  return docs.map((doc) => stripMongoFields(doc));
}

export async function getBeneficiariesByIds(ids) {
  if (!Array.isArray(ids) || ids.length === 0) return [];
  const { beneficiaries } = await getCollections();
  const uniqueIds = Array.from(new Set(ids));
  const cursor = beneficiaries.find({ id: { $in: uniqueIds } });
  const docs = await cursor.toArray();
  return docs.map((doc) => stripMongoFields(doc));
}

export async function getUsersByIds(ids) {
  if (!Array.isArray(ids) || ids.length === 0) return [];
  const { users } = await getCollections();
  const uniqueIds = Array.from(new Set(ids));
  const cursor = users.find({ id: { $in: uniqueIds } });
  const docs = await cursor.toArray();
  return docs.map((doc) => normalizeUser(doc));
}

export async function closeDatabase() {
  await client.close();
  collectionsPromise = null;
}
