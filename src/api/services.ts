import api from "./client";

// Types
export type AuthUser = {
  id: string;
  fullName: string;
  email: string;
  phone?: string;
  role: "customer" | "employee";
  createdAt?: string;
};

export type AuthResult = {
  user: AuthUser;
  token: string;
  csrfToken: string;
};

// ================= LOGIN =================
export async function login(payload: {
  email: string;
  password: string;
}): Promise<AuthResult> {
  const { data } = await api.post("/auth/login", payload);
  return data;
}

// ================= ME =================
export async function me(): Promise<AuthUser> {
  const { data } = await api.get("/me");
  return data;
}

// ================= BENEFICIARIES =================
export async function listBeneficiaries() {
  const { data } = await api.get("/beneficiaries");
  return data;
}

export async function createBeneficiary(payload: {
  name: string;
  bank: string;
  accountNumber: string;
  swift?: string;
  currency?: string;
}) {
  const { data } = await api.post("/beneficiaries", payload);
  return data;
}

// ================= PAYMENTS =================
export async function createPayment(payload: {
  beneficiaryId: string;
  amount: number;
  currency?: string;
  reference?: string;
}) {
  const { data } = await api.post("/payments", payload);
  return data;
}

export async function listTransactions() {
  const { data } = await api.get("/transactions");
  return data;
}

export async function changePassword(payload: {
  oldPassword: string;
  newPassword: string;
}) {
  const { data } = await api.post("/auth/change-password", payload);
  return data as { ok: boolean; message?: string };
}
