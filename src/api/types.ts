export type User = {
  id: string;
  fullName: string;
  email: string;
  phone?: string;
};

export type AuthResponse = {
  user: User;
  token: string;
};

export type Beneficiary = {
  id: string;
  name: string;
  bank: string;
  accountNumber: string;
  swift?: string;
  currency: string; // e.g. "USD"
};

export type Payment = {
  id: string;
  beneficiaryId: string;
  amount: number;
  currency: string;
  reference: string;
  createdAt: string;
};

export type Transaction = Payment & {
  beneficiaryName: string;
  beneficiaryBank?: string;
  customerId?: string;
  customerName?: string;
  customerEmail?: string;
};

export type ApiError = { message: string };
