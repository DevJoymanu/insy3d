export const patterns = {
  fullName: /^[A-Za-z' -]{2,60}$/,
  phone: /^\+?[1-9]\d{7,14}$/,
  email: /^[^\s@]+@[^\s@]{2,}\.[^\s@]{2,}$/,
  bank: /^[A-Za-z0-9' .,&-]{2,60}$/,
  accountNumber: /^\d{6,18}$/,
  currency: /^(USD|EUR|GBP|ZAR|JPY|AUD|CAD|CHF|CNY)$/,
  swift: /^[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?$/,
  iban: /^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$/,
  amount: /^(?!0(?:\.0{1,2})?$)\d{1,9}(?:\.\d{2})?$/,
  reference: /^[A-Za-z0-9 .,'#&\-]{1,40}$/,
  password: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{12,}$/,
} as const;