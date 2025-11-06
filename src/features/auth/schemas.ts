import { z } from "zod";
import { patterns } from "../../security/regex";
import bcrypt from "bcryptjs";

/**
 * Schema validation for Register form.
 * Uses whitelisted patterns from security/regex.ts.
 */
export const registerSchema = z.object({
  fullName: z.string().regex(patterns.fullName, "Only letters and punctuation allowed"),
  email: z.string().regex(patterns.email, "Invalid email"),
  phone: z.string().regex(patterns.phone, "Use international format"),
  password: z.string()
    .min(8, "Min 8 characters")
    .regex(/[A-Z]/, "Need uppercase")
    .regex(/[a-z]/, "Need lowercase")
    .regex(/\d/, "Need a digit")
    .regex(/[^A-Za-z0-9]/, "Need a symbol"),
  confirm: z.string()
}).refine(d => d.password === d.confirm, {
  message: "Passwords must match",
  path: ["confirm"]
});

export type RegisterValues = z.infer<typeof registerSchema>;

/**
 * demoHash: hashes the password client-side just for coursework demo.
 * Real production apps must hash server-side.
 */
export async function demoHash(password: string) {
  const salt = await bcrypt.genSalt(10);
  return bcrypt.hash(password, salt);
}