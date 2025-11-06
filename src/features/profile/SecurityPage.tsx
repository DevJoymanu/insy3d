import { useForm } from "react-hook-form";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import { patterns } from "../../security/regex";
import FormField from "../../components/FormField";
import { useState } from "react";
import { changePassword } from "../../api/services";

const schema = z.object({
  current: z.string().min(1, "Required"),
  next: z.string().regex(patterns.password ?? /.{8,}/, "Strong password required"),
  confirm: z.string()
}).refine(v => v.next === v.confirm, {
  message: "Passwords must match",
  path: ["confirm"]
});
type Values = z.infer<typeof schema>;

function getMsg(e: unknown, fallback = "Could not update password"): string {
  if (typeof e === "string") return e;
  if (e && typeof e === "object") {
    const ex = e as { response?: { data?: { message?: string } }, message?: string };
    return ex.response?.data?.message || ex.message || fallback;
  }
  return fallback;
}

export default function SecurityPage() {
  const [err, setErr] = useState<string | null>(null);
  const [ok, setOk] = useState<string | null>(null);

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting, isValid },
    reset
  } = useForm<Values>({ resolver: zodResolver(schema), mode: "onChange" });

  async function onSubmit(v: Values) {
    setErr(null);
    setOk(null);
    try {
      await changePassword({ oldPassword: v.current, newPassword: v.next });
      setOk("Password updated.");
      reset();
    } catch (e: unknown) {
      setErr(getMsg(e));
    }
  }

  return (
    <div className="container">
      <h1>Security</h1>

      <form className="card" onSubmit={handleSubmit(onSubmit)} noValidate>
        {err && <div className="err" role="alert" style={{ marginBottom: 12 }}>{err}</div>}
        {ok &&  <div className="ok"  role="status" style={{ marginBottom: 12 }}>{ok}</div>}

        <FormField label="Current password" error={errors.current}>
          <input
            type="password"
            {...register("current")}
            autoComplete="current-password"
            aria-invalid={!!errors.current || undefined}
          />
        </FormField>

        <FormField label="New password" error={errors.next} hint="Min 8 chars, mix of cases, number, symbol">
          <input
            type="password"
            {...register("next")}
            autoComplete="new-password"
            aria-invalid={!!errors.next || undefined}
          />
        </FormField>

        <FormField label="Confirm" error={errors.confirm}>
          <input
            type="password"
            {...register("confirm")}
            autoComplete="new-password"
            aria-invalid={!!errors.confirm || undefined}
          />
        </FormField>

        <button className="btn primary" disabled={isSubmitting || !isValid} style={{ width: "100%" }}>
          {isSubmitting ? "Saving…" : "Update password"}
        </button>
      </form>
    </div>
  );
}