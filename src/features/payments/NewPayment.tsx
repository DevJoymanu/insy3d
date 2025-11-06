import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";
import { api } from "../../api/client";
import type { Beneficiary, Payment } from "../../api/types";
import { patterns } from "../../security/regex";
import FormField from "../../components/FormField";
import { useState } from "react";

const schema = z.object({
  beneficiaryId: z.string().min(1, "Pick a beneficiary"),
  amount: z.string().regex(patterns.amount, "Amount like 123.45"),
  currency: z.string().regex(patterns.currency, "Currency required"),
  reference: z.string().regex(patterns.reference, "Letters/numbers only"),
});
type Values = z.infer<typeof schema>;

function getMsg(e: unknown, fallback = "Payment failed"): string {
  if (typeof e === "string") return e;
  if (e && typeof e === "object") {
    const ex = e as { response?: { data?: { message?: string } }, message?: string };
    return ex.response?.data?.message || ex.message || fallback;
  }
  return fallback;
}

export default function NewPayment() {
  const qc = useQueryClient();
  const [ok, setOk] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const { data: bens = [], isLoading: bensLoading } = useQuery<Beneficiary[]>({
    queryKey: ["beneficiaries"],
    queryFn: async () => (await api.get("/beneficiaries")).data
  });

  const pay = useMutation({
    mutationFn: async (v: Values) => {
      const body = { ...v, amount: Number(v.amount) };
      return (await api.post("/payments", body)).data as Payment;
    },
    onSuccess: () => {
      setOk("Payment created.");
      setErr(null);
      qc.invalidateQueries({ queryKey: ["transactions"] });
    },
    onError: (e: unknown) => {
      setErr(getMsg(e));
      setOk(null);
    }
  });

  const {
    register,
    handleSubmit,
    formState: { errors, isSubmitting, isValid },
    reset
  } = useForm<Values>({ resolver: zodResolver(schema), mode: "onChange" });

  return (
    <div className="container">
      <h1>New payment</h1>

      <form
        className="card"
        onSubmit={handleSubmit(async v => {
          await pay.mutateAsync(v);
          if (!pay.isError) reset();
        })}
        noValidate
      >
        {err && <div className="err" role="alert" style={{ marginBottom: 12 }}>{err}</div>}
        {ok &&  <div className="ok"  role="status" style={{ marginBottom: 12 }}>{ok}</div>}

        <FormField label="Beneficiary" error={errors.beneficiaryId}>
          <select {...register("beneficiaryId")} aria-invalid={!!errors.beneficiaryId || undefined} disabled={bensLoading}>
            <option value="">{bensLoading ? "Loading…" : "Select…"}</option>
            {bens.map(b => <option key={b.id} value={b.id}>{b.name} · {b.bank}</option>)}
          </select>
        </FormField>

        <div className="row">
          <div style={{ flex: 1 }}>
            <FormField label="Amount" error={errors.amount}>
              <input {...register("amount")} placeholder="123.45" aria-invalid={!!errors.amount || undefined} />
            </FormField>
          </div>
          <div style={{ flex: 1 }}>
            <FormField label="Currency" error={errors.currency}>
              <select {...register("currency")} aria-invalid={!!errors.currency || undefined}>
                <option value="">Select…</option>
                {["USD","EUR","GBP","ZAR","JPY","AUD","CAD","CHF","CNY"].map(c=>(
                  <option key={c} value={c}>{c}</option>
                ))}
              </select>
            </FormField>
          </div>
        </div>

        <FormField label="Reference" error={errors.reference} hint="Letters and numbers only">
          <input {...register("reference")} placeholder="Invoice 123" aria-invalid={!!errors.reference || undefined} />
        </FormField>

        <button
          className="btn primary"
          disabled={isSubmitting || pay.isPending || !isValid}
          style={{ width: "100%" }}
        >
          {(isSubmitting || pay.isPending) ? "Sending…" : "Send payment"}
        </button>
      </form>
    </div>
  );
}