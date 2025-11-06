import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { useForm } from "react-hook-form";
import { z } from "zod";
import { zodResolver } from "@hookform/resolvers/zod";
import { api } from "../../api/client";
import type { Beneficiary } from "../../api/types";
import { patterns } from "../../security/regex";
import FormField from "../../components/FormField";
import { useState } from "react";

const schema = z.object({
  name: z.string().regex(patterns.fullName, "Name invalid"),
  bank: z.string().regex(patterns.bank, "Bank invalid"),
  accountNumber: z.string().regex(patterns.accountNumber, "8–20 digits"),
  currency: z.string().regex(patterns.currency, "Pick currency"),
  swift: z.string().regex(patterns.swift, "Invalid SWIFT").optional().or(z.literal("")),
});
type Values = z.infer<typeof schema>;

// normalize unknown errors -> string
function getMsg(e: unknown, fallback = "Action failed"): string {
  if (typeof e === "string") return e;
  if (e && typeof e === "object") {
    const ex = e as { response?: { data?: { message?: string } }, message?: string };
    return ex.response?.data?.message || ex.message || fallback;
  }
  return fallback;
}

export default function BeneficiariesPage() {
  const qc = useQueryClient();
  const [ok, setOk] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);

  const { data: list = [], isLoading, isFetching } = useQuery<Beneficiary[]>({
    queryKey: ["beneficiaries"],
    queryFn: async () => (await api.get("/beneficiaries")).data
  });

  const add = useMutation({
    mutationFn: async (v: Values) => (await api.post("/beneficiaries", v)).data as Beneficiary,
    onSuccess: () => {
      setOk("Beneficiary added.");
      setErr(null);
      qc.invalidateQueries({ queryKey: ["beneficiaries"] });
    },
    onError: (e: unknown) => {
      setErr(getMsg(e, "Could not add beneficiary"));
      setOk(null);
    }
  });

  const del = useMutation({
    mutationFn: async (id: string) => (await api.delete(`/beneficiaries/${id}`)).data,
    onSuccess: () => {
      setOk("Beneficiary deleted.");
      setErr(null);
      qc.invalidateQueries({ queryKey: ["beneficiaries"] });
    },
    onError: (e: unknown) => {
      setErr(getMsg(e, "Could not delete beneficiary"));
      setOk(null);
    }
  });

  const {
    register,
    handleSubmit,
    reset,
    formState: { errors, isSubmitting, isValid }
  } = useForm<Values>({ resolver: zodResolver(schema), mode: "onChange" });

  const onSubmit = async (v: Values) => {
    await add.mutateAsync(v);
    reset();
  };

  return (
    <div className="container">
      <h1>Beneficiaries</h1>

      <form className="card" onSubmit={handleSubmit(onSubmit)} style={{ margin: "16px 0" }} noValidate>
        {err && <div className="err" role="alert" style={{ marginBottom: 12 }}>{err}</div>}
        {ok &&  <div className="ok"  role="status" style={{ marginBottom: 12 }}>{ok}</div>}

        <div className="row">
          <div style={{ flex: 1 }}>
            <FormField label="Name" error={errors.name}>
              <input {...register("name")} placeholder="John Smith" aria-invalid={!!errors.name || undefined} />
            </FormField>
          </div>
          <div style={{ flex: 1 }}>
            <FormField label="Bank" error={errors.bank}>
              <input {...register("bank")} placeholder="Bank name" aria-invalid={!!errors.bank || undefined} />
            </FormField>
          </div>
        </div>

        <div className="row">
          <div style={{ flex: 1 }}>
            <FormField label="Account number" error={errors.accountNumber} hint="8–20 digits">
              <input {...register("accountNumber")} placeholder="12345678" aria-invalid={!!errors.accountNumber || undefined} />
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

        <FormField label="SWIFT (optional)" error={errors.swift} hint="8 or 11 characters">
          <input {...register("swift")} placeholder="ABCDZAJJ" aria-invalid={!!errors.swift || undefined} />
        </FormField>

        <button className="btn primary" disabled={isSubmitting || add.isPending || !isValid} style={{ width: "100%" }}>
          {(isSubmitting || add.isPending) ? "Adding…" : "Add beneficiary"}
        </button>
      </form>

      <div className="card">
        <div className="row" style={{ justifyContent: "space-between" }}>
          <h2 style={{ margin: 0 }}>Saved beneficiaries</h2>
          {isFetching && <span className="muted" style={{ fontSize: 12 }}>Refreshing…</span>}
        </div>

        {isLoading ? (
          <p className="muted">Loading…</p>
        ) : list.length === 0 ? (
          <p className="muted">No beneficiaries yet.</p>
        ) : (
          <ul style={{ listStyle: "none", padding: 0, margin: 0 }}>
            {list.map(b => (
              <li key={b.id} className="row" style={{ justifyContent: "space-between", padding: "10px 0", borderBottom: "1px solid #1b2530" }}>
                <span>
                  <strong>{b.name}</strong> · {b.bank} · {b.accountNumber} · {b.currency}
                </span>
                <button
                  className="btn"
                  onClick={() => del.mutate(b.id)}
                  disabled={del.isPending}
                  aria-label={`Delete ${b.name}`}
                >
                  {del.isPending ? "Deleting…" : "Delete"}
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}