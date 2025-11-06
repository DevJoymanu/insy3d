import { useQuery } from "@tanstack/react-query";
import { api } from "../../api/client";
import type { Transaction } from "../../api/types";

export default function EmployeeTransactionsPage() {
  const {
    data = [],
    isLoading,
    isFetching,
    error,
  } = useQuery<Transaction[]>({
    queryKey: ["employee-transactions"],
    queryFn: async () => (await api.get("/transactions")).data,
  });

  return (
    <div className="container">
      <h1>Customer Transactions</h1>

      <div className="card" style={{ overflowX: "auto" }}>
        {error && (
          <div className="err" role="alert" style={{ marginBottom: 12 }}>
            Failed to load transaction history.
          </div>
        )}

        <div className="row" style={{ justifyContent: "space-between", marginBottom: 8 }}>
          <p className="muted" style={{ margin: 0, fontSize: 13 }}>
            {isFetching ? "Refreshing…" : "Monitor customer payments in real time."}
          </p>
        </div>

        {isLoading ? (
          <div className="skeleton" style={{ height: 140 }} />
        ) : data.length === 0 ? (
          <p className="muted">No transactions recorded yet.</p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Date</th>
                <th>Customer</th>
                <th>Email</th>
                <th>Beneficiary</th>
                <th>Bank</th>
                <th className="right">Amount</th>
                <th>Currency</th>
                <th>Reference</th>
              </tr>
            </thead>
            <tbody>
              {data.map((tx) => (
                <tr key={tx.id}>
                  <td>{new Date(tx.createdAt).toLocaleString()}</td>
                  <td>{tx.customerName ?? "Unknown"}</td>
                  <td>{tx.customerEmail ?? "unknown"}</td>
                  <td>{tx.beneficiaryName}</td>
                  <td>{tx.beneficiaryBank ?? "—"}</td>
                  <td className="right">{tx.amount.toFixed(2)}</td>
                  <td>{tx.currency}</td>
                  <td>{tx.reference || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
