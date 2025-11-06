import { useQuery } from "@tanstack/react-query";
import { api } from "../../api/client";
import type { Transaction } from "../../api/types";

export default function TransactionsPage() {
  const { data = [], isLoading, isFetching, error } = useQuery<Transaction[]>({
    queryKey: ["transactions"],
    queryFn: async () => (await api.get("/transactions")).data
  });

  return (
    <div className="container">
      <h1>Transactions</h1>

      <div className="card" style={{ overflowX: "auto" }}>
        {error && <div className="err" role="alert" style={{ marginBottom: 12 }}>
          Failed to load transactions.
        </div>}

        <div className="row" style={{ justifyContent: "space-between", marginBottom: 8 }}>
          <div className="muted" style={{ fontSize: 13 }}>
            {isFetching ? "Refreshing…" : ""}
          </div>
        </div>

        {isLoading ? (
          <div className="skeleton" style={{ height: 120 }} />
        ) : data.length === 0 ? (
          <p className="muted">No transactions yet.</p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Date</th>
                <th>Beneficiary</th>
                <th className="right">Amount</th>
                <th>Currency</th>
                <th>Reference</th>
              </tr>
            </thead>
            <tbody>
              {data.map(tx => (
                <tr key={tx.id}>
                  <td>{new Date(tx.createdAt).toLocaleString()}</td>
                  <td>{tx.beneficiaryName}</td>
                  <td className="right">{tx.amount.toFixed(2)}</td>
                  <td>{tx.currency}</td>
                  <td>{tx.reference}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}