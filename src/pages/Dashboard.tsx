import { useAuth } from "../app/authContext";

export default function Dashboard() {
  const { user } = useAuth();

  return (
    <div className="container">
      <div className="card">
        <h2 style={{ marginTop: 0 }}>
          Welcome{user ? `, ${user.fullName}` : ""}
        </h2>
        <p style={{ opacity: 0.85 }}>
          This is your international payments portal.  
          Use the navigation bar above to manage beneficiaries, make payments,
          and view your transaction history.
        </p>
      </div>
    </div>
  );
}