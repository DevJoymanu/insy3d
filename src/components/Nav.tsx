import { NavLink } from "react-router-dom";
import { useAuth } from "../app/authContext";

export default function Nav() {
  const { user, logout } = useAuth();
  const isEmployee = user?.role === "employee";

  const links = isEmployee
    ? [
        { to: "/employee/transactions", label: "Transactions", end: true },
      ]
    : [
        { to: "/", label: "Dashboard", end: true },
        { to: "/beneficiaries", label: "Beneficiaries" },
        { to: "/pay", label: "New Payment" },
        { to: "/transactions", label: "Transactions" },
        { to: "/security", label: "Security" },
      ];

  return (
    <header className="app-header">
      <div className="container nav-container">
        <h1 className="logo">{isEmployee ? "Payments Staff Portal" : "Payments Portal"}</h1>
        <nav className="nav-links">
          {links.map((link) => (
            <NavLink key={link.to} to={link.to} end={link.end}>
              {link.label}
            </NavLink>
          ))}
        </nav>

        <button
          onClick={() => logout()}
          className="logout-btn"
          aria-label="Logout"
        >
          Logout
        </button>
      </div>
    </header>
  );
}
