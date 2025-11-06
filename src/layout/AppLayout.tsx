import { Outlet } from "react-router-dom";
import Nav from "../components/Nav";
import SecurityBanner from "../components/SecurityBanner";
import { useAuth } from "../app/authContext";

/** Wraps all authenticated pages with the global nav. */
export default function AppLayout() {
  const { user } = useAuth();
  const isEmployee = user?.role === "employee";

  return (
    <>
      <Nav />
      <main style={{ padding: "24px 32px" }}>
        <SecurityBanner heading={isEmployee ? "Employee Access" : "Secure Session"}>
          {isEmployee
            ? "You are viewing the employee oversight portal. Transaction data is read-only and monitored for compliance."
            : "Encrypted session is active, CSRF protection is enforced, and requests are continuously monitored for unusual activity."}
        </SecurityBanner>
        <Outlet />
      </main>
    </>
  );
}
