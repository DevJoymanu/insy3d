import { createBrowserRouter } from "react-router-dom";
import ProtectedRoute from "../components/ProtectedRoute";
import AppLayout from "../layout/AppLayout";

// Auth pages (no nav)
import Login from "../features/auth/Login";

// App pages (with nav)
import Dashboard from "../pages/Dashboard";
import BeneficiariesPage from "../features/beneficiaries/BeneficiariesPage";
import NewPayment from "../features/payments/NewPayment";
import TransactionsPage from "../features/transactions/TransactionsPage";
import EmployeeTransactionsPage from "../features/transactions/EmployeeTransactionsPage";
import SecurityPage from "../features/profile/SecurityPage";
import NotFound from "../pages/NotFound";

export const router = createBrowserRouter([
  { path: "/login", element: <Login /> },

  {
    element: (
      <ProtectedRoute roles={["customer"]} redirectTo="/employee/transactions">
        <AppLayout />
      </ProtectedRoute>
    ),
    children: [
      { path: "/", element: <Dashboard /> },
      { path: "/beneficiaries", element: <BeneficiariesPage /> },
      { path: "/pay", element: <NewPayment /> },
      { path: "/transactions", element: <TransactionsPage /> },
      { path: "/security", element: <SecurityPage /> },
    ],
  },

  {
    path: "/employee",
    element: (
      <ProtectedRoute roles={["employee"]} redirectTo="/">
        <AppLayout />
      </ProtectedRoute>
    ),
    children: [
      { index: true, element: <EmployeeTransactionsPage /> },
      { path: "transactions", element: <EmployeeTransactionsPage /> },
    ],
  },

  { path: "*", element: <NotFound /> },
]);
