import React from "react";
import { Navigate } from "react-router-dom";
import { useAuth } from "../app/authContext";

type Props = {
  children: React.ReactNode;
  roles?: Array<"customer" | "employee">;
  redirectTo?: string;
};

export default function ProtectedRoute({ children, roles, redirectTo }: Props) {
  const { user, isLoading } = useAuth();
  if (isLoading) return null;
  if (!user) return <Navigate to="/login" replace />;
  if (roles && !roles.includes(user.role)) {
    const fallback =
      redirectTo ??
      (user.role === "employee" ? "/employee/transactions" : "/");
    return <Navigate to={fallback} replace />;
  }
  return <>{children}</>;
}
