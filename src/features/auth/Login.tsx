import { useEffect, useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { useAuth } from "../../app/authContext";
import {
  sanitizeInput,
  isValidEmail,
  isAccountLocked,
  getRemainingAttempts,
  logSecurityEvent
} from "../../security/security";
import SecurityBanner from "../../components/SecurityBanner";

function getApiErrorMessage(err: unknown): string {
  if (typeof err === "string") return err;
  if (err && typeof err === "object") {
    const e = err as { response?: { data?: { message?: string } }; message?: string };
    return e.response?.data?.message || e.message || "Login failed";
  }
  return "Login failed";
}

export default function Login() {
  const { login } = useAuth();
  const nav = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [lockStatus, setLockStatus] = useState<{ locked: boolean; remainingTime?: number }>({
    locked: false
  });
  const [remainingAttempts, setRemainingAttempts] = useState(5);

  useEffect(() => {
    if (!email) {
      setLockStatus({ locked: false });
      setRemainingAttempts(5);
      return;
    }

    const sanitizedEmail = sanitizeInput(email.toLowerCase().trim());
    if (!isValidEmail(sanitizedEmail)) {
      return;
    }

    const status = isAccountLocked(sanitizedEmail);
    setLockStatus(status);
    setRemainingAttempts(getRemainingAttempts(sanitizedEmail));

    if (status.locked) {
      setErr(
        `Account locked due to too many failed attempts. Try again in ${status.remainingTime} minutes.`
      );
    } else {
      setErr((previous) => {
        if (previous && previous.includes("Account locked")) {
          return null;
        }
        return previous;
      });
    }
  }, [email]);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setErr(null);

    const sanitizedEmail = sanitizeInput(email.toLowerCase().trim());

    if (!isValidEmail(sanitizedEmail)) {
      const errorMsg = "Invalid email format";
      setErr(errorMsg);
      logSecurityEvent("INVALID_LOGIN_EMAIL", `Invalid email: ${sanitizedEmail}`, "low");
      return;
    }

    if (lockStatus.locked) {
      const message = `Account is locked. Please try again in ${lockStatus.remainingTime} minutes.`;
      setErr(message);
      logSecurityEvent("LOGIN_LOCKED_ACCOUNT", `Locked account attempt: ${sanitizedEmail}`, "high");
      return;
    }

    setBusy(true);
    try {
      logSecurityEvent("LOGIN_ATTEMPT", `Login attempt: ${sanitizedEmail}`, "low");
      const authenticatedUser = await login(sanitizedEmail, password);
      logSecurityEvent("LOGIN_SUCCESS_CLIENT", `Login success: ${sanitizedEmail}`, "low");
      if (authenticatedUser.role === "employee") {
        nav("/employee/transactions", { replace: true });
      } else {
        nav("/", { replace: true });
      }
    } catch (e: unknown) {
      const errorMsg = getApiErrorMessage(e);
      logSecurityEvent("LOGIN_FAILED_CLIENT", `Login failed: ${sanitizedEmail}`, "medium");
      const remaining = getRemainingAttempts(sanitizedEmail);
      setRemainingAttempts(remaining);

      if (remaining <= 3 && remaining > 0) {
        setErr(`${errorMsg}\n\nWarning: ${remaining} attempts remaining before account lockout.`);
      } else {
        setErr(errorMsg);
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="container">
      <header style={{ marginBottom: 16 }}>
        <h1 style={{ margin: 0 }}>Sign in</h1>
        <p style={{ opacity: 0.8, marginTop: 6 }}>
          Welcome back — enter your credentials to continue.
        </p>
      </header>

      <form className="card" onSubmit={onSubmit} noValidate>
        <SecurityBanner heading="Secure Connection">
          Multi-factor hardening is enabled for this authentication flow. Requests are protected by TLS, CSRF tokens, and rate limiting.
        </SecurityBanner>

        {lockStatus.locked && (
          <div
            style={{
              padding: 12,
              marginBottom: 12,
              background: "#fef2f2",
              border: "1px solid #fecaca",
              borderRadius: 6,
              color: "#991b1b"
            }}
          >
            <strong>Account Locked</strong>
            <p style={{ margin: "4px 0 0 0", fontSize: 13 }}>
              Too many failed login attempts. Please try again in <strong>{lockStatus.remainingTime} minutes</strong>.
            </p>
          </div>
        )}

        {!lockStatus.locked && remainingAttempts <= 3 && remainingAttempts > 0 && (
          <div
            style={{
              padding: 12,
              marginBottom: 12,
              background: "#fffbeb",
              border: "1px solid #fde68a",
              borderRadius: 6,
              color: "#92400e"
            }}
          >
            <strong>Security Warning</strong>
            <p style={{ margin: "4px 0 0 0", fontSize: 13 }}>
              <strong>{remainingAttempts} login attempts</strong> remaining before account lockout.
            </p>
          </div>
        )}

        <div className="field">
          <label>Email</label>
          <input
            type="email"
            value={email}
            onChange={(event) => setEmail(event.target.value)}
            autoComplete="username"
            required
            placeholder="you@example.com"
            aria-invalid={!!err || undefined}
            disabled={lockStatus.locked}
          />
        </div>

        <div className="field">
          <label>Password</label>
          <input
            type="password"
            value={password}
            onChange={(event) => setPassword(event.target.value)}
            autoComplete="current-password"
            required
            placeholder="••••••••"
            disabled={lockStatus.locked}
          />
        </div>

        {err && (
          <div className="err" role="alert" style={{ marginTop: 8, whiteSpace: "pre-line" }}>
            {err}
          </div>
        )}

        <button
          className="btn primary"
          type="submit"
          disabled={busy || lockStatus.locked}
          style={{ width: "100%", marginTop: 8 }}
        >
          {busy ? "Signing in…" : "Sign in"}
        </button>

        <details style={{ marginTop: 16, fontSize: 12, opacity: 0.7 }}>
          <summary style={{ cursor: "pointer", userSelect: "none" }}>Security Features Active</summary>
          <ul style={{ marginTop: 8, paddingLeft: 20, lineHeight: 1.6 }}>
            <li>HTTPS encryption for all data</li>
            <li>CSRF token protection</li>
            <li>Brute force prevention (5 attempts max)</li>
            <li>Rate limiting enabled</li>
            <li>XSS &amp; injection protection</li>
          </ul>
        </details>
      </form>

      <p style={{ marginTop: 12, textAlign: "center", opacity: 0.8 }}>
        Need access? Contact an administrator to request credentials.
      </p>
    </div>
  );
}
