import { useForm } from "react-hook-form";
import { zodResolver } from "@hookform/resolvers/zod";
import FormField from "../../components/FormField";
import { useAuth } from "../../app/authContext";
import { Link, useNavigate } from "react-router-dom";
import { useState } from "react";
import { registerSchema, type RegisterValues } from "./schemas";
import {
  sanitizeInput,
  isValidEmail,
  isValidPhone,
  logSecurityEvent,
} from "../../security/security";

// Safe error helper pattern
function getApiErrorMessage(err: unknown): string {
  if (typeof err === "string") return err;
  if (err && typeof err === "object") {
    const e = err as {
      message?: string;
      data?: { message?: string };
      response?: { data?: { message?: string } };
    };
    return (
      e.response?.data?.message ||
      e.data?.message ||
      e.message ||
      "Registration failed. Try again."
    );
  }
  return "Registration failed. Try again.";
}

export default function Register() {
  const nav = useNavigate();
  const { register: doRegister } = useAuth();
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [sanitizationLog, setSanitizationLog] = useState<string[]>([]);

  const {
    register,
    handleSubmit,
    formState: { errors },
    watch,
  } = useForm<RegisterValues>({ resolver: zodResolver(registerSchema) });

  const currentValues = watch();

  const addToSanitizationLog = (message: string) => {
    setSanitizationLog(prev => [...prev, `${new Date().toLocaleTimeString()}: ${message}`]);
  };

  const onSubmit = async (values: RegisterValues) => {
    setBusy(true);
    setErr(null);
    setSanitizationLog([]);

    try {
      // ============================================
      // SECURITY: Sanitize all inputs
      // ============================================
      addToSanitizationLog(`Original name: "${values.fullName}"`);
      addToSanitizationLog(`Original email: "${values.email}"`);

      const sanitizedData = {
        fullName: sanitizeInput(values.fullName.trim()),
        email: sanitizeInput(values.email.toLowerCase().trim()),
        phone: values.phone ? sanitizeInput(values.phone.trim()) : undefined,
        password: values.password,
      };

      addToSanitizationLog(`Sanitized name: "${sanitizedData.fullName}"`);
      addToSanitizationLog(`Sanitized email: "${sanitizedData.email}"`);

      // ============================================
      // SECURITY: Additional validation
      // ============================================

      // Validate email format
      if (!isValidEmail(sanitizedData.email)) {
        const errorMsg = "Invalid email format. Please use a valid email address.";
        setErr(errorMsg);
        addToSanitizationLog(`❌ BLOCKED: ${errorMsg}`);
        logSecurityEvent(
          'INVALID_REGISTRATION_EMAIL',
          `Invalid email in registration: ${sanitizedData.email}`,
          'low'
        );
        return;
      }

      // Validate phone if provided
      if (sanitizedData.phone && !isValidPhone(sanitizedData.phone)) {
        const errorMsg = "Invalid phone number format. Use international format: +27...";
        setErr(errorMsg);
        addToSanitizationLog(`❌ BLOCKED: ${errorMsg}`);
        logSecurityEvent(
          'INVALID_REGISTRATION_PHONE',
          `Invalid phone in registration: ${sanitizedData.phone}`,
          'low'
        );
        return;
      }

      // XSS detection with specific feedback
      const dangerousPatterns = [
        { pattern: /<script[^>]*>.*?<\/script>/gi, name: "script tags" },
        { pattern: /javascript:/gi, name: "javascript protocol" },
        { pattern: /on\w+\s*=/gi, name: "event handlers" },
        { pattern: /&lt;|&gt;/gi, name: "HTML entities" }
      ];

      let detectedThreat = "";
      for (const { pattern, name } of dangerousPatterns) {
        if (pattern.test(values.fullName)) {
          detectedThreat = name;
          break;
        }
      }

      if (detectedThreat) {
        const errorMsg = `Security alert: Potentially dangerous content (${detectedThreat}) detected in name field.`;
        setErr(errorMsg);
        addToSanitizationLog(`🚨 XSS ATTEMPT BLOCKED: Detected ${detectedThreat}`);
        logSecurityEvent(
          'XSS_ATTEMPT_REGISTRATION',
          `Potential XSS in registration name field: ${values.fullName}`,
          'high'
        );
        return;
      }

      // SQL injection detection
      const sqlPatterns = [
        /(\bDROP\s+TABLE\b)/gi,
        /(\bDELETE\s+FROM\b)/gi,
        /(\bINSERT\s+INTO\b)/gi,
        /(\bSELECT\s+\*\b)/gi,
        /(';\s*--)/gi
      ];

      for (const pattern of sqlPatterns) {
        if (pattern.test(values.fullName)) {
          const errorMsg = "Security alert: Invalid characters detected in name field.";
          setErr(errorMsg);
          addToSanitizationLog(`🚨 SQL INJECTION ATTEMPT BLOCKED`);
          logSecurityEvent(
            'SQL_INJECTION_ATTEMPT_REGISTRATION',
            `Potential SQL injection in registration: ${values.fullName}`,
            'high'
          );
          return;
        }
      }

      // ============================================
      // SECURITY: Log registration attempt
      // ============================================
      addToSanitizationLog("✅ All security checks passed");
      logSecurityEvent(
        'REGISTRATION_ATTEMPT',
        `Registration attempt: ${sanitizedData.email}`,
        'low'
      );

      // ============================================
      // Submit registration
      // ============================================
      await doRegister(sanitizedData);

      addToSanitizationLog("🎉 Registration successful!");
      logSecurityEvent(
        'REGISTRATION_SUCCESS_CLIENT',
        `Registration successful: ${sanitizedData.email}`,
        'low'
      );

      nav("/");
    } catch (e: unknown) {
      const errorMsg = getApiErrorMessage(e);
      setErr(errorMsg);
      addToSanitizationLog(`❌ Registration failed: ${errorMsg}`);

      logSecurityEvent(
        'REGISTRATION_FAILED_CLIENT',
        `Registration failed: ${errorMsg}`,
        'medium'
      );
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="container">
      <header style={{ marginBottom: 16 }}>
        <h1 style={{ margin: 0 }}>Create your account</h1>
        <p style={{ opacity: 0.8, marginTop: 6 }}>
          Sign up to manage beneficiaries and send secure international payments.
        </p>
      </header>

      <form className="card" onSubmit={handleSubmit(onSubmit)} noValidate>
        {/* Security Status Badge */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          marginBottom: 16,
          padding: 10,
          background: '#f0fdf4',
          borderRadius: 6,
          fontSize: 13
        }}>
          <span style={{ color: '#16a34a' }}>🔒</span>
          <span style={{ color: '#15803d', fontWeight: 500 }}>Secure Registration</span>
          <span style={{ marginLeft: 'auto', fontSize: 11, opacity: 0.7 }}>
            All data encrypted & validated
          </span>
        </div>

        {err && (
          <div className="err" role="alert" style={{ marginBottom: 12 }}>
            <strong>Security Alert:</strong> {err}
          </div>
        )}

        {/* Sanitization Log */}
        {sanitizationLog.length > 0 && (
          <div style={{
            marginBottom: 16,
            padding: 12,
            background: '#f8f9fa',
            border: '1px solid #e9ecef',
            borderRadius: 6,
            fontSize: 12,
            maxHeight: 200,
            overflowY: 'auto'
          }}>
            <strong style={{ display: 'block', marginBottom: 8, color: '#495057' }}>
              🔍 Security Log:
            </strong>
            {sanitizationLog.map((log, index) => (
              <div
                key={index}
                style={{
                  padding: '4px 0',
                  borderBottom: index < sanitizationLog.length - 1 ? '1px solid #e9ecef' : 'none',
                  fontFamily: 'monospace',
                  color: log.includes('🚨') ? '#dc3545' : log.includes('❌') ? '#fd7e14' : log.includes('✅') ? '#28a745' : '#6c757d'
                }}
              >
                {log}
              </div>
            ))}
          </div>
        )}

        {/* 2-column responsive grid */}
        <div
          className="row"
          style={{
            gap: 16,
            flexWrap: "wrap",
          }}
        >
          <div style={{ flex: 1, minWidth: 260 }}>
            <FormField label="Full name" error={errors.fullName}>
              <input
                {...register("fullName")}
                autoComplete="name"
                placeholder="Jane Doe"
                aria-invalid={!!errors.fullName || undefined}
                maxLength={50}
                style={{
                  borderColor: currentValues.fullName && /<|>|javascript:|on\w+=|DROP|SELECT/i.test(currentValues.fullName)
                    ? '#dc3545'
                    : undefined
                }}
              />
            </FormField>
            {currentValues.fullName && /<|>|javascript:|on\w+=|DROP|SELECT/i.test(currentValues.fullName) && (
              <div style={{ fontSize: 12, color: '#dc3545', marginTop: 4 }}>
                ⚠️ Suspicious pattern detected
              </div>
            )}
          </div>

          <div style={{ flex: 1, minWidth: 260 }}>
            <FormField label="Email" error={errors.email}>
              <input
                type="email"
                {...register("email")}
                autoComplete="email"
                placeholder="jane@example.com"
                aria-invalid={!!errors.email || undefined}
                maxLength={254}
              />
            </FormField>
          </div>

          <div style={{ flex: 1, minWidth: 260 }}>
            <FormField label="Phone (+countrycode…)" error={errors.phone}>
              <input
                {...register("phone")}
                autoComplete="tel"
                placeholder="+27…"
                aria-invalid={!!errors.phone || undefined}
                maxLength={15}
              />
            </FormField>
          </div>

          <div style={{ flex: 1, minWidth: 260 }}>
            <FormField label="Password" error={errors.password}>
              <input
                type="password"
                {...register("password")}
                autoComplete="new-password"
                placeholder="At least 8 chars"
                aria-invalid={!!errors.password || undefined}
                maxLength={128}
              />
            </FormField>
          </div>

          <div style={{ flex: 1, minWidth: 260 }}>
            <FormField label="Confirm" error={errors.confirm}>
              <input
                type="password"
                {...register("confirm")}
                autoComplete="new-password"
                placeholder="Repeat password"
                aria-invalid={!!errors.confirm || undefined}
                maxLength={128}
              />
            </FormField>
          </div>
        </div>

        {/* Password requirements with security info */}
        <div style={{
          marginTop: 12,
          marginBottom: 16,
          padding: 12,
          background: '#f8fafc',
          borderRadius: 6,
          fontSize: 13,
          lineHeight: 1.6
        }}>
          <strong style={{ display: 'block', marginBottom: 6, color: '#334155' }}>
            🔐 Password Requirements:
          </strong>
          <ul style={{ margin: 0, paddingLeft: 20, color: '#64748b' }}>
            <li>At least 8 characters long</li>
            <li>Include uppercase and lowercase letters</li>
            <li>Include at least one number</li>
            <li>Include at least one special character (!@#$%^&*)</li>
          </ul>
          <p style={{
            margin: '8px 0 0 0',
            paddingTop: 8,
            borderTop: '1px solid #e2e8f0',
            fontSize: 12,
            color: '#475569'
          }}>
            <strong>🛡️ Security:</strong> Inputs are sanitized against XSS and SQL injection.
            Suspicious patterns are automatically blocked and logged.
          </p>
        </div>

        <button
          disabled={busy}
          className="btn primary"
          type="submit"
          style={{ width: "100%" }}
        >
          {busy ? "Creating…" : "Create account"}
        </button>

        {/* Security Features Info */}
        <details style={{ marginTop: 16, fontSize: 12, opacity: 0.7 }}>
          <summary style={{ cursor: 'pointer', userSelect: 'none' }}>
            🔐 Security Features Active
          </summary>
          <ul style={{ marginTop: 8, paddingLeft: 20, lineHeight: 1.6 }}>
            <li>✅ Real-time input sanitization & validation</li>
            <li>✅ XSS attack prevention (blocks script tags, event handlers)</li>
            <li>✅ SQL/NoSQL injection protection</li>
            <li>✅ Live security logging</li>
            <li>✅ HTTPS encryption</li>
            <li>✅ CSRF token protection</li>
            <li>✅ Password hashing with bcrypt + salt</li>
          </ul>
        </details>
      </form>

      <p style={{ marginTop: 12, textAlign: "center" }}>
        Already have an account? <Link to="/login">Sign in</Link>
      </p>
    </div>
  );
}
