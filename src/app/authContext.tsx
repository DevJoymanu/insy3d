// src/app/authContext.tsx
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode
} from "react";
import { login as apiLogin, me, type AuthUser } from "../api/services";
import {
  setSecureToken,
  getSecureToken,
  clearSecureToken,
  recordLoginAttempt,
  isAccountLocked,
  clearLoginAttempts,
  logSecurityEvent,
  preventClickjacking,
  generateCsrfToken,
  setCsrfToken,
  getCsrfToken,
  sanitizeInput,
  isValidEmail
} from "../security/security";

/* ---------- Types ---------- */
// User model includes basic auth info and optional last login timestamp.
type User = (AuthUser & { lastLogin?: number }) | null;

// The shape of the AuthContext — defines what the consumer can access.
type AuthContextShape = {
  user: User;
  isLoading: boolean;
  login: (email: string, password: string, rememberMe?: boolean) => Promise<AuthUser>;
  fetchUser: () => Promise<void>;
  logout: () => void;
};

const AuthContext = createContext<AuthContextShape | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User>(null);
  const [isLoading, setIsLoading] = useState(true);

  // Keeps track of idle timeouts for session expiration
  const inactivityTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null);
  const hasInitialized = useRef(false);

  /* ---------- Restore User Session ---------- */
  const fetchUser = useCallback(async () => {
    const token = getSecureToken();
    if (!token) {
      setUser(null);
      return;
    }

    try {
      const current = await me();
      setUser({
        ...current,
        lastLogin: Date.now()
      });
      logSecurityEvent("USER_SESSION_RESTORED", "User session restored", "low");
    } catch (error) {
      // Session token is invalid or expired
      clearSecureToken();
      setUser(null);
      logSecurityEvent("SESSION_RESTORE_FAILED", "Failed to restore user session", "medium");
      throw error;
    }
  }, []);

  /* ---------- Logout Handling ---------- */
  const logout = useCallback(() => {
    const email = user?.email?.toLowerCase() ?? "unknown";

    clearSecureToken();
    setUser(null);
    setCsrfToken(generateCsrfToken());

    if (email !== "unknown") {
      clearLoginAttempts(email);
    }

    // Kill inactivity timer if it exists
    if (inactivityTimerRef.current) {
      clearTimeout(inactivityTimerRef.current);
      inactivityTimerRef.current = null;
    }

    logSecurityEvent("LOGOUT", `User logged out: ${email}`, "low");

    // Force redirect to login if not already there
    if (typeof window !== "undefined" && !window.location.pathname.includes("/login")) {
      window.location.href = "/login";
    }
  }, [user]);

  /* ---------- One-Time Initialization ---------- */
  useEffect(() => {
    if (hasInitialized.current) return;
    hasInitialized.current = true;

    preventClickjacking();

    // Ensure CSRF token exists before anything else
    if (!getCsrfToken()) {
      setCsrfToken(generateCsrfToken());
    }

    logSecurityEvent("APP_INITIALIZED", "Application security initialized", "low");

    // Try restoring user session silently
    (async () => {
      try {
        await fetchUser();
      } catch {
        // Already logged by fetchUser
      } finally {
        setIsLoading(false);
      }
    })();
  }, [fetchUser]);

  /* ---------- Session Timeout / Idle Handling ---------- */
  useEffect(() => {
    if (typeof window === "undefined") {
      return;
    }

    // Clear any timers if user logs out
    if (!user) {
      if (inactivityTimerRef.current) {
        clearTimeout(inactivityTimerRef.current);
        inactivityTimerRef.current = null;
      }
      return;
    }

    // Resets the idle timer every time user interacts
    const resetInactivityTimer = () => {
      if (inactivityTimerRef.current) {
        clearTimeout(inactivityTimerRef.current);
      }

      inactivityTimerRef.current = setTimeout(() => {
        logSecurityEvent("SESSION_TIMEOUT", "User session timed out due to inactivity", "medium");
        logout();
        if (typeof window !== "undefined") {
          window.alert("Your session has expired due to inactivity. Please login again.");
        }
      }, 30 * 60 * 1000); // 30 minutes
    };

    // List of user actions that count as activity
    const activityEvents: Array<keyof WindowEventMap> = ["mousedown", "keydown", "scroll", "touchstart"];
    activityEvents.forEach((event) => window.addEventListener(event, resetInactivityTimer));

    resetInactivityTimer(); // Start timer immediately when logged in

    return () => {
      if (inactivityTimerRef.current) {
        clearTimeout(inactivityTimerRef.current);
        inactivityTimerRef.current = null;
      }
      activityEvents.forEach((event) => window.removeEventListener(event, resetInactivityTimer));
    };
  }, [user, logout]);

  /* ---------- Login ---------- */
  const login = useCallback(
    async (email: string, password: string, rememberMe: boolean = false) => {
      const sanitizedEmail = sanitizeInput(email).toLowerCase().trim();

      // Basic email format validation
      if (!isValidEmail(sanitizedEmail)) {
        logSecurityEvent("INVALID_LOGIN_EMAIL", `Invalid email attempted: ${sanitizedEmail}`, "low");
        throw new Error("Invalid email format");
      }

      // Account lock check to stop brute force attempts
      const lockStatus = isAccountLocked(sanitizedEmail);
      if (lockStatus.locked) {
        logSecurityEvent(
          "ACCOUNT_LOCKED",
          `Login attempt on locked account: ${sanitizedEmail}`,
          "high"
        );
        throw new Error(
          `Account locked due to repeated failures. Try again in ${lockStatus.remainingTime} minutes.`
        );
      }

      logSecurityEvent("LOGIN_ATTEMPT", `Login attempt for: ${sanitizedEmail}`, "low");

      try {
        const res = await apiLogin({ email: sanitizedEmail, password });

        // Store secure token (possibly in persistent storage if rememberMe)
        setSecureToken(res.token, rememberMe);
        setCsrfToken(res.csrfToken || generateCsrfToken());

        setUser({
          ...res.user,
          lastLogin: Date.now(),
        });

        clearLoginAttempts(sanitizedEmail);
        logSecurityEvent("LOGIN_SUCCESS", `User logged in: ${sanitizedEmail}`, "low");
        return res.user;
      } catch (error) {
        recordLoginAttempt(sanitizedEmail);
        logSecurityEvent("LOGIN_FAILED", `Failed login attempt: ${sanitizedEmail}`, "medium");
        throw error;
      }
    },
    []
  );

  /* ---------- Context Provider ---------- */
  return (
    <AuthContext.Provider value={{ user, isLoading, login, fetchUser, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

// Hook to access auth context safely
export const useAuth = () => {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
};
