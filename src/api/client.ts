import axios, {
  AxiosError,
  AxiosHeaders,
  type AxiosRequestConfig,
  type InternalAxiosRequestConfig
} from "axios";
import {
  getSecureToken,
  clearSecureToken,
  getCsrfToken,
  setCsrfToken,
  logSecurityEvent,
  checkRateLimit
} from "../security/security";

const SENSITIVE_ENDPOINT_PATTERNS = [/payment/i, /transaction/i];

function normalizeHeaders(headers: InternalAxiosRequestConfig["headers"]) {
  let resolved = headers;
  if (!resolved) {
    resolved = new AxiosHeaders();
  }

  const setHeader = (name: string, value: string | undefined) => {
    if (resolved instanceof AxiosHeaders) {
      if (value === undefined) {
        resolved.delete(name);
      } else {
        resolved.set(name, value);
      }
    } else {
      const record = resolved as Record<string, string>;
      if (value === undefined) {
        delete record[name];
      } else {
        record[name] = value;
      }
    }
  };

  return { headers: resolved, setHeader };
}

export const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || "https://localhost:3001",
  withCredentials: true,
  timeout: 30000,
  headers: {
    "Content-Type": "application/json",
    "X-Requested-With": "XMLHttpRequest"
  }
});

api.interceptors.request.use(
  (config: InternalAxiosRequestConfig) => {
    const { headers, setHeader } = normalizeHeaders(config.headers);
    config.headers = headers;

    const token = getSecureToken();
    if (token) {
      setHeader("Authorization", `Bearer ${token}`);
    } else {
      setHeader("Authorization", undefined);
    }

    const method = (config.method ?? "get").toUpperCase();
    if (method !== "GET") {
      const csrf = getCsrfToken();
      if (csrf) {
        setHeader("X-CSRF-Token", csrf);
      } else {
        setHeader("X-CSRF-Token", undefined);
      }
    } else {
      setHeader("X-CSRF-Token", undefined);
    }

    const endpoint = config.url || config.baseURL || "unknown";
    const rateKey = `${method}:${endpoint}`;
    if (!checkRateLimit(rateKey, 50, 60_000)) {
      logSecurityEvent(
        "RATE_LIMIT_BLOCKED",
        `Client-side rate limit triggered for ${method} ${endpoint}`,
        "medium"
      );
      return Promise.reject(new Error("Rate limit exceeded. Please try again later."));
    }

    if (SENSITIVE_ENDPOINT_PATTERNS.some((pattern) => pattern.test(endpoint))) {
      logSecurityEvent(
        "SENSITIVE_REQUEST",
        `${method} ${endpoint} initiated`,
        "high"
      );
    }

    setHeader("X-Request-Time", Date.now().toString());
    return config;
  },
  (error) => {
    logSecurityEvent(
      "REQUEST_INTERCEPT_ERROR",
      error?.message ?? "Request interceptor error",
      "medium"
    );
    return Promise.reject(error);
  }
);

api.interceptors.response.use(
  (response) => {
    const csrfHeader = response.headers?.["x-csrf-token"];
    if (typeof csrfHeader === "string" && csrfHeader) {
      setCsrfToken(csrfHeader);
    }
    return response;
  },
  (error: AxiosError<{ message?: string }>) => {
    const status = error.response?.status ?? 0;
    const data = error.response?.data ?? {};
    const message = (data as any)?.message ?? error.message;

    if (status === 401) {
      clearSecureToken();
      logSecurityEvent(
        "UNAUTHORIZED_ACCESS",
        "API returned 401, clearing credentials",
        "high"
      );
      if (typeof window !== "undefined" && !window.location.pathname.includes("/login")) {
        window.location.href = "/login";
      }
    }

    if (status === 403) {
      const severity = (data as any)?.message?.toString().includes("CSRF") ? "critical" : "high";
      logSecurityEvent(
        "CSRF_VALIDATION_FAILED",
        "CSRF validation rejected by server",
        severity
      );
    }

    if (status === 429) {
      logSecurityEvent(
        "SERVER_RATE_LIMIT",
        "Server rate limit response received",
        "medium"
      );
    }

    if (status === 406 || status === 451) {
      logSecurityEvent(
        "SUSPICIOUS_ACTIVITY",
        `Request blocked by server: ${status}`,
        "critical"
      );
    }

    logSecurityEvent(
      "API_ERROR",
      `${status} - ${message}`,
      status >= 500 ? "high" : "low"
    );

    return Promise.reject({
      status,
      message,
      ...data,
      raw: error
    });
  }
);

export async function secureGet<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
  const response = await api.get<T>(url, config);
  return response.data;
}

export async function securePost<T>(url: string, data: unknown, config?: AxiosRequestConfig): Promise<T> {
  const response = await api.post<T>(url, data, config);
  return response.data;
}

export async function securePut<T>(url: string, data: unknown, config?: AxiosRequestConfig): Promise<T> {
  const response = await api.put<T>(url, data, config);
  return response.data;
}

export async function secureDelete<T>(url: string, config?: AxiosRequestConfig): Promise<T> {
  const response = await api.delete<T>(url, config);
  return response.data;
}

export default api;
