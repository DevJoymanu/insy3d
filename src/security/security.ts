// src/security/security.ts
import DOMPurify from "dompurify";

/**
 * Comprehensive Security Module for International Payments Portal
 * Protects against: XSS, CSRF, Injection, Clickjacking, Session Hijacking, Brute Force
 */

// ============================================
// 1. XSS (Cross-Site Scripting) Protection
// ============================================

/**
 * Sanitize HTML content to prevent XSS attacks
 */
export function sanitizeHtml(html: string): string {
    return DOMPurify.sanitize(html, {
        ALLOWED_TAGS: ['b', 'i', 'em', 'strong', 'p', 'br'],
        ALLOWED_ATTR: [],
        KEEP_CONTENT: true,
    });
}

/**
 * Escape HTML special characters
 */
export function escapeHtml(text: string): string {
    const map: Record<string, string> = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#x27;',
        '/': '&#x2F;',
    };
    return text.replace(/[&<>"'/]/g, (char) => map[char]);
}

/**
 * Sanitize all input fields before processing
 */
export function sanitizeInput(input: string): string {
    // Remove any script tags
    let cleaned = input.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '');
    // Remove event handlers
    cleaned = cleaned.replace(/on\w+\s*=\s*["'][^"']*["']/gi, '');
    // Remove javascript: protocol
    cleaned = cleaned.replace(/javascript:/gi, '');
    // Trim whitespace
    cleaned = cleaned.trim();
    return cleaned;
}

// ============================================
// 2. CSRF (Cross-Site Request Forgery) Protection
// ============================================

/**
 * Generate a CSRF token for the session
 */
export function generateCsrfToken(): string {
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

/**
 * Store CSRF token in sessionStorage
 */
export function setCsrfToken(token: string): void {
    sessionStorage.setItem('csrf_token', token);
}

/**
 * Retrieve CSRF token from sessionStorage
 */
export function getCsrfToken(): string | null {
    return sessionStorage.getItem('csrf_token');
}

/**
 * Validate CSRF token matches
 */
export function validateCsrfToken(token: string): boolean {
    const storedToken = getCsrfToken();
    return storedToken !== null && storedToken === token;
}

// ============================================
// 3. SQL/NoSQL Injection Protection
// ============================================

/**
 * Sanitize input to prevent injection attacks
 */
export function sanitizeForDatabase(input: string): string {
    // Remove common SQL injection patterns
    let cleaned = input.replace(/['";\\]/g, '');
    // Remove MongoDB operators
    cleaned = cleaned.replace(/\$[a-zA-Z]+/g, '');
    // Remove comment indicators
    cleaned = cleaned.replace(/(--|\/\*|\*\/|#)/g, '');
    return cleaned.trim();
}

/**
 * Validate and sanitize account numbers (should only contain alphanumeric)
 */
export function sanitizeAccountNumber(accountNumber: string): string | null {
    const regex = /^[A-Z0-9]{8,20}$/;
    const cleaned = accountNumber.toUpperCase().replace(/[^A-Z0-9]/g, '');
    return regex.test(cleaned) ? cleaned : null;
}

/**
 * Validate and sanitize SWIFT codes
 */
export function sanitizeSwiftCode(swiftCode: string): string | null {
    const regex = /^[A-Z]{6}[A-Z0-9]{2}([A-Z0-9]{3})?$/;
    const cleaned = swiftCode.toUpperCase().replace(/[^A-Z0-9]/g, '');
    return regex.test(cleaned) ? cleaned : null;
}

// ============================================
// 4. Clickjacking Protection
// ============================================

/**
 * Set security headers to prevent clickjacking
 * Call this when app initializes
 */
export function preventClickjacking(): void {
    // This is handled on the backend with helmet, but we can add client-side detection
    if (window.self !== window.top) {
        // Page is in an iframe - potential clickjacking attempt
        document.body.innerHTML = '';
        const topWindow = window.top;
        if (topWindow) {
            topWindow.location.href = window.self.location.href;
        }
    }
}

// ============================================
// 5. Session Security & Token Management
// ============================================

/**
 * Secure token storage with expiration
 */
export function setSecureToken(token: string, rememberMe: boolean = false): void {
    const tokenData = {
        token,
        timestamp: Date.now(),
        expiresIn: rememberMe ? 7 * 24 * 60 * 60 * 1000 : 24 * 60 * 60 * 1000, // 7 days or 24 hours
    };

    const storage = rememberMe ? localStorage : sessionStorage;
    storage.setItem('auth_token', token);
    storage.setItem('auth_token_meta', JSON.stringify(tokenData));
}

/**
 * Get token if valid, clear if expired
 */
export function getSecureToken(): string | null {
    const token = localStorage.getItem('auth_token') || sessionStorage.getItem('auth_token');
    const metaStr = localStorage.getItem('auth_token_meta') || sessionStorage.getItem('auth_token_meta');


    
    if (!token || !metaStr) return null;

    try {
        const meta = JSON.parse(metaStr);
        const now = Date.now();

        // Check if token is expired
        if (now - meta.timestamp > meta.expiresIn) {
            clearSecureToken();
            return null;
        }

        return token;
    } catch {
        clearSecureToken();
        return null;
    }
}

/**
 * Clear all authentication tokens
 */
export function clearSecureToken(): void {
    localStorage.removeItem('auth_token');
    localStorage.removeItem('auth_token_meta');
    sessionStorage.removeItem('auth_token');
    sessionStorage.removeItem('auth_token_meta');
    sessionStorage.removeItem('csrf_token');
}

// ============================================
// 6. Brute Force Protection (Client-Side)
// ============================================

interface LoginAttempt {
    count: number;
    firstAttempt: number;
    lockedUntil: number | null;
}

const MAX_LOGIN_ATTEMPTS = 5;
const LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes
const ATTEMPT_WINDOW = 5 * 60 * 1000; // 5 minutes

/**
 * Track login attempts to prevent brute force
 */
export function recordLoginAttempt(email: string): void {
    const key = `login_attempts_${email}`;
    const now = Date.now();

    let attempts: LoginAttempt = {
        count: 1,
        firstAttempt: now,
        lockedUntil: null,
    };

    const stored = sessionStorage.getItem(key);
    if (stored) {
        attempts = JSON.parse(stored);

        // Reset if outside attempt window
        if (now - attempts.firstAttempt > ATTEMPT_WINDOW) {
            attempts = {
                count: 1,
                firstAttempt: now,
                lockedUntil: null,
            };
        } else {
            attempts.count++;

            // Lock account after max attempts
            if (attempts.count >= MAX_LOGIN_ATTEMPTS) {
                attempts.lockedUntil = now + LOCKOUT_DURATION;
            }
        }
    }

    sessionStorage.setItem(key, JSON.stringify(attempts));
}

/**
 * Check if account is locked due to too many attempts
 */
export function isAccountLocked(email: string): { locked: boolean; remainingTime?: number } {
    const key = `login_attempts_${email}`;
    const stored = sessionStorage.getItem(key);

    if (!stored) return { locked: false };

    const attempts: LoginAttempt = JSON.parse(stored);
    const now = Date.now();

    if (attempts.lockedUntil && now < attempts.lockedUntil) {
        const remainingTime = Math.ceil((attempts.lockedUntil - now) / 1000 / 60);
        return { locked: true, remainingTime };
    }

    // Clear lock if expired
    if (attempts.lockedUntil && now >= attempts.lockedUntil) {
        sessionStorage.removeItem(key);
        return { locked: false };
    }

    return { locked: false };
}

/**
 * Clear login attempts after successful login
 */
export function clearLoginAttempts(email: string): void {
    const key = `login_attempts_${email}`;
    sessionStorage.removeItem(key);
}

/**
 * Get remaining attempts before lockout
 */
export function getRemainingAttempts(email: string): number {
    const key = `login_attempts_${email}`;
    const stored = sessionStorage.getItem(key);

    if (!stored) return MAX_LOGIN_ATTEMPTS;

    const attempts: LoginAttempt = JSON.parse(stored);
    const remaining = MAX_LOGIN_ATTEMPTS - attempts.count;
    return Math.max(0, remaining);
}

// ============================================
// 7. Input Validation & Sanitization
// ============================================

/**
 * Validate email format
 */
export function isValidEmail(email: string): boolean {
    const regex = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;
    return regex.test(email) && email.length <= 254;
}

/**
 * Validate phone number (international format)
 */
export function isValidPhone(phone: string): boolean {
    const regex = /^\+?[1-9]\d{1,14}$/;
    return regex.test(phone.replace(/[\s\-()]/g, ''));
}

/**
 * Validate amount (positive number with max 2 decimal places)
 */
export function isValidAmount(amount: string): boolean {
    const regex = /^\d+(\.\d{1,2})?$/;
    const num = parseFloat(amount);
    return regex.test(amount) && num > 0 && num <= 999999999.99;
}

/**
 * Comprehensive input sanitization for payment data
 */
export function sanitizePaymentData(data: any): any {
    return {
        ...data,
        accountNumber: data.accountNumber ? sanitizeAccountNumber(data.accountNumber) : null,
        swiftCode: data.swiftCode ? sanitizeSwiftCode(data.swiftCode) : null,
        amount: data.amount ? sanitizeInput(data.amount.toString()) : null,
        currency: data.currency ? sanitizeInput(data.currency) : null,
        provider: data.provider ? sanitizeInput(data.provider) : null,
    };
}

// ============================================
// 8. Content Security Policy Helper
// ============================================

/**
 * Check if Content Security Policy is properly set
 */
export function validateCSP(): boolean {
    const metaTag = document.querySelector('meta[http-equiv="Content-Security-Policy"]');
    return metaTag !== null;
}

// ============================================
// 9. Secure Random Number Generation
// ============================================

/**
 * Generate cryptographically secure random string
 */
export function generateSecureRandom(length: number = 32): string {
    const array = new Uint8Array(length);
    crypto.getRandomValues(array);
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('');
}

// ============================================
// 10. Rate Limiting Helper (Client-Side)
// ============================================

interface RateLimitState {
    count: number;
    resetTime: number;
}

/**
 * Client-side rate limiting for API calls
 */
export function checkRateLimit(action: string, maxRequests: number = 10, windowMs: number = 60000): boolean {
    const key = `rate_limit_${action}`;
    const now = Date.now();

    let state: RateLimitState = {
        count: 0,
        resetTime: now + windowMs,
    };

    const stored = sessionStorage.getItem(key);
    if (stored) {
        state = JSON.parse(stored);

        // Reset if window expired
        if (now > state.resetTime) {
            state = {
                count: 1,
                resetTime: now + windowMs,
            };
        } else {
            state.count++;
        }
    } else {
        state.count = 1;
    }

    sessionStorage.setItem(key, JSON.stringify(state));

    return state.count <= maxRequests;
}

// ============================================
// 11. Security Audit Logger
// ============================================

interface SecurityEvent {
    type: string;
    timestamp: number;
    details: string;
    severity: 'low' | 'medium' | 'high' | 'critical';
}

/**
 * Log security events for auditing
 */
export function logSecurityEvent(type: string, details: string, severity: SecurityEvent['severity'] = 'medium'): void {
    const event: SecurityEvent = {
        type,
        timestamp: Date.now(),
        details,
        severity,
    };

    // Store in sessionStorage (in production, send to backend)
    const logs = sessionStorage.getItem('security_logs');
    const eventLog: SecurityEvent[] = logs ? JSON.parse(logs) : [];
    eventLog.push(event);

    // Keep only last 50 events
    if (eventLog.length > 50) {
        eventLog.shift();
    }

    sessionStorage.setItem('security_logs', JSON.stringify(eventLog));

    // Log critical events to console
    if (severity === 'critical') {
        console.error('[SECURITY ALERT]', type, details);
    }
}

/**
 * Get security audit log
 */
export function getSecurityLog(): SecurityEvent[] {
    const logs = sessionStorage.getItem('security_logs');
    return logs ? JSON.parse(logs) : [];
}
