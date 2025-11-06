import { describe, it, expect } from 'vitest';
import {
    isValidEmail,
    sanitizeInput,
    generateCsrfToken
} from './security/security';

// Basic smoke test to ensure test setup works
describe('Application Tests', () => {
    it('should pass basic test', () => {
        expect(true).toBe(true);
    });

    it('should perform basic math', () => {
        expect(2 + 2).toBe(4);
    });
});

// Security module tests
describe('Security Functions', () => {
    it('should validate email format', () => {
        expect(isValidEmail('test@example.com')).toBe(true);
        expect(isValidEmail('invalid')).toBe(false);
        expect(isValidEmail('test@')).toBe(false);
    });

    it('should sanitize input', () => {
        const malicious = '<script>alert("xss")</script>';
        const sanitized = sanitizeInput(malicious);

        expect(sanitized).not.toContain('<script>');
    });

    it('should generate CSRF token', () => {
        const token1 = generateCsrfToken();
        const token2 = generateCsrfToken();

        expect(token1).toBeTruthy();
        expect(token2).toBeTruthy();
        expect(token1).not.toBe(token2);
        expect(token1.length).toBeGreaterThan(0);
    });
});