const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const ExpressBrute = require('express-brute');
const MongooseStore = require('express-brute-mongoose');
const mongoose = require('mongoose');
const mongoSanitize = require('express-mongo-sanitize');
const hpp = require('hpp');
const cookieParser = require('cookie-parser');
const crypto = require('crypto');

// ============================================
// 1. Helmet Configuration - Multiple Security Headers
// ============================================

function configureHelmet(app) {
    app.use(helmet({
        // Content Security Policy - Prevents XSS attacks
        contentSecurityPolicy: {
            directives: {
                defaultSrc: ["'self'"],
                scriptSrc: ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com"],
                styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
                fontSrc: ["'self'", "https://fonts.gstatic.com"],
                imgSrc: ["'self'", "data:", "https:"],
                connectSrc: ["'self'"],
                frameSrc: ["'none'"], // Prevents clickjacking
                objectSrc: ["'none'"],
                upgradeInsecureRequests: [],
            },
        },

        // X-Frame-Options - Prevents clickjacking
        frameguard: {
            action: 'deny'
        },

        // X-Content-Type-Options - Prevents MIME sniffing
        noSniff: true,

        // X-XSS-Protection - XSS filter
        xssFilter: true,

        // Strict-Transport-Security - Forces HTTPS
        hsts: {
            maxAge: 31536000, // 1 year
            includeSubDomains: true,
            preload: true
        },

        // Hide X-Powered-By header
        hidePoweredBy: true,

        // Referrer Policy
        referrerPolicy: {
            policy: 'strict-origin-when-cross-origin'
        },

        // Permissions Policy
        permittedCrossDomainPolicies: {
            permittedPolicies: 'none'
        }
    }));
}

// ============================================
// 2. Rate Limiting - Prevents Brute Force & DDoS
// ============================================

// General API rate limiter
const generalLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
    message: 'Too many requests from this IP, please try again later.',
    standardHeaders: true,
    legacyHeaders: false,
    handler: (req, res) => {
        console.log(`[SECURITY] Rate limit exceeded for IP: ${req.ip}`);
        res.status(429).json({
            error: 'Too many requests',
            message: 'You have exceeded the rate limit. Please try again later.',
            retryAfter: Math.ceil(req.rateLimit.resetTime / 1000)
        });
    }
});

// Strict rate limiter for authentication endpoints
const authLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // Limit each IP to 5 login attempts per windowMs
    message: 'Too many login attempts, please try again later.',
    skipSuccessfulRequests: true,
    handler: (req, res) => {
        console.log(`[SECURITY] Auth rate limit exceeded for IP: ${req.ip}`);
        res.status(429).json({
            error: 'Too many login attempts',
            message: 'Account temporarily locked. Please try again in 15 minutes.',
        });
    }
});

// Payment endpoints rate limiter
const paymentLimiter = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 10, // Limit to 10 payments per hour
    message: 'Too many payment requests',
    handler: (req, res) => {
        console.log(`[SECURITY] Payment rate limit exceeded for IP: ${req.ip}`);
        res.status(429).json({
            error: 'Too many payment requests',
            message: 'You have exceeded the maximum number of payments per hour.',
        });
    }
});

// ============================================
// 3. Express Brute - Prevents Brute Force Attacks
// ============================================

function configureBrute(app, mongoConnection) {
    // Create brute force protection store
    const bruteForceSchema = new mongoose.Schema({
        _id: String,
        data: {
            count: Number,
            lastRequest: Date,
            firstRequest: Date
        },
        expires: { type: Date, index: { expires: '1d' } }
    });

    const BruteForceModel = mongoose.model('bruteforce', bruteForceSchema);
    const store = new MongooseStore(BruteForceModel);

    const bruteforce = new ExpressBrute(store, {
        freeRetries: 5,
        minWait: 5 * 60 * 1000, // 5 minutes
        maxWait: 60 * 60 * 1000, // 1 hour
        lifetime: 24 * 60 * 60, // 24 hours
        failCallback: (req, res, next, nextValidRequestDate) => {
            console.log(`[SECURITY] Brute force detected for IP: ${req.ip}`);
            res.status(429).json({
                error: 'Too many failed attempts',
                message: `Too many failed login attempts. Try again after ${nextValidRequestDate}`,
                nextValidRequestDate: nextValidRequestDate
            });
        }
    });

    return {
        prevent: bruteforce.prevent,
        reset: (req, res, next) => {
            if (req.bruteData) {
                req.bruteData.reset();
            }
            next();
        }
    };
}

// ============================================
// 4. CSRF Protection Middleware
// ============================================

function csrfProtection() {
    const tokens = new Map(); // In production, use Redis or database

    return {
        // Generate CSRF token
        generate: (req, res, next) => {
            const token = crypto.randomBytes(32).toString('hex');
            const sessionId = req.sessionID || req.ip;

            tokens.set(sessionId, token);

            // Send token in header and cookie
            res.setHeader('X-CSRF-Token', token);
            res.cookie('csrf-token', token, {
                httpOnly: true,
                secure: true,
                sameSite: 'strict',
                maxAge: 3600000 // 1 hour
            });

            next();
        },

        // Validate CSRF token
        validate: (req, res, next) => {
            // Skip CSRF for GET, HEAD, OPTIONS
            if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) {
                return next();
            }

            const tokenFromHeader = req.headers['x-csrf-token'];
            const sessionId = req.sessionID || req.ip;
            const storedToken = tokens.get(sessionId);

            if (!tokenFromHeader || tokenFromHeader !== storedToken) {
                console.log(`[SECURITY] CSRF validation failed for IP: ${req.ip}`);
                return res.status(403).json({
                    error: 'CSRF validation failed',
                    message: 'Invalid or missing CSRF token'
                });
            }

            next();
        }
    };
}

// ============================================
// 5. Input Sanitization - Prevents Injection Attacks
// ============================================

function sanitizeInputs(app) {
    // Parse cookies
    app.use(cookieParser());

    // Sanitize MongoDB queries - Prevents NoSQL injection
    app.use(mongoSanitize({
        replaceWith: '_',
        onSanitize: ({ req, key }) => {
            console.log(`[SECURITY] Sanitized NoSQL injection attempt: ${key}`);
        },
    }));

    // Prevent HTTP Parameter Pollution
    app.use(hpp());

    // Custom input sanitization middleware
    app.use((req, res, next) => {
        // Sanitize request body
        if (req.body) {
            req.body = sanitizeObject(req.body);
        }

        // Sanitize query parameters
        if (req.query) {
            req.query = sanitizeObject(req.query);
        }

        // Sanitize URL parameters
        if (req.params) {
            req.params = sanitizeObject(req.params);
        }

        next();
    });
}

function sanitizeObject(obj) {
    if (typeof obj !== 'object' || obj === null) {
        return obj;
    }

    const sanitized = {};

    for (const key in obj) {
        if (obj.hasOwnProperty(key)) {
            let value = obj[key];

            // Recursively sanitize nested objects
            if (typeof value === 'object' && value !== null) {
                value = sanitizeObject(value);
            } else if (typeof value === 'string') {
                // Remove potentially dangerous characters
                value = value
                    .replace(/<script[^>]*>.*?<\/script>/gi, '') // Remove script tags
                    .replace(/javascript:/gi, '') // Remove javascript: protocol
                    .replace(/on\w+\s*=/gi, '') // Remove event handlers
                    .trim();
            }

            sanitized[key] = value;
        }
    }

    return sanitized;
}

// ============================================
// 6. CORS Configuration
// ============================================

function configureCors(app) {
    app.use((req, res, next) => {
        const allowedOrigins = [
            'http://localhost:5173',
            'http://localhost:3000',
            'https://yourdomain.com'
        ];

        const origin = req.headers.origin;

        if (allowedOrigins.includes(origin)) {
            res.setHeader('Access-Control-Allow-Origin', origin);
        }

        res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-CSRF-Token, X-Requested-With');
        res.setHeader('Access-Control-Allow-Credentials', 'true');
        res.setHeader('Access-Control-Max-Age', '86400'); // 24 hours

        // Handle preflight
        if (req.method === 'OPTIONS') {
            return res.status(204).end();
        }

        next();
    });
}

// ============================================
// 7. Security Logging Middleware
// ============================================

function securityLogger(req, res, next) {
    const startTime = Date.now();

    // Log suspicious patterns
    const suspiciousPatterns = [
        /(\.\.|\/etc\/|\/proc\/)/i, // Directory traversal
        /(union|select|insert|update|delete|drop)/i, // SQL injection
        /(<script|javascript:|onerror=)/i, // XSS attempts
        /(\$where|\$ne|\$gt|\$regex)/i, // NoSQL injection
    ];

    const fullUrl = req.originalUrl || req.url;
    const body = JSON.stringify(req.body);

    suspiciousPatterns.forEach(pattern => {
        if (pattern.test(fullUrl) || pattern.test(body)) {
            console.warn(`[SECURITY ALERT] Suspicious request detected:`, {
                ip: req.ip,
                method: req.method,
                url: fullUrl,
                userAgent: req.headers['user-agent'],
                timestamp: new Date().toISOString()
            });
        }
    });

    // Log response
    res.on('finish', () => {
        const duration = Date.now() - startTime;

        if (res.statusCode >= 400) {
            console.log(`[SECURITY] ${req.method} ${fullUrl} - ${res.statusCode} (${duration}ms) - IP: ${req.ip}`);
        }
    });

    next();
}

// ============================================
// 8. Request Validation Middleware
// ============================================

function validateRequest(req, res, next) {
    // Check for required headers
    if (!req.headers['user-agent']) {
        console.warn(`[SECURITY] Request without User-Agent from IP: ${req.ip}`);
    }

    // Validate content-type for POST/PUT requests
    if (['POST', 'PUT', 'PATCH'].includes(req.method)) {
        const contentType = req.headers['content-type'];

        if (!contentType || !contentType.includes('application/json')) {
            return res.status(415).json({
                error: 'Unsupported Media Type',
                message: 'Content-Type must be application/json'
            });
        }
    }

    // Check request size (prevent large payload attacks)
    const contentLength = parseInt(req.headers['content-length'] || '0');
    const maxSize = 1024 * 1024; // 1MB

    if (contentLength > maxSize) {
        console.warn(`[SECURITY] Large payload detected: ${contentLength} bytes from IP: ${req.ip}`);
        return res.status(413).json({
            error: 'Payload Too Large',
            message: 'Request body exceeds maximum size'
        });
    }

    next();
}

// ============================================
// 9. Main Security Setup Function
// ============================================

function setupSecurity(app, mongoConnection) {
    console.log('[SECURITY] Initializing security middleware...');

    // 1. Helmet security headers
    configureHelmet(app);

    // 2. CORS configuration
    configureCors(app);

    // 3. Request validation
    app.use(validateRequest);

    // 4. Security logging
    app.use(securityLogger);

    // 5. Input sanitization
    sanitizeInputs(app);

    // 6. Rate limiting
    app.use('/api/', generalLimiter);
    app.use('/api/auth/login', authLimiter);
    app.use('/api/auth/register', authLimiter);
    app.use('/api/payments', paymentLimiter);

    // 7. CSRF protection
    const csrf = csrfProtection();
    app.use(csrf.generate);
    app.use('/api/', csrf.validate);

    // 8. Brute force protection
    const brute = configureBrute(app, mongoConnection);

    console.log('[SECURITY] Security middleware initialized successfully');

    return {
        brute,
        csrf,
        rateLimiters: {
            general: generalLimiter,
            auth: authLimiter,
            payment: paymentLimiter
        }
    };
}

// ============================================
// Export
// ============================================

module.exports = {
    setupSecurity,
    csrfProtection,
    sanitizeObject,
    securityLogger
};
