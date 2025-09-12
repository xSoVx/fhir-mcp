import rateLimit from 'express-rate-limit';
import slowDown from 'express-slow-down';
import { Request, Response, NextFunction } from 'express';

// Rate limit store for tracking by IP and API key
class RateLimitStore {
  private store: Map<string, { count: number; resetTime: number }> = new Map();
  private cleanupInterval: NodeJS.Timeout;

  constructor() {
    // Clean up expired entries every 5 minutes
    this.cleanupInterval = setInterval(() => {
      const now = Date.now();
      for (const [key, value] of this.store.entries()) {
        if (now > value.resetTime) {
          this.store.delete(key);
        }
      }
    }, 5 * 60 * 1000);
  }

  increment(key: string): { totalHits: number; resetTime: Date | undefined } {
    const now = Date.now();
    const windowMs = 15 * 60 * 1000; // 15 minutes
    const resetTime = now + windowMs;

    const existing = this.store.get(key);
    if (!existing || now > existing.resetTime) {
      this.store.set(key, { count: 1, resetTime });
      return { totalHits: 1, resetTime: new Date(resetTime) };
    } else {
      existing.count++;
      return { totalHits: existing.count, resetTime: new Date(existing.resetTime) };
    }
  }

  decrement(key: string): void {
    const existing = this.store.get(key);
    if (existing && existing.count > 0) {
      existing.count--;
    }
  }

  resetKey(key: string): void {
    this.store.delete(key);
  }

  resetAll(): void {
    this.store.clear();
  }

  destroy(): void {
    clearInterval(this.cleanupInterval);
    this.store.clear();
  }
}

const rateLimitStore = new RateLimitStore();

// Key generator for rate limiting
function generateKey(req: Request): string {
  const apiKey = req.get('X-API-Key') || req.get('Authorization');
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  
  if (apiKey) {
    return `api:${apiKey}`;
  }
  return `ip:${ip}`;
}

// Standard rate limiting for general endpoints
export const generalRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
  message: {
    error: 'Too many requests',
    message: 'Rate limit exceeded. Maximum 100 requests per 15 minutes.',
    retryAfter: '15 minutes',
    timestamp: new Date().toISOString()
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: generateKey,
  store: {
    increment: (key: string) => rateLimitStore.increment(key),
    decrement: (key: string) => rateLimitStore.decrement(key),
    resetKey: (key: string) => rateLimitStore.resetKey(key),
    resetAll: () => rateLimitStore.resetAll()
  } as any,
  skip: (req: Request) => {
    // Skip rate limiting for health checks
    return req.path === '/health';
  }
});

// Strict rate limiting for FHIR endpoints
export const fhirRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 50, // Limit to 50 FHIR requests per 15 minutes
  message: {
    error: 'Too many FHIR requests',
    message: 'FHIR rate limit exceeded. Maximum 50 requests per 15 minutes.',
    retryAfter: '15 minutes',
    timestamp: new Date().toISOString()
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: generateKey,
  store: {
    increment: (key: string) => rateLimitStore.increment(key),
    decrement: (key: string) => rateLimitStore.decrement(key),
    resetKey: (key: string) => rateLimitStore.resetKey(key),
    resetAll: () => rateLimitStore.resetAll()
  } as any
});

// Very strict rate limiting for write operations (create/update)
export const writeRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // Limit to 10 write operations per hour
  message: {
    error: 'Too many write requests',
    message: 'Write operation rate limit exceeded. Maximum 10 write operations per hour.',
    retryAfter: '1 hour',
    timestamp: new Date().toISOString()
  },
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: generateKey,
  store: {
    increment: (key: string) => rateLimitStore.increment(key),
    decrement: (key: string) => rateLimitStore.decrement(key),
    resetKey: (key: string) => rateLimitStore.resetKey(key),
    resetAll: () => rateLimitStore.resetAll()
  } as any
});

// Progressive delay for repeated requests
export const progressiveDelay = slowDown({
  windowMs: 5 * 60 * 1000, // 5 minutes
  delayAfter: 10, // Allow 10 requests per window without delay
  delayMs: (used, _req) => {
    const delayAfter = 10; // Use fixed value since slowDown interface varies
    return (used - delayAfter) * 500; // Add 500ms delay for each request after the limit
  },
  maxDelayMs: 10000, // Maximum delay of 10 seconds
  keyGenerator: generateKey,
  skip: (req: Request) => {
    // Skip delay for health checks
    return req.path === '/health';
  }
});

// Suspicious activity detection
class SuspiciousActivityDetector {
  private suspiciousIPs: Set<string> = new Set();
  private failedAttempts: Map<string, { count: number; firstAttempt: number }> = new Map();
  private blockedIPs: Map<string, number> = new Map(); // IP -> block expiry time

  recordFailedAttempt(ip: string): void {
    const now = Date.now();
    const existing = this.failedAttempts.get(ip);
    
    if (!existing || now - existing.firstAttempt > 60000) { // Reset after 1 minute
      this.failedAttempts.set(ip, { count: 1, firstAttempt: now });
    } else {
      existing.count++;
      
      // Block IP after 5 failed attempts in 1 minute
      if (existing.count >= 5) {
        this.suspiciousIPs.add(ip);
        this.blockedIPs.set(ip, now + 15 * 60 * 1000); // Block for 15 minutes
        console.warn(`Suspicious activity detected and blocked IP: ${ip}`);
      }
    }
  }

  isBlocked(ip: string): boolean {
    const blockExpiry = this.blockedIPs.get(ip);
    if (blockExpiry && Date.now() < blockExpiry) {
      return true;
    }
    
    // Clean up expired blocks
    if (blockExpiry) {
      this.blockedIPs.delete(ip);
      this.suspiciousIPs.delete(ip);
    }
    
    return false;
  }

  isSuspicious(ip: string): boolean {
    return this.suspiciousIPs.has(ip);
  }

  clearIP(ip: string): void {
    this.suspiciousIPs.delete(ip);
    this.blockedIPs.delete(ip);
    this.failedAttempts.delete(ip);
  }
}

const suspiciousActivityDetector = new SuspiciousActivityDetector();

// Middleware to check for blocked IPs
export function checkBlocked(req: Request, res: Response, next: NextFunction): void {
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  
  if (suspiciousActivityDetector.isBlocked(ip)) {
    res.status(429).json({
      error: 'IP temporarily blocked',
      message: 'Your IP has been temporarily blocked due to suspicious activity',
      retryAfter: '15 minutes',
      timestamp: new Date().toISOString()
    });
    return;
  }
  
  next();
}

// Middleware to record failed attempts
export function recordFailedAttempt(req: Request, res: Response, next: NextFunction): void {
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  
  // Add a method to record failed attempts that can be called later
  res.locals.recordFailedAttempt = () => {
    suspiciousActivityDetector.recordFailedAttempt(ip);
  };
  
  next();
}

// Error handler that records failed attempts for certain error types
export function handleSuspiciousErrors(err: any, req: Request, res: Response, next: NextFunction): void {
  const statusCode = err.status || err.statusCode || 500;
  
  // Record as suspicious for authentication errors, validation errors, etc.
  if (statusCode === 400 || statusCode === 401 || statusCode === 403) {
    if (res.locals.recordFailedAttempt) {
      res.locals.recordFailedAttempt();
    }
  }
  
  next(err);
}

// Emergency bypass for rate limits (could be triggered by admin API key)
export function createEmergencyBypass(emergencyApiKey: string) {
  return (req: Request, res: Response, next: NextFunction) => {
    const apiKey = req.get('X-Emergency-Key');
    if (apiKey === emergencyApiKey) {
      // Skip all rate limiting by setting bypass headers
      res.setHeader('X-Rate-Limit-Bypass', 'emergency');
      next();
    } else {
      next();
    }
  };
}

// Cleanup function
export function cleanup(): void {
  rateLimitStore.destroy();
}

export { suspiciousActivityDetector };