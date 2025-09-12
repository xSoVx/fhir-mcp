import { PHILevel } from '../types/phi-types.js';

export interface RateLimitConfig {
  windowMs: number; // Time window in milliseconds
  maxRequests: number; // Max requests per window
  skipSuccessfulRequests?: boolean;
  skipFailedRequests?: boolean;
  keyGenerator?: (request: RateLimitRequest) => string;
  onLimitReached?: (key: string, request: RateLimitRequest) => void;
}

export interface RateLimitRequest {
  userId?: string;
  sessionId: string;
  operation: string;
  resourceType?: string;
  phiLevel?: PHILevel;
  ipAddress?: string;
  userAgent?: string;
}

export interface RateLimitResult {
  allowed: boolean;
  remainingRequests: number;
  resetTime: Date;
  reason?: string;
}

export interface RateLimitStats {
  totalRequests: number;
  allowedRequests: number;
  blockedRequests: number;
  activeKeys: number;
}

/**
 * Rate Limiting and Abuse Prevention System
 * Provides configurable rate limiting with PHI-aware restrictions
 */
export class RateLimiter {
  private requestCounts = new Map<string, { count: number; resetTime: Date }>();
  private blockedIPs = new Set<string>();
  private suspiciousActivity = new Map<string, { score: number; lastActivity: Date }>();
  
  // Default configurations for different operation types
  private configs = new Map<string, RateLimitConfig>();

  constructor() {
    this.initializeDefaultConfigs();
    
    // Clean up expired entries every minute
    setInterval(() => this.cleanup(), 60 * 1000);
  }

  /**
   * Initialize default rate limiting configurations
   */
  private initializeDefaultConfigs(): void {
    // General API operations
    this.configs.set('default', {
      windowMs: 60 * 1000, // 1 minute
      maxRequests: 100,
      keyGenerator: (req) => `default:${req.userId || req.sessionId}`
    });

    // PHI-sensitive operations (stricter limits)
    this.configs.set('phi_access', {
      windowMs: 60 * 1000, // 1 minute
      maxRequests: 20,
      keyGenerator: (req) => `phi:${req.userId || req.sessionId}`
    });

    // Search operations
    this.configs.set('search', {
      windowMs: 60 * 1000, // 1 minute
      maxRequests: 50,
      keyGenerator: (req) => `search:${req.userId || req.sessionId}`
    });

    // Create/Update operations (write operations)
    this.configs.set('write', {
      windowMs: 60 * 1000, // 1 minute
      maxRequests: 10,
      keyGenerator: (req) => `write:${req.userId || req.sessionId}`
    });

    // Emergency access (special limits)
    this.configs.set('emergency', {
      windowMs: 60 * 1000, // 1 minute
      maxRequests: 5,
      keyGenerator: (req) => `emergency:${req.userId}`
    });

    // IP-based limiting (for anonymous requests)
    this.configs.set('ip_based', {
      windowMs: 60 * 1000, // 1 minute
      maxRequests: 200,
      keyGenerator: (req) => `ip:${req.ipAddress || 'unknown'}`
    });
  }

  /**
   * Check if request should be rate limited
   */
  public checkRateLimit(request: RateLimitRequest): RateLimitResult {
    // Check if IP is blocked
    if (request.ipAddress && this.blockedIPs.has(request.ipAddress)) {
      return {
        allowed: false,
        remainingRequests: 0,
        resetTime: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
        reason: 'IP_BLOCKED'
      };
    }

    // Check for suspicious activity
    const suspiciousResult = this.checkSuspiciousActivity(request);
    if (!suspiciousResult.allowed) {
      return suspiciousResult;
    }

    // Determine which rate limit configuration to use
    const configKey = this.selectConfig(request);
    const config = this.configs.get(configKey) || this.configs.get('default')!;

    // Generate rate limit key
    const rateLimitKey = config.keyGenerator ? config.keyGenerator(request) : 
      `${configKey}:${request.userId || request.sessionId}`;

    // Check current request count
    const now = new Date();
    
    let requestData = this.requestCounts.get(rateLimitKey);
    
    // Initialize or reset if outside window
    if (!requestData || requestData.resetTime <= now) {
      requestData = {
        count: 0,
        resetTime: new Date(now.getTime() + config.windowMs)
      };
      this.requestCounts.set(rateLimitKey, requestData);
    }

    // Check if limit exceeded
    if (requestData.count >= config.maxRequests) {
      // Record abuse attempt
      this.recordAbuseAttempt(request);
      
      return {
        allowed: false,
        remainingRequests: 0,
        resetTime: requestData.resetTime,
        reason: 'RATE_LIMIT_EXCEEDED'
      };
    }

    // Increment request count
    requestData.count++;

    return {
      allowed: true,
      remainingRequests: config.maxRequests - requestData.count,
      resetTime: requestData.resetTime
    };
  }

  /**
   * Select appropriate rate limit configuration
   */
  private selectConfig(request: RateLimitRequest): string {
    // Emergency access operations
    if (request.operation.includes('emergency')) {
      return 'emergency';
    }

    // PHI-sensitive operations
    if (request.phiLevel === PHILevel.IDENTIFIABLE || request.phiLevel === PHILevel.RESTRICTED) {
      return 'phi_access';
    }

    // Write operations
    if (request.operation.includes('create') || request.operation.includes('update')) {
      return 'write';
    }

    // Search operations
    if (request.operation.includes('search')) {
      return 'search';
    }

    // IP-based limiting for anonymous requests
    if (!request.userId && request.ipAddress) {
      return 'ip_based';
    }

    return 'default';
  }

  /**
   * Check for suspicious activity patterns
   */
  private checkSuspiciousActivity(request: RateLimitRequest): RateLimitResult {
    const key = request.userId || request.ipAddress || request.sessionId;
    const now = new Date();

    let suspicious = this.suspiciousActivity.get(key);
    if (!suspicious) {
      suspicious = { score: 0, lastActivity: now };
      this.suspiciousActivity.set(key, suspicious);
    }

    // Calculate time since last activity
    const timeDiff = now.getTime() - suspicious.lastActivity.getTime();
    
    // Rapid fire requests (< 100ms apart) increase suspicion score
    if (timeDiff < 100) {
      suspicious.score += 10;
    } else if (timeDiff < 1000) {
      suspicious.score += 5;
    } else {
      // Decrease suspicion score over time
      suspicious.score = Math.max(0, suspicious.score - 1);
    }

    // Update last activity
    suspicious.lastActivity = now;

    // Check for suspicious patterns
    if (suspicious.score > 100) {
      // Temporarily block this key
      if (request.ipAddress) {
        this.blockedIPs.add(request.ipAddress);
      }

      return {
        allowed: false,
        remainingRequests: 0,
        resetTime: new Date(now.getTime() + 15 * 60 * 1000), // 15 minutes
        reason: 'SUSPICIOUS_ACTIVITY'
      };
    }

    return {
      allowed: true,
      remainingRequests: 100,
      resetTime: now
    };
  }

  /**
   * Record abuse attempt for monitoring
   */
  private recordAbuseAttempt(request: RateLimitRequest): void {
    console.warn('Rate limit abuse detected:', {
      userId: request.userId,
      sessionId: request.sessionId,
      operation: request.operation,
      ipAddress: request.ipAddress,
      timestamp: new Date().toISOString()
    });

    // Increase suspicion score
    const key = request.userId || request.ipAddress || request.sessionId;
    const suspicious = this.suspiciousActivity.get(key);
    if (suspicious) {
      suspicious.score += 20;
    }
  }

  /**
   * Add custom rate limit configuration
   */
  public addConfig(name: string, config: RateLimitConfig): void {
    this.configs.set(name, config);
  }

  /**
   * Update existing rate limit configuration
   */
  public updateConfig(name: string, updates: Partial<RateLimitConfig>): void {
    const existing = this.configs.get(name);
    if (existing) {
      this.configs.set(name, { ...existing, ...updates });
    }
  }

  /**
   * Block an IP address
   */
  public blockIP(ipAddress: string, duration?: number): void {
    this.blockedIPs.add(ipAddress);
    
    if (duration) {
      // Auto-unblock after duration
      setTimeout(() => {
        this.blockedIPs.delete(ipAddress);
      }, duration);
    }
  }

  /**
   * Unblock an IP address
   */
  public unblockIP(ipAddress: string): void {
    this.blockedIPs.delete(ipAddress);
  }

  /**
   * Check if IP is blocked
   */
  public isIPBlocked(ipAddress: string): boolean {
    return this.blockedIPs.has(ipAddress);
  }

  /**
   * Get current rate limit status for a request
   */
  public getStatus(request: RateLimitRequest): {
    configUsed: string;
    currentCount: number;
    maxRequests: number;
    resetTime: Date;
    isBlocked: boolean;
  } {
    const configKey = this.selectConfig(request);
    const config = this.configs.get(configKey) || this.configs.get('default')!;
    const rateLimitKey = config.keyGenerator ? config.keyGenerator(request) : 
      `${configKey}:${request.userId || request.sessionId}`;

    const requestData = this.requestCounts.get(rateLimitKey);
    const isBlocked = request.ipAddress ? this.blockedIPs.has(request.ipAddress) : false;

    return {
      configUsed: configKey,
      currentCount: requestData?.count || 0,
      maxRequests: config.maxRequests,
      resetTime: requestData?.resetTime || new Date(),
      isBlocked
    };
  }

  /**
   * Get rate limiter statistics
   */
  public getStats(): RateLimitStats {
    let totalRequests = 0;
    let allowedRequests = 0;
    
    for (const data of this.requestCounts.values()) {
      totalRequests += data.count;
      allowedRequests += data.count; // All stored requests were allowed
    }

    return {
      totalRequests,
      allowedRequests,
      blockedRequests: 0, // TODO: Implement blocked request counter
      activeKeys: this.requestCounts.size
    };
  }

  /**
   * Clean up expired entries
   */
  private cleanup(): void {
    const now = new Date();
    
    // Clean up expired request counts
    for (const [key, data] of this.requestCounts.entries()) {
      if (data.resetTime <= now) {
        this.requestCounts.delete(key);
      }
    }

    // Clean up old suspicious activity records (older than 24 hours)
    const dayAgo = new Date(now.getTime() - 24 * 60 * 60 * 1000);
    for (const [key, data] of this.suspiciousActivity.entries()) {
      if (data.lastActivity < dayAgo && data.score === 0) {
        this.suspiciousActivity.delete(key);
      }
    }
  }

  /**
   * Reset rate limits for a specific key
   */
  public resetLimits(key: string): void {
    // Find and remove matching keys
    for (const rateLimitKey of this.requestCounts.keys()) {
      if (rateLimitKey.includes(key)) {
        this.requestCounts.delete(rateLimitKey);
      }
    }
    
    // Reset suspicious activity
    this.suspiciousActivity.delete(key);
  }

  /**
   * Emergency bypass for critical operations
   */
  public emergencyBypass(request: RateLimitRequest): RateLimitResult {
    // Log emergency bypass for audit
    console.warn('Emergency rate limit bypass used:', {
      userId: request.userId,
      operation: request.operation,
      timestamp: new Date().toISOString()
    });

    return {
      allowed: true,
      remainingRequests: 999,
      resetTime: new Date(Date.now() + 60 * 60 * 1000) // 1 hour
    };
  }
}