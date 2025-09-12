export interface SecurityHeadersConfig {
  enableCSP: boolean;
  enableHSTS: boolean;
  enableFrameProtection: boolean;
  enableContentTypeOptions: boolean;
  enableReferrerPolicy: boolean;
  enablePermissionsPolicy: boolean;
  customHeaders?: Record<string, string>;
  healthcareCompliant?: boolean;
}

export interface SecurityHeaders {
  [key: string]: string;
}

/**
 * Security Headers Manager
 * Provides OWASP-compliant security headers for healthcare applications
 */
export class SecurityHeadersManager {
  private config: SecurityHeadersConfig;

  constructor(config: Partial<SecurityHeadersConfig> = {}) {
    this.config = {
      enableCSP: true,
      enableHSTS: true,
      enableFrameProtection: true,
      enableContentTypeOptions: true,
      enableReferrerPolicy: true,
      enablePermissionsPolicy: true,
      healthcareCompliant: true,
      ...config
    };
  }

  /**
   * Generate security headers based on configuration
   */
  public generateHeaders(): SecurityHeaders {
    const headers: SecurityHeaders = {};

    if (this.config.enableCSP) {
      headers['Content-Security-Policy'] = this.generateCSP();
    }

    if (this.config.enableHSTS) {
      headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload';
    }

    if (this.config.enableFrameProtection) {
      headers['X-Frame-Options'] = 'DENY';
    }

    if (this.config.enableContentTypeOptions) {
      headers['X-Content-Type-Options'] = 'nosniff';
    }

    if (this.config.enableReferrerPolicy) {
      headers['Referrer-Policy'] = this.config.healthcareCompliant 
        ? 'no-referrer' // Strictest for healthcare
        : 'strict-origin-when-cross-origin';
    }

    if (this.config.enablePermissionsPolicy) {
      headers['Permissions-Policy'] = this.generatePermissionsPolicy();
    }

    // Additional healthcare-specific headers
    if (this.config.healthcareCompliant) {
      this.addHealthcareHeaders(headers);
    }

    // Standard security headers
    this.addStandardSecurityHeaders(headers);

    // Custom headers
    if (this.config.customHeaders) {
      Object.assign(headers, this.config.customHeaders);
    }

    return headers;
  }

  /**
   * Generate Content Security Policy
   */
  private generateCSP(): string {
    const directives = [
      "default-src 'self'",
      "script-src 'self'",
      "style-src 'self' 'unsafe-inline'", // Allow inline styles for minimal styling
      "img-src 'self' data: https:",
      "font-src 'self'",
      "connect-src 'self'",
      "media-src 'none'",
      "object-src 'none'",
      "child-src 'none'",
      "frame-src 'none'",
      "worker-src 'none'",
      "manifest-src 'none'",
      "base-uri 'self'",
      "form-action 'self'"
    ];

    if (this.config.healthcareCompliant) {
      // Additional restrictions for healthcare compliance
      directives.push(
        "upgrade-insecure-requests",
        "block-all-mixed-content"
      );
    }

    return directives.join('; ');
  }

  /**
   * Generate Permissions Policy (formerly Feature Policy)
   */
  private generatePermissionsPolicy(): string {
    const policies = [
      'accelerometer=()',
      'ambient-light-sensor=()',
      'autoplay=()',
      'battery=()',
      'camera=()',
      'cross-origin-isolated=()',
      'display-capture=()',
      'document-domain=()',
      'encrypted-media=()',
      'execution-while-not-rendered=()',
      'execution-while-out-of-viewport=()',
      'fullscreen=()',
      'geolocation=()',
      'gyroscope=()',
      'keyboard-map=()',
      'magnetometer=()',
      'microphone=()',
      'midi=()',
      'navigation-override=()',
      'payment=()',
      'picture-in-picture=()',
      'publickey-credentials-get=()',
      'screen-wake-lock=()',
      'sync-xhr=()',
      'usb=()',
      'web-share=()',
      'xr-spatial-tracking=()'
    ];

    return policies.join(', ');
  }

  /**
   * Add healthcare-specific security headers
   */
  private addHealthcareHeaders(headers: SecurityHeaders): void {
    // HIPAA compliance headers
    headers['X-Healthcare-Compliant'] = 'true';
    
    // Prevent caching of sensitive data
    headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private';
    headers['Pragma'] = 'no-cache';
    headers['Expires'] = '0';
    
    // Additional privacy headers
    headers['X-PHI-Protection'] = 'enabled';
    headers['X-Content-Security-Audit'] = 'strict';
    
    // Remove server identification for security
    headers['Server'] = 'Healthcare-API';
  }

  /**
   * Add standard security headers
   */
  private addStandardSecurityHeaders(headers: SecurityHeaders): void {
    // Prevent MIME type confusion attacks
    headers['X-Content-Type-Options'] = 'nosniff';
    
    // XSS Protection (for older browsers)
    headers['X-XSS-Protection'] = '1; mode=block';
    
    // DNS Prefetch Control
    headers['X-DNS-Prefetch-Control'] = 'off';
    
    // Download Options (IE)
    headers['X-Download-Options'] = 'noopen';
    
    // Prevent Adobe Flash/Acrobat from loading
    headers['X-Permitted-Cross-Domain-Policies'] = 'none';
    
    // Cross-Origin Resource Sharing (CORS) headers for API
    headers['Access-Control-Allow-Origin'] = 'null'; // Very restrictive for healthcare
    headers['Access-Control-Allow-Credentials'] = 'false';
    headers['Access-Control-Max-Age'] = '0';
  }

  /**
   * Generate CORS headers for API endpoints
   */
  public generateCORSHeaders(allowedOrigins: string[] = []): SecurityHeaders {
    const headers: SecurityHeaders = {};

    if (this.config.healthcareCompliant) {
      // Very restrictive CORS for healthcare
      headers['Access-Control-Allow-Origin'] = 'null';
      headers['Access-Control-Allow-Credentials'] = 'false';
      headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, OPTIONS';
      headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With';
      headers['Access-Control-Max-Age'] = '300'; // 5 minutes max
    } else {
      // Standard CORS configuration
      if (allowedOrigins.length > 0) {
        headers['Access-Control-Allow-Origin'] = allowedOrigins.join(', ');
      } else {
        headers['Access-Control-Allow-Origin'] = '*';
      }
      
      headers['Access-Control-Allow-Credentials'] = 'true';
      headers['Access-Control-Allow-Methods'] = 'GET, POST, PUT, DELETE, PATCH, OPTIONS';
      headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization, X-Requested-With, X-HTTP-Method-Override';
      headers['Access-Control-Max-Age'] = '3600'; // 1 hour
    }

    return headers;
  }

  /**
   * Validate request against security requirements
   */
  public validateRequest(request: {
    headers: Record<string, string>;
    method: string;
    url: string;
    userAgent?: string;
  }): {
    valid: boolean;
    violations: string[];
    riskLevel: 'low' | 'medium' | 'high';
  } {
    const violations: string[] = [];
    let riskLevel: 'low' | 'medium' | 'high' = 'low';

    // Check for required security headers in requests
    if (!request.headers['user-agent']) {
      violations.push('Missing User-Agent header');
      riskLevel = 'medium';
    }

    // Check for suspicious patterns in User-Agent
    if (request.userAgent) {
      const suspiciousPatterns = [
        /bot/i,
        /crawler/i,
        /scanner/i,
        /wget/i,
        /curl/i
      ];

      if (suspiciousPatterns.some(pattern => pattern.test(request.userAgent!))) {
        violations.push('Suspicious User-Agent detected');
        riskLevel = 'medium';
      }
    }

    // Check for HTTP method restrictions
    const allowedMethods = ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'HEAD'];
    if (!allowedMethods.includes(request.method.toUpperCase())) {
      violations.push(`HTTP method ${request.method} not allowed`);
      riskLevel = 'high';
    }

    // Healthcare-specific validations
    if (this.config.healthcareCompliant) {
      // Check for HTTPS requirement (in production)
      if (!request.url.startsWith('https://') && process.env.NODE_ENV === 'production') {
        violations.push('HTTPS required for healthcare compliance');
        riskLevel = 'high';
      }

      // Check for PHI-related endpoints without proper authorization
      if (this.isPHIEndpoint(request.url) && !request.headers.authorization) {
        violations.push('PHI endpoint accessed without authorization');
        riskLevel = 'high';
      }
    }

    return {
      valid: violations.length === 0,
      violations,
      riskLevel
    };
  }

  /**
   * Check if endpoint handles PHI data
   */
  private isPHIEndpoint(url: string): boolean {
    const phiResources = [
      '/Patient',
      '/Observation',
      '/Condition',
      '/MedicationRequest',
      '/Encounter',
      '/Procedure',
      '/DiagnosticReport',
      '/AllergyIntolerance'
    ];

    return phiResources.some(resource => url.includes(resource));
  }

  /**
   * Generate security report
   */
  public generateSecurityReport(): {
    configuration: SecurityHeadersConfig;
    headers: SecurityHeaders;
    complianceLevel: 'basic' | 'enhanced' | 'healthcare';
    recommendations: string[];
  } {
    const headers = this.generateHeaders();
    const recommendations: string[] = [];

    // Check configuration completeness
    if (!this.config.enableCSP) {
      recommendations.push('Enable Content Security Policy for XSS protection');
    }

    if (!this.config.enableHSTS) {
      recommendations.push('Enable HTTP Strict Transport Security');
    }

    if (!this.config.healthcareCompliant) {
      recommendations.push('Enable healthcare compliance mode for enhanced security');
    }

    // Determine compliance level
    let complianceLevel: 'basic' | 'enhanced' | 'healthcare' = 'basic';
    
    if (this.config.healthcareCompliant) {
      complianceLevel = 'healthcare';
    } else if (Object.keys(headers).length >= 10) {
      complianceLevel = 'enhanced';
    }

    return {
      configuration: this.config,
      headers,
      complianceLevel,
      recommendations
    };
  }

  /**
   * Update configuration
   */
  public updateConfig(updates: Partial<SecurityHeadersConfig>): void {
    this.config = { ...this.config, ...updates };
  }

  /**
   * Get current configuration
   */
  public getConfig(): SecurityHeadersConfig {
    return { ...this.config };
  }
}