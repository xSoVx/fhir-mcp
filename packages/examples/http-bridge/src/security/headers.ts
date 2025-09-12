import helmet from 'helmet';
import { Request, Response, NextFunction } from 'express';
import hpp from 'hpp';

// Healthcare-specific Content Security Policy
export const healthcareCSP = helmet.contentSecurityPolicy({
  directives: {
    defaultSrc: ["'self'"],
    scriptSrc: [
      "'self'",
      "'unsafe-inline'", // Allow inline scripts for FHIR apps if needed
      "'unsafe-eval'", // Some FHIR clients may need eval
      "https://*.fhir.org",
      "https://*.hl7.org"
    ],
    styleSrc: [
      "'self'",
      "'unsafe-inline'", // Allow inline styles for FHIR UI components
      "https://*.fhir.org",
      "https://*.hl7.org"
    ],
    imgSrc: [
      "'self'",
      "data:", // Allow data URLs for small images/icons
      "https://*.fhir.org",
      "https://*.hl7.org",
      "https://terminology.hl7.org"
    ],
    connectSrc: [
      "'self'",
      "https://*.fhir.org",
      "https://*.hl7.org",
      "https://hapi.fhir.org",
      "https://tx.fhir.org",
      "wss:", // For WebSocket connections if needed
      "https://terminology.hl7.org"
    ],
    fontSrc: [
      "'self'",
      "https://*.fhir.org",
      "https://*.hl7.org"
    ],
    objectSrc: ["'none'"],
    mediaSrc: ["'self'"],
    frameSrc: [
      "'self'",
      "https://*.fhir.org",
      "https://*.hl7.org"
    ],
    childSrc: [
      "'self'",
      "https://*.fhir.org"
    ],
    formAction: ["'self'"],
    frameAncestors: ["'none'"], // Prevent embedding in frames
    baseUri: ["'self'"],
    upgradeInsecureRequests: []
  },
  reportOnly: false
});

// Comprehensive security headers for healthcare applications
export const securityHeaders = [
  // Use helmet with healthcare-specific configurations
  helmet({
    // Remove X-Powered-By header
    hidePoweredBy: true,
    
    // Set HSTS with long max-age for production
    hsts: {
      maxAge: 31536000, // 1 year
      includeSubDomains: true,
      preload: true
    },
    
    // Prevent MIME type sniffing
    noSniff: true,
    
    // Enable XSS protection
    xssFilter: true,
    
    // Referrer policy for healthcare privacy
    referrerPolicy: {
      policy: ['no-referrer', 'strict-origin-when-cross-origin']
    },
    
    // Note: expectCt is deprecated in newer helmet versions
    // expectCt: {
    //   maxAge: 86400, // 24 hours
    //   enforce: true,
    //   reportUri: '/security/ct-report'
    // },
    
    // DNS prefetch control
    dnsPrefetchControl: {
      allow: false
    },
    
    // Download options for IE
    ieNoOpen: true,
    
    // Frame options
    frameguard: {
      action: 'deny'
    },
    
    // Permissions policy (formerly Feature-Policy)
    permittedCrossDomainPolicies: false
  }),

  // Use our healthcare CSP
  healthcareCSP,

  // HTTP Parameter Pollution protection
  hpp({
    whitelist: ['_include', '_revinclude', 'identifier'] // Allow arrays for these FHIR parameters
  }),

  // Custom headers for healthcare compliance
  (req: Request, res: Response, next: NextFunction) => {
    // HIPAA compliance headers
    res.setHeader('X-Healthcare-Compliance', 'HIPAA-Ready');
    res.setHeader('X-PHI-Protection', 'Enabled');
    
    // Cache control for sensitive data
    if (req.path.includes('/fhir/') || req.path.includes('/terminology/')) {
      res.setHeader('Cache-Control', 'no-cache, no-store, must-revalidate, private');
      res.setHeader('Pragma', 'no-cache');
      res.setHeader('Expires', '0');
    }
    
    // CORS headers for healthcare applications
    res.setHeader('Access-Control-Allow-Origin', process.env.ALLOWED_ORIGINS || '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-API-Key, X-Request-ID');
    res.setHeader('Access-Control-Expose-Headers', 'X-Request-ID, X-Rate-Limit-Remaining');
    res.setHeader('Access-Control-Max-Age', '86400'); // 24 hours
    
    // Request ID for tracing
    const requestId = req.get('X-Request-ID') || generateRequestId();
    res.setHeader('X-Request-ID', requestId);
    req.headers['x-request-id'] = requestId;
    
    // Server information (limited for security)
    res.setHeader('Server', 'FHIR-MCP/1.0');
    
    // Timing information removal
    res.removeHeader('X-Response-Time');
    
    next();
  }
];

// Additional security middleware for sensitive endpoints
export function sensitiveEndpointSecurity(req: Request, res: Response, next: NextFunction): void {
  // Additional headers for write operations
  if (req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH' || req.method === 'DELETE') {
    res.setHeader('X-Operation-Audit', 'Required');
    res.setHeader('X-Data-Classification', 'PHI-Potential');
  }
  
  // Require secure transport
  if (process.env.NODE_ENV === 'production' && !req.secure && req.get('X-Forwarded-Proto') !== 'https') {
    res.status(426).json({
      error: 'Upgrade Required',
      message: 'HTTPS is required for this endpoint in production',
      timestamp: new Date().toISOString()
    });
    return;
  }
  
  next();
}

// Request validation for suspicious patterns
export function validateRequestPatterns(req: Request, res: Response, next: NextFunction): void {
  const userAgent = req.get('User-Agent') || '';
  const suspicious = [
    /sqlmap/i,
    /nikto/i,
    /nmap/i,
    /burp/i,
    /w3af/i,
    /acunetix/i,
    /nessus/i,
    /<script/i,
    /javascript:/i,
    /vbscript:/i,
    /onload=/i,
    /onerror=/i
  ];
  
  // Check User-Agent for suspicious patterns
  if (suspicious.some(pattern => pattern.test(userAgent))) {
    console.warn(`Suspicious User-Agent detected: ${userAgent} from IP: ${req.ip}`);
    res.status(400).json({
      error: 'Bad Request',
      message: 'Invalid request pattern detected',
      timestamp: new Date().toISOString()
    });
    return;
  }
  
  // Check for suspicious query parameters
  const queryString = req.originalUrl.split('?')[1] || '';
  if (suspicious.some(pattern => pattern.test(queryString))) {
    console.warn(`Suspicious query parameters detected: ${queryString} from IP: ${req.ip}`);
    res.status(400).json({
      error: 'Bad Request',
      message: 'Invalid query parameters detected',
      timestamp: new Date().toISOString()
    });
    return;
  }
  
  next();
}

// Security monitoring middleware
export function securityMonitoring(req: Request, res: Response, next: NextFunction): void {
  const startTime = Date.now();
  
  // Log security-relevant events
  const securityEvent = {
    timestamp: new Date().toISOString(),
    ip: req.ip,
    method: req.method,
    path: req.path,
    userAgent: req.get('User-Agent'),
    requestId: req.get('X-Request-ID'),
    contentLength: req.get('Content-Length'),
    origin: req.get('Origin'),
    referer: req.get('Referer')
  };
  
  // Capture response completion for logging
  res.on('finish', () => {
    const duration = Date.now() - startTime;
    
    // Log if request took too long (potential DoS)
    if (duration > 30000) { // 30 seconds
      console.warn(`Slow request detected: ${duration}ms for ${req.method} ${req.path} from ${req.ip}`);
    }
    
    // Log security events for monitoring
    if (process.env.SECURITY_LOGGING === 'true') {
      console.log(JSON.stringify({
        ...securityEvent,
        statusCode: res.statusCode,
        duration,
        type: 'security_event'
      }));
    }
  });
  
  next();
}

// Request ID generator
function generateRequestId(): string {
  return `fhir-mcp-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
}

// Error handler for security violations
export function securityErrorHandler(err: any, req: Request, res: Response, _next: NextFunction): void {
  // Don't reveal internal error details in production
  if (process.env.NODE_ENV === 'production') {
    const sanitizedError = {
      error: 'Internal Server Error',
      message: 'An error occurred while processing your request',
      requestId: req.get('X-Request-ID'),
      timestamp: new Date().toISOString()
    };
    
    // Log the actual error for debugging
    console.error(`Error ${req.get('X-Request-ID')}: ${err.message}`, {
      stack: err.stack,
      ip: req.ip,
      path: req.path,
      method: req.method
    });
    
    res.status(500).json(sanitizedError);
    return;
  }
  
  // In development, provide more details
  res.status(err.status || 500).json({
    error: err.name || 'Error',
    message: err.message,
    stack: err.stack,
    requestId: req.get('X-Request-ID'),
    timestamp: new Date().toISOString()
  });
}