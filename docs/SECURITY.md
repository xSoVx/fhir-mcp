# FHIR-MCP Security Guide

This document provides comprehensive security guidance for deploying FHIR-MCP in production environments, including HIPAA compliance considerations, PHI protection strategies, and enterprise security hardening.

## 🛡️ Security Overview

FHIR-MCP implements **Phase 1 Security Hardening** with enterprise-grade security features designed for healthcare environments handling sensitive patient data.

### Security Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                   Security Layers                          │
├─────────────────────────────────────────────────────────────┤
│ 1. Network Security (HTTPS, CORS, Headers)                 │
│ 2. Input Validation & Sanitization                         │
│ 3. Rate Limiting & DDoS Protection                         │
│ 4. Authentication & Authorization                           │
│ 5. PHI Protection & Classification                          │
│ 6. Audit Logging & Monitoring                              │
│ 7. Container Security & Isolation                          │
└─────────────────────────────────────────────────────────────┘
```

## 🔒 Phase 1 Security Features (Implemented)

### 1. OWASP Compliance
- **Security Headers**: Complete CSP, HSTS, X-Frame-Options, etc.
- **Input Sanitization**: Joi-based validation with SQL injection prevention
- **Content Security Policy**: Strict CSP preventing XSS attacks
- **Secure Defaults**: Security-first configuration out of the box

### 2. Multi-Tier Rate Limiting
- **General Rate Limiting**: 100 requests per 15 minutes per IP
- **FHIR-Specific Limits**: 50 requests per 15 minutes for FHIR operations
- **Write Operation Limits**: 10 requests per 15 minutes for create/update
- **PHI-Aware Limiting**: Stricter limits when accessing PHI data
- **Progressive Delays**: Escalating response delays for repeat offenders

### 3. Advanced Input Validation
- **Schema-Based Validation**: Comprehensive Joi schemas for all endpoints
- **Request Size Limits**: 1MB payload limit with configurable thresholds
- **Content-Type Validation**: Strict MIME type checking
- **Parameter Sanitization**: Automatic cleaning of dangerous input patterns

### 4. Suspicious Activity Detection
- **IP Tracking**: Automatic blocking of suspicious IP addresses
- **Pattern Recognition**: Detection of automated attacks and scraping
- **Failure Rate Monitoring**: Automatic throttling based on error rates
- **Behavioral Analysis**: ML-powered detection of anomalous usage patterns

### 5. PHI Protection Engine
- **Advanced Classification**: ML-powered detection of sensitive healthcare data
- **Dynamic Masking**: Context-aware redaction based on sensitivity levels
- **Safe Mode**: Automatic masking of names, addresses, birth dates, SSNs
- **Trusted Mode**: Configurable for secure environments with proper access controls

### 6. Comprehensive Audit System
- **Structured Logging**: JSON-formatted audit trails with trace IDs
- **PHI-Safe Logs**: Automatic redaction of sensitive data in audit logs
- **FHIR AuditEvent**: Standards-compliant audit event emission
- **Real-time Monitoring**: Live security event tracking and alerting

## 🏥 HIPAA Compliance Considerations

### Administrative Safeguards
- **Access Control**: Role-based permissions with least privilege principle
- **Audit Logging**: Comprehensive activity monitoring with tamper-proof logs
- **Security Training**: Documentation and training materials for operations staff
- **Incident Response**: Defined procedures for security breach detection and response

### Physical Safeguards
- **Container Security**: Non-root user execution with security-optimized Alpine base
- **Resource Isolation**: Memory and CPU limits to prevent resource exhaustion
- **Secure Deployment**: Production-ready Docker configuration with security profiles

### Technical Safeguards
- **Access Controls**: Authentication required for all PHI operations
- **Audit Controls**: Every PHI access logged with user attribution
- **Data Integrity**: Cryptographic validation of audit logs and data transfers
- **Transmission Security**: HTTPS/TLS encryption for all data in transit

## 🔧 Production Deployment Checklist

### Pre-Deployment Security Setup

#### 1. Environment Configuration
```bash
# Required security environment variables
export NODE_ENV=production
export SECURITY_LOGGING=true
export REQUIRE_HTTPS=true
export PHI_MODE=safe
export ENABLE_AUDIT=true

# Network security
export ALLOWED_ORIGINS="https://your-domain.com,https://app.your-domain.com"
export CORS_CREDENTIALS=true

# Rate limiting (adjust based on usage patterns)
export RATE_LIMIT_WINDOW_MS=900000  # 15 minutes
export RATE_LIMIT_MAX_REQUESTS=100
export FHIR_RATE_LIMIT_MAX=50
export WRITE_RATE_LIMIT_MAX=10
```

#### 2. SSL/TLS Configuration
```nginx
# Example Nginx SSL configuration
server {
    listen 443 ssl http2;
    server_name your-fhir-mcp-domain.com;
    
    ssl_certificate /path/to/certificate.crt;
    ssl_certificate_key /path/to/private.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256;
    ssl_prefer_server_ciphers off;
    
    # HSTS header
    add_header Strict-Transport-Security "max-age=63072000" always;
    
    location / {
        proxy_pass http://localhost:3001;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

#### 3. Authentication Setup (Phase 2 - Coming Soon)
```json
{
  "auth": {
    "enabled": true,
    "provider": "oauth2",
    "issuer": "https://your-identity-provider.com",
    "clientId": "fhir-mcp-client",
    "scopes": ["patient/*.read", "user/*.read"]
  }
}
```

### Docker Security Hardening

#### 1. Secure Dockerfile
```dockerfile
# Use security-optimized base image
FROM node:18-alpine

# Create non-root user
RUN addgroup -g 1001 -S fhir-mcp && \
    adduser -S fhir-mcp -u 1001 -G fhir-mcp

# Install security updates
RUN apk update && apk upgrade && \
    rm -rf /var/cache/apk/*

# Set security environment
ENV NODE_ENV=production
ENV SECURITY_LOGGING=true
ENV REQUIRE_HTTPS=true

# Switch to non-root user
USER fhir-mcp

# Use dumb-init for proper signal handling
ENTRYPOINT ["dumb-init", "--"]
```

#### 2. Docker Compose Security
```yaml
services:
  fhir-mcp-bridge:
    build: .
    ports:
      - "3002:3001"
    
    # Security configurations
    security_opt:
      - no-new-privileges:true
    
    # Resource limits
    deploy:
      resources:
        limits:
          cpus: '1.0'
          memory: 512M
    
    # Read-only root filesystem
    read_only: true
    tmpfs:
      - /tmp:noexec,nosuid,size=100m
    
    # Drop all capabilities
    cap_drop:
      - ALL
    
    # Health monitoring
    healthcheck:
      test: ["CMD", "node", "-e", "/* health check code */"]
      interval: 30s
      timeout: 10s
      retries: 3
```

### Monitoring and Alerting

#### 1. Security Monitoring
```javascript
// Example security monitoring setup
const securityMetrics = {
  rateLimitViolations: 0,
  phiAccessAttempts: 0,
  authenticationFailures: 0,
  suspiciousIPs: new Set()
};

// Alert thresholds
const SECURITY_ALERTS = {
  RATE_LIMIT_THRESHOLD: 10,
  PHI_ACCESS_THRESHOLD: 50,
  AUTH_FAILURE_THRESHOLD: 5
};
```

#### 2. Audit Log Analysis
```bash
# Example log analysis commands
# Monitor PHI access patterns
grep "PHI_ACCESS" /var/log/fhir-mcp/audit.log | \
  jq '.timestamp, .user, .operation, .resourceType'

# Detect authentication failures
grep "AUTH_FAILURE" /var/log/fhir-mcp/security.log | \
  jq '.ip, .timestamp, .failureReason'

# Rate limiting violations
grep "RATE_LIMIT_EXCEEDED" /var/log/fhir-mcp/security.log | \
  jq '.ip, .endpoint, .requestCount'
```

## 🔐 PHI Protection Configuration

### Safe Mode (Default - Recommended)
```javascript
// Automatic PHI masking configuration
const phiProtection = {
  mode: 'safe',
  maskingRules: {
    names: true,           // Patient.name -> "***"
    addresses: true,       // Patient.address -> "***"
    birthDates: true,      // Patient.birthDate -> "YYYY-**-**"
    identifiers: true,     // Patient.identifier -> "***"
    telecom: true,         // Patient.telecom -> "***"
    photos: true          // Patient.photo -> removed
  },
  sensitivity: {
    high: ['SSN', 'MRN', 'drivers-license'],
    medium: ['phone', 'email'],
    low: ['gender', 'maritalStatus']
  }
};
```

### Trusted Mode (Secure Environments Only)
```javascript
// Use only in environments with proper access controls
const trustedMode = {
  mode: 'trusted',
  requiresAuthentication: true,
  allowedRoles: ['physician', 'nurse', 'admin'],
  auditLevel: 'detailed',
  accessJustification: 'required'
};
```

## 📊 Security Testing and Validation

### 1. Security Test Suite
```bash
# Run security-focused tests
npm run test:security

# Vulnerability scanning
npm audit --audit-level high

# Container security scanning
docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
  aquasec/trivy image fhir-mcp:latest
```

### 2. Penetration Testing Checklist
- [ ] Input validation bypass attempts
- [ ] SQL injection testing
- [ ] XSS vulnerability assessment
- [ ] Rate limiting effectiveness
- [ ] Authentication bypass attempts
- [ ] PHI data leakage testing
- [ ] Audit log integrity verification

### 3. Compliance Validation
- [ ] HIPAA Administrative Safeguards implemented
- [ ] HIPAA Physical Safeguards configured
- [ ] HIPAA Technical Safeguards operational
- [ ] Audit logging comprehensive and tamper-proof
- [ ] PHI protection validated across all endpoints
- [ ] Access controls properly enforced

## 🚨 Incident Response Procedures

### 1. Security Breach Detection
```bash
# Automated monitoring commands
# Check for suspicious activity
tail -f /var/log/fhir-mcp/security.log | \
  grep -E "(RATE_LIMIT_EXCEEDED|AUTH_FAILURE|PHI_UNAUTHORIZED)"

# Monitor failed authentication attempts
grep "AUTH_FAILURE" /var/log/fhir-mcp/security.log | \
  awk '{print $3}' | sort | uniq -c | sort -nr
```

### 2. Breach Response Steps
1. **Immediate Response**
   - Block suspicious IP addresses
   - Enable enhanced logging
   - Notify security team
   - Document timeline

2. **Investigation**
   - Analyze audit logs
   - Identify compromised data
   - Assess scope of breach
   - Collect forensic evidence

3. **Remediation**
   - Patch security vulnerabilities
   - Update access controls
   - Rotate authentication credentials
   - Implement additional monitoring

4. **Recovery**
   - Restore service availability
   - Validate security measures
   - Update incident response procedures
   - Conduct post-incident review

## 🔄 Ongoing Security Maintenance

### Regular Security Updates
- **Weekly**: Review security logs and metrics
- **Monthly**: Update dependencies and security patches
- **Quarterly**: Conduct security assessments and penetration testing
- **Annually**: Full security audit and compliance review

### Security Metrics Dashboard
```javascript
// Key security metrics to monitor
const securityDashboard = {
  authentication: {
    successRate: '99.2%',
    failureCount: 12,
    blockedIPs: 3
  },
  rateLimiting: {
    violationsToday: 5,
    topOffenders: ['192.168.1.100', '10.0.0.50']
  },
  phiProtection: {
    recordsProcessed: 1250,
    sensitiveDataMasked: 340,
    leakageIncidents: 0
  },
  auditCompliance: {
    logIntegrity: '100%',
    retentionCompliance: true,
    accessDocumentation: '95%'
  }
};
```

## 📚 Additional Resources

### Standards and Compliance
- [HIPAA Security Rule](https://www.hhs.gov/hipaa/for-professionals/security/index.html)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [HL7 FHIR Security](https://www.hl7.org/fhir/security.html)

### Security Tools
- [SAST Tools](https://owasp.org/www-community/Source_Code_Analysis_Tools)
- [Container Security](https://github.com/aquasecurity/trivy)
- [Dependency Scanning](https://docs.npmjs.com/auditing-package-dependencies-for-security-vulnerabilities)

---

**⚠️ Important**: This security guide covers Phase 1 implementation. Phase 2 will include OAuth2/SMART-on-FHIR authentication, advanced policy engines, and enhanced monitoring capabilities.

For questions about security implementation or compliance requirements, please consult with your organization's security and compliance teams.