# Multi-stage Dockerfile for FHIR-MCP with security hardening
FROM node:18-alpine as builder

# Security: Create non-root user
RUN addgroup -g 1001 -S fhir-mcp && \
    adduser -S fhir-mcp -u 1001 -G fhir-mcp

# Install security updates
RUN apk update && apk upgrade && \
    apk add --no-cache dumb-init && \
    rm -rf /var/cache/apk/*

# Set working directory
WORKDIR /usr/src/app

# Copy package files for dependency installation
COPY package*.json ./
COPY packages/mcp-fhir-server/package*.json ./packages/mcp-fhir-server/
COPY packages/examples/http-bridge/package*.json ./packages/examples/http-bridge/

# Install all dependencies (including dev dependencies for building)
RUN npm ci && npm cache clean --force

# Copy source code
COPY packages/ ./packages/
COPY spec/ ./spec/
COPY tsconfig.json ./

# Build the applications
RUN npm run build --workspace=packages/mcp-fhir-server && \
    npm run build --workspace=packages/examples/http-bridge

# Verify build outputs exist
RUN ls -la packages/mcp-fhir-server/dist/ && \
    ls -la packages/examples/http-bridge/dist/

# Production stage
FROM node:18-alpine

# Install security updates and dumb-init
RUN apk update && apk upgrade && \
    apk add --no-cache dumb-init && \
    rm -rf /var/cache/apk/*

# Create non-root user
RUN addgroup -g 1001 -S fhir-mcp && \
    adduser -S fhir-mcp -u 1001 -G fhir-mcp

# Set working directory
WORKDIR /usr/src/app

# Copy package files first
COPY --from=builder --chown=fhir-mcp:fhir-mcp /usr/src/app/package*.json ./
COPY --from=builder --chown=fhir-mcp:fhir-mcp /usr/src/app/packages/mcp-fhir-server/package*.json ./packages/mcp-fhir-server/
COPY --from=builder --chown=fhir-mcp:fhir-mcp /usr/src/app/packages/examples/http-bridge/package*.json ./packages/examples/http-bridge/

# Install only production dependencies
RUN npm ci --only=production && npm cache clean --force

# Copy built applications
COPY --from=builder --chown=fhir-mcp:fhir-mcp /usr/src/app/packages/mcp-fhir-server/dist ./packages/mcp-fhir-server/dist
COPY --from=builder --chown=fhir-mcp:fhir-mcp /usr/src/app/packages/examples/http-bridge/dist ./packages/examples/http-bridge/dist

# Create logs directory
RUN mkdir -p /usr/src/app/logs && chown -R fhir-mcp:fhir-mcp /usr/src/app/logs

# Set security-focused environment variables
ENV NODE_ENV=production
ENV NODE_OPTIONS="--max-old-space-size=512 --no-warnings"
ENV NPM_CONFIG_FUND=false
ENV NPM_CONFIG_AUDIT=true

# Security configurations
ENV SECURITY_LOGGING=true
ENV REQUIRE_HTTPS=true
ENV ALLOWED_ORIGINS=http://localhost:3000,http://localhost:8080
ENV PHI_MODE=safe
ENV ENABLE_AUDIT=true

# FHIR server configuration
ENV FHIR_BASE_URL=https://hapi.fhir.org/baseR4
ENV TERMINOLOGY_BASE_URL=https://tx.fhir.org/r4

# HTTP Bridge configuration
ENV PORT=3001

# Switch to non-root user
USER fhir-mcp

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD node -e "const http = require('http'); \
    const options = { hostname: 'localhost', port: 3001, path: '/health', timeout: 5000 }; \
    const req = http.request(options, (res) => { \
        if (res.statusCode === 200) { console.log('Health check passed'); process.exit(0); } \
        else { console.log('Health check failed with status:', res.statusCode); process.exit(1); } \
    }); \
    req.on('error', (err) => { console.log('Health check error:', err.message); process.exit(1); }); \
    req.on('timeout', () => { console.log('Health check timeout'); req.destroy(); process.exit(1); }); \
    req.setTimeout(5000); \
    req.end();"

# Expose port
EXPOSE 3001

# Labels for security and metadata
LABEL maintainer="FHIR-MCP Team" \
      version="1.0.0" \
      description="FHIR-MCP HTTP Bridge with Phase 1 Security Hardening" \
      security.implemented="input-validation,rate-limiting,security-headers,owasp-compliance" \
      compliance="HIPAA-ready,PHI-protected"

# Use dumb-init to handle signals properly
ENTRYPOINT ["dumb-init", "--"]

# Start the HTTP bridge
CMD ["node", "packages/examples/http-bridge/dist/index.js"]