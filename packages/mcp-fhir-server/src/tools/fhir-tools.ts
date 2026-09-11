import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { FhirProvider } from '../providers/fhir-provider.js';
import { PhiGuard } from '../security/phi-guard.js';
import { AuditLogger } from '../security/audit-logger.js';
import { SecurityMiddleware, SecurityContext } from '../security/security-middleware.js';
import { PHILevel, RESOURCE_PHI_MATRIX } from '../types/phi-types.js';
import { 
  FhirCapabilitiesSchema
} from './schemas.js';

export class FhirTools {
  private securityMiddleware: SecurityMiddleware;

  constructor(
    private fhirProvider: FhirProvider,
    private phiGuard: PhiGuard,
    private auditLogger: AuditLogger,
    securityMiddleware?: SecurityMiddleware
  ) {
    this.securityMiddleware = securityMiddleware || new SecurityMiddleware({
      healthcareCompliant: true
    }, this.auditLogger);
  }

  getCapabilitiesTool(): Tool {
    return {
      name: 'fhir.capabilities',
      description: 'Get FHIR server capabilities and supported operations',
      inputSchema: {
        type: 'object',
        properties: {
          baseUrl: {
            type: 'string',
            description: 'Override base URL for capability statement'
          }
        }
      }
    };
  }

  getSearchTool(): Tool {
    return {
      name: 'fhir.search',
      description: 'Search FHIR resources with parameters, pagination, and field selection',
      inputSchema: {
        type: 'object',
        properties: {
          resourceType: {
            type: 'string',
            description: 'FHIR resource type to search'
          },
          params: {
            type: 'object',
            description: 'FHIR search parameters',
            additionalProperties: {
              oneOf: [
                { type: 'string' },
                { type: 'array', items: { type: 'string' } }
              ]
            }
          },
          count: {
            type: 'number',
            description: 'Maximum number of results (_count parameter)'
          },
          sort: {
            type: 'string',
            description: 'Sort parameter (_sort)'
          },
          elements: {
            type: 'array',
            items: { type: 'string' },
            description: 'Fields to include in results (_elements parameter)'
          }
        },
        required: ['resourceType']
      }
    };
  }

  getReadTool(): Tool {
    return {
      name: 'fhir.read',
      description: 'Read a specific FHIR resource by ID with optional field selection',
      inputSchema: {
        type: 'object',
        properties: {
          resourceType: {
            type: 'string',
            description: 'FHIR resource type'
          },
          id: {
            type: 'string',
            description: 'Resource ID'
          },
          elements: {
            type: 'array',
            items: { type: 'string' },
            description: 'Fields to include in result (_elements parameter)'
          }
        },
        required: ['resourceType', 'id']
      }
    };
  }

  getCreateTool(): Tool {
    return {
      name: 'fhir.create',
      description: 'Create a new FHIR resource (requires write permissions)',
      inputSchema: {
        type: 'object',
        properties: {
          resourceType: {
            type: 'string',
            description: 'FHIR resource type'
          },
          resource: {
            type: 'object',
            description: 'FHIR resource data'
          }
        },
        required: ['resourceType', 'resource']
      }
    };
  }

  getUpdateTool(): Tool {
    return {
      name: 'fhir.update',
      description: 'Update an existing FHIR resource (requires write permissions)',
      inputSchema: {
        type: 'object',
        properties: {
          resourceType: {
            type: 'string',
            description: 'FHIR resource type'
          },
          id: {
            type: 'string',
            description: 'Resource ID'
          },
          resource: {
            type: 'object',
            description: 'Updated FHIR resource data'
          },
          ifMatchVersionId: {
            type: 'string',
            description: 'Version ID for optimistic concurrency control'
          }
        },
        required: ['resourceType', 'id', 'resource']
      }
    };
  }

  async handleCapabilities(args: any): Promise<any> {
    try {
      FhirCapabilitiesSchema.parse(args);
      const capabilities = await this.fhirProvider.getCapabilities();
      
      // Simplify the capability statement for token efficiency
      const simplified = {
        fhirVersion: capabilities.fhirVersion,
        formats: capabilities.format,
        resources: capabilities.rest?.[0]?.resource?.map(r => ({
          type: r.type,
          interactions: r.interaction.map(i => i.code)
        })) || [],
        terminologyOps: capabilities.rest?.[0]?.operation?.map(op => op.name) || []
      };

      this.auditLogger.logFhirOperation('capabilities', 'CapabilityStatement', undefined, true, undefined, {
        fhirVersion: simplified.fhirVersion,
        resourceCount: simplified.resources.length
      });

      return {
        content: [{ type: 'text', text: JSON.stringify(simplified, null, 2) }]
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      this.auditLogger.logFhirOperation('capabilities', 'CapabilityStatement', undefined, false, errorMessage);
      
      return {
        content: [{ type: 'text', text: `Error getting capabilities: ${errorMessage}` }],
        isError: true
      };
    }
  }

  async handleSearch(args: any): Promise<any> {
    // Create security context
    const securityContext: SecurityContext = {
      sessionId: 'search-' + Date.now(),
      operation: 'fhir.search',
      resourceType: args.resourceType,
      phiLevel: this.getResourcePHILevel(args.resourceType)
    };

    try {
      // Process security checks
      const securityResult = await this.securityMiddleware.processRequest(securityContext, args);
      
      if (!securityResult.allowed) {
        return {
          content: [{
            type: 'text', 
            text: `Access denied: ${securityResult.reason}. Violations: ${securityResult.securityViolations?.join(', ') || 'None'}`
          }],
          isError: true
        };
      }

      // Use validated input
      const input = securityResult.validatedInput || args;
      
      const bundle = await this.fhirProvider.search(
        input.resourceType,
        input.params,
        input.elements,
        input.count,
        input.sort
      );

      // Apply PHI protection with enhanced authorization.
      //
      // Control flow here is deliberately fail-closed: if authorization or
      // masking throws, nothing is pushed to maskedEntries, so the *unmasked*
      // resource is dropped rather than returned. That behaviour is preserved.
      // What is added is visibility - suppressedCount - so the caller can tell
      // results were withheld instead of silently receiving a short list.
      const maskedEntries = [];
      let suppressedCount = 0;
      if (bundle.entry) {
        for (const entry of bundle.entry) {
          if (entry.resource) {
            try {
              const authResult = await this.phiGuard.authorizeAndMaskResource(
                entry.resource,
                undefined, // No user context in current implementation
                'read',
                `search_${Date.now()}`
              );

              if (authResult.authorized) {
                maskedEntries.push({
                  ...entry,
                  resource: authResult.maskedResource
                });
              } else {
                // Withheld by policy - counted, never logged with the payload.
                suppressedCount++;
              }
            } catch (error) {
              // Record the failure CLASS only. The thrown object frequently
              // carries the offending resource (directly or in a stack frame),
              // so it must never reach console.* or any log shipper.
              suppressedCount++;
              this.auditLogger.logMaskingFailure({
                resourceType: entry.resource?.resourceType,
                resourceId: entry.resource?.id,
                errorName: error instanceof Error ? error.name : 'unknown',
                stage: 'search'
              });
            }
          }
        }
      }

      const result = {
        total: bundle.total,
        returned: maskedEntries.length,
        suppressedCount,
        entries: maskedEntries.map(entry => ({
          id: entry.resource?.id,
          resource: entry.resource
        })),
        nextPage: bundle.link?.find(l => l.relation === 'next')?.url
      };

      this.auditLogger.logFhirOperation('search', input.resourceType, undefined, true, undefined, {
        resultCount: maskedEntries.length,
        suppressedCount,
        params: input.params
      });

      return {
        content: [{ type: 'text', text: JSON.stringify(result, null, 2) }]
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      this.auditLogger.logFhirOperation('search', 'unknown', undefined, false, errorMessage);
      
      return {
        content: [{ type: 'text', text: `Error searching resources: ${errorMessage}` }],
        isError: true
      };
    }
  }

  async handleRead(args: any): Promise<any> {
    const securityContext: SecurityContext = {
      sessionId: 'read-' + Date.now(),
      operation: 'fhir.read',
      resourceType: args.resourceType,
      phiLevel: this.getResourcePHILevel(args.resourceType)
    };

    try {
      // Process security checks
      const securityResult = await this.securityMiddleware.processRequest(securityContext, args);
      
      if (!securityResult.allowed) {
        return {
          content: [{
            type: 'text', 
            text: `Read access denied: ${securityResult.reason}`
          }],
          isError: true
        };
      }

      const input = securityResult.validatedInput || args;
      const resource = await this.fhirProvider.read(input.resourceType, input.id, input.elements);
      
      // Apply PHI protection with enhanced authorization engine
      const authResult = await this.phiGuard.authorizeAndMaskResource(
        resource,
        undefined, // No user context in current implementation
        'read',
        securityContext.sessionId
      );

      if (!authResult.authorized) {
        this.auditLogger.logFhirOperation('read', input.resourceType, input.id, false, authResult.reason);
        return {
          content: [{ type: 'text', text: `Access denied: ${authResult.reason || 'PHI protection active'}` }],
          isError: true
        };
      }

      const maskedResource = authResult.maskedResource;
      this.auditLogger.logFhirOperation('read', input.resourceType, input.id, true);

      return {
        content: [{ type: 'text', text: JSON.stringify({ resource: maskedResource }, null, 2) }]
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      this.auditLogger.logFhirOperation('read', 'unknown', undefined, false, errorMessage);
      
      return {
        content: [{ type: 'text', text: `Error reading resource: ${errorMessage}` }],
        isError: true
      };
    }
  }

  async handleCreate(args: any): Promise<any> {
    const securityContext: SecurityContext = {
      sessionId: 'create-' + Date.now(),
      operation: 'fhir.create',
      resourceType: args.resourceType,
      phiLevel: this.getResourcePHILevel(args.resourceType)
    };

    try {
      // Process security checks
      const securityResult = await this.securityMiddleware.processRequest(securityContext, args);
      
      if (!securityResult.allowed) {
        return {
          content: [{
            type: 'text', 
            text: `Create denied: ${securityResult.reason}`
          }],
          isError: true
        };
      }

      const input = securityResult.validatedInput || args;
      const resource = { ...input.resource, resourceType: input.resourceType };
      const created = await this.fhirProvider.create(input.resourceType, resource);

      this.auditLogger.logFhirOperation('create', input.resourceType, created.id, true);

      return {
        content: [{ 
          type: 'text', 
          text: JSON.stringify({ 
            id: created.id, 
            versionId: created.meta?.versionId 
          }, null, 2) 
        }]
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      this.auditLogger.logFhirOperation('create', 'unknown', undefined, false, errorMessage);
      
      return {
        content: [{ type: 'text', text: `Error creating resource: ${errorMessage}` }],
        isError: true
      };
    }
  }

  async handleUpdate(args: any): Promise<any> {
    const securityContext: SecurityContext = {
      sessionId: 'update-' + Date.now(),
      operation: 'fhir.update',
      resourceType: args.resourceType,
      phiLevel: this.getResourcePHILevel(args.resourceType)
    };

    try {
      // Process security checks
      const securityResult = await this.securityMiddleware.processRequest(securityContext, args);
      
      if (!securityResult.allowed) {
        return {
          content: [{
            type: 'text', 
            text: `Update denied: ${securityResult.reason}`
          }],
          isError: true
        };
      }

      const input = securityResult.validatedInput || args;
      const resource = { ...input.resource, resourceType: input.resourceType };
      const updated = await this.fhirProvider.update(
        input.resourceType, 
        input.id, 
        resource, 
        input.ifMatchVersionId
      );

      this.auditLogger.logFhirOperation('update', input.resourceType, input.id, true);

      return {
        content: [{ 
          type: 'text', 
          text: JSON.stringify({ 
            id: updated.id, 
            versionId: updated.meta?.versionId 
          }, null, 2) 
        }]
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      this.auditLogger.logFhirOperation('update', 'unknown', undefined, false, errorMessage);
      
      return {
        content: [{ type: 'text', text: `Error updating resource: ${errorMessage}` }],
        isError: true
      };
    }
  }

  /**
   * Helper method to determine PHI level for a resource type
   */
  private getResourcePHILevel(resourceType?: string): PHILevel {
    if (!resourceType) return PHILevel.RESTRICTED;
    return RESOURCE_PHI_MATRIX[resourceType] || PHILevel.RESTRICTED;
  }
}