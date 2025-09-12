import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { FhirProvider } from '../providers/fhir-provider.js';
import { PhiGuard } from '../security/phi-guard.js';
import { AuditLogger } from '../security/audit-logger.js';
import { 
  FhirCapabilitiesSchema, 
  FhirSearchSchema, 
  FhirReadSchema, 
  FhirCreateSchema, 
  FhirUpdateSchema 
} from './schemas.js';

export class FhirTools {
  constructor(
    private fhirProvider: FhirProvider,
    private phiGuard: PhiGuard,
    private auditLogger: AuditLogger
  ) {}

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
    try {
      const input = FhirSearchSchema.parse(args);
      const bundle = await this.fhirProvider.search(
        input.resourceType,
        input.params,
        input.elements,
        input.count,
        input.sort
      );

      // Apply PHI protection
      const maskedEntries = bundle.entry?.map(entry => ({
        ...entry,
        resource: entry.resource ? this.phiGuard.maskResource(entry.resource) : undefined
      })) || [];

      const result = {
        total: bundle.total,
        entries: maskedEntries.map(entry => ({
          id: entry.resource?.id,
          resource: entry.resource
        })),
        nextPage: bundle.link?.find(l => l.relation === 'next')?.url
      };

      this.auditLogger.logFhirOperation('search', input.resourceType, undefined, true, undefined, {
        resultCount: maskedEntries.length,
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
    try {
      const input = FhirReadSchema.parse(args);
      const resource = await this.fhirProvider.read(input.resourceType, input.id, input.elements);
      
      // Apply PHI protection
      const maskedResource = this.phiGuard.maskResource(resource);

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
    try {
      const input = FhirCreateSchema.parse(args);
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
    try {
      const input = FhirUpdateSchema.parse(args);
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
}