import { Tool } from '@modelcontextprotocol/sdk/types.js';
import { TerminologyProvider } from '../providers/terminology-provider.js';
import { AuditLogger } from '../security/audit-logger.js';
import { 
  TerminologyExpandSchema, 
  TerminologyLookupSchema, 
  TerminologyTranslateSchema 
} from './schemas.js';

export class TerminologyTools {
  constructor(
    private terminologyProvider: TerminologyProvider,
    private auditLogger: AuditLogger
  ) {}

  getExpandTool(): Tool {
    return {
      name: 'terminology.expand',
      description: 'Expand a ValueSet to get contained codes',
      inputSchema: {
        type: 'object',
        properties: {
          url: {
            type: 'string',
            description: 'ValueSet canonical URL'
          },
          id: {
            type: 'string',
            description: 'ValueSet identifier'
          },
          filter: {
            type: 'string',
            description: 'Filter text for expansion'
          },
          count: {
            type: 'number',
            description: 'Maximum number of codes to return'
          },
          offset: {
            type: 'number',
            description: 'Offset for pagination'
          }
        }
      }
    };
  }

  getLookupTool(): Tool {
    return {
      name: 'terminology.lookup',
      description: 'Look up properties and display for a code in a CodeSystem',
      inputSchema: {
        type: 'object',
        properties: {
          system: {
            type: 'string',
            description: 'CodeSystem URI'
          },
          code: {
            type: 'string',
            description: 'Code to look up'
          }
        },
        required: ['system', 'code']
      }
    };
  }

  getTranslateTool(): Tool {
    return {
      name: 'terminology.translate',
      description: 'Translate a code from one system to another using ConceptMap',
      inputSchema: {
        type: 'object',
        properties: {
          code: {
            type: 'string',
            description: 'Source code'
          },
          system: {
            type: 'string',
            description: 'Source CodeSystem URI'
          },
          targetSystem: {
            type: 'string',
            description: 'Target CodeSystem URI'
          },
          conceptMapUrlOrId: {
            type: 'string',
            description: 'ConceptMap URL or identifier'
          }
        },
        required: ['code', 'system']
      }
    };
  }

  async handleExpand(args: any): Promise<any> {
    try {
      const input = TerminologyExpandSchema.parse(args);
      const expansion = await this.terminologyProvider.expand(
        input.url,
        input.id,
        input.filter,
        input.count,
        input.offset
      );

      this.auditLogger.logTerminologyOperation('expand', true, undefined, {
        url: input.url,
        filter: input.filter,
        resultCount: expansion.expansion.contains.length
      });

      return {
        content: [{ type: 'text', text: JSON.stringify(expansion, null, 2) }]
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      this.auditLogger.logTerminologyOperation('expand', false, errorMessage);
      
      return {
        content: [{ type: 'text', text: `Error expanding ValueSet: ${errorMessage}` }],
        isError: true
      };
    }
  }

  async handleLookup(args: any): Promise<any> {
    try {
      const input = TerminologyLookupSchema.parse(args);
      const lookup = await this.terminologyProvider.lookup(input.system, input.code);

      this.auditLogger.logTerminologyOperation('lookup', true, undefined, {
        system: input.system,
        code: input.code,
        found: lookup.valid
      });

      return {
        content: [{ type: 'text', text: JSON.stringify(lookup, null, 2) }]
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      this.auditLogger.logTerminologyOperation('lookup', false, errorMessage);
      
      return {
        content: [{ type: 'text', text: `Error looking up code: ${errorMessage}` }],
        isError: true
      };
    }
  }

  async handleTranslate(args: any): Promise<any> {
    try {
      const input = TerminologyTranslateSchema.parse(args);
      const translation = await this.terminologyProvider.translate(
        input.code,
        input.system,
        input.targetSystem,
        input.conceptMapUrlOrId
      );

      this.auditLogger.logTerminologyOperation('translate', true, undefined, {
        sourceCode: input.code,
        sourceSystem: input.system,
        targetSystem: input.targetSystem,
        success: translation.result
      });

      return {
        content: [{ type: 'text', text: JSON.stringify(translation, null, 2) }]
      };
    } catch (error) {
      const errorMessage = error instanceof Error ? error.message : 'Unknown error';
      this.auditLogger.logTerminologyOperation('translate', false, errorMessage);
      
      return {
        content: [{ type: 'text', text: `Error translating code: ${errorMessage}` }],
        isError: true
      };
    }
  }
}