import axios, { AxiosInstance } from 'axios';
import { TerminologyExpansion, TerminologyLookup, TerminologyTranslate } from '../types/fhir.js';

export class TerminologyProvider {
  private client: AxiosInstance;
  private baseUrl: string;

  constructor(baseUrl: string, bearerToken?: string) {
    this.baseUrl = baseUrl.replace(/\/$/, '');
    this.client = axios.create({
      baseURL: this.baseUrl,
      headers: {
        'Accept': 'application/fhir+json',
        'Content-Type': 'application/fhir+json',
        ...(bearerToken && { 'Authorization': `Bearer ${bearerToken}` })
      },
      timeout: 30000
    });
  }

  async expand(
    url?: string,
    id?: string,
    filter?: string,
    count?: number,
    offset?: number
  ): Promise<TerminologyExpansion> {
    const params = new URLSearchParams();
    
    if (url) params.append('url', url);
    if (id) params.append('identifier', id);
    if (filter) params.append('filter', filter);
    if (count) params.append('count', count.toString());
    if (offset) params.append('offset', offset.toString());

    const response = await this.client.get(`/ValueSet/$expand?${params.toString()}`);
    return response.data;
  }

  async lookup(system: string, code: string): Promise<TerminologyLookup> {
    const params = new URLSearchParams();
    params.append('system', system);
    params.append('code', code);

    const response = await this.client.get(`/CodeSystem/$lookup?${params.toString()}`);
    
    // Extract relevant information from Parameters resource
    const parameters = response.data;
    const result: TerminologyLookup = {};

    if (parameters.parameter) {
      for (const param of parameters.parameter) {
        switch (param.name) {
          case 'display':
            result.display = param.valueString;
            break;
          case 'property':
            if (!result.properties) result.properties = {};
            if (param.part) {
              const code = param.part.find((p: any) => p.name === 'code')?.valueCode;
              const value = param.part.find((p: any) => p.name === 'value')?.valueString || 
                           param.part.find((p: any) => p.name === 'value')?.valueBoolean ||
                           param.part.find((p: any) => p.name === 'value')?.valueInteger;
              if (code && value !== undefined) {
                result.properties[code] = value;
              }
            }
            break;
        }
      }
      result.valid = true;
    }

    return result;
  }

  async translate(
    code: string,
    system: string,
    targetSystem?: string,
    conceptMapUrlOrId?: string
  ): Promise<TerminologyTranslate> {
    const params = new URLSearchParams();
    params.append('code', code);
    params.append('system', system);
    if (targetSystem) params.append('targetSystem', targetSystem);
    if (conceptMapUrlOrId) params.append('url', conceptMapUrlOrId);

    const response = await this.client.get(`/ConceptMap/$translate?${params.toString()}`);
    
    // Extract result from Parameters resource
    const parameters = response.data;
    const result: TerminologyTranslate = { result: false };

    if (parameters.parameter) {
      for (const param of parameters.parameter) {
        if (param.name === 'result' && param.valueBoolean) {
          result.result = param.valueBoolean;
        } else if (param.name === 'match' && param.part) {
          const match: any = {};
          for (const part of param.part) {
            switch (part.name) {
              case 'code':
                match.code = part.valueCode;
                break;
              case 'system':
                match.system = part.valueUri;
                break;
              case 'display':
                match.display = part.valueString;
                break;
            }
          }
          if (match.code && match.system) {
            result.match = match;
          }
        }
      }
    }

    return result;
  }
}