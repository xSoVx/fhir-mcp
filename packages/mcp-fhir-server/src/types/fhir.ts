export interface FhirResource {
  id?: string;
  meta?: {
    versionId?: string;
    lastUpdated?: string;
  };
  resourceType: string;
  [key: string]: any;
}

export interface FhirBundle {
  resourceType: 'Bundle';
  type: string;
  total?: number;
  entry?: Array<{
    resource?: FhirResource;
    fullUrl?: string;
  }>;
  link?: Array<{
    relation: string;
    url: string;
  }>;
}

export interface FhirCapabilityStatement {
  resourceType: 'CapabilityStatement';
  fhirVersion: string;
  format: string[];
  rest: Array<{
    mode: string;
    resource?: Array<{
      type: string;
      interaction: Array<{
        code: string;
      }>;
    }>;
    operation?: Array<{
      name: string;
      definition: string;
    }>;
  }>;
}

export interface FhirSearchParams {
  [key: string]: string | string[];
}

export interface TerminologyExpansion {
  expansion: {
    total?: number;
    contains: Array<{
      system: string;
      code: string;
      display?: string;
    }>;
  };
}

export interface TerminologyLookup {
  valid?: boolean;
  display?: string;
  properties?: Record<string, string | number | boolean>;
}

export interface TerminologyTranslate {
  result: boolean;
  match?: {
    code: string;
    system: string;
    display?: string;
  };
}