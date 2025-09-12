import { z } from 'zod';

// FHIR tool schemas
export const FhirCapabilitiesSchema = z.object({
  baseUrl: z.string().optional()
});

export const FhirSearchSchema = z.object({
  resourceType: z.string(),
  params: z.record(z.union([z.string(), z.array(z.string())])).optional().default({}),
  count: z.number().optional(),
  sort: z.string().optional(),
  elements: z.array(z.string()).optional()
});

export const FhirReadSchema = z.object({
  resourceType: z.string(),
  id: z.string(),
  elements: z.array(z.string()).optional()
});

export const FhirCreateSchema = z.object({
  resourceType: z.string(),
  resource: z.record(z.any())
});

export const FhirUpdateSchema = z.object({
  resourceType: z.string(),
  id: z.string(),
  resource: z.record(z.any()),
  ifMatchVersionId: z.string().optional()
});

// Terminology tool schemas
export const TerminologyExpandSchema = z.object({
  url: z.string().optional(),
  id: z.string().optional(),
  filter: z.string().optional(),
  count: z.number().optional(),
  offset: z.number().optional()
});

export const TerminologyLookupSchema = z.object({
  system: z.string(),
  code: z.string()
});

export const TerminologyTranslateSchema = z.object({
  code: z.string(),
  system: z.string(),
  targetSystem: z.string().optional(),
  conceptMapUrlOrId: z.string().optional()
});

// Auth tool schemas
export const AuthLoginSchema = z.object({
  flow: z.enum(['authorization_code', 'client_credentials']),
  clientId: z.string().optional(),
  authUrl: z.string().optional(),
  tokenUrl: z.string().optional(),
  scopes: z.array(z.string()).optional()
});