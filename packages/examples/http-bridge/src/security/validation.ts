import Joi from 'joi';
import { Request, Response, NextFunction } from 'express';

// FHIR resource type validation
const fhirResourceTypes = [
  'Patient', 'Practitioner', 'Organization', 'Location', 'Device',
  'Medication', 'MedicationRequest', 'MedicationDispense', 'MedicationStatement',
  'Observation', 'DiagnosticReport', 'Procedure', 'Condition', 'AllergyIntolerance',
  'Encounter', 'Appointment', 'AppointmentResponse', 'Schedule', 'Slot',
  'Coverage', 'ExplanationOfBenefit', 'Claim', 'ClaimResponse',
  'Bundle', 'Composition', 'DocumentReference', 'Binary'
];

// Base schemas
const fhirIdSchema = Joi.string().pattern(/^[A-Za-z0-9\-.]{1,64}$/).messages({
  'string.pattern.base': 'FHIR ID must contain only alphanumeric characters, dots, and hyphens, max 64 chars'
});

const fhirUrlSchema = Joi.string().uri().max(2048).messages({
  'string.uri': 'Must be a valid URL',
  'string.max': 'URL must not exceed 2048 characters'
});

const fhirResourceTypeSchema = Joi.string().valid(...fhirResourceTypes).messages({
  'any.only': `Resource type must be one of: ${fhirResourceTypes.join(', ')}`
});

// Request validation schemas
export const validationSchemas = {
  // FHIR search parameters
  fhirSearch: Joi.object({
    resourceType: fhirResourceTypeSchema.required(),
    _count: Joi.number().integer().min(1).max(1000).default(20),
    _offset: Joi.number().integer().min(0).default(0),
    _sort: Joi.string().pattern(/^[-+]?[a-zA-Z0-9_.-]+$/).max(100),
    _include: Joi.alternatives().try(
      Joi.string().max(200),
      Joi.array().items(Joi.string().max(200))
    ),
    _revinclude: Joi.alternatives().try(
      Joi.string().max(200),
      Joi.array().items(Joi.string().max(200))
    ),
    _elements: Joi.string().pattern(/^[a-zA-Z0-9_,.-]+$/).max(500),
    _summary: Joi.string().valid('true', 'false', 'text', 'data', 'count'),
    // Common search parameters
    _id: fhirIdSchema,
    _lastUpdated: Joi.string().pattern(/^\d{4}-\d{2}-\d{2}(T\d{2}:\d{2}:\d{2}(\.\d{1,3})?([+-]\d{2}:\d{2}|Z))?$/),
    identifier: Joi.string().max(200),
    name: Joi.string().max(200),
    family: Joi.string().max(200),
    given: Joi.string().max(200),
    birthdate: Joi.string().pattern(/^\d{4}(-\d{2}(-\d{2})?)?$/),
    gender: Joi.string().valid('male', 'female', 'other', 'unknown'),
    active: Joi.string().valid('true', 'false')
  }).unknown(false), // Prevent unknown parameters

  // FHIR read parameters
  fhirRead: Joi.object({
    resourceType: fhirResourceTypeSchema.required(),
    id: fhirIdSchema.required(),
    _summary: Joi.string().valid('true', 'false', 'text', 'data'),
    _elements: Joi.string().pattern(/^[a-zA-Z0-9_,.-]+$/).max(500)
  }).unknown(false),

  // FHIR create/update - basic structure validation
  fhirResource: Joi.object({
    resourceType: fhirResourceTypeSchema.required(),
    id: fhirIdSchema.optional(),
    meta: Joi.object().unknown(true).optional(),
    implicitRules: fhirUrlSchema.optional(),
    language: Joi.string().pattern(/^[a-z]{2}(-[A-Z]{2})?$/).optional(),
    text: Joi.object({
      status: Joi.string().valid('generated', 'extensions', 'additional', 'empty').required(),
      div: Joi.string().max(10000).required()
    }).optional(),
    contained: Joi.array().items(Joi.object().unknown(true)).max(50).optional(),
    extension: Joi.array().items(Joi.object().unknown(true)).max(100).optional(),
    modifierExtension: Joi.array().items(Joi.object().unknown(true)).max(50).optional()
  }).unknown(true), // Allow resource-specific fields

  // Terminology parameters
  terminologyLookup: Joi.object({
    system: fhirUrlSchema.required(),
    code: Joi.string().max(100).required(),
    version: Joi.string().max(50).optional(),
    coding: Joi.object({
      system: fhirUrlSchema.optional(),
      version: Joi.string().max(50).optional(),
      code: Joi.string().max(100).optional(),
      display: Joi.string().max(500).optional(),
      userSelected: Joi.boolean().optional()
    }).optional(),
    date: Joi.string().isoDate().optional(),
    displayLanguage: Joi.string().pattern(/^[a-z]{2}(-[A-Z]{2})?$/).optional(),
    property: Joi.alternatives().try(
      Joi.string().max(100),
      Joi.array().items(Joi.string().max(100)).max(20)
    ).optional()
  }).unknown(false),

  terminologyExpand: Joi.object({
    url: fhirUrlSchema.required(),
    valueSet: Joi.object().unknown(true).optional(),
    context: fhirUrlSchema.optional(),
    contextDirection: Joi.string().valid('incoming', 'outgoing').optional(),
    filter: Joi.string().max(200).optional(),
    date: Joi.string().isoDate().optional(),
    offset: Joi.number().integer().min(0).max(10000).default(0),
    count: Joi.number().integer().min(1).max(1000).default(20),
    includeDesignations: Joi.boolean().optional(),
    designation: Joi.alternatives().try(
      Joi.string().max(100),
      Joi.array().items(Joi.string().max(100)).max(10)
    ).optional(),
    includeDefinition: Joi.boolean().optional(),
    activeOnly: Joi.boolean().optional(),
    excludeNested: Joi.boolean().optional(),
    excludeNotForUI: Joi.boolean().optional(),
    excludePostCoordinated: Joi.boolean().optional(),
    displayLanguage: Joi.string().pattern(/^[a-z]{2}(-[A-Z]{2})?$/).optional(),
    'exclude-system': Joi.alternatives().try(
      fhirUrlSchema,
      Joi.array().items(fhirUrlSchema).max(10)
    ).optional(),
    'system-version': Joi.alternatives().try(
      Joi.string().max(100),
      Joi.array().items(Joi.string().max(100)).max(10)
    ).optional(),
    'check-system-version': Joi.alternatives().try(
      Joi.string().max(100),
      Joi.array().items(Joi.string().max(100)).max(10)
    ).optional(),
    'force-system-version': Joi.alternatives().try(
      Joi.string().max(100),
      Joi.array().items(Joi.string().max(100)).max(10)
    ).optional()
  }).unknown(false)
};

// Validation middleware factory
export function validateRequest(schema: Joi.ObjectSchema) {
  return (req: Request, res: Response, next: NextFunction) => {
    const { error, value } = schema.validate(req.body, {
      abortEarly: false,
      stripUnknown: true,
      convert: true
    });

    if (error) {
      const errorDetails = error.details.map(detail => ({
        field: detail.path.join('.'),
        message: detail.message,
        value: detail.context?.value
      }));

      return res.status(400).json({
        error: 'Validation failed',
        details: errorDetails,
        timestamp: new Date().toISOString()
      });
    }

    // Replace request body with validated and sanitized data
    req.body = value;
    next();
  };
}

// Generic tool parameter validation
export function validateToolParameters(req: Request, res: Response, next: NextFunction) {
  const toolName = req.params.toolName;
  
  // Basic tool name validation
  if (!toolName || !/^[a-zA-Z0-9._-]+$/.test(toolName) || toolName.length > 100) {
    return res.status(400).json({
      error: 'Invalid tool name',
      message: 'Tool name must contain only alphanumeric characters, dots, underscores, and hyphens, max 100 chars',
      timestamp: new Date().toISOString()
    });
  }

  // Basic parameter size check
  const bodyString = JSON.stringify(req.body);
  if (bodyString.length > 100000) { // 100KB limit
    return res.status(413).json({
      error: 'Request too large',
      message: 'Request body must not exceed 100KB',
      timestamp: new Date().toISOString()
    });
  }

  next();
}

// Content-Type validation middleware
export function validateContentType(req: Request, res: Response, next: NextFunction) {
  if (req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH') {
    const contentType = req.get('Content-Type');
    if (!contentType || !contentType.includes('application/json')) {
      return res.status(415).json({
        error: 'Unsupported Media Type',
        message: 'Content-Type must be application/json',
        timestamp: new Date().toISOString()
      });
    }
  }
  next();
}

// Request size validation middleware
export function validateRequestSize(maxSize: number = 1024 * 1024) { // Default 1MB
  return (req: Request, res: Response, next: NextFunction) => {
    const contentLength = parseInt(req.get('Content-Length') || '0', 10);
    if (contentLength > maxSize) {
      return res.status(413).json({
        error: 'Request Entity Too Large',
        message: `Request size must not exceed ${Math.round(maxSize / 1024)}KB`,
        timestamp: new Date().toISOString()
      });
    }
    next();
  };
}