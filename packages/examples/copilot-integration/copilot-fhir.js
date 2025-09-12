/**
 * GitHub Copilot Integration for FhirMCP
 * 
 * This module provides Copilot-friendly functions to interact with FHIR data
 * through the FhirMCP HTTP bridge.
 * 
 * Usage in your code - Copilot will suggest these functions:
 * 
 * @example
 * // Search for patients
 * const patients = await searchPatients({ name: "John" });
 * 
 * // Get patient details
 * const patient = await getPatient("Patient/123");
 * 
 * // Look up a clinical code
 * const codeInfo = await lookupCode("http://loinc.org", "29463-7");
 */

const FHIR_MCP_BASE_URL = 'http://localhost:3001';

/**
 * Search for FHIR resources with Copilot-friendly interface
 * @param {string} resourceType - FHIR resource type (e.g., 'Patient', 'Observation')
 * @param {Object} searchParams - Search parameters
 * @param {string[]} elements - Fields to include in response
 * @param {number} count - Maximum number of results
 * @returns {Promise<Object>} Search results
 */
async function searchFhirResources(resourceType, searchParams = {}, elements = null, count = 10) {
    const requestBody = {
        resourceType,
        params: searchParams,
        count,
        ...(elements && { elements })
    };

    const response = await fetch(`${FHIR_MCP_BASE_URL}/fhir/search`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(requestBody)
    });

    if (!response.ok) {
        throw new Error(`FHIR search failed: ${response.statusText}`);
    }

    const result = await response.json();
    
    // Parse the JSON content from MCP response
    if (result.content && result.content[0] && result.content[0].text) {
        return JSON.parse(result.content[0].text);
    }
    
    return result;
}

/**
 * Search for patients - Copilot will suggest this for patient queries
 * @param {Object} searchParams - Patient search parameters
 * @param {string} searchParams.name - Patient name
 * @param {string} searchParams.family - Family name
 * @param {string} searchParams.given - Given name
 * @param {string} searchParams.gender - Gender (male|female|other|unknown)
 * @param {string} searchParams.birthdate - Birth date (YYYY-MM-DD)
 * @returns {Promise<Object>} Patient search results with PHI protection
 */
async function searchPatients(searchParams) {
    return await searchFhirResources('Patient', searchParams, ['id', 'name', 'gender', 'birthDate'], 10);
}

/**
 * Get a specific patient by ID
 * @param {string} patientId - Patient ID (e.g., "Patient/123" or just "123")
 * @returns {Promise<Object>} Patient resource with PHI masking
 */
async function getPatient(patientId) {
    // Extract ID if full reference provided
    const id = patientId.replace('Patient/', '');
    
    const response = await fetch(`${FHIR_MCP_BASE_URL}/fhir/read`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            resourceType: 'Patient',
            id: id,
            elements: ['id', 'name', 'gender', 'birthDate', 'address', 'telecom']
        })
    });

    if (!response.ok) {
        throw new Error(`Failed to get patient: ${response.statusText}`);
    }

    const result = await response.json();
    
    if (result.content && result.content[0] && result.content[0].text) {
        return JSON.parse(result.content[0].text);
    }
    
    return result;
}

/**
 * Search for observations (lab results, vitals, etc.)
 * @param {string} patientId - Patient ID
 * @param {Object} options - Search options
 * @param {string} options.category - Observation category (vital-signs|laboratory|survey|etc.)
 * @param {string} options.code - LOINC or SNOMED code
 * @param {string} options.date - Date range (e.g., "ge2024-01-01")
 * @param {number} options.count - Max results
 * @returns {Promise<Object>} Observation search results
 */
async function searchObservations(patientId, options = {}) {
    const searchParams = {
        patient: `Patient/${patientId.replace('Patient/', '')}`,
        ...options
    };

    return await searchFhirResources('Observation', searchParams, 
        ['id', 'code', 'effectiveDateTime', 'valueQuantity', 'component', 'interpretation'], 
        options.count || 20);
}

/**
 * Get latest vital signs for a patient
 * @param {string} patientId - Patient ID
 * @returns {Promise<Object>} Latest vital signs
 */
async function getLatestVitals(patientId) {
    return await searchObservations(patientId, {
        category: 'vital-signs',
        _sort: '-date',
        _count: 5
    });
}

/**
 * Get latest lab results for a patient
 * @param {string} patientId - Patient ID
 * @param {string} date - Optional date filter (e.g., "ge2024-01-01")
 * @returns {Promise<Object>} Latest lab results
 */
async function getLatestLabResults(patientId, date = null) {
    const searchParams = {
        category: 'laboratory',
        _sort: '-date',
        _count: 10
    };
    
    if (date) {
        searchParams.date = date;
    }

    return await searchObservations(patientId, searchParams);
}

/**
 * Look up a clinical code meaning
 * @param {string} system - Code system URI (e.g., "http://loinc.org", "http://snomed.info/sct")
 * @param {string} code - The code to look up
 * @returns {Promise<Object>} Code information including display name and properties
 */
async function lookupCode(system, code) {
    const response = await fetch(`${FHIR_MCP_BASE_URL}/terminology/lookup`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            system,
            code
        })
    });

    if (!response.ok) {
        throw new Error(`Code lookup failed: ${response.statusText}`);
    }

    const result = await response.json();
    
    if (result.content && result.content[0] && result.content[0].text) {
        return JSON.parse(result.content[0].text);
    }
    
    return result;
}

/**
 * Expand a ValueSet to get all contained codes
 * @param {string} valueSetUrl - ValueSet canonical URL
 * @param {Object} options - Expansion options
 * @param {string} options.filter - Filter text
 * @param {number} options.count - Maximum codes to return
 * @returns {Promise<Object>} ValueSet expansion
 */
async function expandValueSet(valueSetUrl, options = {}) {
    const response = await fetch(`${FHIR_MCP_BASE_URL}/terminology/expand`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            url: valueSetUrl,
            ...options
        })
    });

    if (!response.ok) {
        throw new Error(`ValueSet expansion failed: ${response.statusText}`);
    }

    const result = await response.json();
    
    if (result.content && result.content[0] && result.content[0].text) {
        return JSON.parse(result.content[0].text);
    }
    
    return result;
}

/**
 * Get FHIR server capabilities
 * @returns {Promise<Object>} Server capabilities
 */
async function getFhirCapabilities() {
    const response = await fetch(`${FHIR_MCP_BASE_URL}/fhir/capabilities`, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({})
    });

    if (!response.ok) {
        throw new Error(`Failed to get capabilities: ${response.statusText}`);
    }

    const result = await response.json();
    
    if (result.content && result.content[0] && result.content[0].text) {
        return JSON.parse(result.content[0].text);
    }
    
    return result;
}

// Common LOINC codes for Copilot suggestions
const COMMON_LOINC_CODES = {
    // Vital Signs
    BLOOD_PRESSURE: '85354-9',
    HEART_RATE: '8867-4',
    RESPIRATORY_RATE: '9279-1',
    BODY_TEMPERATURE: '8310-5',
    OXYGEN_SATURATION: '2708-6',
    BODY_WEIGHT: '29463-7',
    BODY_HEIGHT: '8302-2',
    BMI: '39156-5',
    
    // Common Lab Tests
    HEMOGLOBIN: '718-7',
    HEMATOCRIT: '4544-3',
    GLUCOSE: '2345-7',
    HEMOGLOBIN_A1C: '4548-4',
    CHOLESTEROL_TOTAL: '2093-3',
    CHOLESTEROL_LDL: '2089-1',
    CHOLESTEROL_HDL: '2085-9',
    TRIGLYCERIDES: '2571-8',
    CREATININE: '2160-0'
};

// Export for use in other modules
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        searchFhirResources,
        searchPatients,
        getPatient,
        searchObservations,
        getLatestVitals,
        getLatestLabResults,
        lookupCode,
        expandValueSet,
        getFhirCapabilities,
        COMMON_LOINC_CODES
    };
}

// Example usage for Copilot training:
// 
// // Get patient demographics
// const patient = await getPatient("123");
// console.log(`Patient: ${patient.name?.[0]?.given?.[0]} (${patient.gender})`);
//
// // Search for patients by name
// const patients = await searchPatients({ name: "Smith" });
//
// // Get latest blood pressure
// const vitals = await searchObservations("123", {
//     code: COMMON_LOINC_CODES.BLOOD_PRESSURE,
//     _sort: "-date",
//     _count: 1
// });
//
// // Look up what a code means
// const codeInfo = await lookupCode("http://loinc.org", "29463-7");
// console.log(`Code meaning: ${codeInfo.display}`);