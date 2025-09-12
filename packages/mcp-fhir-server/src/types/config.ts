export interface FhirMcpConfig {
  fhir: {
    baseUrl: string;
    bearerToken?: string;
  };
  terminology: {
    baseUrl: string;
    bearerToken?: string;
  };
  security: {
    phiMode: 'safe' | 'trusted';
    enableAudit: boolean;
  };
}

export interface AuthConfig {
  flow: 'authorization_code' | 'client_credentials';
  clientId?: string;
  authUrl?: string;
  tokenUrl?: string;
  scopes?: string[];
}

export interface PhiGuardConfig {
  mode: 'safe' | 'trusted';
  maskFields: string[];
  removeFields: string[];
}