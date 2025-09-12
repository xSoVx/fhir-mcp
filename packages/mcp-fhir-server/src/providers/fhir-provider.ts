import axios, { AxiosInstance } from 'axios';
import { FhirResource, FhirBundle, FhirCapabilityStatement, FhirSearchParams } from '../types/fhir.js';

export class FhirProvider {
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

  async getCapabilities(): Promise<FhirCapabilityStatement> {
    const response = await this.client.get('/metadata');
    return response.data;
  }

  async search(
    resourceType: string, 
    params: FhirSearchParams = {}, 
    elements?: string[], 
    count?: number, 
    sort?: string
  ): Promise<FhirBundle> {
    const searchParams = new URLSearchParams();
    
    // Add search parameters
    Object.entries(params).forEach(([key, value]) => {
      if (Array.isArray(value)) {
        value.forEach(v => searchParams.append(key, v));
      } else {
        searchParams.append(key, value);
      }
    });

    // Add _elements for field selection
    if (elements && elements.length > 0) {
      searchParams.append('_elements', elements.join(','));
    }

    // Add _count for pagination
    if (count) {
      searchParams.append('_count', count.toString());
    }

    // Add _sort for ordering
    if (sort) {
      searchParams.append('_sort', sort);
    }

    // Add _summary=data for token efficiency when elements not specified
    if (!elements || elements.length === 0) {
      searchParams.append('_summary', 'data');
    }

    const response = await this.client.get(`/${resourceType}?${searchParams.toString()}`);
    return response.data;
  }

  async read(resourceType: string, id: string, elements?: string[]): Promise<FhirResource> {
    let url = `/${resourceType}/${id}`;
    
    if (elements && elements.length > 0) {
      url += `?_elements=${elements.join(',')}`;
    }

    const response = await this.client.get(url);
    return response.data;
  }

  async create(resourceType: string, resource: FhirResource): Promise<FhirResource> {
    const response = await this.client.post(`/${resourceType}`, resource);
    return response.data;
  }

  async update(resourceType: string, id: string, resource: FhirResource, versionId?: string): Promise<FhirResource> {
    const headers: Record<string, string> = {};
    if (versionId) {
      headers['If-Match'] = `W/"${versionId}"`;
    }

    const response = await this.client.put(`/${resourceType}/${id}`, resource, { headers });
    return response.data;
  }
}