import type { CountryConfig } from './types.js';

/**
 * Country-specific metadata for building pkiMetadata in DID Documents.
 * This is the only configuration file — add new countries here.
 */
export const COUNTRY_CONFIGS: Record<string, CountryConfig> = {
  cr: {
    countryCode: 'CR',
    countryName: 'Costa Rica',
    hierarchy: 'Jerarquía Nacional de Certificadores Registrados',
    administrator: 'Banco Central de Costa Rica (BCCR)',
    supervisor: 'Dirección de Gobernanza Digital (MICITT)',
    endEntityHints: {
      'persona-fisica': {
        nationalIdField: 'serialNumber',
        nationalIdFormat: 'CR-cedula',
        nationalIdPattern: '^[0-9]{9,12}$',
        nameField: 'CN',
        emailField: 'SAN:rfc822Name',
        professionalIdField: 'OU',
        documentationUrl: 'https://www.bccr.fi.cr/firma-digital/certificados-de-personas-f%C3%ADsicas',
      },
      'persona-juridica': {
        nationalIdField: 'serialNumber',
        nationalIdFormat: 'CR-cedula-juridica',
        nationalIdPattern: '^[0-9]{10}$',
        nameField: 'CN',
        organizationField: 'O',
        emailField: 'SAN:rfc822Name',
        documentationUrl: 'https://www.bccr.fi.cr/firma-digital/certificados-de-personas-jur%C3%ADdicas',
      },
    },
  },
};

/** Get country config or return a minimal default */
export function getCountryConfig(countryCode: string): CountryConfig {
  return COUNTRY_CONFIGS[countryCode.toLowerCase()] ?? {
    countryCode: countryCode.toUpperCase(),
    countryName: countryCode.toUpperCase(),
    hierarchy: 'National PKI',
    administrator: 'Unknown',
  };
}
