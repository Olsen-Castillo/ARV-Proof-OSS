import type { EvidenceProfileV1 } from './evidence-envelope-v1';

export const ARV_EVIDENCE_PROFILE_DEFINITIONS = {
  'arv.profile.generic-document.v1': {
    required_claims: []
  },
  'arv.profile.academic-credential.v1': {
    required_claims: ['issuer', 'holder', 'credential_type']
  },
  'arv.profile.contract.v1': {
    required_claims: ['contract_type', 'parties']
  },
  'arv.profile.property.v1': {
    required_claims: ['instrument_type', 'property_reference']
  },
  'arv.profile.media.v1': {
    required_claims: ['capture_context']
  },
  'arv.profile.dataset.v1': {
    required_claims: ['dataset_name']
  },
  'arv.profile.software.v1': {
    required_claims: ['software_name', 'version']
  }
} as const;

export type ARVEvidenceProfileId = keyof typeof ARV_EVIDENCE_PROFILE_DEFINITIONS;

export interface EvidenceProfileBoundaryResultV1 {
  supported: boolean;
  profile_id: string;
  missing_claims: string[];
}

function claimIsPresent(profile: EvidenceProfileV1, key: string): boolean {
  if (!Object.prototype.hasOwnProperty.call(profile.claims, key)) return false;
  const value = profile.claims[key];
  if (value === null) return false;
  if (typeof value === 'string' && value.trim().length === 0) return false;
  if (Array.isArray(value) && value.length === 0) return false;
  return true;
}

export function validateEvidenceProfileBoundaryV1(
  profile: EvidenceProfileV1
): EvidenceProfileBoundaryResultV1 {
  const definitions = ARV_EVIDENCE_PROFILE_DEFINITIONS as Record<
    string,
    { required_claims: readonly string[] }
  >;
  const definition = definitions[profile.id];

  if (!definition) {
    return {
      supported: false,
      profile_id: profile.id,
      missing_claims: []
    };
  }

  const missingClaims = definition.required_claims.filter(
    (claim) => !claimIsPresent(profile, claim)
  );

  return {
    supported: true,
    profile_id: profile.id,
    missing_claims: missingClaims
  };
}
