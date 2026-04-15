/**
 * Normalization algorithm — converts X.509 Subject DN fields to did:pki path segments.
 * Implements spec §7 (Derivation Algorithm).
 *
 * The algorithm uses BOTH the Organization (O) and Common Name (CN) fields:
 * - O determines the first path segment (unless it's a country PKI authority)
 * - CN provides qualifier segments (with O's name removed to avoid duplication)
 */

const TRANSLITERATION: Record<string, string> = {
  'á': 'a', 'é': 'e', 'í': 'i', 'ó': 'o', 'ú': 'u',
  'à': 'a', 'è': 'e', 'ì': 'i', 'ò': 'o', 'ù': 'u',
  'â': 'a', 'ê': 'e', 'î': 'i', 'ô': 'o', 'û': 'u',
  'ä': 'a', 'ë': 'e', 'ï': 'i', 'ö': 'o', 'ü': 'u',
  'ã': 'a', 'õ': 'o',
  'ñ': 'n', 'ç': 'c', 'ß': 'ss',
  'ø': 'o', 'å': 'a', 'æ': 'ae',
};

const CA_PREFIXES = ['ca ', 'ac '];

const COUNTRY_SUFFIXES = [
  'costa rica', 'brasil', 'brazil', 'españa', 'spain',
  'mexico', 'méxico', 'colombia', 'chile', 'argentina',
  'peru', 'perú', 'ecuador', 'uruguay', 'panama', 'panamá',
  'el salvador', 'guatemala', 'honduras', 'nicaragua',
  'united states', 'deutschland', 'germany', 'france', 'italia', 'italy',
];

const SEPARATOR_PATTERNS = [' - ', ' / ', ' – ', ' — '];

/**
 * Known hierarchy level keywords that act as segment boundaries.
 * When these words appear at the start of a cleaned CN followed by a space,
 * they form their own segment.
 */
const LEVEL_KEYWORDS = ['politica'];

/** Version suffix pattern: " v2", " v10", etc. at end of string */
const VERSION_SUFFIX = /\s+v\d+$/i;

/** Generation suffix pattern: " G2", " G3", etc. at end of string */
const GENERATION_SUFFIX = /\s+g\d+$/i;

/**
 * Organization names that represent the country PKI authority itself.
 * When O matches one of these, it is OMITTED from the path (the CN alone
 * provides the path segments). Normalized to lowercase for comparison.
 */
const COUNTRY_AUTHORITIES: Record<string, string[]> = {
  cr: [
    'bccr',
    'banco central de costa rica',
    'micitt',
    'ministerio de ciencia, innovacion, tecnologia y telecomunicaciones',
    'persona juridica',   // generic org name used in agente electronico certs
    'persona fisica',     // generic org name used in some end-entity patterns
  ],
  us: ['u.s. government', 'us government'],
  br: ['instituto nacional de tecnologia da informacao', 'iti'],
};

/**
 * Corporate/legal suffixes to strip from Organization names.
 * These are common in European PKI orgs (e.g., "FNMT-RCM", "D-Trust GmbH").
 */
const ORG_SUFFIXES = [
  '-rcm',    // FNMT-RCM (Real Casa de la Moneda)
  ' s.a.', ' sa', ' s.a',
  ' gmbh',
  ' inc.', ' inc',
  ' ltd.', ' ltd',
  ' sas',
  ' as',     // SK ID Solutions AS
  ' ag',
];

/**
 * Well-known abbreviations for PKI programs.
 * Maps normalized org/program names to their canonical short form.
 */
const KNOWN_ABBREVIATIONS: Record<string, string> = {
  'icp-brasil': 'icp',
  'federal pki': 'fpki',
  'federal bridge': 'fpki',
};

/**
 * Transliterate a UTF-8 string to ASCII.
 */
function transliterate(input: string): string {
  let result = '';
  for (const char of input) {
    const lower = char.toLowerCase();
    result += TRANSLITERATION[lower] ?? (lower.charCodeAt(0) > 127 ? '' : char);
  }
  return result;
}

/**
 * Basic string normalization: transliterate, lowercase, trim.
 */
function normalizeString(input: string): string {
  return transliterate(input).toLowerCase().trim();
}

/**
 * Normalize an Organization (O) field value to a single path segment.
 * Strips corporate suffixes and applies known abbreviations.
 */
function normalizeOrg(org: string): string {
  let value = normalizeString(org);

  // Check for known abbreviations first
  for (const [pattern, abbrev] of Object.entries(KNOWN_ABBREVIATIONS)) {
    if (value === pattern || value.startsWith(pattern + ' ')) {
      return abbrev;
    }
  }

  // Strip corporate/legal suffixes
  for (const suffix of ORG_SUFFIXES) {
    if (value.endsWith(suffix)) {
      value = value.slice(0, -suffix.length).trim();
      break;
    }
  }

  // kebab-case
  return value
    .replace(/\s+/g, '-')
    .replace(/--+/g, '-')
    .replace(/^-|-$/g, '');
}

/**
 * Check if an Organization value represents the country's PKI authority.
 * When true, the O field is omitted from the DID path.
 */
function isCountryAuthority(countryCode: string, org: string): boolean {
  const authorities = COUNTRY_AUTHORITIES[countryCode.toLowerCase()];
  if (!authorities) return false;

  const normalized = normalizeString(org);
  return authorities.some(a => normalized === a || normalized.startsWith(a));
}

/**
 * Remove the Organization name from a CN value to avoid duplication.
 * E.g., CN="AC RAIZ FNMT-RCM" with O="FNMT-RCM" → removes "FNMT-RCM" from CN → "AC RAIZ".
 */
function removeOrgFromCN(cn: string, org: string): string {
  const orgNorm = normalizeString(org);
  const cnLower = cn.toLowerCase();

  // Try patterns in order of specificity:
  // 1. Full org as-is (e.g., "fnmt-rcm", "icp-brasil")
  // 2. Full org with hyphens→spaces (e.g., "fnmt rcm")
  // 3. First word of org (e.g., "fnmt")
  const orgAsIs = orgNorm;
  const orgBase = orgNorm.replace(/-/g, ' ');
  const orgFirstWord = orgNorm.split(/[-\s]/)[0];

  const patterns = [orgAsIs, orgBase, orgFirstWord].filter(
    (p, i, arr) => p && p.length >= 2 && arr.indexOf(p) === i
  );

  for (const pattern of patterns) {
    const idx = cnLower.indexOf(pattern);
    if (idx >= 0) {
      cn = cn.slice(0, idx) + cn.slice(idx + pattern.length);
      // Clean up surrounding whitespace, hyphens, separators
      cn = cn
        .replace(/^\s*[-–—/]\s*/, '')
        .replace(/\s*[-–—/]\s*$/, '')
        .replace(/\s{2,}/g, ' ')
        .trim();
      break;
    }
  }

  return cn;
}

/**
 * Normalize a CN value into path segments (after org has been extracted).
 */
function processCN(cn: string): string[] {
  let value = cn;

  // 1. Remove version suffix (e.g., " v2")
  value = value.replace(VERSION_SUFFIX, '');

  // 2. Remove generation suffix (e.g., " G2")
  value = value.replace(GENERATION_SUFFIX, '');

  // 3. Transliterate to ASCII
  value = transliterate(value);

  // 4. Convert to lowercase
  value = value.toLowerCase();

  // 5. Remove CA prefixes
  for (const prefix of CA_PREFIXES) {
    if (value.startsWith(prefix)) {
      value = value.slice(prefix.length);
      break;
    }
  }

  // 6. Remove country suffixes (with separator)
  for (const country of COUNTRY_SUFFIXES) {
    for (const sep of [' - ', ' de ', ' of ', ' del ']) {
      const suffix = sep + country;
      if (value.endsWith(suffix)) {
        value = value.slice(0, -suffix.length);
        break;
      }
    }
  }

  // 7. Split on hierarchy level keywords
  for (const kw of LEVEL_KEYWORDS) {
    if (value.startsWith(kw + ' ')) {
      value = kw + ' - ' + value.slice(kw.length + 1);
      break;
    }
  }

  // 8. Split on known separators
  let segments: string[] = [value];
  for (const sep of SEPARATOR_PATTERNS) {
    segments = segments.flatMap(s => s.split(sep));
  }

  // 9. Normalize each segment: whitespace → hyphen, clean up
  return segments
    .map(s => s.trim())
    .filter(s => s.length > 0)
    .map(s =>
      s
        .replace(/\s+/g, '-')
        .replace(/--+/g, '-')
        .replace(/^-|-$/g, '')
    )
    .filter(s => s.length > 0);
}

/**
 * Normalize a certificate Subject CN into did:pki ca-path segments.
 * This is the CN-only path (used when O is absent or is a country authority).
 *
 * @param cn - The Common Name field from the X.509 Subject DN
 * @returns Array of normalized path segments (e.g., ['sinpe', 'persona-fisica'])
 */
export function normalizeCN(cn: string): string[] {
  return processCN(cn);
}

/**
 * Derive did:pki ca-path segments from both O and CN fields.
 * This is the full derivation algorithm per spec §7.
 *
 * @param countryCode - ISO 3166-1 alpha-2 code (lowercase)
 * @param cn - Common Name from Subject DN
 * @param org - Organization from Subject DN (optional)
 * @returns Array of path segments
 */
export function derivePathSegments(
  countryCode: string,
  cn: string,
  org?: string,
): string[] {
  // If no O field, or O is a country authority → CN-only derivation
  if (!org || isCountryAuthority(countryCode, org)) {
    return processCN(cn);
  }

  // O field present and is NOT the country authority:
  // 1. Normalize O → first segment
  const orgSegment = normalizeOrg(org);

  // 2. Remove O's name from CN to avoid duplication
  const cleanedCN = removeOrgFromCN(cn, org);

  // 3. Process cleaned CN → qualifier segments
  const cnSegments = processCN(cleanedCN);

  // 4. Combine: org segment + CN segments
  if (cnSegments.length === 0) {
    return [orgSegment];
  }

  return [orgSegment, ...cnSegments];
}

/**
 * Derive a did:pki identifier from an X.509 CA certificate's Subject DN.
 *
 * @param countryCode - ISO 3166-1 alpha-2 (from cert's C field)
 * @param cn - Common Name from Subject DN
 * @param org - Organization from Subject DN (optional)
 * @returns The full did:pki string
 */
export function deriveDid(
  countryCode: string,
  cn: string,
  org?: string,
): string {
  const cc = countryCode.toLowerCase();
  const segments = derivePathSegments(cc, cn, org);
  return `did:pki:${cc}:${segments.join(':')}`;
}

/**
 * Given a Subject CN (and optionally O), derive the ca-path key for registry lookup.
 *
 * @returns Colon-joined path segments (e.g., "sinpe:persona-fisica")
 */
export function derivePathKey(cn: string, org?: string, countryCode?: string): string {
  if (org && countryCode) {
    return derivePathSegments(countryCode, cn, org).join(':');
  }
  return normalizeCN(cn).join(':');
}
