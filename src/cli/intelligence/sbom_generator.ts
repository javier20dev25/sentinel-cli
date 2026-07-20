import { LockfileParser, LockfileEntry } from './lockfile_parser'
import { OSVIntegrator, OSVVuln } from './osv_integrator'

export interface SbomComponent {
  type: string
  name: string
  version: string
  purl: string
  properties?: { name: string, value: string }[]
}

export interface SbomResult {
  format: string
  bomFormat: string
  specVersion: string
  serialNumber: string
  version: number
  metadata: any
  components: SbomComponent[]
}

export class SbomGenerator {
  private parser: LockfileParser

  constructor() {
    this.parser = new LockfileParser()
  }

  generate(lockfilePath: string): SbomResult {
    const result = this.parser.parse(lockfilePath)
    return this.generateFromEntries(result.entries, result.format)
  }

  generateFromEntries(entries: LockfileEntry[], format: string): SbomResult {
    return this.toCycloneDx(entries)
  }

  toCycloneDx(entries: LockfileEntry[]): SbomResult {
    const components: SbomComponent[] = entries.map(entry => {
      const component: SbomComponent = {
        type: 'library',
        name: entry.name,
        version: entry.version,
        purl: this.toPurl(entry.name, entry.version),
      }
      if (entry.integrity) {
        component.properties = [
          { name: 'integrity', value: entry.integrity },
        ]
      }
      return component
    })

    return {
      format: 'cyclonedx',
      bomFormat: 'CycloneDX',
      specVersion: '1.5',
      serialNumber: this.generateSerial(),
      version: 1,
      metadata: {
        timestamp: new Date().toISOString(),
        tools: [
          { name: 'sentinel-cli', vendor: 'Sentinel' },
        ],
      },
      components,
    }
  }

  toPurl(name: string, version: string): string {
    const encoded = name.replace(/^@/, '%40')
    return `pkg:npm/${encoded}@${version}`
  }

  private generateSerial(): string {
    const hex = (len: number) =>
      Array.from({ length: len }, () => Math.floor(Math.random() * 16).toString(16)).join('')
    return `urn:uuid:${hex(8)}-${hex(4)}-4${hex(3)}-${hex(4)}-${hex(12)}`
  }
}

export interface CveReference {
  id: string;
  severity: string;
  score: number;
  summary: string;
  affectedVersions: string;
  fixedIn?: string;
}

function dbSeverityToSentinel(dbSev: string): string {
  const upper = dbSev.toUpperCase();
  if (upper === 'CRITICAL') return 'CRITICAL';
  if (upper === 'HIGH') return 'HIGH';
  if (upper === 'MODERATE' || upper === 'MEDIUM') return 'MEDIUM';
  if (upper === 'LOW') return 'LOW';
  return 'MEDIUM';
}

function extractAffectedVersions(vuln: OSVVuln, fallbackVersion: string): { affectedVersions: string; fixedIn?: string } {
  if (!vuln.affected || vuln.affected.length === 0) {
    return { affectedVersions: fallbackVersion };
  }

  let fixedIn: string | undefined;
  const rangeStrs: string[] = [];

  for (const aff of vuln.affected) {
    if (!aff.ranges) continue;
    for (const range of aff.ranges) {
      if (range.type !== 'ECOSYSTEM' || !range.events) continue;
      const parts: string[] = [];
      for (const event of range.events) {
        if (event.introduced !== undefined) parts.push(`>= ${event.introduced}`);
        if (event.fixed !== undefined) { parts.push(`< ${event.fixed}`); fixedIn = event.fixed; }
        if (event.last_affected !== undefined) parts.push(`<= ${event.last_affected}`);
        if (event.limit !== undefined) parts.push(`< ${event.limit}`);
      }
      if (parts.length > 0) rangeStrs.push(parts.join(', '));
    }
  }

  return {
    affectedVersions: rangeStrs.length > 0 ? rangeStrs.join(' || ') : fallbackVersion,
    fixedIn,
  };
}

export function enrichSbomWithCves(sbom: any, osvResults: any[] | null | undefined): any {
  if (!osvResults || osvResults.length === 0) {
    return JSON.parse(JSON.stringify(sbom));
  }
  const enriched = JSON.parse(JSON.stringify(sbom));

  enriched.components = enriched.components.map((component: any) => {
    const osvResult = osvResults.find(
      (r: any) => r.packageName === component.name && r.version === component.version
    );

    if (osvResult && osvResult.vulnerabilities && osvResult.vulnerabilities.length > 0) {
      component.vulnerabilities = osvResult.vulnerabilities.map((v: OSVVuln) => {
        const maxSeverity = OSVIntegrator.getMaxSeverity(v);
        const score = maxSeverity ? maxSeverity.score : 0;
        const severity = maxSeverity
          ? OSVIntegrator.toSentinelSeverity(maxSeverity.score)
          : (v.database_specific?.severity
              ? dbSeverityToSentinel(v.database_specific.severity)
              : 'MEDIUM');

        const { affectedVersions, fixedIn } = extractAffectedVersions(v, component.version);

        return {
          id: v.id,
          severity,
          score,
          summary: v.summary || '',
          affectedVersions,
          ...(fixedIn !== undefined ? { fixedIn } : {}),
        };
      });
    }

    return component;
  });

  return enriched;
}
