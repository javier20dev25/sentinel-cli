import { execSync } from 'child_process'

export interface NpmVulnerability {
  id: string
  packageName: string
  severity: string
  title: string
  cvssScore?: number
  cveId?: string
  fixAvailable?: string
  path: string[]
}

export interface NpmAuditResult {
  auditDate: string
  vulnerabilities: NpmVulnerability[]
  metadata: {
    totalDependencies: number
    totalVulnerabilities: number
    critical: number
    high: number
    medium: number
    low: number
  }
}

const SEVERITY_MAP: Record<string, string> = {
  critical: 'CRITICAL',
  high: 'HIGH',
  moderate: 'MEDIUM',
  medium: 'MEDIUM',
  low: 'LOW',
  info: 'INFO',
}

function mapSeverity(severity: string): string {
  return SEVERITY_MAP[severity.toLowerCase()] || severity.toUpperCase()
}

function extractCveId(advisory: any, via: any[]): string | undefined {
  if (advisory?.cve && Array.isArray(advisory.cve) && advisory.cve.length > 0) {
    return advisory.cve[0]
  }
  for (const item of via) {
    if (typeof item === 'string' && item.startsWith('CVE-')) {
      return item
    }
  }
  if (advisory?.url) {
    const match = advisory.url.match(/GHSA-[a-zA-Z0-9-]+$/)
    if (match) return match[0]
  }
  return undefined
}

function extractId(advisory: any, vuln: any): string {
  if (advisory?.url) {
    const match = advisory.url.match(/GHSA-[a-zA-Z0-9-]+$/)
    if (match) return match[0]
  }
  if (typeof vuln.id === 'number' || typeof vuln.id === 'string') {
    return String(vuln.id)
  }
  return 'unknown'
}

function formatFixAvailable(fix: any): string | undefined {
  if (!fix) return undefined
  if (typeof fix === 'object' && fix.name && fix.version) {
    return `${fix.name}@${fix.version}`
  }
  return undefined
}

function extractPath(via: any[]): string[] {
  const path: string[] = []
  for (const item of via) {
    if (typeof item === 'object' && item.name) {
      path.push(item.name)
    }
  }
  if (path.length === 0) {
    for (const item of via) {
      if (typeof item === 'string') {
        path.push(item)
      }
    }
  }
  return path
}

export class NpmAuditParser {
  async runAudit(): Promise<NpmAuditResult> {
    try {
      const result = execSync('npm audit --json', { shell: true as any, encoding: 'utf8' })
      const raw = JSON.parse(result)
      return this.parseAuditJson(raw)
    } catch (e: any) {
      if (e.stdout) {
        try {
          const raw = JSON.parse(e.stdout.toString())
          return this.parseAuditJson(raw)
        } catch {
          // fall through to throw
        }
      }
      throw e
    }
  }

  parseAuditJson(raw: any): NpmAuditResult {
    const vulns: NpmVulnerability[] = []
    const metadata = {
      totalDependencies: 0,
      totalVulnerabilities: 0,
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
    }

    if (!raw || typeof raw !== 'object') {
      return { auditDate: '', vulnerabilities: vulns, metadata }
    }

    if (raw.metadata) {
      metadata.totalDependencies = raw.metadata.dependencies || 0
      const vulnCounts = raw.metadata.vulnerabilities || {}
      metadata.critical = vulnCounts.critical || 0
      metadata.high = vulnCounts.high || 0
      metadata.medium = vulnCounts.moderate || vulnCounts.medium || 0
      metadata.low = vulnCounts.low || 0
    }

    const auditDate = raw.auditedAt || raw.metadata?.auditedAt || ''

    if (raw.vulnerabilities && typeof raw.vulnerabilities === 'object') {
      for (const [pkgName, entries] of Object.entries(raw.vulnerabilities)) {
        if (!Array.isArray(entries)) continue
        for (const entry of entries) {
          if (!entry || typeof entry !== 'object') continue
          const advisory = entry.advisory || {}
          const via = entry.via || []
          vulns.push({
            id: extractId(advisory, entry),
            packageName: pkgName,
            severity: mapSeverity(entry.severity || 'unknown'),
            title: entry.title || 'No title',
            cvssScore: entry.cvss?.score !== undefined ? entry.cvss.score : undefined,
            cveId: extractCveId(advisory, via),
            fixAvailable: formatFixAvailable(entry.fixAvailable),
            path: extractPath(via),
          })
        }
      }
    }

    metadata.totalVulnerabilities = vulns.length

    return { auditDate, vulnerabilities: vulns, metadata }
  }

  mockData(): NpmAuditResult {
    return {
      auditDate: '2026-06-05T08:00:00.000Z',
      vulnerabilities: [
        {
          id: 'GHSA-xxxx-xxxx-xxxx',
          packageName: 'lodash',
          severity: 'CRITICAL',
          title: 'Prototype Pollution in lodash',
          cvssScore: 9.1,
          cveId: 'CVE-2024-1234',
          fixAvailable: 'lodash@4.17.21',
          path: ['lodash'],
        },
        {
          id: 'GHSA-yyyy-yyyy-yyyy',
          packageName: 'express',
          severity: 'HIGH',
          title: 'Directory Traversal in express',
          cvssScore: 7.5,
          cveId: 'CVE-2024-5678',
          fixAvailable: undefined,
          path: ['express'],
        },
        {
          id: 'GHSA-zzzz-zzzz-zzzz',
          packageName: 'minimatch',
          severity: 'MEDIUM',
          title: 'ReDoS in minimatch',
          cvssScore: 5.3,
          cveId: undefined,
          fixAvailable: 'minimatch@5.1.6',
          path: ['minimatch'],
        },
      ],
      metadata: {
        totalDependencies: 150,
        totalVulnerabilities: 3,
        critical: 1,
        high: 1,
        medium: 1,
        low: 0,
      },
    }
  }
}
