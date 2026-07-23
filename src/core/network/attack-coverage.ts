import * as fs from 'fs'
import * as path from 'path'

export interface AttackTechnique {
  id: string
  name: string
  tactic: string
  platform: string[]
  severity: 'critical' | 'high' | 'medium' | 'low'
  description: string
}

export interface CoverageEntry {
  techniqueId: string
  status: 'covered' | 'partial' | 'not_covered' | 'planned'
  detectionRules: string[]
  attackScenarios: string[]
  atomicTests: string[]
  confidence: number
  lastVerified: number
  notes: string
}

export interface AttackCoverageMatrix {
  version: string
  generatedAt: number
  techniques: AttackTechnique[]
  coverage: CoverageEntry[]
  summary: CoverageSummary
}

export interface CoverageSummary {
  totalTechniques: number
  covered: number
  partial: number
  notCovered: number
  planned: number
  coveragePercent: number
  byTactic: Record<string, { total: number; covered: number }>
  byPlatform: Record<string, { total: number; covered: number }>
  bySeverity: Record<string, { total: number; covered: number }>
  missingCritical: string[]
  missingHigh: string[]
}

const COVERAGE_FILE = path.join(process.cwd(), 'attack-coverage.json')

export const MITRE_TACTICS = [
  'initial-access',
  'execution',
  'persistence',
  'privilege-escalation',
  'defense-evasion',
  'credential-access',
  'discovery',
  'lateral-movement',
  'collection',
  'exfiltration',
  'command-and-control',
  'impact',
  'resource-development',
  'reconnaissance',
]

export const ATTACK_TECHNIQUES: AttackTechnique[] = [
  // Defense Evasion
  { id: 'T1055', name: 'Process Injection', tactic: 'defense-evasion', platform: ['windows'], severity: 'critical', description: 'Inject code into running processes' },
  { id: 'T1055.001', name: 'DLL Injection', tactic: 'defense-evasion', platform: ['windows'], severity: 'critical', description: 'Inject malicious DLLs' },
  { id: 'T1055.012', name: 'Process Hollowing', tactic: 'defense-evasion', platform: ['windows'], severity: 'critical', description: 'Hollow out legitimate process' },
  { id: 'T1562.001', name: 'Disable Windows Event Logging', tactic: 'defense-evasion', platform: ['windows'], severity: 'critical', description: 'Disable event logging' },
  { id: 'T1562.006', name: 'Indicator Blocking', tactic: 'defense-evasion', platform: ['windows'], severity: 'critical', description: 'Block security indicators' },
  { id: 'T1218', name: 'System Binary Proxy Execution', tactic: 'defense-evasion', platform: ['windows'], severity: 'high', description: 'LOLBin execution' },
  { id: 'T1218.011', name: 'Rundll32', tactic: 'defense-evasion', platform: ['windows'], severity: 'high', description: 'Rundll32 proxy execution' },
  { id: 'T1070.004', name: 'File Deletion', tactic: 'defense-evasion', platform: ['windows', 'linux'], severity: 'medium', description: 'Delete files to hide tracks' },
  { id: 'T1140', name: 'Deobfuscate Files', tactic: 'defense-evasion', platform: ['windows', 'linux'], severity: 'medium', description: 'Deobfuscate encoded files' },
  
  // Execution
  { id: 'T1059.004', name: 'Unix Shell', tactic: 'execution', platform: ['linux', 'macos'], severity: 'high', description: 'Shell command execution' },
  { id: 'T1059.006', name: 'Python', tactic: 'execution', platform: ['windows', 'linux'], severity: 'medium', description: 'Python script execution' },
  { id: 'T1059.007', name: 'JavaScript', tactic: 'execution', platform: ['windows', 'linux'], severity: 'medium', description: 'JavaScript execution' },
  { id: 'T1204.002', name: 'Malicious File', tactic: 'execution', platform: ['windows', 'linux'], severity: 'high', description: 'User execution of malicious file' },
  
  // Persistence
  { id: 'T1574.006', name: 'Dynamic Linker Hijacking', tactic: 'persistence', platform: ['linux'], severity: 'critical', description: 'LD_PRELOAD injection' },
  { id: 'T1574.007', name: 'Path Interception', tactic: 'persistence', platform: ['windows'], severity: 'high', description: 'PATH manipulation' },
  { id: 'T1546', name: 'Event Triggered Execution', tactic: 'persistence', platform: ['windows'], severity: 'high', description: 'Triggered execution' },
  
  // Credential Access
  { id: 'T1552.001', name: 'Credentials In Files', tactic: 'credential-access', platform: ['windows', 'linux'], severity: 'critical', description: 'Credentials stored in files' },
  
  // Exfiltration
  { id: 'T1071.004', name: 'DNS', tactic: 'exfiltration', platform: ['windows', 'linux'], severity: 'high', description: 'DNS-based exfiltration' },
  { id: 'T1570', name: 'Lateral Tool Transfer', tactic: 'lateral-movement', platform: ['windows'], severity: 'medium', description: 'Tool transfer via named pipes' },
  
  // Collection
  { id: 'T1005', name: 'Data from Local System', tactic: 'collection', platform: ['windows', 'linux'], severity: 'high', description: 'Collect local data' },
  
  // Supply Chain
  { id: 'T1195.002', name: 'Compromise Software Supply Chain', tactic: 'initial-access', platform: ['windows', 'linux'], severity: 'critical', description: 'Supply chain compromise' },
  
  // Discovery
  { id: 'T1082', name: 'System Information Discovery', tactic: 'discovery', platform: ['windows', 'linux'], severity: 'low', description: 'System info gathering' },
  { id: 'T1083', name: 'File and Directory Discovery', tactic: 'discovery', platform: ['windows', 'linux'], severity: 'low', description: 'File/directory enumeration' },
  
  // Impact
  { id: 'T1565.001', name: 'Stored Data Manipulation', tactic: 'impact', platform: ['windows', 'linux'], severity: 'critical', description: 'Data manipulation' },
]

export const SENTINEL_COVERAGE: CoverageEntry[] = [
  // Defense Evasion - COVERED
  { techniqueId: 'T1055', status: 'covered', detectionRules: ['DR-007', 'DR-013'], attackScenarios: ['ATK-008'], atomicTests: ['art-t1055-dll'], confidence: 0.9, lastVerified: Date.now(), notes: 'DLL injection via CreateRemoteThread' },
  { techniqueId: 'T1055.001', status: 'covered', detectionRules: ['DR-007', 'DR-013'], attackScenarios: ['ATK-008'], atomicTests: ['art-t1055-dll'], confidence: 0.9, lastVerified: Date.now(), notes: 'DLL injection detection' },
  { techniqueId: 'T1055.012', status: 'covered', detectionRules: ['DR-013'], attackScenarios: ['ATK-013'], atomicTests: ['art-t1055-hollow'], confidence: 0.85, lastVerified: Date.now(), notes: 'Process hollowing detection' },
  { techniqueId: 'T1562.001', status: 'covered', detectionRules: ['DR-014'], attackScenarios: ['ATK-002'], atomicTests: ['art-t1562-eventlog'], confidence: 0.8, lastVerified: Date.now(), notes: 'Event logging disable detection' },
  { techniqueId: 'T1562.006', status: 'covered', detectionRules: ['DR-014'], attackScenarios: ['ATK-002'], atomicTests: ['art-t1562-etw'], confidence: 0.85, lastVerified: Date.now(), notes: 'ETW patching detection' },
  { techniqueId: 'T1218', status: 'covered', detectionRules: ['DR-002'], attackScenarios: ['ATK-010'], atomicTests: ['art-t1218-msbuild'], confidence: 0.75, lastVerified: Date.now(), notes: 'LOLBin detection' },
  { techniqueId: 'T1218.011', status: 'covered', detectionRules: ['DR-002'], attackScenarios: ['ATK-010'], atomicTests: ['art-t1218-rundll32'], confidence: 0.7, lastVerified: Date.now(), notes: 'Rundll32 detection' },
  { techniqueId: 'T1070.004', status: 'covered', detectionRules: ['DR-004'], attackScenarios: ['ATK-011'], atomicTests: ['art-t1070-delete'], confidence: 0.65, lastVerified: Date.now(), notes: 'File deletion detection' },
  
  // Execution - COVERED
  { techniqueId: 'T1059.004', status: 'covered', detectionRules: ['DR-001', 'DR-003'], attackScenarios: ['ATK-016'], atomicTests: ['art-t1059-shell'], confidence: 0.7, lastVerified: Date.now(), notes: 'npm postinstall detection' },
  { techniqueId: 'T1059.006', status: 'covered', detectionRules: ['DR-001'], attackScenarios: ['ATK-017', 'ATK-020'], atomicTests: ['art-t1059-python'], confidence: 0.65, lastVerified: Date.now(), notes: 'Python/Gradle/Maven detection' },
  { techniqueId: 'T1059.007', status: 'covered', detectionRules: ['DR-001'], attackScenarios: ['ATK-018', 'ATK-019'], atomicTests: ['art-t1059-rust'], confidence: 0.65, lastVerified: Date.now(), notes: 'Rust/Cargo/MSBuild detection' },
  
  // Persistence - COVERED
  { techniqueId: 'T1574.006', status: 'covered', detectionRules: ['DR-002', 'DR-007'], attackScenarios: ['ATK-005'], atomicTests: ['art-t1574-ldpreload'], confidence: 0.9, lastVerified: Date.now(), notes: 'LD_PRELOAD injection detection' },
  { techniqueId: 'T1574.007', status: 'partial', detectionRules: ['DR-002'], attackScenarios: ['ATK-003'], atomicTests: ['art-t1574-path'], confidence: 0.6, lastVerified: Date.now(), notes: 'PATH hijacking - needs more testing' },
  
  // Credential Access - COVERED
  { techniqueId: 'T1552.001', status: 'covered', detectionRules: ['DR-003', 'DR-008'], attackScenarios: ['ATK-024'], atomicTests: ['art-t1552-secrets'], confidence: 0.85, lastVerified: Date.now(), notes: 'GitHub Actions secret exfil detection' },
  
  // Exfiltration - COVERED
  { techniqueId: 'T1071.004', status: 'covered', detectionRules: ['DR-003', 'DR-010'], attackScenarios: ['ATK-007'], atomicTests: ['art-t1071-doh'], confidence: 0.8, lastVerified: Date.now(), notes: 'DoH exfiltration detection' },
  { techniqueId: 'T1570', status: 'covered', detectionRules: ['DR-011'], attackScenarios: ['ATK-006'], atomicTests: ['art-t1570-pipes'], confidence: 0.7, lastVerified: Date.now(), notes: 'Named pipe detection' },
  
  // Supply Chain - COVERED
  { techniqueId: 'T1195.002', status: 'covered', detectionRules: ['DR-001', 'DR-003', 'DR-008'], attackScenarios: ['ATK-016', 'ATK-017', 'ATK-018', 'ATK-019', 'ATK-020', 'ATK-023', 'ATK-026'], atomicTests: ['art-t1195-supply'], confidence: 0.75, lastVerified: Date.now(), notes: 'Supply chain attacks' },
  
  // Collection - PARTIAL
  { techniqueId: 'T1005', status: 'partial', detectionRules: ['DR-004'], attackScenarios: [], atomicTests: [], confidence: 0.5, lastVerified: Date.now(), notes: 'Basic file collection detection' },
  
  // Discovery - NOT COVERED
  { techniqueId: 'T1082', status: 'not_covered', detectionRules: [], attackScenarios: [], atomicTests: [], confidence: 0, lastVerified: 0, notes: 'System info discovery not yet covered' },
  { techniqueId: 'T1083', status: 'not_covered', detectionRules: [], attackScenarios: [], atomicTests: [], confidence: 0, lastVerified: 0, notes: 'File enumeration not yet covered' },
  
  // Impact - PLANNED
  { techniqueId: 'T1565.001', status: 'planned', detectionRules: [], attackScenarios: ['ATK-012'], atomicTests: ['art-t1565-poison'], confidence: 0, lastVerified: 0, notes: 'ML poisoning - future work' },
]

export function generateCoverageMatrix(): AttackCoverageMatrix {
  const coverageMap = new Map<string, CoverageEntry>()
  for (const entry of SENTINEL_COVERAGE) {
    coverageMap.set(entry.techniqueId, entry)
  }
  
  const coverage: CoverageEntry[] = ATTACK_TECHNIQUES.map(tech => {
    const existing = coverageMap.get(tech.id)
    return existing || {
      techniqueId: tech.id,
      status: 'not_covered' as const,
      detectionRules: [],
      attackScenarios: [],
      atomicTests: [],
      confidence: 0,
      lastVerified: 0,
      notes: 'Not yet covered',
    }
  })
  
  const summary = computeCoverageSummary(ATTACK_TECHNIQUES, coverage)
  
  return {
    version: '1.0.0',
    generatedAt: Date.now(),
    techniques: ATTACK_TECHNIQUES,
    coverage,
    summary,
  }
}

export function computeCoverageSummary(
  techniques: AttackTechnique[],
  coverage: CoverageEntry[]
): CoverageSummary {
  const coverageMap = new Map<string, CoverageEntry>()
  for (const entry of coverage) {
    coverageMap.set(entry.techniqueId, entry)
  }
  
  let covered = 0
  let partial = 0
  let notCovered = 0
  let planned = 0
  
  const byTactic: Record<string, { total: number; covered: number }> = {}
  const byPlatform: Record<string, { total: number; covered: number }> = {}
  const bySeverity: Record<string, { total: number; covered: number }> = {}
  const missingCritical: string[] = []
  const missingHigh: string[] = []
  
  for (const tech of techniques) {
    const entry = coverageMap.get(tech.id)
    const status = entry?.status || 'not_covered'
    
    if (status === 'covered') covered++
    else if (status === 'partial') partial++
    else if (status === 'planned') planned++
    else notCovered++
    
    // By tactic
    if (!byTactic[tech.tactic]) {
      byTactic[tech.tactic] = { total: 0, covered: 0 }
    }
    byTactic[tech.tactic].total++
    if (status === 'covered' || status === 'partial') {
      byTactic[tech.tactic].covered++
    }
    
    // By platform
    for (const plat of tech.platform) {
      if (!byPlatform[plat]) {
        byPlatform[plat] = { total: 0, covered: 0 }
      }
      byPlatform[plat].total++
      if (status === 'covered' || status === 'partial') {
        byPlatform[plat].covered++
      }
    }
    
    // By severity
    if (!bySeverity[tech.severity]) {
      bySeverity[tech.severity] = { total: 0, covered: 0 }
    }
    bySeverity[tech.severity].total++
    if (status === 'covered' || status === 'partial') {
      bySeverity[tech.severity].covered++
    }
    
    // Missing critical/high
    if (status === 'not_covered' && tech.severity === 'critical') {
      missingCritical.push(`${tech.id}: ${tech.name}`)
    }
    if (status === 'not_covered' && tech.severity === 'high') {
      missingHigh.push(`${tech.id}: ${tech.name}`)
    }
  }
  
  const coveragePercent = techniques.length > 0
    ? ((covered + partial) / techniques.length * 100)
    : 0
  
  return {
    totalTechniques: techniques.length,
    covered,
    partial,
    notCovered,
    planned,
    coveragePercent,
    byTactic,
    byPlatform,
    bySeverity,
    missingCritical,
    missingHigh,
  }
}

export function saveCoverageMatrix(matrix: AttackCoverageMatrix): void {
  fs.writeFileSync(COVERAGE_FILE, JSON.stringify(matrix, null, 2))
}

export function loadCoverageMatrix(): AttackCoverageMatrix | null {
  if (fs.existsSync(COVERAGE_FILE)) {
    return JSON.parse(fs.readFileSync(COVERAGE_FILE, 'utf-8')) as AttackCoverageMatrix
  }
  return null
}

export function renderCoverageMatrix(matrix: AttackCoverageMatrix): string {
  const lines: string[] = []
  
  lines.push('')
  lines.push('════════════════════════════════════════════════════════════')
  lines.push('  MITRE ATT&CK COVERAGE MATRIX')
  lines.push('════════════════════════════════════════════════════════════')
  lines.push('')
  lines.push(`  Version: ${matrix.version}`)
  lines.push(`  Generated: ${new Date(matrix.generatedAt).toISOString()}`)
  lines.push('')
  lines.push('  ── Summary ──────────────────────────────────────────────')
  lines.push(`  Total Techniques:  ${matrix.summary.totalTechniques}`)
  lines.push(`  Covered:           ${matrix.summary.covered}`)
  lines.push(`  Partial:           ${matrix.summary.partial}`)
  lines.push(`  Not Covered:       ${matrix.summary.notCovered}`)
  lines.push(`  Planned:           ${matrix.summary.planned}`)
  lines.push(`  Coverage:          ${matrix.summary.coveragePercent.toFixed(1)}%`)
  lines.push('')
  
  lines.push('  ── By Tactic ──────────────────────────────────────────')
  for (const [tactic, stats] of Object.entries(matrix.summary.byTactic)) {
    const rate = stats.total > 0 ? (stats.covered / stats.total * 100).toFixed(0) : '0'
    const bar = '█'.repeat(Math.min(Math.round(stats.covered / stats.total * 20), 20))
    lines.push(`  ${tactic.padEnd(25)} ${bar.padEnd(20)} ${stats.covered}/${stats.total} (${rate}%)`)
  }
  lines.push('')
  
  lines.push('  ── By Platform ────────────────────────────────────────')
  for (const [platform, stats] of Object.entries(matrix.summary.byPlatform)) {
    const rate = stats.total > 0 ? (stats.covered / stats.total * 100).toFixed(0) : '0'
    lines.push(`  ${platform.padEnd(10)} ${stats.covered}/${stats.total} (${rate}%)`)
  }
  lines.push('')
  
  lines.push('  ── By Severity ────────────────────────────────────────')
  for (const [severity, stats] of Object.entries(matrix.summary.bySeverity)) {
    const rate = stats.total > 0 ? (stats.covered / stats.total * 100).toFixed(0) : '0'
    lines.push(`  ${severity.padEnd(10)} ${stats.covered}/${stats.total} (${rate}%)`)
  }
  lines.push('')
  
  if (matrix.summary.missingCritical.length > 0) {
    lines.push('  ── Missing Critical ───────────────────────────────────')
    for (const tech of matrix.summary.missingCritical) {
      lines.push(`  ✗ ${tech}`)
    }
    lines.push('')
  }
  
  if (matrix.summary.missingHigh.length > 0) {
    lines.push('  ── Missing High ──────────────────────────────────────')
    for (const tech of matrix.summary.missingHigh) {
      lines.push(`  ✗ ${tech}`)
    }
    lines.push('')
  }
  
  lines.push('  ── Coverage Heatmap ───────────────────────────────────')
  lines.push('  Status: █ Covered  ▓ Partial  ░ Not Covered  ▒ Planned')
  lines.push('')
  
  for (const tech of matrix.techniques) {
    const entry = matrix.coverage.find(c => c.techniqueId === tech.id)
    const status = entry?.status || 'not_covered'
    const icon = status === 'covered' ? '█' : status === 'partial' ? '▓' : status === 'planned' ? '▒' : '░'
    lines.push(`  ${icon} ${tech.id.padEnd(10)} ${tech.name}`)
  }
  lines.push('')
  
  lines.push('════════════════════════════════════════════════════════════')
  
  return lines.join('\n')
}
