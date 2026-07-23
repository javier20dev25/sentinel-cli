import * as fs from 'fs'
import * as path from 'path'
import { ReplayDataset, ReplayResult, ReplayReport, loadReplayDataset, listReplayDatasets, replayDataset, generateReplayReport, renderReplayReport, saveReplayDataset, saveReplayFile } from './replay-system'
import { BuildRecord } from './build-types'

export interface RegressionTest {
  id: string
  name: string
  attackId: string
  techniqueId: string
  campaign: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  platform: 'windows' | 'linux' | 'macos' | 'all'
  description: string
  setupCommand?: string
  teardownCommand?: string
  expectedVerdict: 'CLEAN' | 'REVIEW' | 'BLOCK'
  expectedTrustScore?: number
  expectedFindings: string[]
  timeout?: number
}

export interface RegressionSuite {
  id: string
  name: string
  version: string
  createdAt: number
  tests: RegressionTest[]
}

export interface RegressionRun {
  suiteId: string
  timestamp: number
  results: RegressionResult[]
  durationMs: number
  summary: RegressionSummary
}

export interface RegressionResult {
  testId: string
  status: 'passed' | 'failed' | 'skipped' | 'error'
  actualVerdict?: 'CLEAN' | 'REVIEW' | 'BLOCK'
  actualTrustScore?: number
  actualFindings?: string[]
  error?: string
  durationMs: number
}

export interface RegressionSummary {
  total: number
  passed: number
  failed: number
  skipped: number
  errors: number
  passRate: number
  detectionRate: number
  falsePositiveRate: boolean
}

const SUITES_DIR = path.join(process.cwd(), 'regression-suites')

export function ensureSuitesDir(): void {
  if (!fs.existsSync(SUITES_DIR)) {
    fs.mkdirSync(SUITES_DIR, { recursive: true })
  }
}

export function createRegressionSuite(suite: RegressionSuite): void {
  ensureSuitesDir()
  const filePath = path.join(SUITES_DIR, `${suite.id}.json`)
  fs.writeFileSync(filePath, JSON.stringify(suite, null, 2))
}

export function loadRegressionSuite(suiteId: string): RegressionSuite | null {
  const filePath = path.join(SUITES_DIR, `${suiteId}.json`)
  if (fs.existsSync(filePath)) {
    return JSON.parse(fs.readFileSync(filePath, 'utf-8')) as RegressionSuite
  }
  return null
}

export function listRegressionSuites(): RegressionSuite[] {
  ensureSuitesDir()
  const suites: RegressionSuite[] = []
  const files = fs.readdirSync(SUITES_DIR).filter(f => f.endsWith('.json'))
  for (const file of files) {
    const filePath = path.join(SUITES_DIR, file)
    suites.push(JSON.parse(fs.readFileSync(filePath, 'utf-8')) as RegressionSuite)
  }
  return suites
}

export function saveRegressionRun(run: RegressionRun): void {
  ensureSuitesDir()
  const runsDir = path.join(SUITES_DIR, 'runs')
  if (!fs.existsSync(runsDir)) {
    fs.mkdirSync(runsDir, { recursive: true })
  }
  const filePath = path.join(runsDir, `${run.suiteId}-${run.timestamp}.json`)
  fs.writeFileSync(filePath, JSON.stringify(run, null, 2))
}

export function generateRegressionReport(run: RegressionRun): string {
  const lines: string[] = []
  
  lines.push('')
  lines.push('════════════════════════════════════════════════════════════')
  lines.push('  REGRESSION SUITE RESULTS')
  lines.push('════════════════════════════════════════════════════════════')
  lines.push('')
  lines.push(`  Suite:     ${run.suiteId}`)
  lines.push(`  Timestamp: ${new Date(run.timestamp).toISOString()}`)
  lines.push(`  Duration:  ${(run.durationMs / 1000).toFixed(1)}s`)
  lines.push('')
  lines.push('  ── Summary ──────────────────────────────────────────────')
  lines.push(`  Total:     ${run.summary.total}`)
  lines.push(`  Passed:    ${run.summary.passed}`)
  lines.push(`  Failed:    ${run.summary.failed}`)
  lines.push(`  Skipped:   ${run.summary.skipped}`)
  lines.push(`  Errors:    ${run.summary.errors}`)
  lines.push(`  Pass Rate: ${(run.summary.passRate * 100).toFixed(1)}%`)
  lines.push(`  Detection: ${(run.summary.detectionRate * 100).toFixed(1)}%`)
  lines.push(`  FP Rate:   ${run.summary.falsePositiveRate ? 'YES' : 'NO'}`)
  lines.push('')
  
  lines.push('  ── Test Results ────────────────────────────────────────')
  for (const result of run.results) {
    const icon = result.status === 'passed' ? '✓' : result.status === 'failed' ? '✗' : result.status === 'skipped' ? '○' : '!'
    lines.push(`  ${icon} ${result.testId}`)
    if (result.status === 'failed') {
      lines.push(`    Expected: verdict match | Actual: ${result.actualVerdict}`)
    }
    if (result.status === 'error') {
      lines.push(`    Error: ${result.error}`)
    }
  }
  lines.push('')
  
  lines.push('════════════════════════════════════════════════════════════')
  
  return lines.join('\n')
}

export function createDefaultRegressionSuite(): RegressionSuite {
  return {
    id: 'sentinel-default',
    name: 'Sentinel Default Regression Suite',
    version: '1.0.0',
    createdAt: Date.now(),
    tests: [
      {
        id: 'reg-dll-injection',
        name: 'DLL Injection Detection',
        attackId: 'ATK-008',
        techniqueId: 'T1055.001',
        campaign: 'toolchain-hijack',
        severity: 'critical',
        platform: 'windows',
        description: 'Detect DLL injection via CreateRemoteThread',
        expectedVerdict: 'BLOCK',
        expectedTrustScore: 30,
        expectedFindings: ['DR-007', 'DR-013'],
      },
      {
        id: 'reg-etw-patching',
        name: 'ETW Patching Detection',
        attackId: 'ATK-002',
        techniqueId: 'T1562.006',
        campaign: 'sensor-evasion',
        severity: 'critical',
        platform: 'windows',
        description: 'Detect ETW patching to evade logging',
        expectedVerdict: 'BLOCK',
        expectedTrustScore: 25,
        expectedFindings: ['DR-014'],
      },
      {
        id: 'reg-ld-preload',
        name: 'LD_PRELOAD Injection',
        attackId: 'ATK-005',
        techniqueId: 'T1574.006',
        campaign: 'secret-exfiltration',
        severity: 'critical',
        platform: 'linux',
        description: 'Detect LD_PRELOAD library injection',
        expectedVerdict: 'BLOCK',
        expectedTrustScore: 35,
        expectedFindings: ['DR-002', 'DR-007'],
      },
      {
        id: 'reg-named-pipes',
        name: 'Named Pipe Communication',
        attackId: 'ATK-006',
        techniqueId: 'T1570',
        campaign: 'secret-exfiltration',
        severity: 'medium',
        platform: 'windows',
        description: 'Detect suspicious named pipe usage',
        expectedVerdict: 'REVIEW',
        expectedTrustScore: 60,
        expectedFindings: ['DR-011'],
      },
      {
        id: 'reg-doh-exfil',
        name: 'DNS over HTTPS Exfiltration',
        attackId: 'ATK-007',
        techniqueId: 'T1071.004',
        campaign: 'secret-exfiltration',
        severity: 'high',
        platform: 'all',
        description: 'Detect DoH-based data exfiltration',
        expectedVerdict: 'BLOCK',
        expectedTrustScore: 40,
        expectedFindings: ['DR-003', 'DR-010'],
      },
      {
        id: 'reg-process-hollowing',
        name: 'Process Hollowing Detection',
        attackId: 'ATK-013',
        techniqueId: 'T1055.012',
        campaign: 'ml-poisoning',
        severity: 'critical',
        platform: 'windows',
        description: 'Detect process hollowing technique',
        expectedVerdict: 'BLOCK',
        expectedTrustScore: 20,
        expectedFindings: ['DR-013'],
      },
      {
        id: 'reg-lolbins',
        name: 'LOLBin Usage Detection',
        attackId: 'ATK-010',
        techniqueId: 'T1218',
        campaign: 'graph-poisoning',
        severity: 'high',
        platform: 'windows',
        description: 'Detect Living off the Land binary usage',
        expectedVerdict: 'REVIEW',
        expectedTrustScore: 55,
        expectedFindings: ['DR-002'],
      },
      {
        id: 'reg-npm-postinstall',
        name: 'npm postinstall Exfiltration',
        attackId: 'ATK-016',
        techniqueId: 'T1059.004',
        campaign: 'supply-chain',
        severity: 'critical',
        platform: 'all',
        description: 'Detect malicious npm postinstall script',
        expectedVerdict: 'BLOCK',
        expectedTrustScore: 30,
        expectedFindings: ['DR-001', 'DR-003'],
      },
      {
        id: 'reg-git-hooks',
        name: 'Git Hook Exfiltration',
        attackId: 'ATK-021',
        techniqueId: 'T1554',
        campaign: 'git-attacks',
        severity: 'high',
        platform: 'all',
        description: 'Detect malicious git hooks',
        expectedVerdict: 'REVIEW',
        expectedTrustScore: 50,
        expectedFindings: ['DR-001'],
      },
      {
        id: 'reg-actions-secret',
        name: 'GitHub Actions Secret Exfil',
        attackId: 'ATK-024',
        techniqueId: 'T1552.001',
        campaign: 'ci-attacks',
        severity: 'critical',
        platform: 'all',
        description: 'Detect GitHub Actions secret exfiltration',
        expectedVerdict: 'BLOCK',
        expectedTrustScore: 25,
        expectedFindings: ['DR-003', 'DR-008'],
      },
      {
        id: 'reg-clean-build',
        name: 'Clean Build Verification',
        attackId: '',
        techniqueId: '',
        campaign: '',
        severity: 'info',
        platform: 'all',
        description: 'Verify clean builds pass correctly',
        expectedVerdict: 'CLEAN',
        expectedTrustScore: 80,
        expectedFindings: [],
      },
      {
        id: 'reg-hermetic-build',
        name: 'Hermetic Build Detection',
        attackId: '',
        techniqueId: '',
        campaign: '',
        severity: 'info',
        platform: 'all',
        description: 'Verify hermetic builds get bonus trust',
        expectedVerdict: 'CLEAN',
        expectedTrustScore: 90,
        expectedFindings: [],
      },
    ],
  }
}

export function renderRegressionCoverage(suite: RegressionSuite): string {
  const lines: string[] = []
  
  lines.push('')
  lines.push('════════════════════════════════════════════════════════════')
  lines.push('  REGRESSION COVERAGE')
  lines.push('════════════════════════════════════════════════════════════')
  lines.push('')
  lines.push(`  Suite: ${suite.name}`)
  lines.push(`  Tests: ${suite.tests.length}`)
  lines.push('')
  
  const bySeverity: Record<string, number> = {}
  const byCampaign: Record<string, number> = {}
  const byPlatform: Record<string, number> = {}
  
  for (const test of suite.tests) {
    bySeverity[test.severity] = (bySeverity[test.severity] || 0) + 1
    if (test.campaign) {
      byCampaign[test.campaign] = (byCampaign[test.campaign] || 0) + 1
    }
    byPlatform[test.platform] = (byPlatform[test.platform] || 0) + 1
  }
  
  lines.push('  ── By Severity ──────────────────────────────────────')
  for (const [sev, count] of Object.entries(bySeverity)) {
    const bar = '█'.repeat(Math.min(count * 3, 30))
    lines.push(`  ${sev.padEnd(10)} ${bar} ${count}`)
  }
  lines.push('')
  
  lines.push('  ── By Campaign ──────────────────────────────────────')
  for (const [camp, count] of Object.entries(byCampaign)) {
    const bar = '█'.repeat(Math.min(count * 3, 30))
    lines.push(`  ${camp.padEnd(20)} ${bar} ${count}`)
  }
  lines.push('')
  
  lines.push('  ── By Platform ─────────────────────────────────────')
  for (const [plat, count] of Object.entries(byPlatform)) {
    const bar = '█'.repeat(Math.min(count * 3, 30))
    lines.push(`  ${plat.padEnd(10)} ${bar} ${count}`)
  }
  lines.push('')
  
  lines.push('════════════════════════════════════════════════════════════')
  
  return lines.join('\n')
}
