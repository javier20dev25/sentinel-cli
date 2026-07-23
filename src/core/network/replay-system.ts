import * as fs from 'fs'
import * as path from 'path'
import { BuildRecord } from './build-types'

export interface ReplayDataset {
  id: string
  name: string
  attackId?: string
  techniqueId?: string
  campaign?: string
  createdAt: number
  platform: 'windows' | 'linux' | 'macos' | 'all'
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  description: string
  files: ReplayFile[]
  tags: string[]
  expectedVerdict: 'CLEAN' | 'REVIEW' | 'BLOCK'
  expectedTrustScore?: number
  expectedFindings?: string[]
}

export interface ReplayFile {
  name: string
  type: 'build' | 'events' | 'timeline' | 'graph' | 'trust' | 'expected'
  path: string
  sha256?: string
  size: number
}

export interface ReplayResult {
  datasetId: string
  attackId?: string
  timestamp: number
  actualVerdict: 'CLEAN' | 'REVIEW' | 'BLOCK'
  actualTrustScore: number
  actualFindings: string[]
  expectedVerdict: string
  expectedTrustScore?: number
  expectedFindings?: string[]
  verdictMatch: boolean
  scoreDelta: number
  findingsDelta: { missing: string[]; extra: string[] }
  detectionRate: number
  falsePositiveRate: boolean
  durationMs: number
}

export interface ReplayReport {
  timestamp: number
  totalDatasets: number
  passed: number
  failed: number
  skipped: number
  detectionRate: number
  falsePositiveRate: number
  results: ReplayResult[]
  bySeverity: Record<string, { total: number; detected: number }>
  byCampaign: Record<string, { total: number; detected: number }>
  summary: string
}

const DATASETS_DIR = path.join(process.cwd(), 'datasets')

export function ensureDatasetsDir(): void {
  if (!fs.existsSync(DATASETS_DIR)) {
    fs.mkdirSync(DATASETS_DIR, { recursive: true })
  }
  const subdirs = ['windows', 'linux', 'macos', 'atomic', 'caldera', 'expected']
  for (const sub of subdirs) {
    const dir = path.join(DATASETS_DIR, sub)
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true })
    }
  }
}

export function saveReplayDataset(dataset: ReplayDataset): string {
  ensureDatasetsDir()
  const dir = path.join(DATASETS_DIR, dataset.platform, dataset.id)
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true })
  }
  const metaPath = path.join(dir, 'dataset.json')
  fs.writeFileSync(metaPath, JSON.stringify(dataset, null, 2))
  return dir
}

export function saveReplayFile(datasetId: string, platform: string, fileName: string, data: unknown): string {
  ensureDatasetsDir()
  const dir = path.join(DATASETS_DIR, platform, datasetId)
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true })
  }
  const filePath = path.join(dir, fileName)
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2))
  return filePath
}

export function loadReplayDataset(datasetId: string, platform?: string): ReplayDataset | null {
  const platforms = platform ? [platform] : ['windows', 'linux', 'macos', 'atomic', 'caldera']
  for (const p of platforms) {
    const metaPath = path.join(DATASETS_DIR, p, datasetId, 'dataset.json')
    if (fs.existsSync(metaPath)) {
      return JSON.parse(fs.readFileSync(metaPath, 'utf-8')) as ReplayDataset
    }
  }
  return null
}

export function loadReplayFile(datasetId: string, platform: string, fileName: string): unknown | null {
  const filePath = path.join(DATASETS_DIR, platform, datasetId, fileName)
  if (fs.existsSync(filePath)) {
    return JSON.parse(fs.readFileSync(filePath, 'utf-8'))
  }
  return null
}

export function listReplayDatasets(platform?: string, campaign?: string): ReplayDataset[] {
  ensureDatasetsDir()
  const datasets: ReplayDataset[] = []
  const platforms = platform ? [platform] : ['windows', 'linux', 'macos', 'atomic', 'caldera']
  
  for (const p of platforms) {
    const platformDir = path.join(DATASETS_DIR, p)
    if (!fs.existsSync(platformDir)) continue
    
    const entries = fs.readdirSync(platformDir, { withFileTypes: true })
    for (const entry of entries) {
      if (!entry.isDirectory()) continue
      const metaPath = path.join(platformDir, entry.name, 'dataset.json')
      if (fs.existsSync(metaPath)) {
        const dataset = JSON.parse(fs.readFileSync(metaPath, 'utf-8')) as ReplayDataset
        if (!campaign || dataset.campaign === campaign) {
          datasets.push(dataset)
        }
      }
    }
  }
  return datasets
}

export function createReplayDatasetFromRecord(
  record: BuildRecord,
  options: {
    name: string
    attackId?: string
    techniqueId?: string
    campaign?: string
    severity?: ReplayDataset['severity']
    description?: string
    tags?: string[]
    expectedVerdict?: ReplayDataset['expectedVerdict']
    expectedTrustScore?: number
    expectedFindings?: string[]
  }
): ReplayDataset {
  const id = `replay-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`
  
  const dataset: ReplayDataset = {
    id,
    name: options.name,
    attackId: options.attackId,
    techniqueId: options.techniqueId,
    campaign: options.campaign,
    createdAt: Date.now(),
    platform: (record.platform as ReplayDataset['platform']) || 'all',
    severity: options.severity || 'info',
    description: options.description || `Replay dataset for ${options.name}`,
    files: [],
    tags: options.tags || [],
    expectedVerdict: options.expectedVerdict || 'CLEAN',
    expectedTrustScore: options.expectedTrustScore,
    expectedFindings: options.expectedFindings,
  }
  
  const dir = saveReplayDataset(dataset)
  
  // Save build record
  const buildPath = saveReplayFile(id, dataset.platform, 'build.json', record)
  dataset.files.push({
    name: 'build.json',
    type: 'build',
    path: buildPath,
    size: fs.statSync(buildPath).size,
  })
  
  // Save events
  if (record.processes?.length || record.files?.length || record.network?.length) {
    const events = {
      processes: record.processes,
      files: record.files,
      network: record.network,
    }
    const eventsPath = saveReplayFile(id, dataset.platform, 'events.json', events)
    dataset.files.push({
      name: 'events.json',
      type: 'events',
      path: eventsPath,
      size: fs.statSync(eventsPath).size,
    })
  }
  
  // Save evidence graph
  if (record.evidenceGraph) {
    const graphPath = saveReplayFile(id, dataset.platform, 'graph.json', record.evidenceGraph)
    dataset.files.push({
      name: 'graph.json',
      type: 'graph',
      path: graphPath,
      size: fs.statSync(graphPath).size,
    })
  }
  
  // Save trust result
  if (record.trustResult) {
    const trustPath = saveReplayFile(id, dataset.platform, 'trust.json', record.trustResult)
    dataset.files.push({
      name: 'trust.json',
      type: 'trust',
      path: trustPath,
      size: fs.statSync(trustPath).size,
    })
  }
  
  // Update dataset with file info
  saveReplayDataset(dataset)
  
  return dataset
}

export function replayDataset(
  dataset: ReplayDataset,
  actualVerdict: 'CLEAN' | 'REVIEW' | 'BLOCK',
  actualTrustScore: number,
  actualFindings: string[],
  durationMs: number
): ReplayResult {
  const verdictMatch = actualVerdict === dataset.expectedVerdict
  const scoreDelta = dataset.expectedTrustScore !== undefined
    ? actualTrustScore - dataset.expectedTrustScore
    : 0
  
  const expectedFindings = dataset.expectedFindings || []
  const missing = expectedFindings.filter(f => !actualFindings.includes(f))
  const extra = actualFindings.filter(f => !expectedFindings.includes(f))
  
  const detectionRate = expectedFindings.length > 0
    ? (expectedFindings.length - missing.length) / expectedFindings.length
    : (actualFindings.length === 0 ? 1 : 0)
  
  const falsePositiveRate = extra.length > 0 && expectedFindings.length === 0
  
  return {
    datasetId: dataset.id,
    attackId: dataset.attackId,
    timestamp: Date.now(),
    actualVerdict,
    actualTrustScore,
    actualFindings,
    expectedVerdict: dataset.expectedVerdict,
    expectedTrustScore: dataset.expectedTrustScore,
    expectedFindings: dataset.expectedFindings,
    verdictMatch,
    scoreDelta,
    findingsDelta: { missing, extra },
    detectionRate,
    falsePositiveRate,
    durationMs,
  }
}

export function generateReplayReport(results: ReplayResult[]): ReplayReport {
  const passed = results.filter(r => r.verdictMatch).length
  const failed = results.filter(r => !r.verdictMatch).length
  const skipped = 0
  
  const detectionRate = results.length > 0
    ? results.reduce((sum, r) => sum + r.detectionRate, 0) / results.length
    : 0
  
  const falsePositiveRate = results.some(r => r.falsePositiveRate) ? 1 : 0
  
  const bySeverity: Record<string, { total: number; detected: number }> = {}
  const byCampaign: Record<string, { total: number; detected: number }> = {}
  
  for (const result of results) {
    const dataset = loadReplayDataset(result.datasetId)
    if (dataset) {
      if (!bySeverity[dataset.severity]) {
        bySeverity[dataset.severity] = { total: 0, detected: 0 }
      }
      bySeverity[dataset.severity].total++
      if (result.verdictMatch) {
        bySeverity[dataset.severity].detected++
      }
      
      if (dataset.campaign) {
        if (!byCampaign[dataset.campaign]) {
          byCampaign[dataset.campaign] = { total: 0, detected: 0 }
        }
        byCampaign[dataset.campaign].total++
        if (result.verdictMatch) {
          byCampaign[dataset.campaign].detected++
        }
      }
    }
  }
  
  const summary = [
    `Replay Report: ${passed}/${results.length} passed (${(passed / results.length * 100).toFixed(1)}%)`,
    `Detection Rate: ${(detectionRate * 100).toFixed(1)}%`,
    falsePositiveRate ? 'False Positives: YES' : 'False Positives: NO',
    '',
    'By Severity:',
    ...Object.entries(bySeverity).map(([sev, stats]) =>
      `  ${sev}: ${stats.detected}/${stats.total} detected`
    ),
    '',
    'By Campaign:',
    ...Object.entries(byCampaign).map(([camp, stats]) =>
      `  ${camp}: ${stats.detected}/${stats.total} detected`
    ),
  ].join('\n')
  
  return {
    timestamp: Date.now(),
    totalDatasets: results.length,
    passed,
    failed,
    skipped,
    detectionRate,
    falsePositiveRate,
    results,
    bySeverity,
    byCampaign,
    summary,
  }
}

export function renderReplayReport(report: ReplayReport): string {
  const lines: string[] = []
  
  lines.push('')
  lines.push('════════════════════════════════════════════════════════════')
  lines.push('  REPLAY REGRESSION REPORT')
  lines.push('════════════════════════════════════════════════════════════')
  lines.push('')
  
  const passRate = report.totalDatasets > 0
    ? (report.passed / report.totalDatasets * 100).toFixed(1)
    : '0.0'
  
  lines.push(`  Total Datasets:  ${report.totalDatasets}`)
  lines.push(`  Passed:          ${report.passed}`)
  lines.push(`  Failed:          ${report.failed}`)
  lines.push(`  Pass Rate:       ${passRate}%`)
  lines.push(`  Detection Rate:  ${(report.detectionRate * 100).toFixed(1)}%`)
  lines.push(`  False Positives: ${report.falsePositiveRate ? 'YES' : 'NO'}`)
  lines.push('')
  
  lines.push('  ── By Severity ──────────────────────────────────────')
  for (const [sev, stats] of Object.entries(report.bySeverity)) {
    const rate = stats.total > 0 ? (stats.detected / stats.total * 100).toFixed(0) : '0'
    lines.push(`  ${sev.padEnd(10)} ${stats.detected}/${stats.total} detected (${rate}%)`)
  }
  lines.push('')
  
  lines.push('  ── By Campaign ──────────────────────────────────────')
  for (const [camp, stats] of Object.entries(report.byCampaign)) {
    const rate = stats.total > 0 ? (stats.detected / stats.total * 100).toFixed(0) : '0'
    lines.push(`  ${camp.padEnd(20)} ${stats.detected}/${stats.total} detected (${rate}%)`)
  }
  lines.push('')
  
  lines.push('  ── Failed Datasets ──────────────────────────────────')
  const failed = report.results.filter(r => !r.verdictMatch)
  if (failed.length === 0) {
    lines.push('  None')
  } else {
    for (const result of failed) {
      const dataset = loadReplayDataset(result.datasetId)
      lines.push(`  ✗ ${dataset?.name || result.datasetId}`)
      lines.push(`    Expected: ${result.expectedVerdict} | Actual: ${result.actualVerdict}`)
      if (result.findingsDelta.missing.length > 0) {
        lines.push(`    Missing: ${result.findingsDelta.missing.join(', ')}`)
      }
      if (result.findingsDelta.extra.length > 0) {
        lines.push(`    Extra: ${result.findingsDelta.extra.join(', ')}`)
      }
    }
  }
  lines.push('')
  
  lines.push('════════════════════════════════════════════════════════════')
  
  return lines.join('\n')
}
