import * as fs from 'fs'
import * as path from 'path'
import * as os from 'os'
import { BuildRecord, TrendResult, TrendMetric } from './build-types'

function buildsDir(record: BuildRecord): string {
  const base = path.join(os.homedir(), '.sentinel', 'builds')
  const cmd = record.command.replace(/[^a-z0-9]/gi, '_')
  const cwd = record.cwd.replace(/[^a-z0-9]/gi, '_')
  const key = `${cmd}_${cwd}`
  const dir = path.join(base, key)
  fs.mkdirSync(dir, { recursive: true })
  return dir
}

function loadHistoricalBuilds(record: BuildRecord, maxBuilds = 200): BuildRecord[] {
  const dir = buildsDir(record)
  if (!fs.existsSync(dir)) return [record]

  const files = fs.readdirSync(dir)
    .filter(f => f.endsWith('.json'))
    .sort()
    .reverse()
    .slice(0, maxBuilds)

  const builds: BuildRecord[] = []
  for (const f of files) {
    try {
      const data = JSON.parse(fs.readFileSync(path.join(dir, f), 'utf8'))
      builds.push(data)
    } catch {}
  }

  builds.reverse()
  return builds
}

export function saveToTrendStore(record: BuildRecord): void {
  const dir = buildsDir(record)
  const ts = (record.startTime || new Date().toISOString()).replace(/[^0-9]/g, '').substring(0, 14)
  const filePath = path.join(dir, `${ts}_${Date.now()}.json`)
  fs.writeFileSync(filePath, JSON.stringify(record, null, 2), 'utf8')
}

export function computeTrend(record: BuildRecord): TrendResult {
  const builds = loadHistoricalBuilds(record)
  const buildsAnalyzed = builds.length
  const timeRangeMs = builds.length >= 2
    ? (new Date(builds[builds.length - 1].startTime).getTime() - new Date(builds[0].startTime).getTime())
    : 0

  const metrics = computeAllMetrics(builds)
  const findings = generateTrendFindings(metrics)
  const overallDrift = computeOverallDrift(metrics)

  return { buildsAnalyzed, timeRangeMs, metrics, overallDrift, findings }
}

function computeAllMetrics(builds: BuildRecord[]): TrendMetric[] {
  const extractors: { name: string; fn: (b: BuildRecord) => number }[] = [
    { name: 'duration_ms', fn: b => b.durationMs },
    { name: 'process_count', fn: b => b.summary.totalProcesses },
    { name: 'artifact_count', fn: b => b.summary.artifactsHashed },
    { name: 'file_creations', fn: b => b.summary.filesCreated },
    { name: 'file_modifications', fn: b => b.summary.filesModified },
    { name: 'file_deletions', fn: b => b.summary.filesDeleted },
    { name: 'file_ops_total', fn: b => b.summary.filesCreated + b.summary.filesModified + b.summary.filesDeleted },
    { name: 'network_connections', fn: b => b.summary.networkConnections },
    { name: 'tool_count', fn: b => b.summary.buildToolsDetected.length },
    { name: 'unique_processes', fn: b => b.summary.uniqueProcesses.length },
  ]

  return extractors.map(e => computeMetric(e.name, builds, e.fn))
}

function computeMetric(name: string, builds: BuildRecord[], extract: (b: BuildRecord) => number): TrendMetric {
  const series = builds.map(extract)
  const timestamps = builds.map(b => new Date(b.startTime).getTime())

  const n = series.length
  if (n < 2) {
    return {
      metric: name, values: series, timestamps,
      slope: 0, cusum: 0, ewma: series[0] || 0,
      mean: series[0] || 0, std: 0,
      drift: 'none', alert: false,
    }
  }

  const mean = series.reduce((a, b) => a + b, 0) / n
  const variance = series.reduce((sum, v) => sum + (v - mean) ** 2, 0) / (n - 1 || 1)
  const std = Math.sqrt(variance)

  const slope = computeLinearSlope(series)
  const ewma = computeEwma(series, 0.3)
  const cusum = computeCusum(series, mean, std)

  const driftSlope = slope !== 0 ? Math.abs(slope) / (Math.abs(mean) || 1) : 0
  const cusumPeak = Math.abs(cusum)
  const driftRatio = Math.max(driftSlope, cusumPeak / (Math.abs(mean) * n || 1))

  let drift: TrendMetric['drift'] = 'none'
  let alert = false

  if (driftRatio > 0.2) { drift = 'high'; alert = true }
  else if (driftRatio > 0.1) { drift = 'medium'; alert = cusumPeak > std * 3 }
  else if (driftRatio > 0.03) { drift = 'low'; alert = false }

  return {
    metric: name, values: series, timestamps,
    slope: Math.round(slope * 1000) / 1000,
    cusum: Math.round(cusum * 1000) / 1000,
    ewma: Math.round(ewma * 1000) / 1000,
    mean: Math.round(mean * 100) / 100,
    std: Math.round(std * 100) / 100,
    drift, alert,
  }
}

function computeLinearSlope(values: number[]): number {
  const n = values.length
  if (n < 2) return 0
  const indices = values.map((_, i) => i)
  const meanX = (n - 1) / 2
  const meanY = values.reduce((a, b) => a + b, 0) / n
  let num = 0, den = 0
  for (let i = 0; i < n; i++) {
    const dx = i - meanX
    const dy = values[i] - meanY
    num += dx * dy
    den += dx * dx
  }
  return den !== 0 ? num / den : 0
}

function computeEwma(values: number[], alpha: number): number {
  let ewma = values[0]
  for (let i = 1; i < values.length; i++) {
    ewma = alpha * values[i] + (1 - alpha) * ewma
  }
  return ewma
}

function computeCusum(values: number[], target: number, std: number): number {
  if (std === 0) return 0
  let cusum = 0
  const k = std * 0.5
  for (let i = 0; i < values.length; i++) {
    cusum = Math.max(0, cusum + (values[i] - target) / std - k)
  }
  return cusum
}

function computeOverallDrift(metrics: TrendMetric[]): TrendResult['overallDrift'] {
  if (metrics.some(m => m.drift === 'high')) return 'high'
  if (metrics.some(m => m.drift === 'medium')) return 'medium'
  if (metrics.some(m => m.drift === 'low')) return 'low'
  return 'none'
}

function generateTrendFindings(metrics: TrendMetric[]): string[] {
  const findings: string[] = []
  for (const m of metrics) {
    if (m.alert) {
      findings.push(`${m.metric}: drift ${m.drift} (slope=${m.slope}, cusum=${m.cusum}, mean=${m.mean})`)
    } else if (m.drift === 'medium' || m.drift === 'low') {
      findings.push(`${m.metric}: minor drift (slope=${m.slope})`)
    }
  }
  return findings
}

export function renderTrend(result: TrendResult): string {
  const lines: string[] = [
    'Trend Analysis',
    '==============',
    `Builds analyzed: ${result.buildsAnalyzed}`,
    `Time range: ${result.timeRangeMs > 0 ? `${Math.round(result.timeRangeMs / 3600000)}h` : 'single build'}`,
    `Overall drift: ${result.overallDrift}`,
    '',
    'Metrics',
    '-------',
  ]

  for (const m of result.metrics) {
    const alertIcon = m.alert ? '⚠' : ' '
    const driftIcon = m.drift === 'high' ? '⬆' : m.drift === 'medium' ? '↗' : m.drift === 'low' ? '→' : '✓'
    lines.push(`  ${alertIcon}${driftIcon} ${m.metric}: mean=${m.mean}, slope=${m.slope}/build, drift=${m.drift}`)
  }

  if (result.findings.length > 0) {
    lines.push('', 'Findings', '--------')
    for (const f of result.findings) lines.push(`  - ${f}`)
  }

  return lines.join('\n')
}
