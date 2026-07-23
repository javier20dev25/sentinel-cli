import * as fs from 'fs'
import * as path from 'path'
import { BuildRecord } from './build-types'

export interface StressTestConfig {
  id: string
  name: string
  description: string
  createdAt: number
  totalBuilds: number
  maliciousRatio: number
  concurrency: number
  timeoutMs: number
  platform: 'windows' | 'linux' | 'macos' | 'all'
  attackDistribution: AttackDistribution
}

export interface AttackDistribution {
  [attackId: string]: number
}

export interface StressTestResult {
  configId: string
  timestamp: number
  durationMs: number
  buildsProcessed: number
  buildsFailed: number
  throughput: number
  memoryUsage: MemorySnapshot
  accuracy: AccuracyMetrics
  performance: PerformanceMetrics
  findings: StressFinding[]
  summary: string
}

export interface MemorySnapshot {
  heapUsed: number
  heapTotal: number
  rss: number
  external: number
  arrayBuffers: number
}

export interface AccuracyMetrics {
  truePositives: number
  falsePositives: number
  trueNegatives: number
  falseNegatives: number
  precision: number
  recall: number
  f1Score: number
  accuracy: number
}

export interface PerformanceMetrics {
  avgAnalysisTimeMs: number
  p50AnalysisTimeMs: number
  p95AnalysisTimeMs: number
  p99AnalysisTimeMs: number
  maxAnalysisTimeMs: number
  totalAnalysisTimeMs: number
  avgMemoryPerBuild: number
  peakMemory: number
}

export interface StressFinding {
  type: 'performance' | 'accuracy' | 'memory' | 'stability'
  severity: 'critical' | 'high' | 'medium' | 'low'
  description: string
  metric: string
  value: number
  threshold: number
}

const STRESS_DIR = path.join(process.cwd(), 'stress-tests')

export function ensureStressDir(): void {
  if (!fs.existsSync(STRESS_DIR)) {
    fs.mkdirSync(STRESS_DIR, { recursive: true })
  }
}

export function saveStressConfig(config: StressTestConfig): void {
  ensureStressDir()
  const filePath = path.join(STRESS_DIR, `${config.id}-config.json`)
  fs.writeFileSync(filePath, JSON.stringify(config, null, 2))
}

export function loadStressConfig(configId: string): StressTestConfig | null {
  const filePath = path.join(STRESS_DIR, `${configId}-config.json`)
  if (fs.existsSync(filePath)) {
    return JSON.parse(fs.readFileSync(filePath, 'utf-8')) as StressTestConfig
  }
  return null
}

export function saveStressResult(result: StressTestResult): void {
  ensureStressDir()
  const filePath = path.join(STRESS_DIR, `${result.configId}-${result.timestamp}.json`)
  fs.writeFileSync(filePath, JSON.stringify(result, null, 2))
}

export function loadStressResult(configId: string, timestamp: number): StressTestResult | null {
  const filePath = path.join(STRESS_DIR, `${configId}-${timestamp}.json`)
  if (fs.existsSync(filePath)) {
    return JSON.parse(fs.readFileSync(filePath, 'utf-8')) as StressTestResult
  }
  return null
}

export function listStressResults(configId: string): StressTestResult[] {
  ensureStressDir()
  const results: StressTestResult[] = []
  const files = fs.readdirSync(STRESS_DIR).filter(f => f.startsWith(`${configId}-`) && f.endsWith('.json'))
  for (const file of files) {
    if (file.includes('config')) continue
    const filePath = path.join(STRESS_DIR, file)
    results.push(JSON.parse(fs.readFileSync(filePath, 'utf-8')) as StressTestResult)
  }
  return results.sort((a, b) => b.timestamp - a.timestamp)
}

export function createDefaultStressConfig(): StressTestConfig {
  return {
    id: `stress-${Date.now()}`,
    name: 'Default Stress Test',
    description: 'Default stress test with 200 builds, 10% malicious',
    createdAt: Date.now(),
    totalBuilds: 200,
    maliciousRatio: 0.1,
    concurrency: 10,
    timeoutMs: 300000,
    platform: 'all',
    attackDistribution: {
      'ATK-008': 0.15,
      'ATK-002': 0.1,
      'ATK-005': 0.1,
      'ATK-006': 0.1,
      'ATK-007': 0.1,
      'ATK-010': 0.1,
      'ATK-013': 0.1,
      'ATK-016': 0.1,
      'ATK-024': 0.05,
      'ATK-021': 0.05,
    },
  }
}

export function createStressResult(
  configId: string,
  builds: Array<{ record: BuildRecord; expected: 'CLEAN' | 'BLOCK'; actual: 'CLEAN' | 'BLOCK'; analysisTimeMs: number }>
): StressTestResult {
  const durationMs = builds.reduce((sum, b) => sum + b.analysisTimeMs, 0)
  const throughput = builds.length / (durationMs / 1000)
  
  const truePositives = builds.filter(b => b.expected === 'BLOCK' && b.actual === 'BLOCK').length
  const falsePositives = builds.filter(b => b.expected === 'CLEAN' && b.actual === 'BLOCK').length
  const trueNegatives = builds.filter(b => b.expected === 'CLEAN' && b.actual === 'CLEAN').length
  const falseNegatives = builds.filter(b => b.expected === 'BLOCK' && b.actual === 'CLEAN').length
  
  const precision = truePositives + falsePositives > 0
    ? truePositives / (truePositives + falsePositives)
    : 0
  const recall = truePositives + falseNegatives > 0
    ? truePositives / (truePositives + falseNegatives)
    : 0
  const f1Score = precision + recall > 0
    ? 2 * (precision * recall) / (precision + recall)
    : 0
  const accuracy = builds.length > 0
    ? (truePositives + trueNegatives) / builds.length
    : 0
  
  const analysisTimes = builds.map(b => b.analysisTimeMs).sort((a, b) => a - b)
  const p50Index = Math.floor(analysisTimes.length * 0.5)
  const p95Index = Math.floor(analysisTimes.length * 0.95)
  const p99Index = Math.floor(analysisTimes.length * 0.99)
  
  const memBefore = process.memoryUsage()
  
  const findings: StressFinding[] = []
  
  if (falsePositives > 0) {
    findings.push({
      type: 'accuracy',
      severity: 'high',
      description: `False positives detected: ${falsePositives}`,
      metric: 'falsePositives',
      value: falsePositives,
      threshold: 0,
    })
  }
  
  if (falseNegatives > 0) {
    findings.push({
      type: 'accuracy',
      severity: 'critical',
      description: `False negatives detected: ${falseNegatives}`,
      metric: 'falseNegatives',
      value: falseNegatives,
      threshold: 0,
    })
  }
  
  if (analysisTimes[p95Index] > 1000) {
    findings.push({
      type: 'performance',
      severity: 'medium',
      description: `P95 analysis time exceeds 1s: ${analysisTimes[p95Index].toFixed(0)}ms`,
      metric: 'p95AnalysisTimeMs',
      value: analysisTimes[p95Index],
      threshold: 1000,
    })
  }
  
  if (throughput < 10) {
    findings.push({
      type: 'performance',
      severity: 'medium',
      description: `Low throughput: ${throughput.toFixed(1)} builds/sec`,
      metric: 'throughput',
      value: throughput,
      threshold: 10,
    })
  }
  
  const summary = [
    `Stress Test Results: ${builds.length} builds in ${(durationMs / 1000).toFixed(1)}s`,
    `Throughput: ${throughput.toFixed(1)} builds/sec`,
    `Accuracy: ${(accuracy * 100).toFixed(1)}% (P: ${(precision * 100).toFixed(1)}%, R: ${(recall * 100).toFixed(1)}%, F1: ${(f1Score * 100).toFixed(1)}%)`,
    `Findings: ${findings.length}`,
    findings.map(f => `  ${f.severity.toUpperCase()}: ${f.description}`).join('\n'),
  ].join('\n')
  
  return {
    configId,
    timestamp: Date.now(),
    durationMs,
    buildsProcessed: builds.length,
    buildsFailed: 0,
    throughput,
    memoryUsage: {
      heapUsed: memBefore.heapUsed,
      heapTotal: memBefore.heapTotal,
      rss: memBefore.rss,
      external: memBefore.external,
      arrayBuffers: memBefore.arrayBuffers,
    },
    accuracy: {
      truePositives,
      falsePositives,
      trueNegatives,
      falseNegatives,
      precision,
      recall,
      f1Score,
      accuracy,
    },
    performance: {
      avgAnalysisTimeMs: analysisTimes.reduce((a, b) => a + b, 0) / analysisTimes.length,
      p50AnalysisTimeMs: analysisTimes[p50Index],
      p95AnalysisTimeMs: analysisTimes[p95Index],
      p99AnalysisTimeMs: analysisTimes[p99Index],
      maxAnalysisTimeMs: analysisTimes[analysisTimes.length - 1],
      totalAnalysisTimeMs: durationMs,
      avgMemoryPerBuild: memBefore.heapUsed / builds.length,
      peakMemory: memBefore.rss,
    },
    findings,
    summary,
  }
}

export function renderStressResult(result: StressTestResult): string {
  const lines: string[] = []
  
  lines.push('')
  lines.push('════════════════════════════════════════════════════════════')
  lines.push('  STRESS TEST RESULTS')
  lines.push('════════════════════════════════════════════════════════════')
  lines.push('')
  lines.push(`  Config:     ${result.configId}`)
  lines.push(`  Timestamp:  ${new Date(result.timestamp).toISOString()}`)
  lines.push(`  Duration:   ${(result.durationMs / 1000).toFixed(1)}s`)
  lines.push('')
  lines.push('  ── Throughput ───────────────────────────────────────────')
  lines.push(`  Builds Processed: ${result.buildsProcessed}`)
  lines.push(`  Builds/Second:    ${result.throughput.toFixed(1)}`)
  lines.push('')
  lines.push('  ── Accuracy ────────────────────────────────────────────')
  lines.push(`  True Positives:   ${result.accuracy.truePositives}`)
  lines.push(`  False Positives:  ${result.accuracy.falsePositives}`)
  lines.push(`  True Negatives:   ${result.accuracy.trueNegatives}`)
  lines.push(`  False Negatives:  ${result.accuracy.falseNegatives}`)
  lines.push(`  Precision:        ${(result.accuracy.precision * 100).toFixed(1)}%`)
  lines.push(`  Recall:           ${(result.accuracy.recall * 100).toFixed(1)}%`)
  lines.push(`  F1 Score:         ${(result.accuracy.f1Score * 100).toFixed(1)}%`)
  lines.push(`  Accuracy:         ${(result.accuracy.accuracy * 100).toFixed(1)}%`)
  lines.push('')
  lines.push('  ── Performance ─────────────────────────────────────────')
  lines.push(`  Avg Analysis:     ${result.performance.avgAnalysisTimeMs.toFixed(0)}ms`)
  lines.push(`  P50 Analysis:     ${result.performance.p50AnalysisTimeMs.toFixed(0)}ms`)
  lines.push(`  P95 Analysis:     ${result.performance.p95AnalysisTimeMs.toFixed(0)}ms`)
  lines.push(`  P99 Analysis:     ${result.performance.p99AnalysisTimeMs.toFixed(0)}ms`)
  lines.push(`  Max Analysis:     ${result.performance.maxAnalysisTimeMs.toFixed(0)}ms`)
  lines.push('')
  lines.push('  ── Memory ──────────────────────────────────────────────')
  lines.push(`  Heap Used:        ${(result.memoryUsage.heapUsed / 1024 / 1024).toFixed(1)}MB`)
  lines.push(`  Heap Total:       ${(result.memoryUsage.heapTotal / 1024 / 1024).toFixed(1)}MB`)
  lines.push(`  RSS:              ${(result.memoryUsage.rss / 1024 / 1024).toFixed(1)}MB`)
  lines.push(`  Peak Memory:      ${(result.performance.peakMemory / 1024 / 1024).toFixed(1)}MB`)
  lines.push('')
  
  if (result.findings.length > 0) {
    lines.push('  ── Findings ────────────────────────────────────────────')
    for (const finding of result.findings) {
      const icon = finding.severity === 'critical' ? '✗' : finding.severity === 'high' ? '!' : '○'
      lines.push(`  ${icon} [${finding.severity.toUpperCase()}] ${finding.description}`)
    }
    lines.push('')
  }
  
  lines.push('════════════════════════════════════════════════════════════')
  
  return lines.join('\n')
}

export function renderStressComparison(results: StressTestResult[]): string {
  if (results.length < 2) {
    return '  Need at least 2 results for comparison'
  }
  
  const lines: string[] = []
  
  lines.push('')
  lines.push('════════════════════════════════════════════════════════════')
  lines.push('  STRESS TEST COMPARISON')
  lines.push('════════════════════════════════════════════════════════════')
  lines.push('')
  lines.push('  ── Trend ────────────────────────────────────────────────')
  
  for (let i = 0; i < results.length - 1; i++) {
    const prev = results[i + 1]
    const curr = results[i]
    
    const throughputDelta = curr.throughput - prev.throughput
    const accuracyDelta = curr.accuracy.accuracy - prev.accuracy.accuracy
    const memoryDelta = curr.memoryUsage.heapUsed - prev.memoryUsage.heapUsed
    
    lines.push(`  ${new Date(curr.timestamp).toLocaleDateString()}`)
    lines.push(`    Throughput: ${curr.throughput.toFixed(1)} (${throughputDelta >= 0 ? '+' : ''}${throughputDelta.toFixed(1)})`)
    lines.push(`    Accuracy:  ${(curr.accuracy.accuracy * 100).toFixed(1)}% (${accuracyDelta >= 0 ? '+' : ''}${(accuracyDelta * 100).toFixed(1)}%)`)
    lines.push(`    Memory:    ${(curr.memoryUsage.heapUsed / 1024 / 1024).toFixed(1)}MB (${memoryDelta >= 0 ? '+' : ''}${(memoryDelta / 1024 / 1024).toFixed(1)}MB)`)
  }
  
  lines.push('')
  lines.push('════════════════════════════════════════════════════════════')
  
  return lines.join('\n')
}
