import * as path from 'path'
import * as fs from 'fs'
import * as os from 'os'
import { BuildRecord, BuildBaselineStats, BuildNormalityResult } from './build-types'
import { computeBuildDna } from './build-dna'

const MAX_BASELINE_BUILDS = 50

function baselinePath(): string {
  const dir = path.join(os.homedir(), '.sentinel', 'baselines')
  fs.mkdirSync(dir, { recursive: true })
  return dir
}

function buildKey(record: BuildRecord): string {
  const cmd = record.command.replace(/[^a-z0-9]/gi, '_')
  const cwd = record.cwd.replace(/[^a-z0-9]/gi, '_')
  return `${cmd}_${cwd}`
}

function baselineFile(key: string): string {
  return path.join(baselinePath(), `${key}.json`)
}

export function loadBaseline(record: BuildRecord): BuildRecord[] {
  const file = baselineFile(buildKey(record))
  try {
    const data = JSON.parse(fs.readFileSync(file, 'utf8'))
    return Array.isArray(data) ? data : [data]
  } catch {
    return []
  }
}

export function saveToBaseline(record: BuildRecord) {
  const key = buildKey(record)
  const file = baselineFile(key)
  let baseline: BuildRecord[] = []
  try {
    baseline = JSON.parse(fs.readFileSync(file, 'utf8'))
    if (!Array.isArray(baseline)) baseline = [baseline]
  } catch {
    baseline = []
  }
  baseline.unshift(record)
  if (baseline.length > MAX_BASELINE_BUILDS) {
    baseline = baseline.slice(0, MAX_BASELINE_BUILDS)
  }
  fs.writeFileSync(file, JSON.stringify(baseline, null, 2), 'utf8')
}

export function computeBaselineStats(records: BuildRecord[]): BuildBaselineStats | null {
  if (records.length < 2) return null

  const durations = records.map(r => r.durationMs)
  const artCounts = records.map(r => r.summary.artifactsHashed)
  const fileOps = records.map(r => r.summary.filesCreated + r.summary.filesModified + r.summary.filesDeleted)

  const mean = (vals: number[]) => vals.reduce((a, b) => a + b, 0) / vals.length
  const std = (vals: number[], m: number) => Math.sqrt(vals.reduce((a, b) => a + (b - m) ** 2, 0) / vals.length)

  const meanDur = mean(durations)
  const stdDur = std(durations, meanDur)
  const meanArt = mean(artCounts)
  const stdArt = std(artCounts, meanArt)
  const meanOps = mean(fileOps)
  const stdOps = std(fileOps, meanOps)

  const toolchainSets = records.map(r => new Set(r.summary.uniqueProcesses))
  const typicalToolchain = [...toolchainSets.reduce((acc, s) => {
    for (const t of s) acc.set(t, (acc.get(t) || 0) + 1)
    return acc
  }, new Map<string, number>())]
    .filter(([_, count]) => count >= records.length * 0.8)
    .map(([t]) => t)
    .sort()

  const dnaSigs = records.map(r => {
    const dna = computeBuildDna(r)
    return dna.processGraphSignature
  })
  const sigCounts = new Map<string, number>()
  for (const sig of dnaSigs) sigCounts.set(sig, (sigCounts.get(sig) || 0) + 1)
  const typicalGraphSig = [...sigCounts.entries()].sort((a, b) => b[1] - a[1])[0]?.[0] || null

  return {
    count: records.length,
    meanDurationMs: Math.round(meanDur),
    stdDurationMs: Math.round(stdDur),
    meanArtifactCount: Math.round(meanArt * 10) / 10,
    stdArtifactCount: Math.round(stdArt * 10) / 10,
    meanFileOps: Math.round(meanOps * 10) / 10,
    stdFileOps: Math.round(stdOps * 10) / 10,
    typicalToolchain,
    typicalGraphSignature: typicalGraphSig,
  }
}

export function computeNormality(record: BuildRecord, stats: BuildBaselineStats): BuildNormalityResult {
  const z = (val: number, mean: number, sd: number) => sd === 0 ? 0 : (val - mean) / sd

  const zDur = z(record.durationMs, stats.meanDurationMs, stats.stdDurationMs)
  const zArt = z(record.summary.artifactsHashed, stats.meanArtifactCount, stats.stdArtifactCount)
  const zOps = z(
    record.summary.filesCreated + record.summary.filesModified + record.summary.filesDeleted,
    stats.meanFileOps, stats.stdFileOps,
  )

  const absZ = (z: number) => Math.abs(z)
  const overall = Math.max(0, 1 - (absZ(zDur) + absZ(zArt) + absZ(zOps)) / 9)

  const isOutlier = absZ(zDur) > 3 || absZ(zArt) > 3 || absZ(zOps) > 3

  return {
    zScoreDuration: Math.round(zDur * 100) / 100,
    zScoreArtifacts: Math.round(zArt * 100) / 100,
    zScoreFileOps: Math.round(zOps * 100) / 100,
    overallNormality: Math.round(overall * 1000) / 1000,
    isOutlier,
  }
}
