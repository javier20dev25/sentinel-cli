import * as fs from 'fs'
import * as path from 'path'
import { BuildRecord } from './build-types'

export interface BaselineEntry {
  id: string
  name: string
  command: string
  timestamp: number
  platform: string
  buildRecord: BuildRecord
  trustScore: number
  verdict: 'CLEAN' | 'REVIEW' | 'BLOCK'
  hash: string
}

export interface BaselineProfile {
  id: string
  name: string
  description: string
  createdAt: number
  updatedAt: number
  entries: BaselineEntry[]
  stats: BaselineStats
}

export interface BaselineStats {
  count: number
  meanTrustScore: number
  stdTrustScore: number
  minTrustScore: number
  maxTrustScore: number
  meanDurationMs: number
  stdDurationMs: number
  meanProcesses: number
  stdProcesses: number
  meanFiles: number
  stdFiles: number
  meanNetwork: number
  stdNetwork: number
  typicalTools: string[]
  typicalFiles: string[]
  typicalHosts: string[]
}

export interface BaselineDeviation {
  field: string
  expected: number
  actual: number
  zScore: number
  severity: 'info' | 'warning' | 'critical'
  description: string
}

const BASELINES_DIR = path.join(process.cwd(), 'baselines')

export function ensureBaselinesDir(): void {
  if (!fs.existsSync(BASELINES_DIR)) {
    fs.mkdirSync(BASELINES_DIR, { recursive: true })
  }
}

export function saveBaselineProfile(profile: BaselineProfile): void {
  ensureBaselinesDir()
  const filePath = path.join(BASELINES_DIR, `${profile.id}.json`)
  fs.writeFileSync(filePath, JSON.stringify(profile, null, 2))
}

export function loadBaselineProfile(profileId: string): BaselineProfile | null {
  const filePath = path.join(BASELINES_DIR, `${profileId}.json`)
  if (fs.existsSync(filePath)) {
    return JSON.parse(fs.readFileSync(filePath, 'utf-8')) as BaselineProfile
  }
  return null
}

export function listBaselineProfiles(): BaselineProfile[] {
  ensureBaselinesDir()
  const profiles: BaselineProfile[] = []
  const files = fs.readdirSync(BASELINES_DIR).filter(f => f.endsWith('.json'))
  for (const file of files) {
    const filePath = path.join(BASELINES_DIR, file)
    profiles.push(JSON.parse(fs.readFileSync(filePath, 'utf-8')) as BaselineProfile)
  }
  return profiles
}

export function createBaselineProfile(
  id: string,
  name: string,
  description: string
): BaselineProfile {
  const profile: BaselineProfile = {
    id,
    name,
    description,
    createdAt: Date.now(),
    updatedAt: Date.now(),
    entries: [],
    stats: computeBaselineStats([]),
  }
  saveBaselineProfile(profile)
  return profile
}

export function addBaselineEntry(
  profileId: string,
  command: string,
  record: BuildRecord
): BaselineEntry {
  const profile = loadBaselineProfile(profileId)
  if (!profile) {
    throw new Error(`Baseline profile not found: ${profileId}`)
  }
  
  const entry: BaselineEntry = {
    id: `bl-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    name: `${command} @ ${new Date().toISOString()}`,
    command,
    timestamp: Date.now(),
    platform: record.platform,
    buildRecord: record,
    trustScore: record.trustResult?.overallTrust || 80,
    verdict: (record.trustResult?.overallTrust || 80) >= 80 ? 'CLEAN' : (record.trustResult?.overallTrust || 80) >= 50 ? 'REVIEW' : 'BLOCK',
    hash: computeBuildHash(record),
  }
  
  profile.entries.push(entry)
  profile.stats = computeBaselineStats(profile.entries)
  profile.updatedAt = Date.now()
  saveBaselineProfile(profile)
  
  return entry
}

function computeBuildHash(record: BuildRecord): string {
  const parts = [
    record.command,
    record.args.join(' '),
    record.cwd,
    record.platform,
    record.summary.buildToolsDetected.sort().join(','),
    record.summary.uniqueProcesses.sort().join(','),
  ]
  
  let hash = 0
  for (const part of parts) {
    for (let i = 0; i < part.length; i++) {
      hash = ((hash << 5) - hash + part.charCodeAt(i)) | 0
    }
  }
  return hash.toString(16)
}

export function computeBaselineStats(entries: BaselineEntry[]): BaselineStats {
  if (entries.length === 0) {
    return {
      count: 0,
      meanTrustScore: 0,
      stdTrustScore: 0,
      minTrustScore: 0,
      maxTrustScore: 0,
      meanDurationMs: 0,
      stdDurationMs: 0,
      meanProcesses: 0,
      stdProcesses: 0,
      meanFiles: 0,
      stdFiles: 0,
      meanNetwork: 0,
      stdNetwork: 0,
      typicalTools: [],
      typicalFiles: [],
      typicalHosts: [],
    }
  }
  
  const trustScores = entries.map(e => e.trustScore)
  const durations = entries.map(e => e.buildRecord.durationMs)
  const processes = entries.map(e => e.buildRecord.summary.totalProcesses)
  const files = entries.map(e => e.buildRecord.summary.filesCreated + e.buildRecord.summary.filesModified)
  const networks = entries.map(e => e.buildRecord.summary.networkConnections)
  
  const toolCounts = new Map<string, number>()
  const fileCounts = new Map<string, number>()
  const hostCounts = new Map<string, number>()
  
  for (const entry of entries) {
    for (const tool of entry.buildRecord.summary.buildToolsDetected) {
      toolCounts.set(tool, (toolCounts.get(tool) || 0) + 1)
    }
    for (const file of entry.buildRecord.files.map(f => f.filePath)) {
      fileCounts.set(file, (fileCounts.get(file) || 0) + 1)
    }
    for (const host of entry.buildRecord.network.map(n => n.host)) {
      hostCounts.set(host, (hostCounts.get(host) || 0) + 1)
    }
  }
  
  const typicalTools = Array.from(toolCounts.entries())
    .filter(([_, count]) => count >= entries.length * 0.7)
    .map(([tool]) => tool)
  
  const typicalFiles = Array.from(fileCounts.entries())
    .filter(([_, count]) => count >= entries.length * 0.7)
    .map(([file]) => file)
  
  const typicalHosts = Array.from(hostCounts.entries())
    .filter(([_, count]) => count >= entries.length * 0.7)
    .map(([host]) => host)
  
  return {
    count: entries.length,
    meanTrustScore: mean(trustScores),
    stdTrustScore: std(trustScores),
    minTrustScore: Math.min(...trustScores),
    maxTrustScore: Math.max(...trustScores),
    meanDurationMs: mean(durations),
    stdDurationMs: std(durations),
    meanProcesses: mean(processes),
    stdProcesses: std(processes),
    meanFiles: mean(files),
    stdFiles: std(files),
    meanNetwork: mean(networks),
    stdNetwork: std(networks),
    typicalTools,
    typicalFiles,
    typicalHosts,
  }
}

function mean(arr: number[]): number {
  if (arr.length === 0) return 0
  return arr.reduce((a, b) => a + b, 0) / arr.length
}

function std(arr: number[]): number {
  if (arr.length === 0) return 0
  const m = mean(arr)
  const variance = arr.reduce((sum, val) => sum + (val - m) ** 2, 0) / arr.length
  return Math.sqrt(variance)
}

export function detectBaselineDeviation(
  profileId: string,
  record: BuildRecord
): BaselineDeviation[] {
  const profile = loadBaselineProfile(profileId)
  if (!profile || profile.entries.length < 3) {
    return []
  }
  
  const deviations: BaselineDeviation[] = []
  const stats = profile.stats
  
  // Trust score deviation
  const trustScore = record.trustResult?.overallTrust || 80
  const trustZScore = stats.stdTrustScore > 0
    ? (trustScore - stats.meanTrustScore) / stats.stdTrustScore
    : 0
  if (Math.abs(trustZScore) > 2) {
    deviations.push({
      field: 'trustScore',
      expected: stats.meanTrustScore,
      actual: trustScore,
      zScore: trustZScore,
      severity: Math.abs(trustZScore) > 3 ? 'critical' : 'warning',
      description: `Trust score ${trustScore} is ${Math.abs(trustZScore).toFixed(1)} std devs from baseline mean ${stats.meanTrustScore.toFixed(1)}`,
    })
  }
  
  // Duration deviation
  const durationZScore = stats.stdDurationMs > 0
    ? (record.durationMs - stats.meanDurationMs) / stats.stdDurationMs
    : 0
  if (Math.abs(durationZScore) > 2) {
    deviations.push({
      field: 'duration',
      expected: stats.meanDurationMs,
      actual: record.durationMs,
      zScore: durationZScore,
      severity: Math.abs(durationZScore) > 3 ? 'warning' : 'info',
      description: `Duration ${record.durationMs}ms is ${Math.abs(durationZScore).toFixed(1)} std devs from baseline mean ${stats.meanDurationMs.toFixed(1)}ms`,
    })
  }
  
  // Process count deviation
  const processZScore = stats.stdProcesses > 0
    ? (record.summary.totalProcesses - stats.meanProcesses) / stats.stdProcesses
    : 0
  if (Math.abs(processZScore) > 2) {
    deviations.push({
      field: 'processCount',
      expected: stats.meanProcesses,
      actual: record.summary.totalProcesses,
      zScore: processZScore,
      severity: Math.abs(processZScore) > 3 ? 'warning' : 'info',
      description: `Process count ${record.summary.totalProcesses} is ${Math.abs(processZScore).toFixed(1)} std devs from baseline mean ${stats.meanProcesses.toFixed(1)}`,
    })
  }
  
  // New tools
  const newTools = record.summary.buildToolsDetected.filter(
    tool => !stats.typicalTools.includes(tool)
  )
  if (newTools.length > 0) {
    deviations.push({
      field: 'newTools',
      expected: stats.typicalTools.length,
      actual: newTools.length,
      zScore: 0,
      severity: 'warning',
      description: `New tools detected: ${newTools.join(', ')}`,
    })
  }
  
  // Network anomaly
  const newHosts = record.network
    .map(n => n.host)
    .filter(host => !stats.typicalHosts.includes(host))
  if (newHosts.length > 0) {
    deviations.push({
      field: 'newHosts',
      expected: stats.typicalHosts.length,
      actual: newHosts.length,
      zScore: 0,
      severity: 'critical',
      description: `New network hosts detected: ${newHosts.join(', ')}`,
    })
  }
  
  return deviations
}

export function renderBaselineProfile(profile: BaselineProfile): string {
  const lines: string[] = []
  
  lines.push('')
  lines.push('════════════════════════════════════════════════════════════')
  lines.push('  BASELINE PROFILE')
  lines.push('════════════════════════════════════════════════════════════')
  lines.push('')
  lines.push(`  Name:        ${profile.name}`)
  lines.push(`  Description: ${profile.description}`)
  lines.push(`  Created:     ${new Date(profile.createdAt).toISOString()}`)
  lines.push(`  Updated:     ${new Date(profile.updatedAt).toISOString()}`)
  lines.push(`  Entries:     ${profile.entries.length}`)
  lines.push('')
  lines.push('  ── Statistics ──────────────────────────────────────────')
  lines.push(`  Trust Score:     ${profile.stats.meanTrustScore.toFixed(1)} ± ${profile.stats.stdTrustScore.toFixed(1)}`)
  lines.push(`  Duration:        ${(profile.stats.meanDurationMs / 1000).toFixed(2)}s ± ${(profile.stats.stdDurationMs / 1000).toFixed(2)}s`)
  lines.push(`  Processes:       ${profile.stats.meanProcesses.toFixed(1)} ± ${profile.stats.stdProcesses.toFixed(1)}`)
  lines.push(`  Files:           ${profile.stats.meanFiles.toFixed(1)} ± ${profile.stats.stdFiles.toFixed(1)}`)
  lines.push(`  Network:         ${profile.stats.meanNetwork.toFixed(1)} ± ${profile.stats.stdNetwork.toFixed(1)}`)
  lines.push('')
  
  if (profile.stats.typicalTools.length > 0) {
    lines.push('  ── Typical Tools ──────────────────────────────────────')
    for (const tool of profile.stats.typicalTools) {
      lines.push(`  • ${tool}`)
    }
    lines.push('')
  }
  
  if (profile.stats.typicalHosts.length > 0) {
    lines.push('  ── Typical Hosts ──────────────────────────────────────')
    for (const host of profile.stats.typicalHosts) {
      lines.push(`  • ${host}`)
    }
    lines.push('')
  }
  
  lines.push('  ── Recent Entries ─────────────────────────────────────')
  for (const entry of profile.entries.slice(-5).reverse()) {
    lines.push(`  ${entry.hash.slice(0, 8)} | ${entry.trustScore} | ${entry.command.slice(0, 40)}`)
  }
  lines.push('')
  
  lines.push('════════════════════════════════════════════════════════════')
  
  return lines.join('\n')
}
