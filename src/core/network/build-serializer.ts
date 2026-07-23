import { BuildRecord } from './build-types'

const TRIMMED_FIELDS = new Set([
  'cmdline', 'argv', 'responseFileContent', 'snippet', 'context',
])

const MAX_STRING_LENGTH = 500
const MAX_ARRAY_ITEMS = 1000
const MAX_PROCESSES = 500
const MAX_FILES = 2000
const MAX_NETWORK = 500
const MAX_READS = 500
const MAX_HASH_CHAIN = 100

export interface SerializationReport {
  originalSizeBytes: number
  compressedSizeBytes: number
  trimmedFields: number
  truncatedArrays: number
  skippedOptional: string[]
}

export function compactRecord(record: BuildRecord): BuildRecord {
  const report: SerializationReport = {
    originalSizeBytes: 0,
    compressedSizeBytes: 0,
    trimmedFields: 0,
    truncatedArrays: 0,
    skippedOptional: [],
  }

  const result: BuildRecord = {
    ...record,
    processes: trimArray(record.processes, MAX_PROCESSES).map(p => ({
      ...p,
      cmdline: trimString(p.cmdline, MAX_STRING_LENGTH, report),
    })),
    files: trimArray(record.files, MAX_FILES).map(f => ({
      ...f,
    })),
    network: trimArray(record.network, MAX_NETWORK).map(n => ({
      ...n,
    })),
    hashChain: trimArray(record.hashChain, MAX_HASH_CHAIN),
  }

  if (record.readFiles) {
    result.readFiles = trimArray(record.readFiles, MAX_READS)
  }

  if (record.artifactHashes && record.artifactHashes.length > 200) {
    result.artifactHashes = record.artifactHashes.slice(0, 200)
    report.truncatedArrays++
  }

  if (record.compilerInvocations) {
    result.compilerInvocations = {
      ...record.compilerInvocations,
      invocations: trimArray(record.compilerInvocations.invocations, 50).map(inv => ({
        ...inv,
        responseFileContent: inv.responseFileContent.map(c => trimString(c, 2000, report)),
        argv: inv.argv.map(a => trimString(a, 200, report)),
      })),
      suspiciousInvocations: trimArray(record.compilerInvocations.suspiciousInvocations, 50),
    }
  }

  if (record.secretFlow) {
    result.secretFlow = {
      ...record.secretFlow,
      secretAccesses: trimArray(record.secretFlow.secretAccesses, 100).map(s => ({
        ...s,
        snippet: trimString(s.snippet, 100, report),
        context: trimString(s.context, 100, report),
      })),
      chains: trimArray(record.secretFlow.chains, 50),
    }
  }

  if (record.processMaps) {
    result.processMaps = trimArray(record.processMaps, 50).map(m => ({
      ...m,
      regions: trimArray(m.regions, 100),
      suspiciousRegions: trimArray(m.suspiciousRegions, 50),
    }))
  }

  if (record.summary?.anomalies && record.summary.anomalies.length > 200) {
    result.summary = { ...result.summary, anomalies: record.summary.anomalies.slice(0, 200) }
    report.truncatedArrays++
  }

  report.originalSizeBytes = estimateSize(record)
  report.compressedSizeBytes = estimateSize(result)

  return result
}

function trimString(s: string, maxLen: number, report?: SerializationReport): string {
  if (s && s.length > maxLen) {
    if (report) report.trimmedFields++
    return s.substring(0, maxLen) + '...'
  }
  return s
}

function trimArray<T>(arr: T[], maxLen: number): T[] {
  if (!arr) return arr
  if (arr.length > maxLen) {
    return arr.slice(0, maxLen)
  }
  return arr
}

function estimateSize(obj: unknown): number {
  try {
    return Buffer.byteLength(JSON.stringify(obj), 'utf-8')
  } catch {
    return 0
  }
}

export function renderSerializationReport(report: SerializationReport): string[] {
  const saved = report.originalSizeBytes - report.compressedSizeBytes
  const pct = report.originalSizeBytes > 0
    ? Math.round((saved / report.originalSizeBytes) * 100)
    : 0
  return [
    'Serialization Report',
    '====================',
    `  Original: ${formatBytes(report.originalSizeBytes)}`,
    `  Compressed: ${formatBytes(report.compressedSizeBytes)}`,
    `  Saved: ${formatBytes(saved)} (${pct}%)`,
    `  Trimmed string fields: ${report.trimmedFields}`,
    `  Truncated arrays: ${report.truncatedArrays}`,
  ]
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes}B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)}MB`
}

export const SERIALIZATION_LIMITS = {
  maxProcesses: MAX_PROCESSES,
  maxFiles: MAX_FILES,
  maxNetwork: MAX_NETWORK,
  maxReads: MAX_READS,
  maxHashChain: MAX_HASH_CHAIN,
  maxStringLength: MAX_STRING_LENGTH,
  maxAnomalies: 200,
  maxArtifacts: 200,
  maxCompilerInvocations: 50,
  maxSecrets: 100,
  maxSecretChains: 50,
  maxProcessMaps: 50,
  maxMemoryRegions: 100,
  maxSuspiciousRegions: 50,
}
