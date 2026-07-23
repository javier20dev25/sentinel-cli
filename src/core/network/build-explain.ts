import { BuildRecord, BuildGraphEdge, BuildExplanation, ExplainEvent, ExplainResult, CausalNode, ConfidenceBreakdown } from './build-types'
import { computeMultiDna, computeMultiDnaSimilarity, inferBuildGraph, generateExplanation } from './build-dna'
import { computeBaselineStats, loadBaseline } from './build-baseline'
import { buildCausalDag, renderCausalDag } from './build-causal-dag'
import * as path from 'path'

function arrow(type: string): string {
  switch (type) {
    case 'produced': return '→'
    case 'consumed': return '←'
    case 'spawned': return '⇒'
    case 'configured': return '∼'
    default: return '—'
  }
}

function confidenceLabel(score: number): 'HIGH' | 'MODERATE' | 'LOW' {
  if (score >= 0.8) return 'HIGH'
  if (score >= 0.5) return 'MODERATE'
  return 'LOW'
}

export function buildExplainExplanation(
  record: BuildRecord,
  graph: BuildGraphEdge[],
  prevRecord?: BuildRecord,
  releaseRecord?: BuildRecord,
): BuildExplanation {
  const multiDna = computeMultiDna(record)
  const prevMultiDna = prevRecord ? computeMultiDna(prevRecord) : undefined
  const releaseMultiDna = releaseRecord ? computeMultiDna(releaseRecord) : undefined

  const baseExplanation = generateExplanation(
    record,
    graph,
    releaseRecord || prevRecord,
    multiDna,
    releaseMultiDna || prevMultiDna,
  )

  const baseline = loadBaseline(record)
  const stats = baseline?.length ? computeBaselineStats(baseline) : null

  const reasons: string[] = []
  const changes: string[] = []
  let rootCause: string = 'Unspecified change detected'
  let causalChain: string[] = []
  let confidence = baseExplanation.confidence

  const events = collectEvents(record, prevRecord || releaseRecord)

  if (events.length === 0) {
    return {
      summary: 'No significant deviation from baseline',
      confidence: 1,
      confidenceLabel: 'HIGH',
      confidenceBreakdown: {
        overall: 1, toolchain: 1, environment: 1, artifact: 1,
        network: 1, graph: 1, behavior: 1,
        nSignals: 0, diversity: 0, severityBonus: 0,
      },
      reasons: [],
      changes: [],
      rootCause: 'No changes detected',
      causalDag: [],
    }
  }

  const highSeverity = events.filter(e => e.severity === 'high')
  const warnings = events.filter(e => e.severity === 'warning')

  if (highSeverity.length > 0) {
    const rootEvent = findRootEvent(highSeverity, events)
    causalChain = buildCausalChain(rootEvent, events)
    reasons.push(...summarizeReasons(events, 5))
    rootCause = causalChain.join('\n')
  } else if (warnings.length > 0) {
    const rootEvent = findRootEvent(warnings, events)
    causalChain = buildCausalChain(rootEvent, events)
    reasons.push(...summarizeReasons(events, 5))
    rootCause = causalChain.join('\n')
  } else {
    const rootEvent = events[0]
    causalChain = buildCausalChain(rootEvent, events)
    reasons.push(...summarizeReasons(events, 5))
    rootCause = causalChain.join('\n')
  }

  for (const e of events) {
    changes.push(formatChange(e))
  }

  const nSignals = events.length
  const diversity = new Set(events.map(e => e.type)).size
  const persistencePenalty = stats ? computePersistencePenalty(events, stats) : 0
  const severityBonus = highSeverity.length > 0 ? 0.2 : 0
  const diversityBonus = (diversity / 6) * 0.2

  confidence = Math.min(1, Math.max(0.1,
    0.5 + (nSignals > 0 ? Math.min(nSignals / 10, 0.3) : 0) +
    diversityBonus +
    severityBonus -
    persistencePenalty
  ))
  confidence = Math.round(confidence * 100) / 100

  const summary = reasons.length > 0
    ? reasons[0] + (reasons.length > 1 ? ` (+${reasons.length - 1} more)` : '')
    : 'No significant deviation from baseline'

  const causalDag = buildCausalDag(record, graph)

  const breakdown: ConfidenceBreakdown = {
    overall: confidence,
    toolchain: baseExplanation.confidenceBreakdown.toolchain,
    environment: baseExplanation.confidenceBreakdown.environment,
    artifact: baseExplanation.confidenceBreakdown.artifact,
    network: baseExplanation.confidenceBreakdown.network,
    graph: baseExplanation.confidenceBreakdown.graph,
    behavior: baseExplanation.confidenceBreakdown.behavior,
    nSignals,
    diversity: diversity,
    severityBonus: severityBonus,
  }

  return {
    summary,
    confidence,
    confidenceLabel: confidenceLabel(confidence),
    confidenceBreakdown: breakdown,
    reasons: reasons.slice(0, 5),
    changes: changes.slice(0, 10),
    rootCause: rootCause || causalChain[0] || 'Unspecified change detected',
    causalDag,
  }
}

function collectEvents(record: BuildRecord, compareAgainst?: BuildRecord): ExplainEvent[] {
  const events: ExplainEvent[] = []

  if (!compareAgainst) return events

  const prevProcesses = new Map(compareAgainst.processes.map(p => [p.name + '_' + p.pid, p]))
  const currProcesses = new Map(record.processes.map(p => [p.name + '_' + p.pid, p]))

  for (const [key, p] of currProcesses) {
    if (!prevProcesses.has(key)) {
      const parent = record.processes.find(pp => pp.pid === p.ppid)
      events.push({
        type: 'process_spawn',
        processName: p.name,
        parentProcess: parent?.pname || 'unknown',
        severity: DANGEROUS_SET.has(p.name) ? 'high' : 'warning',
        stage: estimateStage(p.timestamp, record.durationMs),
        known: BUILD_TOOL_SET.has(p.name),
      })
    }
  }

  const prevFiles = new Set(compareAgainst.artifactHashes.map(a => a.filePath))
  const currFiles = new Set(record.artifactHashes.map(a => a.filePath))

  for (const f of record.files) {
    if (f.operation === 'created') {
      events.push({
        type: 'file_create',
        fileName: f.filePath.split(/[/\\]/).pop(),
        severity: 'warning',
        stage: estimateStage(f.timestamp, record.durationMs),
      })
    }
  }

  for (const f of record.artifactHashes) {
    const prevHash = compareAgainst.artifactHashes.find(a => a.filePath === f.filePath)
    if (prevHash && prevHash.sha256 !== f.sha256) {
      events.push({
        type: 'artifact_hash',
        artifact: f.filePath.split(/[/\\]/).pop(),
        oldHash: prevHash.sha256.substring(0, 12),
        newHash: f.sha256.substring(0, 12),
        oldSize: prevHash.size,
        newSize: f.size,
        severity: 'high',
      })
    }
  }

  for (const f of record.artifactHashes) {
    if (!prevFiles.has(f.filePath)) {
      events.push({
        type: 'artifact_hash',
        artifact: f.filePath.split(/[/\\]/).pop(),
        oldHash: '(none)',
        newHash: f.sha256.substring(0, 12),
        newSize: f.size,
        severity: 'high',
      })
    }
  }

  const prevHosts = new Set(compareAgainst.network.filter(n => n.type === 'tcp').map(n => n.host))
  const currHosts = new Set(record.network.filter(n => n.type === 'tcp').map(n => n.host))
  for (const h of currHosts) {
    if (!prevHosts.has(h)) {
      const entry = record.network.find(n => n.host === h)
      events.push({
        type: 'network_conn',
        host: h,
        port: entry?.port,
        severity: SUSPICIOUS_DOMAINS.some(d => h.includes(d)) ? 'high' : 'warning',
      })
    }
  }

  const prevDnsHosts = new Set(compareAgainst.network.filter(n => n.type === 'dns').map(n => n.host))
  const currDnsHosts = new Set(record.network.filter(n => n.type === 'dns').map(n => n.host))
  for (const h of currDnsHosts) {
    if (!prevDnsHosts.has(h)) {
      events.push({
        type: 'dns_query',
        host: h,
        severity: SUSPICIOUS_DOMAINS.some(d => h.includes(d)) ? 'high' : 'info',
      })
    }
  }

  return events
}

const DANGEROUS_SET = new Set(['curl', 'wget', 'fetch', 'perl', 'openssl', 'base64', 'nc', 'ncat', 'socat'])
const BUILD_TOOL_SET = new Set([
  'gcc', 'g++', 'clang', 'clang++', 'ld', 'link', 'ld.lld', 'ar', 'make',
  'cmake', 'ninja', 'cargo', 'rustc', 'go', 'javac', 'node', 'tsc', 'python', 'python3',
])
const SUSPICIOUS_DOMAINS = ['.ru', '.cn', '.tk', '.ml', '.ga', '.su']

function estimateStage(timestamp: number, totalDurationMs: number): string {
  const pct = timestamp / totalDurationMs
  if (pct < 0.1) return 'initialization'
  if (pct < 0.3) return 'configuration'
  if (pct < 0.7) return 'compilation'
  return 'finalization'
}

function findRootEvent(highSev: ExplainEvent[], allEvents: ExplainEvent[]): ExplainEvent {
  const timelineFirst = allEvents[0]
  const highFirst = highSev[0]
  return highFirst || timelineFirst
}

function buildCausalChain(root: ExplainEvent, allEvents: ExplainEvent[]): string[] {
  const chain: string[] = []
  const rootDesc = describeEvent(root)
  chain.push(rootDesc)

  const remaining = allEvents.filter(e => e !== root)
  const timeline = [root, ...remaining.sort((a, b) => {
    const order = ['process_spawn', 'network_conn', 'dns_query', 'file_create', 'artifact_hash']
    return order.indexOf(a.type) - order.indexOf(b.type)
  })]

  const seen = new Set<string>()
  for (const e of timeline) {
    const desc = describeEvent(e)
    if (desc !== rootDesc && !seen.has(desc) && chain.length < 6) {
      chain.push(desc)
      seen.add(desc)
    }
  }

  return chain
}

function describeEvent(e: ExplainEvent): string {
  switch (e.type) {
    case 'process_spawn':
      return `New process: ${e.processName}${e.parentProcess ? ` (spawned by ${e.parentProcess})` : ''}`
    case 'file_create':
      return `New file: ${e.fileName}`
    case 'artifact_hash':
      return `Artifact changed: ${e.artifact}`
    case 'network_conn':
      return `New connection: ${e.host}${e.port ? `:${e.port}` : ''}`
    case 'dns_query':
      return `New DNS: ${e.host}`
    default:
      return ''
  }
}

function summarizeReasons(events: ExplainEvent[], max: number): string[] {
  const reasons: string[] = []
  const byType = new Map<string, ExplainEvent[]>()
  for (const e of events) {
    const key = byType.get(e.type) || []
    key.push(e)
    byType.set(e.type, key)
  }

  if (byType.has('artifact_hash') && byType.get('artifact_hash')!.length > 0) {
    const arts = byType.get('artifact_hash')!
    const names = arts.map(a => a.artifact).join(', ')
    reasons.push(`Artifact hash changed: ${names}`)
  }

  if (byType.has('process_spawn') && byType.get('process_spawn')!.length > 0) {
    const procs = byType.get('process_spawn')!
    const names = procs.map(p => p.processName).join(', ')
    reasons.push(`New process(es) detected: ${names}`)
  }

  if (byType.has('network_conn')) {
    const hosts = byType.get('network_conn')!.map(n => n.host).join(', ')
    reasons.push(`New network connections: ${hosts}`)
  }

  if (byType.has('dns_query')) {
    reasons.push(`New DNS queries observed`)
  }

  if (byType.has('file_create')) {
    reasons.push(`New files generated during build`)
  }

  if (reasons.length === 0 && events.length > 0) {
    reasons.push(`${events.length} difference(s) detected`)
  }

  return reasons.slice(0, max)
}

function formatChange(e: ExplainEvent): string {
  switch (e.type) {
    case 'artifact_hash':
      return `${e.artifact}: SHA256 ${e.oldHash} → ${e.newHash}${e.oldSize && e.newSize && e.oldSize !== e.newSize ? ` (size ${e.oldSize}B → ${e.newSize}B)` : ''}`
    case 'process_spawn':
      return `PROCESS ADDED: ${e.processName}${e.parentProcess ? ` (parent: ${e.parentProcess})` : ''} in ${e.stage} stage` +
        (e.known !== undefined ? ` [${e.known ? 'known' : 'unknown'}]` : '') +
        (DANGEROUS_SET.has(e.processName || '') ? ' ⚠ suspicious tool' : '')
    case 'file_create':
      return `FILE CREATED: ${e.fileName} in ${e.stage} stage`
    case 'network_conn':
      return `NETWORK NEW: ${e.host}:${e.port || ''}${SUSPICIOUS_DOMAINS.some(d => (e.host || '').includes(d)) ? ' ⚠ suspicious domain' : ''}`
    case 'dns_query':
      return `DNS NEW: ${e.host}${SUSPICIOUS_DOMAINS.some(d => (e.host || '').includes(d)) ? ' ⚠ suspicious domain' : ''}`
    default:
      return ''
  }
}

function computePersistencePenalty(events: ExplainEvent[], stats: { meanDurationMs: number; stdDurationMs: number }): number {
  const networkEvents = events.filter(e => e.type === 'network_conn' || e.type === 'dns_query')
  if (networkEvents.length > 0 && stats.stdDurationMs > 0) {
    return 0.1
  }
  return 0
}

export function toExplainResult(
  buildId: string,
  explanation: BuildExplanation,
  comparedAgainst: string,
): ExplainResult {
  return {
    buildId,
    comparedAgainst,
    summary: explanation.summary,
    reasons: explanation.reasons,
    changes: explanation.changes,
    rootCause: explanation.rootCause,
    confidence: explanation.confidence,
  }
}
