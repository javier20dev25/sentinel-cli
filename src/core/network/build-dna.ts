import * as crypto from 'crypto'
import { BuildRecord, BuildGraphEdge, BuildExplanation, CausalNode, ConfidenceBreakdown } from './build-types'

function sha256(data: string): string {
  return crypto.createHash('sha256').update(data).digest('hex')
}

function jaccard(a: Set<string>, b: Set<string>): number {
  const union = new Set([...a, ...b])
  if (union.size === 0) return 1
  const intersection = new Set([...a].filter(x => b.has(x)))
  return intersection.size / union.size
}

function numericSim(a: number, b: number, tol = 0.15): number {
  if (a === b) return 1
  const max = Math.max(a, b)
  if (max === 0) return 1
  const ratio = Math.min(a, b) / max
  return ratio >= (1 - tol) ? ratio : Math.max(0, ratio - tol) / (1 - tol)
}

function fprint(data: string): string {
  return sha256(data).substring(0, 16)
}

function sortedKeys(obj: Record<string, string>): string[] {
  return Object.entries(obj).map(([k, v]) => `${k}=${v}`).sort()
}

export function computeMultiDna(record: BuildRecord): {
  toolchain: string
  environment: string
  artifact: string
  network: string
  graph: string
  behavior: string
} {
  const tc = [...new Set(record.summary.uniqueProcesses)].sort().join(',')
  const env = sortedKeys(record.env).join('|')
  const art = record.artifactHashes.map(a => a.sha256).sort().join(',')
  const netHosts = [...new Set(record.network.map(n => n.host))].sort().join(',')
  const net = `${record.network.filter(n => n.type === 'tcp').length}tcp_${netHosts}`

  const shape: string[] = []
  function walk(nodes: typeof record.summary.processTree, d: number) {
    for (const n of nodes) { shape.push(`${' '.repeat(d)}${n.name}`); walk(n.children, d + 1) }
  }
  walk(record.summary.processTree, 0)
  const graph = shape.join('\n')

  const behaviorTokens: string[] = []
  const toolMap: Record<string, string> = {
    'gcc': 'compile', 'g++': 'compile', 'clang': 'compile', 'clang++': 'compile',
    'ld': 'link', 'link': 'link', 'ld.lld': 'link', 'lld-link': 'link',
    'ar': 'archive', 'lib.exe': 'archive', 'ranlib': 'archive',
    'strip': 'strip', 'objcopy': 'strip',
    'make': 'build-system', 'cmake': 'build-system', 'ninja': 'build-system',
    'configure': 'configure', 'autoconf': 'configure',
    'python': 'script', 'python3': 'script', 'node': 'script',
    'curl': 'download', 'wget': 'download',
    'docker': 'container', 'podman': 'container',
    'tar': 'package', 'zip': 'package',
  }
  for (const name of [...new Set(record.summary.uniqueProcesses)]) {
    const behavior = toolMap[name] || 'other'
    if (!behaviorTokens.includes(behavior)) behaviorTokens.push(behavior)
  }

  return {
    toolchain: fprint(tc),
    environment: fprint(env),
    artifact: fprint(art),
    network: fprint(net),
    graph: fprint(graph),
    behavior: fprint(behaviorTokens.join('->')),
  }
}

export function computeMultiDnaSimilarity(
  a: ReturnType<typeof computeMultiDna>,
  b: ReturnType<typeof computeMultiDna>,
) {
  const exact = (x: string, y: string) => x === y ? 1 : 0
  const toolSim = exact(a.toolchain, b.toolchain)
  const envSim = exact(a.environment, b.environment)
  const artSim = exact(a.artifact, b.artifact)
  const netSim = exact(a.network, b.network)
  const graphSim = exact(a.graph, b.graph)
  const behSim = exact(a.behavior, b.behavior)

  const weights = [0.2, 0.1, 0.25, 0.1, 0.2, 0.15]
  const overall = (
    toolSim * weights[0] + envSim * weights[1] + artSim * weights[2] +
    netSim * weights[3] + graphSim * weights[4] + behSim * weights[5]
  )

  return {
    overall: Math.round(overall * 1000) / 1000,
    toolchain: toolSim,
    environment: envSim,
    artifact: artSim,
    network: netSim,
    graph: graphSim,
    behavior: behSim,
  }
}

export function computeBuildDna(record: BuildRecord) {
  const toolchain = [...new Set(record.summary.uniqueProcesses)].sort()
  const envPairs = sortedKeys(record.env)
  const artifactDigests = record.artifactHashes.map(a => a.sha256).sort()

  const treeShape: string[] = []
  function walk(nodes: typeof record.summary.processTree, depth: number) {
    for (const n of nodes) {
      treeShape.push(`${' '.repeat(depth)}${n.name}`)
      walk(n.children, depth + 1)
    }
  }
  walk(record.summary.processTree, 0)
  const graphSig = sha256(treeShape.join('\n'))

  const netHosts = [...new Set(record.network.map(n => n.host))].sort()
  const netProfile = `${record.network.filter(n => n.type === 'tcp').length}tcp_${netHosts.join(',')}`

  return {
    toolchain,
    envVector: envPairs,
    artifactHashes: artifactDigests,
    processGraphSignature: graphSig,
    networkProfile: netProfile,
    totalFileOps: record.summary.filesCreated + record.summary.filesModified + record.summary.filesDeleted,
    durationMs: record.durationMs,
    anomalyCount: record.summary.anomalies.length,
  }
}

export function computeDnaSimilarity(a: ReturnType<typeof computeBuildDna>, b: ReturnType<typeof computeBuildDna>) {
  const toolSim = jaccard(new Set(a.toolchain), new Set(b.toolchain))
  const artSim = jaccard(new Set(a.artifactHashes), new Set(b.artifactHashes))
  const graphSim = a.processGraphSignature === b.processGraphSignature ? 1 : jaccard(
    new Set(a.processGraphSignature.match(/.{1,8}/g) || []),
    new Set(b.processGraphSignature.match(/.{1,8}/g) || []),
  )
  const netSim = jaccard(new Set(a.networkProfile.split(',')), new Set(b.networkProfile.split(',')))
  const opSim = numericSim(a.totalFileOps, b.totalFileOps)
  const durationSim = numericSim(a.durationMs, b.durationMs)
  const anomalySim = a.anomalyCount === b.anomalyCount ? 1 : 0.5

  const weights = [0.25, 0.25, 0.2, 0.1, 0.1, 0.05, 0.05]
  const overall = (
    toolSim * weights[0] + artSim * weights[1] + graphSim * weights[2] +
    netSim * weights[3] + opSim * weights[4] + durationSim * weights[5] + anomalySim * weights[6]
  )
  return { overall: Math.round(overall * 1000) / 1000, toolchain: toolSim, artifacts: artSim, processGraph: graphSim, network: netSim }
}

export function buildDnaFingerprint(dna: ReturnType<typeof computeBuildDna>): string {
  const parts = [
    `tc:${dna.toolchain.join(',')}`,
    `art:${dna.artifactHashes.length}`,
    `net:${dna.networkProfile}`,
    `ops:${dna.totalFileOps}`,
    `dur:${dna.durationMs}`,
    `anom:${dna.anomalyCount}`,
  ]
  return sha256(parts.join('|'))
}

export function inferBuildGraph(record: BuildRecord): BuildGraphEdge[] {
  const edges: BuildGraphEdge[] = []
  const procs = record.processes.filter(p => p.pid !== 0).sort((a, b) => a.timestamp - b.timestamp)

  for (const p of procs) {
    if (p.ppid && p.ppid !== p.pid) {
      edges.push({ from: p.pname || '?', to: p.name, type: 'spawned', fromPid: p.ppid, toPid: p.pid, timestamp: p.timestamp })
    }
  }

  const created = record.files.filter(f => f.operation === 'created').sort((a, b) => a.timestamp - b.timestamp)
  for (const f of created) {
    const fname = f.filePath.split(/[/\\]/).pop() || f.filePath
    const nearest = procs
      .filter(p => Math.abs(p.timestamp - f.timestamp) < 3000)
      .sort((a, b) => Math.abs(a.timestamp - f.timestamp) - Math.abs(b.timestamp - f.timestamp))
    if (nearest.length > 0) {
      edges.push({ from: nearest[0].name, to: fname, type: 'produced', fromPid: nearest[0].pid, timestamp: f.timestamp })
    }
  }

  return edges
}

export function deriveBehaviorChain(record: BuildRecord): string[] {
  const toolBehavior: Record<string, string> = {
    'configure': 'configure', 'autoconf': 'configure', 'automake': 'configure',
    'cmake': 'configure', 'meson': 'configure',
    'gcc': 'compile', 'g++': 'compile', 'clang': 'compile', 'clang++': 'compile', 'cc': 'compile', 'c++': 'compile',
    'ld': 'link', 'link': 'link', 'ld.lld': 'link', 'lld-link': 'link',
    'ar': 'archive', 'lib.exe': 'archive', 'ranlib': 'archive',
    'strip': 'strip', 'objcopy': 'strip',
    'make': 'build-system', 'ninja': 'build-system', 'nmake': 'build-system',
    'python': 'generate-script', 'python3': 'generate-script', 'node': 'generate-script',
    'curl': 'download', 'wget': 'download',
    'docker': 'containerize', 'podman': 'containerize',
    'tar': 'package', 'zip': 'package',
  }

  const seen = new Set<string>()
  const chain: string[] = []
  const procs = record.processes.filter(p => p.pid !== 0).sort((a, b) => a.timestamp - b.timestamp)
  for (const p of procs) {
    const beh = toolBehavior[p.name]
    if (beh && !seen.has(beh)) {
      seen.add(beh)
      chain.push(beh)
    }
  }
  return chain
}

export function generateExplanation(
  record: BuildRecord,
  graph: BuildGraphEdge[],
  prevRecord?: BuildRecord,
  multiDna?: ReturnType<typeof computeMultiDna>,
  prevMultiDna?: ReturnType<typeof computeMultiDna>,
): BuildExplanation {
  const reasons: string[] = []
  const changes: string[] = []
  let rootCause: string = 'No root cause identified'

  if (record.summary.anomalies.length > 0) {
    for (const a of record.summary.anomalies) {
      reasons.push(`Anomaly detected: ${a}`)
    }
  }

  if (prevRecord && multiDna && prevMultiDna) {
    const sim = computeMultiDnaSimilarity(multiDna, prevMultiDna)

    if (sim.toolchain < 1) {
      reasons.push('Toolchain changed')
      const oldTc = [...new Set(prevRecord.summary.uniqueProcesses)].sort()
      const newTc = [...new Set(record.summary.uniqueProcesses)].sort()
      const added = newTc.filter(t => !oldTc.includes(t))
      const removed = oldTc.filter(t => !newTc.includes(t))
      if (added.length > 0) changes.push(`NEW TOOL: ${added.join(', ')}`)
      if (removed.length > 0) changes.push(`REMOVED TOOL: ${removed.join(', ')}`)
    }

    if (sim.artifact < 1) {
      reasons.push('Artifact contents changed')
      const oldArts = new Set(prevRecord.artifactHashes.map(a => a.sha256))
      const newArts = new Set(record.artifactHashes.map(a => a.sha256))
      const added = record.artifactHashes.filter(a => !oldArts.has(a.sha256))
      const removed = prevRecord.artifactHashes.filter(a => !newArts.has(a.sha256))
      if (added.length > 0) {
        for (const a of added) changes.push(`NEW ARTIFACT: ${a.filePath.split(/[/\\]/).pop()} (SHA256 ${a.sha256.substring(0, 12)})`)
      }
      if (removed.length > 0) {
        for (const a of removed) changes.push(`REMOVED ARTIFACT: ${a.filePath.split(/[/\\]/).pop()} (SHA256 ${a.sha256.substring(0, 12)})`)
      }
    }

    if (sim.graph < 1) {
      reasons.push('Process graph structure changed')
      const prevGraph = inferBuildGraph(prevRecord)
      const newEdges = graph.filter(e => !prevGraph.some(p => p.from === e.from && p.to === e.to && p.type === e.type))
      const removedEdges = prevGraph.filter(e => !graph.some(p => p.from === e.from && p.to === e.to && p.type === e.type))
      for (const e of newEdges.slice(0, 5)) changes.push(`NEW EDGE: ${e.from} ${arrow(e.type)} ${e.to}`)
      for (const e of removedEdges.slice(0, 5)) changes.push(`REMOVED EDGE: ${e.from} ${arrow(e.type)} ${e.to}`)

      if (newEdges.length > 0) {
        rootCause = `New process relationship detected: ${newEdges[0].from} ${arrow(newEdges[0].type)} ${newEdges[0].to}`
      }
    }

    if (sim.network < 1) {
      reasons.push('Network profile changed')
      const prevHosts = new Set(prevRecord.network.map(n => n.host))
      const currHosts = new Set(record.network.map(n => n.host))
      const newHosts = [...currHosts].filter(h => !prevHosts.has(h))
      for (const h of newHosts) changes.push(`NEW NETWORK: ${h}`)
    }

    if (sim.environment < 1) {
      reasons.push('Environment changed')
      const prevEnv = prevRecord.env
      const currEnv = record.env
      for (const k of Object.keys({ ...prevEnv, ...currEnv })) {
        if (prevEnv[k] !== currEnv[k]) {
          changes.push(`ENV CHANGED: ${k} = ${currEnv[k] || '(unset)'} (was ${prevEnv[k] || '(unset)'})`)
        }
      }
    }
  }

  if (record.network.length > 0 && reasons.length === 0) {
    reasons.push('Network connections observed during build')
  }

  const fileOps = record.summary.filesCreated + record.summary.filesModified + record.summary.filesDeleted
  if (fileOps > 0 && reasons.length === 0 && changes.length === 0) {
    reasons.push(`${fileOps} file operation${fileOps > 1 ? 's' : ''} during build`)
  }

  if (rootCause === 'No root cause identified' && reasons.length > 0) {
    rootCause = reasons[0]
  }

  const summary = reasons.length > 0
    ? reasons[0] + (reasons.length > 1 ? ` (${reasons.length - 1} more reason${reasons.length > 2 ? 's' : ''})` : '')
    : 'Build matches expected pattern'

  const conf = reasons.length === 0 ? 1 : Math.max(0, 1 - reasons.length * 0.15)
  const confLabel = conf >= 0.8 ? 'HIGH' : conf >= 0.5 ? 'MODERATE' : 'LOW'

  const breakdown = computeConfidenceBreakdown(record, multiDna, prevMultiDna)

  return {
    summary,
    confidence: conf,
    confidenceLabel: confLabel,
    confidenceBreakdown: breakdown,
    reasons,
    changes,
    rootCause,
    causalDag: [],
  }
}

function computeConfidenceBreakdown(
  record: BuildRecord,
  multiDna?: ReturnType<typeof computeMultiDna>,
  prevMultiDna?: ReturnType<typeof computeMultiDna>,
): ConfidenceBreakdown {
  const toolchain = multiDna && prevMultiDna ? (multiDna.toolchain === prevMultiDna.toolchain ? 1 : 0.2) : 0.5
  const environment = multiDna && prevMultiDna ? (multiDna.environment === prevMultiDna.environment ? 1 : 0.3) : 0.5
  const artifact = multiDna && prevMultiDna ? (multiDna.artifact === prevMultiDna.artifact ? 1 : 0.1) : 0.5
  const network = multiDna && prevMultiDna ? (multiDna.network === prevMultiDna.network ? 1 : 0.3) : 0.5
  const graph = multiDna && prevMultiDna ? (multiDna.graph === prevMultiDna.graph ? 1 : 0.2) : 0.5
  const behavior = multiDna && prevMultiDna ? (multiDna.behavior === prevMultiDna.behavior ? 1 : 0.3) : 0.5

  const nSignals = record.summary.anomalies.length + (record.network.length > 0 ? 1 : 0) + (record.summary.totalProcesses > 0 ? 1 : 0)
  const diversity = new Set(record.summary.anomalies.concat(record.network.map(n => n.type)).concat(record.files.map(f => f.operation))).size
  const severityBonus = record.summary.anomalies.length > 0 ? 0.2 : 0

  const weights = [0.2, 0.1, 0.25, 0.1, 0.2, 0.15]
  const overall = toolchain * weights[0] + environment * weights[1] + artifact * weights[2] +
    network * weights[3] + graph * weights[4] + behavior * weights[5]

  return {
    overall: Math.round(overall * 1000) / 1000,
    toolchain, environment, artifact, network, graph, behavior,
    nSignals, diversity, severityBonus,
  }
}

function arrow(type: string): string {
  switch (type) {
    case 'produced': return '->'
    case 'consumed': return '<-'
    case 'spawned': return '=>'
    case 'configured': return '~~'
    default: return '--'
  }
}
