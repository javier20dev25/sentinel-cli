import {
  EvidenceSource,
  BuildProcessEvent,
  FileReadEvent,
  BuildNetEvent,
  BuildFileEvent,
  ObservationConfidence,
  EvidenceGraph,
  EvidenceEdge,
  EvidenceNode,
  EvidenceRelation,
  ConfidencePath,
} from './build-types'

const SOURCE_CONFIDENCE: Record<EvidenceSource, number> = {
  etw: 98,
  ebpf: 97,
  auditd: 95,
  ftrace: 94,
  endpoint_security: 96,
  procfs: 85,
  handle: 78,
  cim_query: 82,
  ps: 72,
  polling: 65,
  mtime_heuristic: 42,
  process_maps: 88,
  named_pipe: 70,
}

export const SIGNAL_WEIGHTS: Record<string, number> = {
  processes: 0.25,
  files: 0.20,
  network: 0.15,
  reads: 0.15,
  compiler_invocations: 0.10,
  secret_flow: 0.05,
  path_resolution: 0.05,
  identity: 0.05,
}

const RELATION_DEGRADATION: Record<EvidenceRelation, number> = {
  spawned: 0.05,
  read: 0.15,
  wrote: 0.20,
  created: 0.10,
  modified: 0.20,
  deleted: 0.20,
  compiled: 0.10,
  linked: 0.10,
  archived: 0.15,
  generated: 0.15,
  downloaded: 0.20,
  configured: 0.15,
  uploaded: 0.10,
  exfiltrated: 0.05,
  loaded: 0.10,
  accessed: 0.10,
  connected: 0.15,
  triggered: 0.10,
  heuristic_association: 0.40,
}

export function evidenceConfidence(source: EvidenceSource): number {
  return SOURCE_CONFIDENCE[source] ?? 50
}

export function processConfidence(proc: BuildProcessEvent): number {
  const base = proc.source ? evidenceConfidence(proc.source) : 65
  const hasExit = proc.exitTime != null ? 5 : 0
  const hasStart = proc.startTime != null ? 5 : 0
  return Math.min(100, base + hasExit + hasStart)
}

export function fileReadConfidence(event: FileReadEvent): number {
  const base = event.source ? evidenceConfidence(event.source) : 50
  const hasSize = event.size > 0 ? 5 : 0
  return Math.min(100, base + hasSize)
}

export function netEventConfidence(event: BuildNetEvent): number {
  const base = event.source ? evidenceConfidence(event.source) : 60
  const hasPort = event.port != null ? 5 : 0
  return Math.min(100, base + hasPort)
}

export function fileEventConfidence(event: BuildFileEvent): number {
  const base = event.source ? evidenceConfidence(event.source) : 50
  const hasSha256 = event.sha256 != null ? 10 : 0
  return Math.min(100, base + hasSha256)
}

export interface CoverageResult {
  observed: number
  expected: number
  ratio: number
}

export function computeObservationConfidence(
  processes: BuildProcessEvent[],
  files: BuildFileEvent[],
  network: BuildNetEvent[],
  reads: FileReadEvent[],
): ObservationConfidence {
  const processConfidences = processes.map(p => processConfidence(p))
  const fileConfidences = files.map(f => fileEventConfidence(f))
  const netConfidences = network.map(n => netEventConfidence(n))
  const readConfidences = reads.map(r => fileReadConfidence(r))

  const allConfidences = [...processConfidences, ...fileConfidences, ...netConfidences, ...readConfidences]
  const avgProc = average(processConfidences)
  const avgFiles = average(fileConfidences)
  const avgNet = average(netConfidences)
  const avgReads = average(readConfidences)

  const signals: Record<string, number> = {}
  signals.processes = avgProc
  signals.files = avgFiles
  signals.network = avgNet
  signals.reads = avgReads

  const signalValues = Object.values(signals).filter(v => !isNaN(v))
  const overall = signalValues.length > 0
    ? Math.round(weightedAverage(signalValues, getWeights(signalValues.length)))
    : 0

  const sources = new Set<EvidenceSource>()
  for (const p of processes) if (p.source) sources.add(p.source)
  for (const f of files) if (f.source) sources.add(f.source)
  for (const n of network) if (n.source) sources.add(n.source)
  for (const r of reads) if (r.source) sources.add(r.source)

  const coverage = allConfidences.length > 0
    ? Math.round(allConfidences.filter(c => c >= 50).length / allConfidences.length * 100)
    : 0

  return {
    overall,
    signals,
    coverage,
    sources: [...sources],
    weakestSignal: signalValues.length > 0 ? Math.min(...signalValues) : 0,
    strongestSignal: signalValues.length > 0 ? Math.max(...signalValues) : 0,
  }
}

function average(values: number[]): number {
  const valid = values.filter(v => !isNaN(v))
  return valid.length > 0 ? Math.round(valid.reduce((a, b) => a + b, 0) / valid.length) : 0
}

function weightedAverage(values: number[], weights: number[]): number {
  const totalWeight = weights.reduce((a, b) => a + b, 0)
  if (totalWeight === 0) return 0
  return values.reduce((sum, v, i) => sum + v * weights[i], 0) / totalWeight
}

function getWeights(count: number): number[] {
  const w = [0.35, 0.30, 0.20, 0.15]
  return w.slice(0, count)
}

export const OBSERVATION_LABELS: Record<string, string> = {
  processes: 'Process Events',
  files: 'File Events',
  network: 'Network Events',
  reads: 'File Read Events',
}

export function renderObservationConfidence(oc: ObservationConfidence): string[] {
  const lines: string[] = [
    'Observation Confidence',
    '======================',
    `  Overall: ${oc.overall}/100`,
    `  Coverage: ${oc.coverage}%`,
    `  Sources: ${oc.sources.join(', ') || 'none'}`,
    `  Weakest signal: ${oc.weakestSignal}`,
    `  Strongest signal: ${oc.strongestSignal}`,
    '',
    '  Signal Breakdown:',
  ]
  for (const [key, val] of Object.entries(oc.signals)) {
    const label = OBSERVATION_LABELS[key] || key
    lines.push(`    ${label}: ${val}/100`)
  }
  return lines
}

// ── Confidence Propagation ────────────────────────────────────

export function relationDegradation(relation: EvidenceRelation): number {
  return RELATION_DEGRADATION[relation] ?? 0.30
}

export function propagateConfidence(
  initialConfidence: number,
  edges: EvidenceEdge[],
): number {
  let confidence = initialConfidence
  for (const edge of edges) {
    confidence = confidence * (1 - edge.degradation)
  }
  return Math.max(0, Math.round(confidence))
}

export function propagateGraphConfidence(graph: EvidenceGraph): EvidenceGraph {
  const nodeMap = new Map(graph.nodes.map(n => [n.id, { ...n }]))
  const inDegree = new Map<string, number>()
  const queue: string[] = []

  for (const node of graph.nodes) {
    inDegree.set(node.id, 0)
  }
  for (const edge of graph.edges) {
    inDegree.set(edge.to, (inDegree.get(edge.to) || 0) + 1)
  }
  for (const [id, deg] of inDegree) {
    if (deg === 0) queue.push(id)
  }

  let processed = 0
  while (queue.length > 0) {
    const currentId = queue.shift()!
    const currentNode = nodeMap.get(currentId)!
    processed++
    const outEdges = graph.edges.filter(e => e.from === currentId)

    for (const edge of outEdges) {
      const targetNode = nodeMap.get(edge.to)
      if (!targetNode) continue

      const propagated = currentNode.confidence * (1 - edge.degradation) / 100
      const existing = targetNode.confidence / 100
      const combined = 1 - (1 - existing) * (1 - propagated)
      targetNode.confidence = Math.round(Math.min(100, combined * 100))

      const existingInf = targetNode.inferenceConfidence / 100
      const combinedInf = 1 - (1 - existingInf) * (1 - propagated)
      targetNode.inferenceConfidence = Math.round(Math.min(100, combinedInf * 100))

      const targetInDeg = (inDegree.get(edge.to) || 1) - 1
      inDegree.set(edge.to, Math.max(0, targetInDeg))
      if (targetInDeg === 0) {
        queue.push(edge.to)
      }
    }
  }

  const unprocessed = graph.nodes.length - processed
  if (unprocessed > 0) {
    const unprocessedIds = new Set(graph.nodes.map(n => n.id))
    for (const [id] of nodeMap) unprocessedIds.delete(id)
    for (const [id] of inDegree) {
      if ((inDegree.get(id) || 0) > 0) {
        const cyclicIds = new Set<string>()

        function traverseCycle(start: string): void {
          const seen = new Set<string>()
          const stack = [start]
          while (stack.length > 0) {
            const c = stack.pop()!
            if (seen.has(c)) { cyclicIds.add(c); continue }
            seen.add(c)
            for (const e of graph.edges) {
              if (e.from === c && (inDegree.get(e.to) || 0) > 0) { stack.push(e.to) }
            }
          }
        }

        traverseCycle(id)
        for (const cid of cyclicIds) {
          const cn = nodeMap.get(cid)
          if (cn) cn.confidence = Math.round(cn.confidence * 0.95)
        }
      }
    }
  }

  return {
    ...graph,
    nodes: [...nodeMap.values()],
  }
}

export function findConfidencePaths(
  graph: EvidenceGraph,
  fromId: string,
  toId: string,
  maxDepth = 10,
): ConfidencePath[] {
  const paths: ConfidencePath[] = []

  function dfs(
    current: string,
    target: string,
    visited: Set<string>,
    pathEdges: EvidenceEdge[],
  ) {
    if (pathEdges.length > maxDepth) return
    if (current === target) {
      const initialNode = graph.nodes.find(n => n.id === pathEdges[0]?.from || fromId)
      const initialConfidence = initialNode?.confidence || 80
      const propagated = propagateConfidence(initialConfidence, pathEdges)
      const degradationFactor = pathEdges.length > 0
        ? 1 - pathEdges.reduce((p, e) => p * (1 - e.degradation), 1)
        : 0

      paths.push({
        path: [fromId, ...pathEdges.map(e => e.to)],
        edges: pathEdges.map(e => e.relation),
        initialConfidence,
        propagatedConfidence: propagated,
        degradationFactor: Math.round(degradationFactor * 100),
      })
      return
    }

    for (const edge of graph.edges) {
      if (edge.from === current && !visited.has(edge.to)) {
        visited.add(edge.to)
        pathEdges.push(edge)
        dfs(edge.to, target, visited, pathEdges)
        pathEdges.pop()
        visited.delete(edge.to)
      }
    }
  }

  const visited = new Set([fromId])
  dfs(fromId, toId, visited, [])
  paths.sort((a, b) => b.propagatedConfidence - a.propagatedConfidence)
  return paths
}

export function propagateFromSeed(
  graph: EvidenceGraph,
  seedNodeId: string,
  maxDepth = 10,
): EvidenceGraph {
  const nodeMap = new Map(graph.nodes.map(n => [n.id, { ...n }]))
  const visited = new Set<string>()
  const queue: Array<{ id: string; depth: number }> = [{ id: seedNodeId, depth: 0 }]
  visited.add(seedNodeId)

  while (queue.length > 0) {
    const { id: currentId, depth } = queue.shift()!
    if (depth >= maxDepth) continue

    const currentNode = nodeMap.get(currentId)
    if (!currentNode) continue

    const outEdges = graph.edges.filter(e => e.from === currentId)
    for (const edge of outEdges) {
      if (visited.has(edge.to)) continue
      visited.add(edge.to)
      const targetNode = nodeMap.get(edge.to)
      if (!targetNode) continue

      const propagated = currentNode.confidence * (1 - edge.degradation) / 100
      const existing = targetNode.confidence / 100
      const combined = 1 - (1 - existing) * (1 - propagated)
      targetNode.confidence = Math.round(Math.min(100, combined * 100))

      const existingInf = targetNode.inferenceConfidence / 100
      const combinedInf = 1 - (1 - existingInf) * (1 - propagated)
      targetNode.inferenceConfidence = Math.round(Math.min(100, combinedInf * 100))
      queue.push({ id: edge.to, depth: depth + 1 })
    }
  }

  return {
    ...graph,
    nodes: [...nodeMap.values()],
  }
}

export function renderConfidencePaths(paths: ConfidencePath[], maxPaths = 5): string[] {
  if (paths.length === 0) return ['No confidence paths found']

  const lines: string[] = [
    'Confidence Propagation Paths',
    '============================',
    `  Found ${paths.length} path(s)`,
    '',
  ]

  for (const path of paths.slice(0, maxPaths)) {
    const pathStr = path.edges.join(' → ') || 'direct'
    lines.push(`  ${path.initialConfidence} → ${path.propagatedConfidence} (${path.degradationFactor}% degradation)`)
    lines.push(`    Path: ${pathStr}`)
    lines.push('')
  }

  return lines
}

export function renderConfidencePropagation(graph: EvidenceGraph): string[] {
  const lines: string[] = [
    'Confidence Propagation',
    '======================',
    `  Nodes before: ${graph.nodes.length}`,
    `  Edges: ${graph.edges.length}`,
    '',
  ]

  const propagated = propagateGraphConfidence(graph)
  const changes = graph.nodes.filter((n, i) => {
    const after = propagated.nodes[i]
    return after && n.confidence !== after.confidence
  })

  if (changes.length > 0) {
    lines.push('  Propagated changes:')
    for (const node of changes) {
      const after = propagated.nodes.find(n => n.id === node.id)
      if (after && after.confidence !== node.confidence) {
        const arrow = after.confidence < node.confidence ? '↓' : '↑'
        lines.push(`    ${node.label}: ${node.confidence} ${arrow} ${after.confidence}`)
      }
    }
  } else {
    lines.push('  No propagation changes (all nodes are roots or saturated)')
  }

  return lines
}
