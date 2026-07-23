import {
  EvidenceGraph, EvidenceEdge, EvidenceNode, EvidenceRelation,
  TemporalEvidenceGraph, TemporalPath, BayesianNetwork, BayesianRelation,
  DominatorAnalysis, EvidenceGraphMetrics, EVIDENCE_SCHEMA_VERSION,
} from './build-types'

// ── Temporal Evidence Graph ─────────────────────────────────────
export function buildTemporalEvidenceGraph(graph: EvidenceGraph): TemporalEvidenceGraph {
  const nodeMap = new Map<string, EvidenceNode>()
  for (const n of graph.nodes) nodeMap.set(n.id, n)

  // Compute edge latencies from node timestamps
  const edges = graph.edges.map(e => {
    if (e.latencyMs !== undefined) return e
    const fromNode = nodeMap.get(e.from)
    const toNode = nodeMap.get(e.to)
    if (fromNode && toNode) {
      const latencyMs = Math.max(0, toNode.timestamp - fromNode.timestamp)
      return { ...e, latencyMs }
    }
    return e
  })

  // BFS from root to find all paths
  const outgoing = new Map<string, EvidenceEdge[]>()
  for (const e of edges) {
    if (!outgoing.has(e.from)) outgoing.set(e.from, [])
    outgoing.get(e.from)!.push(e)
  }

  const paths: TemporalPath[] = []
  const visited = new Set<string>()

  function dfs(current: string, pathNodes: string[], pathEdges: EvidenceEdge[]): void {
    if (visited.has(current)) return
    visited.add(current)

    const children = outgoing.get(current) || []
    if (children.length === 0) {
      // Leaf: record path
      const totalLatencyMs = pathEdges.reduce((s, e) => s + (e.latencyMs || 0), 0)
      const causalDelayMs = pathEdges.reduce((s, e) => s + (e.causalDelayMs || e.latencyMs || 0), 0)
      const timestamps = pathNodes.map(id => nodeMap.get(id)?.timestamp || 0)
      const timeSpanMs = timestamps.length > 0
        ? Math.max(...timestamps) - Math.min(...timestamps)
        : 0
      const bottleneckEdge = pathEdges.reduce(
        (max, e) => (e.latencyMs || 0) > (max?.latencyMs || 0) ? e : max,
        undefined as EvidenceEdge | undefined,
      )
      paths.push({
        nodes: [...pathNodes],
        edges: [...pathEdges],
        totalLatencyMs,
        causalDelayMs,
        timeSpanMs,
        bottleneckEdge,
      })
    } else {
      for (const child of children) {
        dfs(child.to, [...pathNodes, child.to], [...pathEdges, child])
      }
    }

    visited.delete(current)
  }

  // Start from root
  const root = graph.nodes.find(n => !graph.edges.some(e => e.to === n.id))
  if (root) {
    dfs(root.id, [root.id], [])
  }

  const longestCausalChain = paths.reduce(
    (max, p) => (p.nodes.length > max.nodes.length ? p : max),
    paths[0] || { nodes: [], edges: [], totalLatencyMs: 0, causalDelayMs: 0, timeSpanMs: 0 },
  )

  const criticalPath = paths.reduce(
    (max, p) => (p.causalDelayMs > max.causalDelayMs ? p : max),
    paths[0] || { nodes: [], edges: [], totalLatencyMs: 0, causalDelayMs: 0, timeSpanMs: 0 },
  )

  const latencies = edges.map(e => e.latencyMs || 0).filter(l => l > 0)
  const avgEdgeLatencyMs = latencies.length > 0
    ? Math.round(latencies.reduce((s, l) => s + l, 0) / latencies.length)
    : 0
  const maxEdgeLatencyMs = latencies.length > 0 ? Math.max(...latencies) : 0

  return {
    graph,
    paths,
    longestCausalChain,
    avgEdgeLatencyMs,
    maxEdgeLatencyMs,
    criticalPath,
  }
}

export function renderTemporalEvidenceGraph(teg: TemporalEvidenceGraph): string[] {
  const lines: string[] = [
    'Temporal Evidence Graph',
    '=======================',
    `  Total paths: ${teg.paths.length}`,
    `  Avg edge latency: ${teg.avgEdgeLatencyMs}ms`,
    `  Max edge latency: ${teg.maxEdgeLatencyMs}ms`,
    `  Longest causal chain: ${teg.longestCausalChain.nodes.length} nodes`,
    `  Critical path latency: ${teg.criticalPath.causalDelayMs}ms`,
    '',
    '  Paths by latency:',
  ]

  const sorted = [...teg.paths].sort((a, b) => b.totalLatencyMs - a.totalLatencyMs)
  for (const p of sorted.slice(0, 5)) {
    const label = p.nodes.map(id => {
      const node = teg.graph.nodes.find(n => n.id === id)
      return node?.label || id.substring(0, 8)
    }).join(' → ')
    lines.push(`    ${label} (${p.totalLatencyMs}ms, ${p.nodes.length} nodes)`)
  }
  if (sorted.length > 5) lines.push(`    ... and ${sorted.length - 5} more`)

  return lines
}

// ── Bayesian Network ────────────────────────────────────────────
const DEFAULT_BAYESIAN_PRIORS: Record<EvidenceRelation, { prior: number; likelihoodPos: number; likelihoodNeg: number }> = {
  spawned:       { prior: 0.95, likelihoodPos: 0.99, likelihoodNeg: 0.01 },
  compiled:      { prior: 0.90, likelihoodPos: 0.98, likelihoodNeg: 0.02 },
  accessed:      { prior: 0.70, likelihoodPos: 0.90, likelihoodNeg: 0.10 },
  connected:     { prior: 0.60, likelihoodPos: 0.85, likelihoodNeg: 0.15 },
  created:       { prior: 0.80, likelihoodPos: 0.95, likelihoodNeg: 0.05 },
  modified:      { prior: 0.75, likelihoodPos: 0.92, likelihoodNeg: 0.08 },
  deleted:       { prior: 0.50, likelihoodPos: 0.80, likelihoodNeg: 0.20 },
  read:          { prior: 0.65, likelihoodPos: 0.88, likelihoodNeg: 0.12 },
  wrote:         { prior: 0.75, likelihoodPos: 0.92, likelihoodNeg: 0.08 },
  linked:        { prior: 0.85, likelihoodPos: 0.96, likelihoodNeg: 0.04 },
  archived:      { prior: 0.70, likelihoodPos: 0.88, likelihoodNeg: 0.12 },
  uploaded:      { prior: 0.30, likelihoodPos: 0.70, likelihoodNeg: 0.30 },
  exfiltrated:   { prior: 0.10, likelihoodPos: 0.60, likelihoodNeg: 0.40 },
  configured:    { prior: 0.70, likelihoodPos: 0.90, likelihoodNeg: 0.10 },
  loaded:        { prior: 0.75, likelihoodPos: 0.92, likelihoodNeg: 0.08 },
  triggered:     { prior: 0.40, likelihoodPos: 0.75, likelihoodNeg: 0.25 },
  generated:     { prior: 0.80, likelihoodPos: 0.95, likelihoodNeg: 0.05 },
  downloaded:    { prior: 0.35, likelihoodPos: 0.72, likelihoodNeg: 0.28 },
  heuristic_association: { prior: 0.50, likelihoodPos: 0.80, likelihoodNeg: 0.20 },
}

export function buildBayesianNetwork(graph: EvidenceGraph): BayesianNetwork {
  const relationCounts = new Map<EvidenceRelation, { pos: number; neg: number }>()
  for (const edge of graph.edges) {
    if (!relationCounts.has(edge.relation)) {
      relationCounts.set(edge.relation, { pos: 0, neg: 0 })
    }
    const counts = relationCounts.get(edge.relation)!
    if (edge.confidence > 0.5) counts.pos++
    else counts.neg++
  }

  const relations: BayesianRelation[] = []
  for (const [relation, counts] of relationCounts) {
    const defaults = DEFAULT_BAYESIAN_PRIORS[relation] || { prior: 0.5, likelihoodPos: 0.7, likelihoodNeg: 0.3 }
    const total = counts.pos + counts.neg
    const priorP = total > 0 ? counts.pos / total : defaults.prior
    const likelihoodPositive = total > 0
      ? (counts.pos / total) * 0.9 + defaults.likelihoodPos * 0.1
      : defaults.likelihoodPos
    const likelihoodNegative = total > 0
      ? (counts.neg / total) * 0.9 + defaults.likelihoodNeg * 0.1
      : defaults.likelihoodNeg

    // Bayes: P(positive|evidence) = P(evidence|positive) * P(positive) / P(evidence)
    const pEvidence = likelihoodPositive * priorP + likelihoodNegative * (1 - priorP)
    const posteriorGivenEvidence = pEvidence > 0
      ? (likelihoodPositive * priorP) / pEvidence
      : priorP
    const posteriorGivenNoEvidence = (1 - likelihoodPositive) * priorP > 0
      ? ((1 - likelihoodPositive) * priorP) / ((1 - likelihoodPositive) * priorP + (1 - likelihoodNegative) * (1 - priorP))
      : priorP

    relations.push({
      relation,
      priorP: Math.round(priorP * 1000) / 1000,
      likelihoodPositive: Math.round(likelihoodPositive * 1000) / 1000,
      likelihoodNegative: Math.round(likelihoodNegative * 1000) / 1000,
      posteriorGivenEvidence: Math.round(posteriorGivenEvidence * 1000) / 1000,
      posteriorGivenNoEvidence: Math.round(posteriorGivenNoEvidence * 1000) / 1000,
      sampleCount: total,
    })
  }

  // Global prior: weighted average of all priors
  const totalEdges = graph.edges.length
  const globalPrior = relations.length > 0
    ? relations.reduce((s, r) => s + r.priorP * r.sampleCount, 0) / totalEdges
    : 0.5

  // Overall posterior: combined evidence
  let posteriorProduct = 1
  for (const r of relations) {
    posteriorProduct *= (1 - r.posteriorGivenEvidence)
  }
  const overallPosterior = Math.round((1 - posteriorProduct) * 1000) / 1000

  return {
    relations,
    globalPrior: Math.round(globalPrior * 1000) / 1000,
    overallPosterior,
    calibrationVersion: EVIDENCE_SCHEMA_VERSION,
  }
}

export function renderBayesianNetwork(bn: BayesianNetwork): string[] {
  const lines: string[] = [
    'Bayesian Network',
    '================',
    `  Global prior: ${bn.globalPrior}`,
    `  Overall posterior: ${bn.overallPosterior}`,
    `  Calibration version: ${bn.calibrationVersion}`,
    '',
    '  Relation posteriors:',
  ]

  const sorted = [...bn.relations].sort((a, b) => b.posteriorGivenEvidence - a.posteriorGivenEvidence)
  for (const r of sorted) {
    const delta = r.posteriorGivenEvidence - r.priorP
    const deltaStr = delta >= 0 ? `+${delta.toFixed(3)}` : delta.toFixed(3)
    lines.push(`    ${r.relation}: prior=${r.priorP} posterior=${r.posteriorGivenEvidence} (Δ${deltaStr}) n=${r.sampleCount}`)
  }

  return lines
}

// ── Dominator Analysis ──────────────────────────────────────────
export function analyzeDominators(
  current: EvidenceGraph,
  previous?: EvidenceGraph,
): DominatorAnalysis {
  // Extract immediate dominators from graph structure
  const incoming = new Map<string, string[]>()
  for (const n of current.nodes) incoming.set(n.id, [])
  for (const e of current.edges) incoming.get(e.to)?.push(e.from)

  const idoms: Record<string, string | null> = {}
  for (const n of current.nodes) idoms[n.id] = null

  // Iterative dominator algorithm
  let changed = true
  while (changed) {
    changed = false
    for (const node of current.nodes) {
      const preds = incoming.get(node.id) || []
      if (preds.length === 0) {
        if (idoms[node.id] !== node.id) { idoms[node.id] = node.id; changed = true }
        continue
      }
      let newIdom: string | null = null
      for (const p of preds) {
        if (idoms[p] !== null) {
          newIdom = newIdom === null ? p : idoms[intersectDomId(idoms, p, newIdom)]
        }
      }
      if (newIdom !== null && newIdom !== node.id && idoms[node.id] !== newIdom) {
        idoms[node.id] = newIdom
        changed = true
      }
    }
  }

  // Find root dominator (node that dominates everything)
  const dominatorCounts = new Map<string, number>()
  for (const [id, dom] of Object.entries(idoms)) {
    if (dom !== null && dom !== id) {
      dominatorCounts.set(dom, (dominatorCounts.get(dom) || 0) + 1)
    }
  }

  let dominantProcess: string | null = null
  let maxCount = 0
  for (const [id, count] of dominatorCounts) {
    if (count > maxCount) { maxCount = count; dominantProcess = id }
  }

  // Previous dominators
  let previousDominators: Record<string, string | null> | null = null
  let dominantProcessChanged = false
  let toolchainShiftDetected = false
  const anomalySignals: string[] = []

  if (previous) {
    const prevIncoming = new Map<string, string[]>()
    for (const n of previous.nodes) prevIncoming.set(n.id, [])
    for (const e of previous.edges) prevIncoming.get(e.to)?.push(e.from)
    const prevIdoms: Record<string, string | null> = {}
    for (const n of previous.nodes) prevIdoms[n.id] = null
    let prevChanged = true
    while (prevChanged) {
      prevChanged = false
      for (const node of previous.nodes) {
        const preds = prevIncoming.get(node.id) || []
        if (preds.length === 0) {
          if (prevIdoms[node.id] !== node.id) { prevIdoms[node.id] = node.id; prevChanged = true }
          continue
        }
        let newIdom: string | null = null
        for (const p of preds) {
          if (prevIdoms[p] !== null) {
            newIdom = newIdom === null ? p : prevIdoms[intersectDomId(prevIdoms, p, newIdom)]
          }
        }
        if (newIdom !== null && newIdom !== node.id && prevIdoms[node.id] !== newIdom) {
          prevIdoms[node.id] = newIdom
          prevChanged = true
        }
      }
    }
    previousDominators = prevIdoms

    // Compare
    const prevDomCounts = new Map<string, number>()
    for (const [, dom] of Object.entries(prevIdoms)) {
      if (dom !== null) prevDomCounts.set(dom, (prevDomCounts.get(dom) || 0) + 1)
    }
    let prevDominant: string | null = null
    let prevMax = 0
    for (const [id, count] of prevDomCounts) {
      if (count > prevMax) { prevMax = count; prevDominant = id }
    }

    if (prevDominant !== dominantProcess) {
      dominantProcessChanged = true
      anomalySignals.push(`Dominant process changed: ${prevDominant} → ${dominantProcess}`)
    }

    // Check for toolchain hijack: if the new dominant is not a known build tool
    const buildToolPatterns = ['gcc', 'clang', 'make', 'cmake', 'go', 'cargo', 'npm', 'node', 'python', 'pip', 'gradle', 'mvn', 'rustc', 'javac', 'tsc', 'webpack', 'rollup', 'esbuild', 'vite']
    if (dominantProcess) {
      const dominantLabel = current.nodes.find(n => n.id === dominantProcess)?.label || ''
      const isBuildTool = buildToolPatterns.some(t => dominantLabel.toLowerCase().includes(t))
      if (!isBuildTool) {
        toolchainShiftDetected = true
        anomalySignals.push(`Non-build-tool dominant: ${dominantLabel}`)
      }
    }
  }

  // Dominant path
  const dominantPath: string[] = []
  if (dominantProcess) {
    let current = dominantProcess
    const seen = new Set<string>()
    while (current && !seen.has(current)) {
      seen.add(current)
      dominantPath.unshift(current)
      current = idoms[current] || current
      if (current === dominantProcess) break
    }
  }

  const hijackRiskScore = toolchainShiftDetected ? 0.85
    : dominantProcessChanged ? 0.5
    : anomalySignals.length > 0 ? 0.3
    : 0.0

  return {
    currentDominators: idoms,
    previousDominators,
    dominantProcess,
    dominantProcessChanged,
    toolchainShiftDetected,
    hijackRiskScore,
    dominantPath,
    anomalySignals,
  }
}

function intersectDomId(idoms: Record<string, string | null>, f1: string, f2: string): string {
  let a: string | null = f1
  let b: string | null = f2
  while (a !== b) {
    while (a !== null && (idoms[a] === null || a > b!)) a = idoms[a]
    while (b !== null && (idoms[b] === null || b > a!)) b = idoms[b]
  }
  return a!
}

export function renderDominatorAnalysis(analysis: DominatorAnalysis): string[] {
  const lines: string[] = [
    'Dominator Analysis',
    '==================',
    `  Dominant process: ${analysis.dominantProcess || 'none'}`,
    `  Dominant changed: ${analysis.dominantProcessChanged}`,
    `  Toolchain shift: ${analysis.toolchainShiftDetected}`,
    `  Hijack risk: ${(analysis.hijackRiskScore * 100).toFixed(1)}%`,
  ]

  if (analysis.anomalySignals.length > 0) {
    lines.push('', '  Anomaly signals:')
    for (const s of analysis.anomalySignals) {
      lines.push(`    ⚠ ${s}`)
    }
  }

  if (analysis.dominantPath.length > 0) {
    lines.push('', '  Dominant path:')
    lines.push(`    ${analysis.dominantPath.join(' → ')}`)
  }

  return lines
}

// ── Graph Metrics (full) ────────────────────────────────────────
export function computeFullGraphMetrics(
  graph: EvidenceGraph,
  teg?: TemporalEvidenceGraph,
  bn?: BayesianNetwork,
  da?: DominatorAnalysis,
): EvidenceGraphMetrics {
  const n = graph.nodes.length
  const nodeIds = graph.nodes.map(nd => nd.id)

  // Basic
  const nodeCount = n
  const edgeCount = graph.edges.length
  const graphDensity = n > 1 ? Math.round((edgeCount / (n * (n - 1))) * 10000) / 10000 : 0

  // Entropy
  const typeCounts = new Map<string, number>()
  for (const node of graph.nodes) typeCounts.set(node.type, (typeCounts.get(node.type) || 0) + 1)
  let entropy = 0
  for (const count of typeCounts.values()) {
    const p = count / n
    entropy -= p * Math.log2(p)
  }
  const maxEntropy = typeCounts.size > 0 ? Math.log2(typeCounts.size) : 1
  const graphEntropy = maxEntropy > 0 ? Math.round((entropy / maxEntropy) * 1000) / 1000 : 0

  // DAG detection
  const visited = new Set<string>()
  const recStack = new Set<string>()
  let hasCycle = false
  const outgoing = new Map<string, string[]>()
  for (const id of nodeIds) outgoing.set(id, [])
  for (const e of graph.edges) outgoing.get(e.from)?.push(e.to)
  function dfsCycle(id: string): void {
    if (hasCycle) return
    visited.add(id); recStack.add(id)
    for (const next of outgoing.get(id) || []) {
      if (!visited.has(next)) dfsCycle(next)
      else if (recStack.has(next)) hasCycle = true
    }
    recStack.delete(id)
  }
  for (const id of nodeIds) { if (!visited.has(id)) dfsCycle(id); if (hasCycle) break }
  const isDag = !hasCycle

  // SCC count (Kosaraju if cyclic)
  let sccCount = n
  if (hasCycle) {
    const visited2 = new Set<string>()
    const order: string[] = []
    function dfsOrder(id: string): void {
      visited2.add(id)
      for (const next of outgoing.get(id) || []) { if (!visited2.has(next)) dfsOrder(next) }
      order.push(id)
    }
    for (const id of nodeIds) if (!visited2.has(id)) dfsOrder(id)
    const incoming = new Map<string, string[]>()
    for (const id of nodeIds) incoming.set(id, [])
    for (const e of graph.edges) incoming.get(e.to)?.push(e.from)
    const visited3 = new Set<string>()
    function dfsReverse(id: string): void {
      visited3.add(id)
      for (const prev of incoming.get(id) || []) { if (!visited3.has(prev)) dfsReverse(prev) }
    }
    sccCount = 0
    for (const id of order.reverse()) { if (!visited3.has(id)) { sccCount++; dfsReverse(id) } }
  }

  // Max depth (DFS from roots)
  const incomingMap = new Map<string, string[]>()
  for (const id of nodeIds) incomingMap.set(id, [])
  for (const e of graph.edges) incomingMap.get(e.to)?.push(e.from)
  const roots = nodeIds.filter(id => incomingMap.get(id)?.length === 0)
  let maxDepth = 0
  const depthCache = new Map<string, number>()
  function dfsDepth(id: string, depth: number): number {
    if (depthCache.has(id)) return depthCache.get(id)!
    let max = depth
    for (const next of outgoing.get(id) || []) {
      max = Math.max(max, dfsDepth(next, depth + 1))
    }
    depthCache.set(id, max)
    return max
  }
  for (const root of roots) maxDepth = Math.max(maxDepth, dfsDepth(root, 0))

  // Component count (weakly connected)
  const visitedComp = new Set<string>()
  let componentCount = 0
  const bidirectional = new Map<string, string[]>()
  for (const id of nodeIds) bidirectional.set(id, [])
  for (const e of graph.edges) {
    bidirectional.get(e.from)?.push(e.to)
    bidirectional.get(e.to)?.push(e.from)
  }
  function dfsComp(id: string): void {
    visitedComp.add(id)
    for (const next of bidirectional.get(id) || []) { if (!visitedComp.has(next)) dfsComp(next) }
  }
  for (const id of nodeIds) { if (!visitedComp.has(id)) { componentCount++; dfsComp(id) } }

  // Centrality (betweenness + closeness)
  const betweenness: Record<string, number> = {}
  const closeness: Record<string, number> = {}
  for (const id of nodeIds) { betweenness[id] = 0; closeness[id] = 0 }

  for (const s of nodeIds) {
    const stack: string[] = []
    const paths = new Map<string, string[][]>()
    const sigma = new Map<string, number>()
    const d = new Map<string, number>()
    const delta = new Map<string, number>()
    for (const id of nodeIds) { paths.set(id, []); sigma.set(id, 0); delta.set(id, 0) }
    sigma.set(s, 1); d.set(s, 0)
    const q = [s]
    for (let i = 0; i < q.length; i++) {
      const v = q[i]; stack.push(v)
      for (const w of outgoing.get(v) || []) {
        if (!d.has(w)) { d.set(w, (d.get(v) || 0) + 1); q.push(w) }
        if ((d.get(w) || 0) === (d.get(v) || 0) + 1) {
          sigma.set(w, (sigma.get(w) || 0) + (sigma.get(v) || 0))
          paths.get(w)?.push([v])
        }
      }
    }
    while (stack.length > 0) {
      const w = stack.pop()!
      for (const predList of paths.get(w) || []) {
        for (const v of predList) {
          delta.set(v, (delta.get(v) || 0) + ((sigma.get(v) || 0) / (sigma.get(w) || 1)) * (1 + (delta.get(w) || 0)))
        }
      }
      if (w !== s) betweenness[w] = (betweenness[w] || 0) + (delta.get(w) || 0)
    }
  }
  const maxBetweenness = Math.max(...Object.values(betweenness), 1)
  const avgBetweenness = Object.values(betweenness).reduce((s, v) => s + v, 0) / n
  for (const id of nodeIds) betweenness[id] = Math.round((betweenness[id] / maxBetweenness) * 1000) / 1000

  // Closeness
  for (const id of nodeIds) {
    const dMap = new Map<string, number>()
    const q = [id]; dMap.set(id, 0)
    for (let i = 0; i < q.length; i++) {
      const cur = q[i]
      for (const next of outgoing.get(cur) || []) {
        if (!dMap.has(next)) { dMap.set(next, (dMap.get(cur) || 0) + 1); q.push(next) }
      }
    }
    const reachable = nodeIds.filter(x => dMap.has(x))
    if (reachable.length > 1) {
      closeness[id] = Math.round(((reachable.length - 1) / reachable.reduce((s, x) => s + (dMap.get(x) || 0), 0)) * 1000) / 1000
    }
  }
  const maxCloseness = Math.max(...Object.values(closeness), 0)
  const avgCloseness = Object.values(closeness).reduce((s, v) => s + v, 0) / n

  // IDom count
  const idomCount = da ? Object.entries(da.currentDominators).filter(([, v]) => v !== null).length : 0

  // Temporal metrics
  const longestCausalChainMs = teg?.longestCausalChain.totalLatencyMs || 0
  const criticalPathMs = teg?.criticalPath.causalDelayMs || 0
  const avgEdgeLatencyMs = teg?.avgEdgeLatencyMs || 0
  const maxEdgeLatencyMs = teg?.maxEdgeLatencyMs || 0

  const edgeLatencies = graph.edges.map(e => e.latencyMs || 0).filter(l => l > 0)
  const edgeLatencyVariance = edgeLatencies.length > 1
    ? Math.round(edgeLatencies.reduce((s, l) => s + Math.pow(l - avgEdgeLatencyMs, 2), 0) / edgeLatencies.length)
    : 0

  const timestamps = graph.nodes.map(n => n.timestamp).filter(t => t > 0)
  const temporalSpanMs = timestamps.length > 0 ? Math.max(...timestamps) - Math.min(...timestamps) : 0

  // Signal-specific metrics
  const secretNodes = graph.nodes.filter(n => n.type === 'SECRET_ACCESSED' || n.type === 'SECRET_EXFILTRATED')
  const networkNodes = graph.nodes.filter(n => n.type === 'NETWORK_CONNECT' || n.type === 'NETWORK_UPLOAD' || n.type === 'NETWORK_DOWNLOAD')
  const secretPathLength = secretNodes.length
  const networkPathLength = networkNodes.length

  const compilerNodes = graph.nodes.filter(n => n.type === 'COMPILER_STARTED' || n.type === 'COMPILER_FINISHED')
  const compilerDiversity = new Set(compilerNodes.map(n => n.label)).size

  // Toolchain entropy
  const processNodes = graph.nodes.filter(n => n.type.startsWith('PROCESS'))
  const toolCounts = new Map<string, number>()
  for (const p of processNodes) toolCounts.set(p.label, (toolCounts.get(p.label) || 0) + 1)
  let toolEntropy = 0
  for (const count of toolCounts.values()) {
    const p = count / processNodes.length
    toolEntropy -= p * Math.log2(p)
  }
  const toolchainEntropy = processNodes.length > 0
    ? Math.round((toolEntropy / Math.log2(Math.max(toolCounts.size, 1))) * 1000) / 1000
    : 0

  // Process tree depth
  const processDepthCache = new Map<string, number>()
  function dfsProcessDepth(id: string, depth: number): number {
    if (processDepthCache.has(id)) return processDepthCache.get(id)!
    let max = depth
    for (const next of outgoing.get(id) || []) {
      const nextNode = graph.nodes.find(n => n.id === next)
      if (nextNode?.type.startsWith('PROCESS')) {
        max = Math.max(max, dfsProcessDepth(next, depth + 1))
      }
    }
    processDepthCache.set(id, max)
    return max
  }
  let processTreeDepth = 0
  for (const root of roots) processTreeDepth = Math.max(processTreeDepth, dfsProcessDepth(root, 0))

  // Branch factor
  const outDegrees = nodeIds.map(id => outgoing.get(id)?.length || 0)
  const avgBranchFactor = outDegrees.reduce((s, d) => s + d, 0) / n

  // Root eccentricity: max shortest path from any root
  let rootEccentricity = 0
  for (const root of roots) {
    const dMap = new Map<string, number>()
    const q = [root]; dMap.set(root, 0)
    for (let i = 0; i < q.length; i++) {
      const cur = q[i]
      for (const next of outgoing.get(cur) || []) {
        if (!dMap.has(next)) { dMap.set(next, (dMap.get(cur) || 0) + 1); q.push(next) }
      }
    }
    const maxDist = Math.max(...Array.from(dMap.values()), 0)
    rootEccentricity = Math.max(rootEccentricity, maxDist)
  }

  // Inference/observation degradation
  const infDegradations = graph.edges.map(e => e.degradation).filter(d => d > 0)
  const avgInferenceDegradation = infDegradations.length > 0
    ? Math.round(infDegradations.reduce((s, d) => s + d, 0) / infDegradations.length * 1000) / 1000
    : 0

  const obsConfs = graph.nodes.map(n => n.observationConfidence).filter(c => c > 0)
  const avgObservationDegradation = obsConfs.length > 0
    ? Math.round((1 - obsConfs.reduce((s, c) => s + c, 0) / obsConfs.length / 100) * 1000) / 1000
    : 0

  // Confidence variance
  const confs = graph.nodes.map(n => n.confidence)
  const avgConf = confs.reduce((s, c) => s + c, 0) / n
  const confidenceVariance = n > 1
    ? Math.round(confs.reduce((s, c) => s + Math.pow(c - avgConf, 2), 0) / n)
    : 0

  // Contract violation ratio
  const contractNodes = graph.nodes.filter(n => n.type === 'CONTRACT_VIOLATED')
  const contractViolationRatio = n > 0 ? Math.round((contractNodes.length / n) * 1000) / 1000 : 0

  // File read ratio
  const fileReadNodes = graph.nodes.filter(n => n.type === 'FILE_READ' || n.type === 'FILE_WRITTEN')
  const fileReadRatio = n > 0 ? Math.round((fileReadNodes.length / n) * 1000) / 1000 : 0

  // Ratios
  const secretToProcessRatio = processNodes.length > 0
    ? Math.round((secretPathLength / processNodes.length) * 1000) / 1000
    : 0
  const networkToProcessRatio = processNodes.length > 0
    ? Math.round((networkPathLength / processNodes.length) * 1000) / 1000
    : 0

  return {
    nodeCount,
    edgeCount,
    graphDensity,
    graphEntropy,
    maxDepth,
    componentCount,
    sccCount,
    isDag,
    avgBetweenness: Math.round(avgBetweenness * 1000) / 1000,
    maxBetweenness,
    avgCloseness: Math.round(avgCloseness * 1000) / 1000,
    maxCloseness,
    idomCount,
    longestCausalChainMs,
    criticalPathMs,
    avgEdgeLatencyMs,
    maxEdgeLatencyMs,
    edgeLatencyVariance,
    temporalSpanMs,
    secretPathLength,
    networkPathLength,
    compilerDiversity,
    toolchainEntropy,
    processTreeDepth,
    avgBranchFactor: Math.round(avgBranchFactor * 1000) / 1000,
    rootEccentricity,
    avgInferenceDegradation,
    avgObservationDegradation,
    confidenceVariance,
    contractViolationRatio,
    fileReadRatio,
    secretToProcessRatio,
    networkToProcessRatio,
  }
}

export function renderFullGraphMetrics(m: EvidenceGraphMetrics): string[] {
  return [
    'Full Graph Metrics',
    '==================',
    `  Nodes: ${m.nodeCount} | Edges: ${m.edgeCount} | Density: ${m.graphDensity}`,
    `  Entropy: ${m.graphEntropy} | DAG: ${m.isDag} | SCC: ${m.sccCount}`,
    `  Max depth: ${m.maxDepth} | Components: ${m.componentCount}`,
    '',
    '  Centrality:',
    `    Betweenness: avg=${m.avgBetweenness} max=${m.maxBetweenness}`,
    `    Closeness: avg=${m.avgCloseness} max=${m.maxCloseness}`,
    `    IDom count: ${m.idomCount}`,
    '',
    '  Temporal:',
    `    Longest chain: ${m.longestCausalChainMs}ms`,
    `    Critical path: ${m.criticalPathMs}ms`,
    `    Avg latency: ${m.avgEdgeLatencyMs}ms | Max: ${m.maxEdgeLatencyMs}ms`,
    `    Variance: ${m.edgeLatencyVariance} | Span: ${m.temporalSpanMs}ms`,
    '',
    '  Paths:',
    `    Secret: ${m.secretPathLength} | Network: ${m.networkPathLength}`,
    `    Secret/Process: ${m.secretToProcessRatio} | Network/Process: ${m.networkToProcessRatio}`,
    '',
    '  Structure:',
    `    Compiler diversity: ${m.compilerDiversity}`,
    `    Toolchain entropy: ${m.toolchainEntropy}`,
    `    Process tree depth: ${m.processTreeDepth}`,
    `    Avg branch factor: ${m.avgBranchFactor}`,
    `    Root eccentricity: ${m.rootEccentricity}`,
    '',
    '  Confidence:',
    `    Avg inference degradation: ${m.avgInferenceDegradation}`,
    `    Avg observation degradation: ${m.avgObservationDegradation}`,
    `    Confidence variance: ${m.confidenceVariance}`,
    '',
    '  Ratios:',
    `    Contract violations: ${m.contractViolationRatio}`,
    `    File read: ${m.fileReadRatio}`,
  ]
}
