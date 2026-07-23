import {
  BuildProcessEvent, BuildFileEvent, BuildNetEvent, FileReadEvent,
  BuildRecord, CompilerInvocationIdentity, SecretFlow,
  EvidenceNode, EvidenceEdge, EvidenceGraph, EvidenceType, EvidenceSource,
  EvidenceRelation, EVIDENCE_SCHEMA_VERSION,
} from './build-types'

let nodeCounter = 0
function nextId(): string {
  return `ev${++nodeCounter}`
}

function sourceFromRecord(record: BuildRecord): EvidenceSource {
  if (record.recordOptions?.observeOnly) return 'procfs'
  if (record.platform === 'win32') return 'cim_query'
  if (record.platform === 'linux') return 'procfs'
  return 'polling'
}

export function buildEvidenceGraph(
  record: BuildRecord,
): EvidenceGraph {
  const nodes: EvidenceNode[] = []
  const edges: EvidenceEdge[] = []
  const now = Date.now()
  const source = record.observationConfidence?.sources[0] || sourceFromRecord(record)

  const pidNodes = new Map<number, string>()
  const fileNodes = new Map<string, string>()
  const netNodes = new Map<string, string>()

  for (const proc of record.processes) {
    const id = nextId()
    if (pidNodes.has(proc.pid)) continue
    pidNodes.set(proc.pid, id)
    const durationMs = proc.startTime && proc.exitTime ? proc.exitTime - proc.startTime : undefined
    nodes.push({
      id,
      type: proc.exitTime ? 'PROCESS_EXITED' : 'PROCESS_CREATED',
      label: proc.name,
      timestamp: proc.timestamp,
      ...nodeConfidence(proc.source || source),
      source: proc.source || source,
      pid: proc.pid,
      processName: proc.name,
      attributes: { cmdline: proc.cmdline, ppid: proc.ppid, pname: proc.pname, ...(durationMs !== undefined ? { durationMs } : {}) },
    })

    if (proc.ppid && proc.ppid !== proc.pid && pidNodes.has(proc.ppid)) {
      edges.push({
        from: pidNodes.get(proc.ppid)!,
        to: id,
        relation: 'spawned',
        confidence: 95,
        timestamp: proc.timestamp,
        degradation: 0.05,
      })
    }
  }

  for (const file of record.files) {
    if (fileNodes.has(file.filePath)) continue
    const id = nextId()
    const type: EvidenceType = file.operation === 'created' ? 'FILE_CREATED'
      : file.operation === 'deleted' ? 'FILE_DELETED'
      : 'FILE_MODIFIED'
    fileNodes.set(file.filePath, id)
    nodes.push({
      id,
      type,
      label: file.filePath.split(/[\\/]/).pop() || file.filePath,
      timestamp: file.timestamp,
      ...nodeConfidence(file.source || source),
      source: file.source || source,
      filePath: file.filePath,
      sha256: file.sha256,
      size: file.size,
      attributes: { operation: file.operation },
    })

    if (record.processes.length > 0) {
      const closest = findClosestProcess(record.processes, file.timestamp)
      if (closest && pidNodes.has(closest.pid)) {
        edges.push({
          from: pidNodes.get(closest.pid)!,
          to: id,
          relation: file.operation === 'created' ? 'created' : 'modified',
          confidence: 70,
          timestamp: file.timestamp,
          degradation: 0.30,
        })
      }
    }
  }

  for (const net of record.network) {
    const id = nextId()
    const key = `${net.type}:${net.host}:${net.port || ''}`
    netNodes.set(key, id)
    const type: EvidenceType = net.type === 'dns' ? 'NETWORK_DNS_QUERY' : 'NETWORK_CONNECT'
    nodes.push({
      id,
      type,
      label: `${net.host}${net.port ? `:${net.port}` : ''}`,
      timestamp: net.timestamp,
      ...nodeConfidence(net.source || source),
      source: net.source || source,
      host: net.host,
      port: net.port,
      attributes: { protocol: net.type },
    })

    if (record.processes.length > 0) {
      const closest = findClosestProcess(record.processes, net.timestamp)
      if (closest && pidNodes.has(closest.pid)) {
        edges.push({
          from: pidNodes.get(closest.pid)!,
          to: id,
          relation: 'connected',
          confidence: 75,
          timestamp: net.timestamp,
          degradation: 0.25,
        })
      }
    }
  }

  if (record.readFiles) {
    for (const read of record.readFiles) {
      const id = nextId()
      nodes.push({
        id,
        type: 'FILE_READ',
        label: read.filePath.split(/[\\/]/).pop() || read.filePath,
        timestamp: read.timestamp,
        ...nodeConfidence(read.source || source),
        source: read.source || source,
        pid: read.pid,
        processName: read.processName,
        filePath: read.filePath,
        size: read.size,
        attributes: {},
      })

      if (pidNodes.has(read.pid)) {
        edges.push({
          from: pidNodes.get(read.pid)!,
          to: id,
          relation: 'read',
          confidence: 85,
          timestamp: read.timestamp,
          degradation: 0.15,
        })
      }
    }
  }

  if (record.secretFlow) {
    for (const secret of record.secretFlow.secretAccesses) {
      const id = nextId()
      nodes.push({
        id,
        type: 'SECRET_ACCESSED',
        label: secret.type,
        timestamp: secret.timestamp || now,
        ...nodeConfidence('procfs', { observationConfidence: 90, inferenceConfidence: 100 }),
        source: 'procfs',
        pid: secret.pid,
        processName: secret.processName,
        filePath: secret.filePath,
        severity: secret.severity,
        attributes: { match: secret.match, snippet: secret.snippet },
      })

      if (secret.pid && pidNodes.has(secret.pid)) {
        edges.push({
          from: pidNodes.get(secret.pid)!,
          to: id,
          relation: 'accessed',
          confidence: 90,
          timestamp: secret.timestamp || now,
          degradation: 0.10,
        })
      }
    }

    for (const chain of record.secretFlow.chains) {
      if (chain.hasExfilRisk) {
        const id = nextId()
        nodes.push({
          id,
          type: 'SECRET_EXFILTRATED',
          label: `${chain.processName} (PID ${chain.pid})`,
          timestamp: now,
          ...nodeConfidence('polling', { observationConfidence: 85, inferenceConfidence: 100 }),
          source: 'polling',
          pid: chain.pid,
          processName: chain.processName,
          severity: chain.severity,
          attributes: { networkEvents: chain.networkEvents.length },
        })
        if (pidNodes.has(chain.pid)) {
          edges.push({
            from: pidNodes.get(chain.pid)!,
            to: id,
            relation: 'exfiltrated',
            confidence: 80,
            timestamp: now,
            degradation: 0.20,
          })
        }
      }
    }
  }

  if (record.compilerInvocations) {
    for (const inv of record.compilerInvocations.invocations) {
      const id = nextId()
      nodes.push({
        id,
        type: 'COMPILER_STARTED',
        label: inv.tool,
        timestamp: inv.timestamp,
        ...nodeConfidence('procfs', { observationConfidence: 88, inferenceConfidence: 100 }),
        source: 'procfs',
        pid: inv.pid,
        attributes: {
          argv: inv.argv.slice(0, 10),
          inputFiles: inv.inputFiles,
          outputFiles: inv.outputFiles,
          hasResponseFile: inv.hasResponseFile,
          fromStdin: inv.fromStdin,
          fromMemfd: inv.fromMemfd,
        },
      })
      if (pidNodes.has(inv.pid)) {
        edges.push({
          from: pidNodes.get(inv.pid)!,
          to: id,
          relation: 'loaded',
          confidence: 90,
          timestamp: inv.timestamp,
          degradation: 0.10,
        })
      }
    }
  }

  const buildId = `${record.command}_${Date.now()}`
  const rootPid = record.processes[0]?.pid || 0

  return {
    nodes,
    edges,
    buildId,
    rootPid,
    rootProcess: record.processes.find(p => p.pid === rootPid)?.name || record.command,
    createdAt: Date.now(),
    schemaVersion: EVIDENCE_SCHEMA_VERSION,
  }
}

export function queryGraphByType(graph: EvidenceGraph, type: EvidenceType): EvidenceNode[] {
  return graph.nodes.filter(n => n.type === type)
}

export function queryGraphByPid(graph: EvidenceGraph, pid: number): EvidenceNode[] {
  return graph.nodes.filter(n => n.pid === pid)
}

export function queryGraphBySeverity(graph: EvidenceGraph, severity: string): EvidenceNode[] {
  return graph.nodes.filter(n => n.severity === severity)
}

export function queryOutgoingEdges(graph: EvidenceGraph, nodeId: string): EvidenceEdge[] {
  return graph.edges.filter(e => e.from === nodeId)
}

export function queryIncomingEdges(graph: EvidenceGraph, nodeId: string): EvidenceEdge[] {
  return graph.edges.filter(e => e.to === nodeId)
}

export function findPathsBetween(
  graph: EvidenceGraph,
  fromId: string,
  toId: string,
  maxDepth = 10,
): EvidenceEdge[][] {
  const paths: EvidenceEdge[][] = []

  function dfs(current: string, target: string, visited: Set<string>, path: EvidenceEdge[]) {
    if (path.length > maxDepth) return
    if (current === target) {
      paths.push([...path])
      return
    }
    for (const edge of graph.edges) {
      if (edge.from === current && !visited.has(edge.to)) {
        visited.add(edge.to)
        path.push(edge)
        dfs(edge.to, target, visited, path)
        path.pop()
        visited.delete(edge.to)
      }
    }
  }

  const visited = new Set([fromId])
  dfs(fromId, toId, visited, [])
  return paths
}

export function queryConnectedNodes(graph: EvidenceGraph, nodeId: string): EvidenceNode[] {
  const connectedIds = new Set<string>()
  for (const edge of graph.edges) {
    if (edge.from === nodeId) connectedIds.add(edge.to)
    if (edge.to === nodeId) connectedIds.add(edge.from)
  }
  return graph.nodes.filter(n => connectedIds.has(n.id))
}

export function getSubgraph(graph: EvidenceGraph, nodeIds: Set<string>): EvidenceGraph {
  const nodeSet = new Set(nodeIds)
  const subNodes = graph.nodes.filter(n => nodeSet.has(n.id))
  const subEdges = graph.edges.filter(e => nodeSet.has(e.from) && nodeSet.has(e.to))
  return {
    ...graph,
    nodes: subNodes,
    edges: subEdges,
  }
}

export function queryGraphBySource(graph: EvidenceGraph, source: EvidenceSource): EvidenceNode[] {
  return graph.nodes.filter(n => n.source === source)
}

export function renderEvidenceGraph(graph: EvidenceGraph, maxNodes = 50): string[] {
  const lines: string[] = [
    'Evidence Graph',
    '==============',
    `  Build: ${graph.buildId}`,
    `  Root: ${graph.rootProcess} (PID ${graph.rootPid})`,
    `  Nodes: ${graph.nodes.length}`,
    `  Edges: ${graph.edges.length}`,
    '',
    '  High-Confidence Nodes (>85):',
  ]

  const highConf = graph.nodes.filter(n => n.confidence >= 85).slice(0, maxNodes)
  for (const node of highConf) {
    const edgeCount = graph.edges.filter(e => e.from === node.id || e.to === node.id).length
    lines.push(`    [${node.confidence}] ${node.type} ${node.label} (${edgeCount} edges)`)
  }

  const lowConf = graph.nodes.filter(n => n.confidence < 50)
  if (lowConf.length > 0) {
    lines.push('', `  Low-Confidence Nodes (<50): ${lowConf.length}`)
    for (const node of lowConf.slice(0, 10)) {
      lines.push(`    [${node.confidence}] ${node.type} ${node.label}`)
    }
  }

  const severityNodes = graph.nodes.filter(n => n.severity === 'critical' || n.severity === 'high')
  if (severityNodes.length > 0) {
    lines.push('', `  Severity Nodes: ${severityNodes.length}`)
    for (const node of severityNodes) {
      lines.push(`    [${node.severity?.toUpperCase()}] ${node.type} ${node.label}`)
    }
  }

  return lines
}

function evidenceBaseConfidence(source: EvidenceSource): number {
  const map: Record<string, number> = {
    etw: 98, ebpf: 97, endpoint_security: 96, auditd: 95,
    ftrace: 94, process_maps: 88, procfs: 85, cim_query: 82,
    handle: 78, ps: 72, polling: 65, mtime_heuristic: 42,
    named_pipe: 70,
  }
  return map[source] ?? 50
}

function nodeConfidence(
  source: EvidenceSource,
  overrides?: { observationConfidence?: number; inferenceConfidence?: number }
): { confidence: number; observationConfidence: number; inferenceConfidence: number } {
  const obs = overrides?.observationConfidence ?? evidenceBaseConfidence(source)
  const inf = overrides?.inferenceConfidence ?? 100
  return {
    observationConfidence: obs,
    inferenceConfidence: inf,
    confidence: Math.round(obs * inf / 100),
  }
}

export { evidenceBaseConfidence }

function findClosestProcess(processes: BuildProcessEvent[], timestamp: number): BuildProcessEvent | null {
  let closest: BuildProcessEvent | null = null
  let minDiff = Infinity
  for (const p of processes) {
    const diff = Math.abs(p.timestamp - timestamp)
    if (diff < minDiff) {
      minDiff = diff
      closest = p
    }
  }
  return closest
}

// ── Graph Properties ──────────────────────────────────────────
export interface EvidenceGraphStats {
  nodeCount: number
  edgeCount: number
  nodeCountByType: Record<string, number>
  edgeCountByRelation: Record<string, number>
  degreeCentrality: Record<string, number>
  maxFanOut: { nodeId: string; count: number; label: string }
  avgFanOut: number
  maxDepth: number
  componentCount: number
  largestComponentSize: number
  nodeCountBySeverity: Record<string, number>
  avgConfidence: number
  minConfidence: number
  maxConfidence: number
}

export function computeGraphStats(graph: EvidenceGraph): EvidenceGraphStats {
  const nodeCount = graph.nodes.length
  const edgeCount = graph.edges.length

  const nodeCountByType: Record<string, number> = {}
  for (const node of graph.nodes) {
    nodeCountByType[node.type] = (nodeCountByType[node.type] || 0) + 1
  }

  const edgeCountByRelation: Record<string, number> = {}
  for (const edge of graph.edges) {
    edgeCountByRelation[edge.relation] = (edgeCountByRelation[edge.relation] || 0) + 1
  }

  const outDegree = new Map<string, number>()
  for (const edge of graph.edges) {
    outDegree.set(edge.from, (outDegree.get(edge.from) || 0) + 1)
  }
  const degreeCentrality: Record<string, number> = {}
  let maxFanOutCount = 0
  let maxFanOutNode = ''
  for (const node of graph.nodes) {
    const deg = outDegree.get(node.id) || 0
    degreeCentrality[node.id] = deg
    if (deg > maxFanOutCount) {
      maxFanOutCount = deg
      maxFanOutNode = node.id
    }
  }
  const maxFanOutLabel = graph.nodes.find(n => n.id === maxFanOutNode)?.label || ''
  const avgFanOut = nodeCount > 0
    ? Object.values(degreeCentrality).reduce((a, b) => a + b, 0) / nodeCount
    : 0

  const visitedComponents = new Set<string>()
  const componentSizes: number[] = []
  const adjacency = new Map<string, string[]>()
  for (const node of graph.nodes) adjacency.set(node.id, [])
  for (const edge of graph.edges) {
    adjacency.get(edge.from)?.push(edge.to)
    adjacency.get(edge.to)?.push(edge.from)
  }
  for (const node of graph.nodes) {
    if (visitedComponents.has(node.id)) continue
    const stack = [node.id]
    let size = 0
    while (stack.length > 0) {
      const current = stack.pop()!
      if (visitedComponents.has(current)) continue
      visitedComponents.add(current)
      size++
      for (const neighbor of adjacency.get(current) || []) {
        if (!visitedComponents.has(neighbor)) stack.push(neighbor)
      }
    }
    componentSizes.push(size)
  }
  const componentCount = componentSizes.length
  const largestComponentSize = componentSizes.length > 0 ? Math.max(...componentSizes) : 0

  let maxDepth = 0
  const depths = new Map<string, number>()
  const rootIds = graph.nodes
    .filter(n => !graph.edges.some(e => e.to === n.id))
    .map(n => n.id)
  const dfsDepth = (nodeId: string, depth: number): void => {
    const existing = depths.get(nodeId)
    if (existing !== undefined && existing >= depth) return
    depths.set(nodeId, depth)
    if (depth > maxDepth) maxDepth = depth
    for (const edge of graph.edges) {
      if (edge.from === nodeId) dfsDepth(edge.to, depth + 1)
    }
  }
  for (const id of rootIds) dfsDepth(id, 0)

  const nodeCountBySeverity: Record<string, number> = {}
  for (const node of graph.nodes) {
    const sev = node.severity || 'unknown'
    nodeCountBySeverity[sev] = (nodeCountBySeverity[sev] || 0) + 1
  }

  const confidenceValues = graph.nodes.map(n => n.confidence)
  const avgConfidence = confidenceValues.length > 0
    ? Math.round(confidenceValues.reduce((a, b) => a + b, 0) / confidenceValues.length)
    : 0
  const minConfidence = confidenceValues.length > 0 ? Math.min(...confidenceValues) : 0
  const maxConfidence = confidenceValues.length > 0 ? Math.max(...confidenceValues) : 0

  return {
    nodeCount,
    edgeCount,
    nodeCountByType,
    edgeCountByRelation,
    degreeCentrality,
    maxFanOut: { nodeId: maxFanOutNode, count: maxFanOutCount, label: maxFanOutLabel },
    avgFanOut,
    maxDepth,
    componentCount,
    largestComponentSize,
    nodeCountBySeverity,
    avgConfidence,
    minConfidence,
    maxConfidence,
  }
}

export function renderGraphStats(stats: EvidenceGraphStats): string[] {
  const lines: string[] = [
    'Evidence Graph Stats',
    '====================',
    `  Nodes: ${stats.nodeCount}`,
    `  Edges: ${stats.edgeCount}`,
    `  Components: ${stats.componentCount} (largest: ${stats.largestComponentSize})`,
    `  Max depth: ${stats.maxDepth}`,
    `  Avg fan-out: ${stats.avgFanOut.toFixed(2)}`,
    `  Max fan-out: ${stats.maxFanOut.label} (${stats.maxFanOut.count})`,
    `  Avg confidence: ${stats.avgConfidence}`,
    `  Confidence range: ${stats.minConfidence} – ${stats.maxConfidence}`,
    '',
    '  Nodes by type:',
  ]
  for (const [type, count] of Object.entries(stats.nodeCountByType).sort((a, b) => b[1] - a[1])) {
    lines.push(`    ${type}: ${count}`)
  }
  lines.push('', '  Edges by relation:')
  for (const [rel, count] of Object.entries(stats.edgeCountByRelation).sort((a, b) => b[1] - a[1])) {
    lines.push(`    ${rel}: ${count}`)
  }
  if (Object.keys(stats.nodeCountBySeverity).length > 0) {
    lines.push('', '  Nodes by severity:')
    for (const [sev, count] of Object.entries(stats.nodeCountBySeverity)) {
      lines.push(`    ${sev}: ${count}`)
    }
  }
  return lines
}

// ── Advanced Graph Algorithms ───────────────────────────────────
export interface AdvancedGraphStats {
  betweennessCentrality: Record<string, number>
  closenessCentrality: Record<string, number>
  graphDensity: number
  graphEntropy: number
  immediateDominators: Record<string, string | null>
  dominanceFrontier: Record<string, string[]>
  isDag: boolean
  sccCount: number
}

export function computeAdvancedGraphStats(graph: EvidenceGraph): AdvancedGraphStats {
  const nodeIds = graph.nodes.map(n => n.id)
  const idSet = new Set(nodeIds)
  const n = nodeIds.length

  // Build adjacency
  const outgoing = new Map<string, string[]>()

  for (const id of nodeIds) {
    outgoing.set(id, [])
  }
  for (const edge of graph.edges) {
    outgoing.get(edge.from)?.push(edge.to)
  }

  // Betweenness centrality (Brandes for unweighted directed)
  const betweenness: Record<string, number> = {}
  for (const id of nodeIds) betweenness[id] = 0

  for (const s of nodeIds) {
    const stack: string[] = []
    const paths = new Map<string, string[][]>()
    const sigma = new Map<string, number>()
    const d = new Map<string, number>()
    const delta = new Map<string, number>()

    for (const id of nodeIds) {
      paths.set(id, [])
      sigma.set(id, 0)
      delta.set(id, 0)
    }
    sigma.set(s, 1)
    d.set(s, 0)

    const q = [s]
    for (let i = 0; i < q.length; i++) {
      const v = q[i]
      stack.push(v)
      for (const w of outgoing.get(v) || []) {
        if (!d.has(w)) {
          d.set(w, (d.get(v) || 0) + 1)
          q.push(w)
        }
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
      if (w !== s) {
        betweenness[w] = (betweenness[w] || 0) + (delta.get(w) || 0)
      }
    }
  }

  const maxBetweenness = Math.max(...Object.values(betweenness), 1)
  for (const id of nodeIds) {
    betweenness[id] = Math.round((betweenness[id] / maxBetweenness) * 1000) / 1000
  }

  // Closeness centrality: C(u) = (reachable-1) / sum distances
  const closeness: Record<string, number> = {}
  for (const id of nodeIds) {
    const dMap = new Map<string, number>()
    const q = [id]
    dMap.set(id, 0)
    for (let i = 0; i < q.length; i++) {
      const cur = q[i]
      const curDist = dMap.get(cur)!
      for (const next of outgoing.get(cur) || []) {
        if (!dMap.has(next)) {
          dMap.set(next, curDist + 1)
          q.push(next)
        }
      }
    }
    const reachable = nodeIds.filter(x => dMap.has(x))
    if (reachable.length <= 1) {
      closeness[id] = 0
      continue
    }
    const totalDist = reachable.reduce((s, x) => s + (dMap.get(x) || 0), 0)
    closeness[id] = Math.round(((reachable.length - 1) / totalDist) * 1000) / 1000
  }

  // Graph density: |E| / (|V| * (|V|-1))
  const graphDensity = n > 1
    ? Math.round((graph.edges.length / (n * (n - 1))) * 10000) / 10000
    : 0

  // Graph entropy: Shannon entropy of node type distribution
  const typeCounts = new Map<string, number>()
  for (const node of graph.nodes) {
    typeCounts.set(node.type, (typeCounts.get(node.type) || 0) + 1)
  }
  const total = graph.nodes.length
  let entropy = 0
  for (const count of typeCounts.values()) {
    const p = count / total
    entropy -= p * Math.log2(p)
  }
  const maxEntropy = typeCounts.size > 0 ? Math.log2(typeCounts.size) : 1
  const graphEntropy = maxEntropy > 0 ? Math.round((entropy / maxEntropy) * 1000) / 1000 : 0

  // Dominator tree (iterative data-flow for DAG)
  const incoming = new Map<string, string[]>()
  for (const id of nodeIds) incoming.set(id, [])
  for (const edge of graph.edges) {
    incoming.get(edge.to)?.push(edge.from)
  }

  const entry = graph.nodes.find(n =>
    n.pid === graph.rootPid || !graph.edges.some(e => e.to === n.id)
  )
  const idoms: Record<string, string | null> = {}
  for (const id of nodeIds) idoms[id] = null
  if (entry) idoms[entry.id] = entry.id

  let changed = true
  while (changed) {
    changed = false
    for (const node of graph.nodes) {
      const preds = incoming.get(node.id) || []
      if (preds.length === 0) {
        if (idoms[node.id] !== node.id) {
          idoms[node.id] = node.id
          changed = true
        }
        continue
      }
      let newIdom: string | null = null
      for (const p of preds) {
        if (idoms[p] !== null) {
          newIdom = newIdom === null ? p : intersectDom(idoms, p, newIdom)
        }
      }
      if (newIdom !== null && newIdom !== node.id) {
        if (idoms[node.id] !== newIdom) {
          idoms[node.id] = newIdom
          changed = true
        }
      }
    }
  }
  for (const [id, dom] of Object.entries(idoms)) {
    idoms[id] = dom === id ? null : dom
  }

  // Dominance frontier
  const domFrontier: Record<string, string[]> = {}
  for (const id of nodeIds) domFrontier[id] = []
  for (const edge of graph.edges) {
    const u = edge.from
    const v = edge.to
    if (idoms[v] !== u) {
      if (!domFrontier[u]?.includes(v)) domFrontier[u]?.push(v)
    }
  }

  // Cycle detection (DFS-based)
  const visited = new Set<string>()
  const recStack = new Set<string>()
  let hasCycle = false
  function dfsCycle(id: string): void {
    if (hasCycle) return
    visited.add(id)
    recStack.add(id)
    for (const next of outgoing.get(id) || []) {
      if (!visited.has(next)) dfsCycle(next)
      else if (recStack.has(next)) hasCycle = true
    }
    recStack.delete(id)
  }
  for (const id of nodeIds) {
    if (!visited.has(id)) dfsCycle(id)
    if (hasCycle) break
  }

  // SCC count (Kosaraju if cyclic, node count if DAG)
  let sccCount = 0
  if (!hasCycle) {
    sccCount = nodeIds.length
  } else {
    const visited2 = new Set<string>()
    const order: string[] = []
    function dfsOrder(id: string): void {
      visited2.add(id)
      for (const next of outgoing.get(id) || []) {
        if (!visited2.has(next)) dfsOrder(next)
      }
      order.push(id)
    }
    for (const id of nodeIds) if (!visited2.has(id)) dfsOrder(id)

    const visited3 = new Set<string>()
    function dfsReverse(id: string): void {
      visited3.add(id)
      for (const prev of incoming.get(id) || []) {
        if (!visited3.has(prev)) dfsReverse(prev)
      }
    }
    for (const id of order.reverse()) {
      if (!visited3.has(id)) {
        sccCount++
        dfsReverse(id)
      }
    }
  }

  return {
    betweennessCentrality: betweenness,
    closenessCentrality: closeness,
    graphDensity,
    graphEntropy,
    immediateDominators: idoms,
    dominanceFrontier: domFrontier,
    isDag: !hasCycle,
    sccCount,
  }
}

function intersectDom(
  idoms: Record<string, string | null>,
  finger1: string,
  finger2: string,
): string {
  let f1: string | null = finger1
  let f2: string | null = finger2
  while (f1 !== f2) {
    while (f1 !== null && f1 !== finger1 && (idoms[f1] === null || f1 < f2!)) {
      f1 = idoms[f1]
    }
    while (f2 !== null && f2 !== finger2 && (idoms[f2] === null || f2 < f1!)) {
      f2 = idoms[f2]
    }
  }
  return f1!
}

export function renderAdvancedGraphStats(stats: AdvancedGraphStats, topN = 5): string[] {
  const lines: string[] = [
    'Advanced Graph Stats',
    '====================',
    `  Density: ${stats.graphDensity}`,
    `  Entropy: ${stats.graphEntropy}`,
    `  Is DAG: ${stats.isDag}`,
    `  SCC count: ${stats.sccCount}`,
    '',
    '  Top Betweenness Centrality:',
  ]

  const topBetween = Object.entries(stats.betweennessCentrality)
    .sort((a, b) => b[1] - a[1])
    .slice(0, topN)
  for (const [id, val] of topBetween) {
    lines.push(`    ${id}: ${val}`)
  }

  lines.push('', '  Top Closeness Centrality:')
  const topClose = Object.entries(stats.closenessCentrality)
    .sort((a, b) => b[1] - a[1])
    .slice(0, topN)
  for (const [id, val] of topClose) {
    lines.push(`    ${id}: ${val}`)
  }

  const idomEntries = Object.entries(stats.immediateDominators).filter(([, v]) => v !== null)
  if (idomEntries.length > 0) {
    lines.push('', '  Immediate Dominators:')
    for (const [node, dom] of idomEntries.slice(0, topN)) {
      lines.push(`    ${node} → idom: ${dom}`)
    }
    if (idomEntries.length > topN) lines.push(`    ... and ${idomEntries.length - topN} more`)
  }

  return lines
}
