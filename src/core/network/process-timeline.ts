import {
  BuildRecord,
  EvidenceNode,
  EvidenceEdge,
  EvidenceGraph,
  ProcessTimeline,
  ProcessTimelineEvent,
  EvidenceType,
  EvidenceSource,
} from './build-types'

export function buildProcessTimelines(
  record: BuildRecord,
  graph?: EvidenceGraph,
): ProcessTimeline[] {
  const graphNodes = graph?.nodes || []
  const graphEdges = graph?.edges || []
  const timelineMap = new Map<number, ProcessTimelineEvent[]>()

  const procMap = new Map(record.processes.map(p => [p.pid, p]))

  const pidNodeMap = new Map<number, EvidenceNode>()
  for (const node of graphNodes) {
    if (node.pid) pidNodeMap.set(node.pid, node)
  }

  const orphanEvents: ProcessTimelineEvent[] = []

  for (const node of graphNodes) {
    const targetPid = resolvePidForNode(node, graphEdges, graphNodes, pidNodeMap)

    if (!targetPid) {
      orphanEvents.push(makeEvent(node, procMap, graph, 0))
      continue
    }

    const events = timelineMap.get(targetPid) || []
    events.push(makeEvent(node, procMap, graph, targetPid))
    timelineMap.set(targetPid, events)
  }

  const timelines: ProcessTimeline[] = []
  for (const [pid, rawEvents] of timelineMap) {
    const proc = procMap.get(pid)
    rawEvents.sort((a, b) => a.timestamp - b.timestamp)
    const events = rawEvents.map((e, i) => ({ ...e, sequenceIndex: i }))

    const childPids: number[] = []
    if (graph) {
      const pidNode = graph.nodes.find(n => n.pid === pid)
      if (pidNode) {
        for (const edge of graph.edges) {
          if (edge.from === pidNode.id && edge.relation === 'spawned') {
            const child = graph.nodes.find(n => n.id === edge.to)
            if (child && child.pid) childPids.push(child.pid)
          }
        }
      }
    }

    const secretsRead = events.filter(e => e.type === 'SECRET_ACCESSED' || e.type === 'SECRET_EXFILTRATED').length
    const filesCreated = events.filter(e => e.type === 'FILE_CREATED' || e.type === 'FILE_WRITTEN').length
    const networkConnections = events.filter(e =>
      e.type === 'NETWORK_CONNECT' || e.type === 'NETWORK_DNS_QUERY'
    ).length
    const dataUploadedBytes = estimateUploadBytes(events)

    timelines.push({
      pid,
      processName: proc?.name || events[0]?.processName || 'unknown',
      cmdline: proc?.cmdline || '',
      ppid: proc?.ppid || 0,
      startTime: proc?.startTime || events[0]?.timestamp || 0,
      exitTime: proc?.exitTime,
      events,
      totalEvents: events.length,
      secretsRead,
      filesCreated,
      networkConnections,
      dataUploadedBytes,
      childPids,
    })
  }

  timelines.sort((a, b) => a.startTime - b.startTime)
  return timelines
}

export function renderProcessTimeline(timeline: ProcessTimeline, maxEvents = 30): string[] {
  const lines: string[] = [
    `Process Timeline: ${timeline.processName} (PID ${timeline.pid})`,
    '='.repeat(50),
    `  Cmdline: ${timeline.cmdline.substring(0, 120)}`,
    `  PPID: ${timeline.ppid}`,
    `  Duration: ${timeline.exitTime ? timeline.exitTime - timeline.startTime : 'running'}ms`,
    `  Events: ${timeline.totalEvents}`,
    `  Children: ${timeline.childPids.length}`,
    `  Secrets: ${timeline.secretsRead}`,
    `  Files: ${timeline.filesCreated}`,
    `  Network: ${timeline.networkConnections}`,
    `  Data uploaded: ${formatBytes(timeline.dataUploadedBytes)}`,
    '',
    '  Event Sequence:',
  ]

  const startTime = timeline.startTime
  for (const event of timeline.events.slice(0, maxEvents)) {
    const offset = event.timestamp - startTime
    const icon = eventIcon(event.type)
    const confidenceBar = confidenceIndicator(event.confidence)
    lines.push(
      `  ${icon} +${offset.toString().padStart(6)}ms [${event.confidence.toString().padStart(2)}${confidenceBar}] ${event.type} ${event.label}`,
    )
    if (event.detail) {
      lines.push(`         ${event.detail}`)
    }
  }

  if (timeline.events.length > maxEvents) {
    lines.push(`  ... and ${timeline.events.length - maxEvents} more events`)
  }

  return lines
}

export function renderTimelineSummary(timelines: ProcessTimeline[]): string[] {
  const lines: string[] = [
    'Process Timeline Summary',
    '========================',
    `  Total processes tracked: ${timelines.length}`,
    '',
  ]

  const withExfil = timelines.filter(t => t.secretsRead > 0 && t.networkConnections > 0)
  if (withExfil.length > 0) {
    lines.push('  ⚠ Processes with Secret + Network activity:')
    for (const t of withExfil) {
      lines.push(`    ${t.processName} (PID ${t.pid}): ${t.secretsRead} secrets, ${t.networkConnections} connections`)
    }
    lines.push('')
  }

  const withUpload = timelines.filter(t => t.dataUploadedBytes > 1024)
  if (withUpload.length > 0) {
    lines.push('  📤 Processes with significant uploads:')
    for (const t of withUpload) {
      lines.push(`    ${t.processName} (PID ${t.pid}): ${formatBytes(t.dataUploadedBytes)}`)
    }
    lines.push('')
  }

  const fastest = [...timelines].sort((a, b) => {
    const aDur = a.exitTime ? a.exitTime - a.startTime : Infinity
    const bDur = b.exitTime ? b.exitTime - b.startTime : Infinity
    return aDur - bDur
  }).slice(0, 5)

  lines.push('  Fastest processes:')
  for (const t of fastest) {
    const dur = t.exitTime ? t.exitTime - t.startTime : 'running'
    lines.push(`    ${t.processName} (PID ${t.pid}): ${dur}ms, ${t.totalEvents} events`)
  }

  return lines
}

export function findExfilTimelines(timelines: ProcessTimeline[]): ProcessTimeline[] {
  return timelines.filter(t =>
    t.secretsRead > 0 && t.networkConnections > 0 && t.events.some(e =>
      e.type === 'NETWORK_CONNECT' || e.type === 'NETWORK_UPLOAD'
    )
  )
}

function formatDetail(node: EvidenceNode): string {
  const parts: string[] = []
  if (node.filePath && node.type !== 'FILE_CREATED' && node.type !== 'FILE_MODIFIED') {
    parts.push(node.filePath)
  }
  if (node.host) {
    parts.push(`${node.host}${node.port ? `:${node.port}` : ''}`)
  }
  if (node.sha256) {
    parts.push(`sha256:${node.sha256.substring(0, 12)}...`)
  }
  if (node.attributes?.cmdline) {
    const cmd = String(node.attributes.cmdline).substring(0, 80)
    parts.push(cmd)
  }
  return parts.join(' | ')
}

function extractPids(graph: EvidenceGraph, node: EvidenceNode): number[] {
  const pids: number[] = []
  for (const edge of graph.edges) {
    if (edge.from === node.id) {
      const target = graph.nodes.find(n => n.id === edge.to)
      if (target?.pid) pids.push(target.pid)
    }
  }
  return pids
}

function extractFiles(node: EvidenceNode): string[] {
  return node.filePath ? [node.filePath] : []
}

function extractHosts(node: EvidenceNode): string[] {
  return node.host ? [node.host] : []
}

function resolvePidForNode(
  node: EvidenceNode,
  edges: EvidenceEdge[],
  nodes: EvidenceNode[],
  pidNodeMap: Map<number, EvidenceNode>,
): number | undefined {
  if (node.pid) return node.pid

  const incomingEdges = edges.filter(e => e.to === node.id)
  for (const edge of incomingEdges) {
    const sourceNode = nodes.find(n => n.id === edge.from)
    if (sourceNode?.pid) return sourceNode.pid
    if (sourceNode) {
      const viaPid = resolvePidForNode(sourceNode, edges, nodes, pidNodeMap)
      if (viaPid) return viaPid
    }
  }

  return undefined
}

function makeEvent(
  node: EvidenceNode,
  procMap: Map<number, { name: string }>,
  graph: EvidenceGraph | undefined,
  resolvedPid: number,
): ProcessTimelineEvent {
  const durationMs = node.attributes?.durationMs as number | undefined
  return {
    pid: resolvedPid || node.pid || 0,
    processName: node.processName || procMap.get(resolvedPid)?.name || 'unknown' || node.label,
    sequenceIndex: 0,
    type: node.type,
    label: node.label,
    timestamp: node.timestamp,
    confidence: node.confidence,
    observationConfidence: node.observationConfidence,
    inferenceConfidence: node.inferenceConfidence,
    source: node.source,
    detail: formatDetail(node),
    relatedPids: graph && node.pid ? extractPids(graph, node) : [],
    relatedFiles: extractFiles(node),
    relatedHosts: extractHosts(node),
    durationMs,
  }
}

function estimateUploadBytes(events: ProcessTimelineEvent[]): number {
  let total = 0
  for (const e of events) {
    if (e.type === 'NETWORK_UPLOAD') {
      total += 4096
    }
  }
  return total
}

function eventIcon(type: EvidenceType): string {
  switch (type) {
    case 'PROCESS_CREATED': return '▶'
    case 'PROCESS_EXITED': return '■'
    case 'FILE_CREATED': return '+'
    case 'FILE_MODIFIED': return '~'
    case 'FILE_DELETED': return '-'
    case 'FILE_READ': return 'R'
    case 'NETWORK_CONNECT': return '→'
    case 'NETWORK_DNS_QUERY': return '?'
    case 'NETWORK_UPLOAD': return '↑'
    case 'NETWORK_DOWNLOAD': return '↓'
    case 'SECRET_ACCESSED': return '🔑'
    case 'SECRET_EXFILTRATED': return '⚠'
    case 'COMPILER_STARTED': return '⚙'
    case 'LINKER_STARTED': return '🔗'
    case 'ARTIFACT_CREATED': return '📦'
    case 'CONTRACT_VIOLATED': return '!'
    default: return '·'
  }
}

function confidenceIndicator(confidence: number): string {
  if (confidence >= 90) return '██'
  if (confidence >= 70) return '▇▇'
  if (confidence >= 50) return '▅▅'
  return '▂▂'
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes}B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)}MB`
}
