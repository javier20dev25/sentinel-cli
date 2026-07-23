import { BuildRecord, ProvenanceGraph, ProvenanceNode, ProvenanceEdge } from './build-types'
import { inferBuildGraph } from './build-dna'

const COMPILERS = new Set(['gcc', 'g++', 'clang', 'clang++', 'cc', 'c++', 'rustc', 'javac'])
const LINKERS = new Set(['ld', 'ld.lld', 'lld-link', 'link', 'link.exe'])
const ARCHIVERS = new Set(['ar', 'lib.exe', 'ranlib'])
const SCRIPTS = new Set(['configure', 'autoconf', 'automake', 'meson', 'cmake', 'python', 'python3', 'node'])
const DOWNLOADERS = new Set(['curl', 'wget', 'fetch'])

const SOURCE_EXT = new Set(['.c', '.cc', '.cpp', '.cxx', '.h', '.hpp', '.rs', '.go', '.java', '.ts', '.js', '.py', '.s', '.S', '.asm'])
const INTERMEDIATE_EXT = new Set(['.o', '.obj', '.lo', '.lib', '.a', '.rlib', '.class'])
const ARTIFACT_EXT = new Set(['.so', '.dll', '.exe', '.out', '.wasm', '.node', '.dylib', '.bin', '.elf'])

export function buildProvenanceGraph(record: BuildRecord, prevRecord?: BuildRecord): ProvenanceGraph {
  const nodes: Map<string, ProvenanceNode> = new Map()
  const edges: ProvenanceEdge[] = []
  const stages: Set<string> = new Set()

  addToolNodes(record, nodes, stages)
  addFileNodes(record, nodes)
  addArtifactNodes(record, nodes)
  addProvenanceEdges(record, nodes, edges, stages)
  addGraphEdges(record, nodes, edges)
  addReadEdges(record, nodes, edges)

  const stagesOrdered = ['configure', 'compile', 'archive', 'link', 'download', 'package', 'finalize']
    .filter(s => stages.has(s))

  return {
    nodes: [...nodes.values()],
    edges,
    stages: stagesOrdered,
    buildId: record.startTime,
  }
}

function addToolNodes(record: BuildRecord, nodes: Map<string, ProvenanceNode>, stages: Set<string>): void {
  const toolSet = new Set(record.summary.uniqueProcesses)
  for (const tool of toolSet) {
    nodes.set(tool, {
      id: tool,
      label: tool,
      type: 'tool',
      detail: '',
    })

    if (COMPILERS.has(tool)) stages.add('compile')
    if (LINKERS.has(tool)) stages.add('link')
    if (ARCHIVERS.has(tool)) stages.add('archive')
    if (SCRIPTS.has(tool)) stages.add('configure')
    if (DOWNLOADERS.has(tool)) stages.add('download')
  }
}

function addFileNodes(record: BuildRecord, nodes: Map<string, ProvenanceNode>): void {
  for (const f of record.files) {
    const fname = f.filePath.split(/[/\\]/).pop() || f.filePath
    const ext = '.' + (fname.split('.').pop() || '')
    let type: ProvenanceNode['type'] = 'intermediate'

    if (SOURCE_EXT.has(ext)) type = 'source'
    else if (ARTIFACT_EXT.has(ext)) type = 'artifact'

    const id = `file:${f.filePath}`
    if (!nodes.has(id)) {
      nodes.set(id, {
        id,
        label: fname,
        type,
        detail: `${f.size}B (${f.operation})`,
        size: f.size,
        timestamp: f.timestamp,
      })
    }
  }
}

function addArtifactNodes(record: BuildRecord, nodes: Map<string, ProvenanceNode>): void {
  for (const a of record.artifactHashes) {
    const fname = a.filePath.split(/[/\\]/).pop() || a.filePath
    const id = `artifact:${a.filePath}`
    if (!nodes.has(id)) {
      nodes.set(id, {
        id,
        label: fname,
        type: 'artifact',
        detail: `SHA256 ${a.sha256.substring(0, 12)} (${a.size}B)`,
        sha256: a.sha256,
        size: a.size,
      })
    } else {
      const existing = nodes.get(id)!
      existing.sha256 = a.sha256
      existing.size = a.size
    }
  }
}

function addProvenanceEdges(
  record: BuildRecord,
  nodes: Map<string, ProvenanceNode>,
  edges: ProvenanceEdge[],
  stages: Set<string>,
): void {
  for (const f of record.files) {
    if (f.operation !== 'created') continue
    const fname = f.filePath.split(/[/\\]/).pop() || f.filePath
    const ext = '.' + (fname.split('.').pop() || '')

    const nearestTool = findNearestTool(record, f.timestamp)
    if (!nearestTool) continue

    let edgeType: ProvenanceEdge['type'] = 'generated'
    if (COMPILERS.has(nearestTool) && SOURCE_EXT.has(ext)) edgeType = 'compiled'
    else if (COMPILERS.has(nearestTool) && INTERMEDIATE_EXT.has(ext)) edgeType = 'compiled'
    else if (LINKERS.has(nearestTool)) edgeType = 'linked'
    else if (ARCHIVERS.has(nearestTool)) edgeType = 'archived'
    else if (DOWNLOADERS.has(nearestTool)) edgeType = 'downloaded'
    else if (SCRIPTS.has(nearestTool)) edgeType = 'configured'

    const targetId = `file:${f.filePath}`
    edges.push({
      from: nearestTool,
      to: targetId,
      type: edgeType,
      tool: nearestTool,
      timestamp: f.timestamp,
    })
  }

  for (const a of record.artifactHashes) {
    const fname = a.filePath.split(/[/\\]/).pop() || a.filePath
    const artifactId = `artifact:${a.filePath}`

    const producer = edges.find(e => {
      const targetLabel = e.to.startsWith('file:') ? nodes.get(e.to)?.label : null
      return targetLabel === fname || e.to === artifactId
    })

    if (producer) {
      edges.push({
        from: producer.to,
        to: artifactId,
        type: 'generated',
        tool: producer.tool,
        timestamp: producer.timestamp,
      })
    }
  }
}

function addGraphEdges(record: BuildRecord, nodes: Map<string, ProvenanceNode>, edges: ProvenanceEdge[]): void {
  const graphEdges = inferBuildGraph(record)
  for (const ge of graphEdges) {
    if (ge.type !== 'spawned') continue
    if (!nodes.has(ge.from) || !nodes.has(ge.to)) continue

    edges.push({
      from: ge.from,
      to: ge.to,
      type: 'generated',
      tool: ge.from,
      timestamp: ge.timestamp,
    })
  }
}

function findNearestTool(record: BuildRecord, timestamp: number): string | null {
  const procs = record.processes.filter(p => p.pid !== 0).sort((a, b) => a.timestamp - b.timestamp)
  let nearest: string | null = null
  let minDist = Infinity
  for (const p of procs) {
    const dist = Math.abs(p.timestamp - timestamp)
    if (dist < minDist && dist < 10000) {
      minDist = dist
      nearest = p.name
    }
  }
  return nearest
}

export function renderProvenanceGraph(pg: ProvenanceGraph): string {
  const lines: string[] = [
    'Provenance Graph',
    '================',
    `Build: ${pg.buildId}`,
    `Stages: ${pg.stages.join(' → ')}`,
    `Nodes: ${pg.nodes.length}, Edges: ${pg.edges.length}`,
    '',
  ]

  const stageGroups = groupNodesByStage(pg)

  for (const stage of pg.stages) {
    lines.push(`[${stage.toUpperCase()}]`)
    const items = stageGroups.get(stage) || []
    for (const item of items) {
      lines.push(`  ${item.icon} ${item.label}`)
    }
    lines.push('')
  }

  return lines.join('\n')
}

function groupNodesByStage(pg: ProvenanceGraph): Map<string, { icon: string; label: string }[]> {
  const groups = new Map<string, { icon: string; label: string }[]>()
  const stageMap: Record<string, string[]> = {
    configure: ['configure', 'autoconf', 'automake', 'cmake', 'meson', 'python', 'python3', 'node'],
    compile: ['gcc', 'g++', 'clang', 'clang++', 'cc', 'c++', 'rustc', 'javac'],
    archive: ['ar', 'lib.exe', 'ranlib', 'ld'],
    link: ['ld', 'ld.lld', 'lld-link', 'link', 'link.exe'],
    download: ['curl', 'wget', 'fetch'],
  }

  for (const stage of pg.stages) {
    groups.set(stage, [])
  }

  for (const n of pg.nodes) {
    let assigned = false
    for (const stage of pg.stages) {
      const tools = stageMap[stage] || []
      if ((n.type === 'tool' && tools.includes(n.label)) || (n.type !== 'tool' && hasEdgeToTool(pg, n.id, tools))) {
        const icon = n.type === 'tool' ? '→' : n.type === 'source' ? '·' : n.type === 'artifact' ? '•' : '▸'
        groups.get(stage)?.push({ icon, label: `${n.label} (${n.type})` })
        assigned = true
        break
      }
    }
    if (!assigned) {
      if (!groups.has('finalize')) groups.set('finalize', [])
      const icon = n.type === 'tool' ? '→' : n.type === 'artifact' ? '•' : '▸'
      groups.get('finalize')?.push({ icon, label: `${n.label} (${n.type})` })
    }
  }

  return groups
}

function hasEdgeToTool(pg: ProvenanceGraph, nodeId: string, tools: string[]): boolean {
  return pg.edges.some(e => (e.from === nodeId && tools.includes(e.tool)) || (e.to === nodeId && tools.includes(e.tool)))
}

function addReadEdges(record: BuildRecord, nodes: Map<string, ProvenanceNode>, edges: ProvenanceEdge[]): void {
  if (!record.readFiles) return

  for (const r of record.readFiles) {
    const fname = r.filePath.split(/[/\\]/).pop() || r.filePath
    const ext = '.' + (fname.split('.').pop() || '')
    const fileId = `file:${r.filePath}`

    if (!nodes.has(fileId)) {
      nodes.set(fileId, {
        id: fileId,
        label: fname,
        type: SOURCE_EXT.has(ext) ? 'source' : 'intermediate',
        detail: `${r.size}B (read)`,
        size: r.size,
        timestamp: r.timestamp,
      })
    }

    const toolName = r.processName
    if (!nodes.has(toolName)) {
      nodes.set(toolName, {
        id: toolName,
        label: toolName,
        type: 'tool',
        detail: '',
      })
    }

    const alreadyExists = edges.some(e => e.from === toolName && e.to === fileId && e.type === 'read')
    if (!alreadyExists) {
      edges.push({
        from: toolName,
        to: fileId,
        type: 'read',
        tool: toolName,
        timestamp: r.timestamp,
      })
    }
  }
}
