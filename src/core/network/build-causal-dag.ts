import { BuildRecord, BuildGraphEdge, CausalNode, ProcessNode } from './build-types'
import { inferBuildGraph } from './build-dna'

const DANGEROUS_SET = new Set(['curl', 'wget', 'fetch', 'perl', 'openssl', 'base64', 'nc', 'ncat', 'socat'])

export function buildCausalDag(record: BuildRecord, graph?: BuildGraphEdge[]): CausalNode[] {
  const edges = graph || inferBuildGraph(record)
  const rootProcesses = record.summary.processTree
  if (rootProcesses.length === 0) {
    return buildFromProcessList(record, edges)
  }
  return buildFromTree(rootProcesses, edges, record, 0)
}

function buildFromTree(
  nodes: ProcessNode[],
  edges: BuildGraphEdge[],
  record: BuildRecord,
  depth: number,
): CausalNode[] {
  const result: CausalNode[] = []
  for (const n of nodes) {
    const nodeType: CausalNode['type'] = DANGEROUS_SET.has(n.name) ? 'behavior' : 'process'
    const cn: CausalNode = {
      id: `proc:${n.name}:${n.pid}`,
      label: n.name,
      type: nodeType,
      detail: n.cmdline.substring(0, 120),
      depth,
      children: [],
    }

    addProducedFiles(cn, n, edges, record, depth)
    addSpawnedChildren(cn, n, edges, record, depth)
    addNetworkEvents(cn, n, record, depth)

    result.push(cn)
  }
  return result
}

function addProducedFiles(cn: CausalNode, n: ProcessNode, edges: BuildGraphEdge[], record: BuildRecord, depth: number): void {
  const produced = edges.filter(e => e.type === 'produced' && e.from === n.name)
  for (const p of produced) {
    cn.children.push({
      id: `file:${p.to}`,
      label: p.to,
      type: 'file',
      detail: `produced by ${n.name}`,
      depth: depth + 1,
      children: [],
    })
  }

  const artifacts = record.artifactHashes.filter(a => {
    const fname = a.filePath.split(/[/\\]/).pop() || ''
    return cn.children.some(c => c.label === fname)
  })
  for (const a of artifacts) {
    const fname = a.filePath.split(/[/\\]/).pop() || a.filePath
    if (!cn.children.some(c => c.label === fname && c.type === 'artifact')) {
      cn.children.push({
        id: `artifact:${a.filePath}`,
        label: fname,
        type: 'artifact',
        detail: `SHA256 ${a.sha256.substring(0, 12)} (${a.size}B)`,
        depth: depth + 1,
        children: [],
      })
    }
  }
}

function addSpawnedChildren(cn: CausalNode, n: ProcessNode, edges: BuildGraphEdge[], record: BuildRecord, depth: number): void {
  if (n.children.length > 0) {
    const childDag = buildFromTree(n.children, edges, record, depth + 1)
    cn.children.push(...childDag)
  }
}

function addNetworkEvents(cn: CausalNode, n: ProcessNode, record: BuildRecord, depth: number): void {
  const procEvents = record.processes.filter(p => p.name === n.name)
  for (const pe of procEvents) {
    const nearbyNet = record.network.filter(net => Math.abs(net.timestamp - pe.timestamp) < 5000)
    for (const net of nearbyNet.slice(0, 3)) {
      if (!cn.children.some(c => c.label === net.host)) {
        cn.children.push({
          id: `net:${net.host}:${net.timestamp}`,
          label: net.host,
          type: 'network',
          detail: `${net.type}${net.port ? `:${net.port}` : ''}`,
          depth: depth + 1,
          children: [],
        })
      }
    }
  }
}

function buildFromProcessList(record: BuildRecord, edges: BuildGraphEdge[]): CausalNode[] {
  const result: CausalNode[] = []
  const procs = record.processes.filter(p => p.pid !== 0).sort((a, b) => a.timestamp - b.timestamp)

  const topLevel = procs.filter(p => p.ppid === 0 || !procs.some(pp => pp.pid === p.ppid))
  for (const p of topLevel) {
    const nodeType: CausalNode['type'] = DANGEROUS_SET.has(p.name) ? 'behavior' : 'process'
    const cn: CausalNode = {
      id: `proc:${p.name}:${p.pid}`,
      label: p.name,
      type: nodeType,
      detail: p.cmdline.substring(0, 120),
      depth: 0,
      children: [],
      timestamp: p.timestamp,
    }

    const childProcs = procs.filter(cp => cp.ppid === p.pid && cp.pid !== p.pid)
    for (const cp of childProcs) {
      cn.children.push({
        id: `proc:${cp.name}:${cp.pid}`,
        label: cp.name,
        type: 'process',
        detail: cp.cmdline.substring(0, 120),
        depth: 1,
        children: [],
        timestamp: cp.timestamp,
      })
    }

    result.push(cn)
  }

  return result
}

export function renderCausalDag(nodes: CausalNode[], indent = ''): string[] {
  const lines: string[] = []
  for (const n of nodes) {
    const icon = n.type === 'process' ? '→' : n.type === 'file' ? '·' : n.type === 'artifact' ? '•' : n.type === 'network' ? '○' : '►'
    lines.push(`${indent}${icon} ${n.label}${n.detail ? ` (${n.detail})` : ''}`)
    if (n.children.length > 0) {
      lines.push(...renderCausalDag(n.children, indent + '  '))
    }
  }
  return lines
}
