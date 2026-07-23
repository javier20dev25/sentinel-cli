import {
  BuildRecord,
} from '../../core/network/build-types'
import {
  computeBuildDna, computeMultiDna, computeMultiDnaSimilarity,
  buildDnaFingerprint, inferBuildGraph, deriveBehaviorChain,
  generateExplanation,
} from '../../core/network/build-dna'
import {
  loadBaseline, saveToBaseline, computeBaselineStats, computeNormality,
} from '../../core/network/build-baseline'
import { buildTemporalEvidenceGraph, buildBayesianNetwork, analyzeDominators, renderTemporalEvidenceGraph, renderBayesianNetwork, renderDominatorAnalysis } from '../../core/network/temporal-graph'
import { generateCausalNarrative, renderCausalNarrative } from '../../core/network/graph-analytics'
import { computeGraphStats, renderGraphStats } from '../../core/network/evidence-graph'
import * as pc from 'picocolors'

function fmtSize(bytes: number): string {
  if (bytes === 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(1024))
  return `${(bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0)} ${units[i]}`
}

function elapsed(ms: number): string {
  const s = Math.floor(ms / 1000)
  const m = Math.floor(s / 60)
  return m > 0 ? `${m}m ${s % 60}s` : `${s}s`
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

function indentText(text: string, pad = 4): string {
  return text.split('\n').map(l => ' '.repeat(pad) + l).join('\n')
}

export function renderBuildStory(record: BuildRecord, _prevRecord?: BuildRecord): string {
  const lines: string[] = []
  const s = record.summary
  const dna = computeBuildDna(record)
  const multiDna = computeMultiDna(record)
  const fp = buildDnaFingerprint(dna)
  const graph = inferBuildGraph(record)
  const behaviorChain = deriveBehaviorChain(record)
  const baseline = loadBaseline(record)
  const stats = computeBaselineStats(baseline)
  const normality = stats ? computeNormality(record, stats) : null

  const buildId = record.startTime.replace(/[^0-9]/g, '').substring(0, 14)

  lines.push('')
  lines.push('='.repeat(64))
  lines.push('  BUILD STORY')
  lines.push('='.repeat(64))
  lines.push('')

  lines.push(`  Build #${buildId}`)
  lines.push(`  Command:   ${record.command} ${record.args.join(' ')}`)
  lines.push(`  Duration:  ${elapsed(record.durationMs)}`)
  lines.push(`  Exit code: ${record.exitCode}`)
  lines.push(`  DNA:       ${fp.substring(0, 16)}`)
  lines.push('')

  if (stats && normality) {
    lines.push(`  Historical baseline: ${stats.count} build${stats.count > 1 ? 's' : ''}`)
    lines.push(`  Normality: ${(normality.overallNormality * 100).toFixed(1)}%`)
    if (normality.isOutlier) {
      lines.push(`  Outlier detected (z-score duration: ${normality.zScoreDuration > 0 ? '+' : ''}${normality.zScoreDuration.toFixed(1)})`)
    }
    lines.push('')
  }

  if (_prevRecord) {
    const prevMulti = computeMultiDna(_prevRecord)
    const sim = computeMultiDnaSimilarity(multiDna, prevMulti)
    lines.push(`  Similarity vs previous build: ${(sim.overall * 100).toFixed(1)}%`)
    lines.push(`    Toolchain:  ${(sim.toolchain * 100).toFixed(0)}%`)
    lines.push(`    Env:        ${(sim.environment * 100).toFixed(0)}%`)
    lines.push(`    Artifacts:  ${(sim.artifact * 100).toFixed(0)}%`)
    lines.push(`    Graph:      ${(sim.graph * 100).toFixed(0)}%`)
    lines.push(`    Behavior:   ${(sim.behavior * 100).toFixed(0)}%`)
    lines.push(`    Network:    ${(sim.network * 100).toFixed(0)}%`)
    lines.push('')
  } else if (stats) {
    lines.push('  (first build tracked — no comparison available)')
    lines.push('')
  }

  if (s.anomalies.length > 0) {
    lines.push('  Anomalies')
    for (const a of s.anomalies) {
      lines.push(`    [WARN] ${a}`)
    }
    lines.push('')
  }

  if (graph.length > 0) {
    lines.push('  Build Graph (DAG)')
    const dag = buildDagChains(graph)
    for (const chain of dag.slice(0, 8)) {
      lines.push(`    ${chain}`)
    }
    if (dag.length > 8) {
      lines.push(`    (${dag.length - 8} more edges)`)
    }
    lines.push('')
  }

  if (behaviorChain.length > 0) {
    lines.push('  Behavior chain:')
    lines.push('    ' + behaviorChain.join(' -> '))
    lines.push('')
  }

  lines.push('  Changes (Git-style)')

  if (s.anomalies.length > 0) {
    for (const a of s.anomalies) lines.push(`    ${'ANOMALY'.padEnd(12)} ${a}`)
  }

  if (_prevRecord) {
    const prevGraph = inferBuildGraph(_prevRecord)
    const newEdges = graph.filter(e => !prevGraph.some(p => p.from === e.from && p.to === e.to && p.type === e.type))
    const removedEdges = prevGraph.filter(e => !graph.some(p => p.from === e.from && p.to === e.to && p.type === e.type))

    for (const e of newEdges) {
      if (e.type === 'spawned') lines.push(`    ${'NEW PROCESS'.padEnd(12)} ${e.from} ${arrow(e.type)} ${e.to}`)
      else if (e.type === 'produced') lines.push(`    ${'NEW ARTIFACT'.padEnd(12)} ${e.from} ${arrow(e.type)} ${e.to}`)
    }
    for (const e of removedEdges) {
      if (e.type === 'spawned') lines.push(`    ${'REMOVED PROCESS'.padEnd(12)} ${e.from} ${arrow(e.type)} ${e.to}`)
      else if (e.type === 'produced') lines.push(`    ${'REMOVED ARTIFACT'.padEnd(12)} ${e.from} ${arrow(e.type)} ${e.to}`)
    }

    const prevTc = new Set(_prevRecord.summary.uniqueProcesses)
    const currTc = new Set(record.summary.uniqueProcesses)
    for (const t of currTc) { if (!prevTc.has(t)) lines.push(`    ${'NEW TOOL'.padEnd(12)} ${t}`) }
    for (const t of prevTc) { if (!currTc.has(t)) lines.push(`    ${'REMOVED TOOL'.padEnd(12)} ${t}`) }

    const prevEnv = _prevRecord.env
    const currEnv = record.env
    for (const k of Object.keys({ ...prevEnv, ...currEnv })) {
      if (prevEnv[k] !== currEnv[k]) {
        lines.push(`    ${'ENV CHANGED'.padEnd(12)} ${k} = ${currEnv[k] || '(unset)'}`)
      }
    }

    const prevHosts = new Set(_prevRecord.network.map(n => n.host))
    const currHosts = new Set(record.network.map(n => n.host))
    for (const h of currHosts) { if (!prevHosts.has(h)) lines.push(`    ${'NEW HOST'.padEnd(12)} ${h}`) }
  }

  const createdFiles = record.files.filter(f => f.operation === 'created')
  for (const f of createdFiles.slice(0, 10)) {
    lines.push(`    ${'CREATED'.padEnd(12)} ${f.filePath.split(/[/\\]/).pop()} (${fmtSize(f.size)})`)
  }
  const moddedFiles = record.files.filter(f => f.operation === 'modified')
  for (const f of moddedFiles.slice(0, 10)) {
    lines.push(`    ${'MODIFIED'.padEnd(12)} ${f.filePath.split(/[/\\]/).pop()} (${fmtSize(f.size)})`)
  }
  const deletedFiles = record.files.filter(f => f.operation === 'deleted')
  for (const f of deletedFiles.slice(0, 10)) {
    lines.push(`    ${'DELETED'.padEnd(12)} ${f.filePath.split(/[/\\]/).pop()}`)
  }

  if (record.network.length > 0) {
    for (const n of record.network) {
      if (n.type === 'dns') lines.push(`    ${'DNS'.padEnd(12)} ${n.host}`)
      else lines.push(`    ${'TCP'.padEnd(12)} ${n.host}:${n.port}`)
    }
  }

  if (!_prevRecord) {
    const createdCount = createdFiles.length
    const moddedCount = moddedFiles.length
    const deleteCount = deletedFiles.length
    if (createdCount + moddedCount + deleteCount === 0) {
      lines.push(`    ${'(none)'.padEnd(12)} No file changes detected`)
    }
  }
  lines.push('')

  const explanation = generateExplanation(record, graph, _prevRecord, multiDna, _prevRecord ? computeMultiDna(_prevRecord) : undefined)

  if (explanation.reasons.length > 0 || explanation.changes.length > 0) {
    lines.push('  Explanation')
    lines.push(`    ${explanation.summary}`)
    if (explanation.rootCause) {
      lines.push(`    Root cause: ${explanation.rootCause}`)
    }
    if (explanation.confidence < 0.85) {
      lines.push(`    Confidence: ${(explanation.confidence * 100).toFixed(0)}%`)
    }
    for (const r of explanation.reasons.slice(1, 5)) {
      lines.push(`    ${r}`)
    }
    lines.push('')
  }

  // ── Evidence Graph Analysis ──────────────────────────────────
  const evGraph = record.evidenceGraph
  if (evGraph && evGraph.nodes.length > 0) {
    lines.push(pc.cyan(pc.bold('  ─── Evidence Graph ───')))
    const graphStats = computeGraphStats(evGraph)
    lines.push(`  Nodes: ${graphStats.nodeCount}  |  Edges: ${graphStats.edgeCount}  |  Components: ${graphStats.componentCount}`)
    lines.push(`  Confidence: avg=${graphStats.avgConfidence} min=${graphStats.minConfidence} max=${graphStats.maxConfidence}`)
    if (Object.keys(graphStats.nodeCountByType).length > 0) {
      lines.push(`  Node types:`)
      for (const [type, count] of Object.entries(graphStats.nodeCountByType).sort((a, b) => b[1] - a[1])) {
        lines.push(`    ${type}: ${count}`)
      }
    }
    if (record.confidencePaths && record.confidencePaths.length > 0) {
      lines.push(`  Confidence paths found: ${record.confidencePaths.length}`)
      for (const cp of record.confidencePaths.slice(0, 3)) {
        const fromLabel = evGraph.nodes.find(n => n.id === cp.path[0])?.label || cp.path[0]
        const toLabel = evGraph.nodes.find(n => n.id === cp.path[cp.path.length - 1])?.label || cp.path[cp.path.length - 1]
        lines.push(`    ${fromLabel} → ${toLabel}: confidence=${cp.propagatedConfidence.toFixed(3)} hops=${cp.path.length}`)
      }
    }
    lines.push('')

    // ── Temporal Evidence Graph ──────────────────────────────
    const teg = buildTemporalEvidenceGraph(evGraph)
    if (teg.paths.length > 0) {
      lines.push(pc.cyan(pc.bold('  ─── Temporal Graph ───')))
      lines.push(`  Paths: ${teg.paths.length}  |  Avg latency: ${teg.avgEdgeLatencyMs}ms  |  Max latency: ${teg.maxEdgeLatencyMs}ms`)
      lines.push(`  Critical path: ${teg.criticalPath.causalDelayMs}ms (${teg.criticalPath.nodes.length} nodes)`)
      if (teg.criticalPath.bottleneckEdge) {
        const bn = teg.criticalPath.bottleneckEdge
        lines.push(`  Bottleneck: ${bn.from} → ${bn.to} (${bn.latencyMs || 0}ms)`)
      }
      lines.push('')
    }

    // ── Bayesian Network ────────────────────────────────────
    const bn = buildBayesianNetwork(evGraph)
    if (bn.relations.length > 0) {
      lines.push(pc.cyan(pc.bold('  ─── Bayesian Network ───')))
      lines.push(`  Global prior: ${bn.globalPrior}  |  Overall posterior: ${bn.overallPosterior}`)
      const sortedRels = [...bn.relations].sort((a, b) => b.posteriorGivenEvidence - a.posteriorGivenEvidence)
      for (const r of sortedRels.slice(0, 5)) {
        const delta = r.posteriorGivenEvidence - r.priorP
        const deltaStr = delta >= 0 ? `+${delta.toFixed(3)}` : delta.toFixed(3)
        lines.push(`    ${r.relation}: prior=${r.priorP} posterior=${r.posteriorGivenEvidence} (Δ${deltaStr}) n=${r.sampleCount}`)
      }
      lines.push('')
    }

    // ── Dominator Analysis ──────────────────────────────────
    const da = analyzeDominators(evGraph)
    if (da.dominantProcess) {
      lines.push(pc.cyan(pc.bold('  ─── Dominator Analysis ───')))
      const dominantNode = evGraph.nodes.find(n => n.id === da.dominantProcess)
      lines.push(`  Dominant process: ${dominantNode?.label || da.dominantProcess}`)
      if (da.toolchainShiftDetected) {
        lines.push(pc.red(pc.bold('  ⚠ TOOLCHAIN SHIFT DETECTED')))
      }
      lines.push(`  Hijack risk: ${(da.hijackRiskScore * 100).toFixed(1)}%`)
      if (da.dominantPath.length > 0) {
        lines.push(`  Dominant path: ${da.dominantPath.join(' → ')}`)
      }
      if (da.anomalySignals.length > 0) {
        for (const s of da.anomalySignals) {
          lines.push(pc.yellow(`    ⚠ ${s}`))
        }
      }
      lines.push('')
    }

    // ── Causal Narrative ────────────────────────────────────
    const narrative = generateCausalNarrative(evGraph)
    if (narrative.events.length > 0) {
      lines.push(pc.cyan(pc.bold('  ─── Causal Narrative ───')))
      lines.push(`  ${narrative.summary}`)
      lines.push('')
      lines.push(pc.bold('  Timeline:'))
      for (const t of narrative.timeline.slice(0, 10)) {
        lines.push(`    ${t}`)
      }
      if (narrative.timeline.length > 10) {
        lines.push(`    ... and ${narrative.timeline.length - 10} more events`)
      }
      lines.push('')
      if (narrative.keyFindings.length > 0) {
        lines.push(pc.bold('  Key findings:'))
        for (const f of narrative.keyFindings) {
          lines.push(`    • ${f}`)
        }
      }
      if (narrative.recommendations.length > 0) {
        lines.push('')
        lines.push(pc.bold('  Recommendations:'))
        for (const r of narrative.recommendations) {
          lines.push(pc.dim(`    → ${r}`))
        }
      }
      lines.push('')
    }
  }

  // ── Confidence & Hermetic Scores ──────────────────────────────
  if (record.observationConfidence !== undefined) {
    lines.push(`  Observation confidence: ${record.observationConfidence}`)
  }
  if (record.hermetricScore !== undefined) {
    const score = record.hermetricScore
    const scoreColor = score >= 80 ? pc.green : score >= 50 ? pc.yellow : pc.red
    lines.push(`  Hermetic score: ${scoreColor(score + '/100')}`)
  }
  if (record.reproducibilityScore !== undefined) {
    const score = record.reproducibilityScore
    const scoreColor = score >= 80 ? pc.green : score >= 50 ? pc.yellow : pc.red
    lines.push(`  Reproducibility: ${scoreColor(score + '/100')}`)
  }
  if (record.observationConfidence !== undefined || record.hermetricScore !== undefined) {
    lines.push('')
  }

  lines.push(`  Verdict: ${s.anomalies.length > 0 ? 'REVIEW' : 'CLEAN'}`)
  lines.push(`  DNA: ${fp.substring(0, 16)}...${fp.substring(fp.length - 8)}`)
  lines.push('='.repeat(64))
  lines.push('')

  return lines.join('\n')
}

function buildDagChains(edges: ReturnType<typeof inferBuildGraph>): string[] {
  const result: string[] = []
  const byFrom = new Map<string, typeof edges>()
  const byTo = new Map<string, typeof edges>()
  for (const e of edges) {
    if (!byFrom.has(e.from)) byFrom.set(e.from, [])
    byFrom.get(e.from)!.push(e)
    if (!byTo.has(e.to)) byTo.set(e.to, [])
    byTo.get(e.to)!.push(e)
  }

  const roots = [...new Set(edges.map(e => e.from))].filter(f => !byTo.has(f) || byTo.get(f)!.every(e => e.type !== 'spawned'))

  function walk(node: string, depth: number, visited: Set<string>) {
    if (depth > 10 || visited.has(node)) return
    visited.add(node)
    const out = byFrom.get(node) || []
    for (const e of out) {
      const prefix = '  '.repeat(depth)
      result.push(`${prefix}${node} ${arrow(e.type)} ${e.to}`)
      walk(e.to, depth + 1, new Set(visited))
    }
  }

  for (const r of roots) walk(r, 0, new Set())
  return result
}
