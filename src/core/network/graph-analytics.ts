import {
  EvidenceGraph, EvidenceNode, EvidenceEdge, EvidenceType, EvidenceRelation,
} from './build-types'
import {
  computeAdvancedGraphStats, computeGraphStats,
} from './evidence-graph'
import {
  buildTemporalEvidenceGraph, buildBayesianNetwork, analyzeDominators,
  computeFullGraphMetrics,
} from './temporal-graph'
import { TemporalEvidenceGraph, BayesianNetwork, DominatorAnalysis, EvidenceGraphMetrics } from './build-types'

// ── Graph Diff ──────────────────────────────────────────────────
export interface NodeDiff {
  id: string
  type: EvidenceType
  label: string
  status: 'added' | 'removed' | 'unchanged'
  node?: EvidenceNode
}

export interface EdgeDiff {
  from: string
  to: string
  relation: EvidenceRelation
  status: 'added' | 'removed' | 'unchanged'
  confidenceDelta?: number
  latencyDelta?: number
}

export interface CentralityDiff {
  nodeId: string
  label: string
  betweennessBefore: number
  betweennessAfter: number
  closenessBefore: number
  closenessAfter: number
  betweennessDelta: number
  closenessDelta: number
  significantChange: boolean
}

export interface DominatorDiff {
  nodeLabel: string
  idomBefore: string | null
  idomAfter: string | null
  changed: boolean
}

export interface GraphDiffResult {
  buildIdA: string
  buildIdB: string
  timestampA: number
  timestampB: number

  nodesAdded: NodeDiff[]
  nodesRemoved: NodeDiff[]
  nodesUnchanged: number
  totalNodeDelta: number

  edgesAdded: EdgeDiff[]
  edgesRemoved: EdgeDiff[]
  edgesUnchanged: number
  totalEdgeDelta: number

  centralityShifts: CentralityDiff[]
  maxCentralityShift: number

  dominatorChanges: DominatorDiff[]
  dominantProcessChanged: boolean

  criticalPathBefore: string[]
  criticalPathAfter: string[]
  criticalPathChanged: boolean

  bayesianShift: {
    relation: string
    posteriorBefore: number
    posteriorAfter: number
    delta: number
  }[]

  graphStatsBefore: EvidenceGraphMetrics
  graphStatsAfter: EvidenceGraphMetrics
  statsDelta: {
    densityDelta: number
    entropyDelta: number
    depthDelta: number
    componentDelta: number
  }

  anomalySignals: string[]
  riskScore: number
}

export function computeGraphDiff(
  graphA: EvidenceGraph,
  graphB: EvidenceGraph,
): GraphDiffResult {
  // Node diff
  const nodesA = new Map(graphA.nodes.map(n => [n.id, n]))
  const nodesB = new Map(graphB.nodes.map(n => [n.id, n]))
  const nodeDiffs: NodeDiff[] = []

  for (const [id, node] of nodesA) {
    if (!nodesB.has(id)) {
      nodeDiffs.push({ id, type: node.type, label: node.label, status: 'removed', node })
    }
  }
  for (const [id, node] of nodesB) {
    if (!nodesA.has(id)) {
      nodeDiffs.push({ id, type: node.type, label: node.label, status: 'added', node })
    }
  }

  const nodesAdded = nodeDiffs.filter(d => d.status === 'added')
  const nodesRemoved = nodeDiffs.filter(d => d.status === 'removed')
  const nodesUnchanged = graphA.nodes.length - nodesRemoved.length

  // Edge diff
  const edgesA = new Set(graphA.edges.map(e => `${e.from}|${e.to}|${e.relation}`))
  const edgesB = new Set(graphB.edges.map(e => `${e.from}|${e.to}|${e.relation}`))
  const edgeMapA = new Map(graphA.edges.map(e => [`${e.from}|${e.to}|${e.relation}`, e]))
  const edgeMapB = new Map(graphB.edges.map(e => [`${e.from}|${e.to}|${e.relation}`, e]))
  const edgeDiffs: EdgeDiff[] = []

  for (const key of edgesA) {
    if (!edgesB.has(key)) {
      const e = edgeMapA.get(key)!
      edgeDiffs.push({ from: e.from, to: e.to, relation: e.relation, status: 'removed' })
    }
  }
  for (const key of edgesB) {
    if (!edgesA.has(key)) {
      const e = edgeMapB.get(key)!
      edgeDiffs.push({ from: e.from, to: e.to, relation: e.relation, status: 'added' })
    }
  }

  const edgesAdded = edgeDiffs.filter(d => d.status === 'added')
  const edgesRemoved = edgeDiffs.filter(d => d.status === 'removed')
  const edgesUnchanged = graphA.edges.length - edgesRemoved.length

  // Centrality diff
  const advA = computeAdvancedGraphStats(graphA)
  const advB = computeAdvancedGraphStats(graphB)
  const centralityShifts: CentralityDiff[] = []
  let maxCentralityShift = 0

  for (const id of nodesA.keys()) {
    if (!nodesB.has(id)) continue
    const node = nodesA.get(id)!
    const betBefore = advA.betweennessCentrality[id] || 0
    const betAfter = advB.betweennessCentrality[id] || 0
    const cloBefore = advA.closenessCentrality[id] || 0
    const cloAfter = advB.closenessCentrality[id] || 0
    const betDelta = Math.abs(betAfter - betBefore)
    const cloDelta = Math.abs(cloAfter - cloBefore)
    const significantChange = betDelta > 0.2 || cloDelta > 0.2

    if (significantChange) {
      centralityShifts.push({
        nodeId: id,
        label: node.label,
        betweennessBefore: betBefore,
        betweennessAfter: betAfter,
        closenessBefore: cloBefore,
        closenessAfter: cloAfter,
        betweennessDelta: Math.round(betDelta * 1000) / 1000,
        closenessDelta: Math.round(cloDelta * 1000) / 1000,
        significantChange,
      })
    }
    maxCentralityShift = Math.max(maxCentralityShift, betDelta, cloDelta)
  }

  // Dominator diff
  const daA = analyzeDominators(graphA)
  const daB = analyzeDominators(graphB)
  const dominatorChanges: DominatorDiff[] = []

  for (const [id, idomB] of Object.entries(daB.currentDominators)) {
    const idomA = daA.currentDominators[id]
    if (idomA !== idomB) {
      const node = nodesB.get(id)
      dominatorChanges.push({
        nodeLabel: node?.label || id.substring(0, 12),
        idomBefore: idomA,
        idomAfter: idomB,
        changed: true,
      })
    }
  }

  // Critical path diff
  const tegA = buildTemporalEvidenceGraph(graphA)
  const tegB = buildTemporalEvidenceGraph(graphB)
  const criticalPathBefore = tegA.criticalPath.nodes
  const criticalPathAfter = tegB.criticalPath.nodes
  const criticalPathChanged = JSON.stringify(criticalPathBefore) !== JSON.stringify(criticalPathAfter)

  // Bayesian shift
  const bnA = buildBayesianNetwork(graphA)
  const bnB = buildBayesianNetwork(graphB)
  const bayesianShift: { relation: string; posteriorBefore: number; posteriorAfter: number; delta: number }[] = []

  for (const rA of bnA.relations) {
    const rB = bnB.relations.find(r => r.relation === rA.relation)
    if (rB) {
      const delta = Math.round((rB.posteriorGivenEvidence - rA.posteriorGivenEvidence) * 1000) / 1000
      if (Math.abs(delta) > 0.01) {
        bayesianShift.push({
          relation: rA.relation,
          posteriorBefore: rA.posteriorGivenEvidence,
          posteriorAfter: rB.posteriorGivenEvidence,
          delta,
        })
      }
    }
  }

  // Stats delta
  const statsA = computeFullGraphMetrics(graphA, tegA, bnA, daA)
  const statsB = computeFullGraphMetrics(graphB, tegB, bnB, daB)
  const statsDelta = {
    densityDelta: Math.round((statsB.graphDensity - statsA.graphDensity) * 10000) / 10000,
    entropyDelta: Math.round((statsB.graphEntropy - statsA.graphEntropy) * 1000) / 1000,
    depthDelta: statsB.maxDepth - statsA.maxDepth,
    componentDelta: statsB.componentCount - statsA.componentCount,
  }

  // Anomaly signals
  const anomalySignals: string[] = []
  if (nodesAdded.length > 0) anomalySignals.push(`${nodesAdded.length} node(s) added`)
  if (nodesRemoved.length > 0) anomalySignals.push(`${nodesRemoved.length} node(s) removed`)
  if (edgesAdded.length > 0) anomalySignals.push(`${edgesAdded.length} edge(s) added`)
  if (edgesRemoved.length > 0) anomalySignals.push(`${edgesRemoved.length} edge(s) removed`)
  if (dominatorChanges.length > 0) anomalySignals.push(`${dominatorChanges.length} dominator(s) changed`)
  if (criticalPathChanged) anomalySignals.push('Critical path changed')
  if (daB.toolchainShiftDetected) anomalySignals.push('Toolchain shift detected')
  if (centralityShifts.length > 0) anomalySignals.push(`${centralityShifts.length} centrality shift(s)`)

  // Risk score
  let riskScore = 0
  if (daB.toolchainShiftDetected) riskScore += 0.3
  if (nodesAdded.filter(n => n.type === 'NETWORK_CONNECT' || n.type === 'NETWORK_UPLOAD').length > 0) riskScore += 0.2
  if (nodesAdded.filter(n => n.type === 'SECRET_ACCESSED' || n.type === 'SECRET_EXFILTRATED').length > 0) riskScore += 0.25
  if (dominatorChanges.length > 0) riskScore += 0.1
  if (criticalPathChanged) riskScore += 0.1
  if (maxCentralityShift > 0.5) riskScore += 0.05
  riskScore = Math.min(riskScore, 1)

  return {
    buildIdA: graphA.buildId,
    buildIdB: graphB.buildId,
    timestampA: graphA.createdAt,
    timestampB: graphB.createdAt,
    nodesAdded,
    nodesRemoved,
    nodesUnchanged,
    totalNodeDelta: nodesAdded.length - nodesRemoved.length,
    edgesAdded,
    edgesRemoved,
    edgesUnchanged,
    totalEdgeDelta: edgesAdded.length - edgesRemoved.length,
    centralityShifts,
    maxCentralityShift: Math.round(maxCentralityShift * 1000) / 1000,
    dominatorChanges,
    dominantProcessChanged: daA.dominantProcess !== daB.dominantProcess,
    criticalPathBefore,
    criticalPathAfter,
    criticalPathChanged,
    bayesianShift,
    graphStatsBefore: statsA,
    graphStatsAfter: statsB,
    statsDelta,
    anomalySignals,
    riskScore: Math.round(riskScore * 1000) / 1000,
  }
}

export function renderGraphDiff(diff: GraphDiffResult): string[] {
  const lines: string[] = [
    'Graph Diff',
    '==========',
    `  Build A: ${diff.buildIdA}`,
    `  Build B: ${diff.buildIdB}`,
    '',
    '  Node changes:',
    `    Added: ${diff.nodesAdded.length}`,
    `    Removed: ${diff.nodesRemoved.length}`,
    `    Unchanged: ${diff.nodesUnchanged}`,
    `    Net delta: ${diff.totalEdgeDelta > 0 ? '+' : ''}${diff.totalNodeDelta}`,
  ]

  if (diff.nodesAdded.length > 0) {
    lines.push('', '  Added nodes:')
    for (const n of diff.nodesAdded.slice(0, 5)) {
      lines.push(`    + ${n.label} (${n.type})`)
    }
    if (diff.nodesAdded.length > 5) lines.push(`    ... and ${diff.nodesAdded.length - 5} more`)
  }

  if (diff.nodesRemoved.length > 0) {
    lines.push('', '  Removed nodes:')
    for (const n of diff.nodesRemoved.slice(0, 5)) {
      lines.push(`    - ${n.label} (${n.type})`)
    }
    if (diff.nodesRemoved.length > 5) lines.push(`    ... and ${diff.nodesRemoved.length - 5} more`)
  }

  lines.push('', '  Edge changes:')
  lines.push(`    Added: ${diff.edgesAdded.length}`)
  lines.push(`    Removed: ${diff.edgesRemoved.length}`)
  lines.push(`    Net delta: ${diff.totalEdgeDelta > 0 ? '+' : ''}${diff.totalEdgeDelta}`)

  if (diff.dominatorChanges.length > 0) {
    lines.push('', '  Dominator changes:')
    for (const d of diff.dominatorChanges.slice(0, 5)) {
      lines.push(`    ${d.nodeLabel}: ${d.idomBefore || 'root'} → ${d.idomAfter || 'root'}`)
    }
  }

  if (diff.criticalPathChanged) {
    lines.push('', '  Critical path changed:')
    lines.push(`    Before: ${diff.criticalPathBefore.join(' → ')}`)
    lines.push(`    After:  ${diff.criticalPathAfter.join(' → ')}`)
  }

  if (diff.bayesianShift.length > 0) {
    lines.push('', '  Bayesian shifts:')
    for (const s of diff.bayesianShift.slice(0, 5)) {
      const arrow = s.delta > 0 ? '↑' : '↓'
      lines.push(`    ${s.relation}: ${s.posteriorBefore} → ${s.posteriorAfter} (${arrow}${Math.abs(s.delta).toFixed(3)})`)
    }
  }

  lines.push('', '  Stats delta:')
  lines.push(`    Density: ${diff.statsDelta.densityDelta > 0 ? '+' : ''}${diff.statsDelta.densityDelta}`)
  lines.push(`    Entropy: ${diff.statsDelta.entropyDelta > 0 ? '+' : ''}${diff.statsDelta.entropyDelta}`)
  lines.push(`    Depth: ${diff.statsDelta.depthDelta > 0 ? '+' : ''}${diff.statsDelta.depthDelta}`)
  lines.push(`    Components: ${diff.statsDelta.componentDelta > 0 ? '+' : ''}${diff.statsDelta.componentDelta}`)

  lines.push('', `  Risk score: ${(diff.riskScore * 100).toFixed(1)}%`)

  if (diff.anomalySignals.length > 0) {
    lines.push('', '  Anomaly signals:')
    for (const s of diff.anomalySignals) {
      lines.push(`    ⚠ ${s}`)
    }
  }

  return lines
}

// ── Continuous Learning Pipeline ────────────────────────────────
export interface ModelVersion {
  version: string
  trainedAt: number
  trainedOnExamples: number
  accuracy: number
  precision: number
  recall: number
  f1: number
  auc: number
  weights: Record<string, number>
  intercept: number
  featureNames: string[]
  metadata: {
    platform?: string
    nodeVersion?: string
    commandPattern?: string
    labelDistribution: Record<string, number>
  }
}

export interface LearningPipeline {
  modelVersions: ModelVersion[]
  currentModel: ModelVersion | null
  feedbackLog: FeedbackEntry[]
  trainingRuns: TrainingRun[]
}

export interface FeedbackEntry {
  buildId: string
  timestamp: number
  predictedLabel: string
  actualLabel: string
  confidence: number
  correct: boolean
}

export interface TrainingRun {
  id: string
  timestamp: number
  examplesUsed: number
  accuracy: number
  auc: number
  previousVersion: string | null
  newVersion: string
  promoted: boolean
  reason: string
}

export class ContinuousLearner {
  private pipeline: LearningPipeline = {
    modelVersions: [],
    currentModel: null,
    feedbackLog: [],
    trainingRuns: [],
  }

  get pipeline_data(): LearningPipeline {
    return { ...this.pipeline }
  }

  recordFeedback(
    buildId: string,
    predictedLabel: string,
    actualLabel: string,
    confidence: number,
  ): void {
    this.pipeline.feedbackLog.push({
      buildId,
      timestamp: Date.now(),
      predictedLabel,
      actualLabel,
      confidence,
      correct: predictedLabel === actualLabel,
    })
  }

  getAccuracyLastN(n: number): number {
    if (n <= 0) return 0
    const recent = this.pipeline.feedbackLog.slice(-n)
    if (recent.length === 0) return 0
    return recent.filter(f => f.correct).length / recent.length
  }

  shouldRetrain(minFeedbackCount = 10, minAccuracyDrop = 0.1): boolean {
    const recent = this.pipeline.feedbackLog.slice(-20)
    if (recent.length < minFeedbackCount) return false

    const currentAccuracy = recent.filter(f => f.correct).length / recent.length
    if (this.pipeline.currentModel && this.pipeline.currentModel.accuracy > 0) {
      const drop = this.pipeline.currentModel.accuracy - currentAccuracy
      return drop > minAccuracyDrop
    }
    return recent.length >= minFeedbackCount
  }

  registerModelVersion(version: ModelVersion): void {
    this.pipeline.modelVersions.push(version)
    this.pipeline.currentModel = version
  }

  promoteModel(version: string, accuracy: number, auc: number, weights: Record<string, number>, intercept: number, featureNames: string[], trainedOn: number): ModelVersion {
    const newVersion: ModelVersion = {
      version,
      trainedAt: Date.now(),
      trainedOnExamples: trainedOn,
      accuracy,
      precision: 0,
      recall: 0,
      f1: 0,
      auc,
      weights,
      intercept,
      featureNames,
      metadata: {
        labelDistribution: {},
      },
    }
    this.registerModelVersion(newVersion)

    this.pipeline.trainingRuns.push({
      id: `run-${Date.now()}`,
      timestamp: Date.now(),
      examplesUsed: trainedOn,
      accuracy,
      auc,
      previousVersion: this.pipeline.modelVersions.length > 1
        ? this.pipeline.modelVersions[this.pipeline.modelVersions.length - 2].version
        : null,
      newVersion: version,
      promoted: true,
      reason: 'Manual promotion',
    })

    return newVersion
  }

  rollback(targetVersion: string): ModelVersion | null {
    const target = this.pipeline.modelVersions.find(v => v.version === targetVersion)
    if (target) {
      this.pipeline.currentModel = target
      this.pipeline.trainingRuns.push({
        id: `rollback-${Date.now()}`,
        timestamp: Date.now(),
        examplesUsed: 0,
        accuracy: target.accuracy,
        auc: target.auc,
        previousVersion: this.pipeline.currentModel?.version || null,
        newVersion: targetVersion,
        promoted: false,
        reason: `Rollback to ${targetVersion}`,
      })
      return target
    }
    return null
  }

  getVersionHistory(): ModelVersion[] {
    return [...this.pipeline.modelVersions]
  }

  getLatestModel(): ModelVersion | null {
    return this.pipeline.currentModel
  }

  getFeedbackStats(): {
    total: number
    correct: number
    incorrect: number
    accuracy: number
    byPredictedLabel: Record<string, { total: number; correct: number }>
  } {
    const byPredictedLabel: Record<string, { total: number; correct: number }> = {}
    let correct = 0

    for (const f of this.pipeline.feedbackLog) {
      correct += f.correct ? 1 : 0
      if (!byPredictedLabel[f.predictedLabel]) {
        byPredictedLabel[f.predictedLabel] = { total: 0, correct: 0 }
      }
      byPredictedLabel[f.predictedLabel].total++
      if (f.correct) byPredictedLabel[f.predictedLabel].correct++
    }

    return {
      total: this.pipeline.feedbackLog.length,
      correct,
      incorrect: this.pipeline.feedbackLog.length - correct,
      accuracy: this.pipeline.feedbackLog.length > 0
        ? correct / this.pipeline.feedbackLog.length
        : 0,
      byPredictedLabel,
    }
  }
}

export function renderContinuousLearner(learner: ContinuousLearner): string[] {
  const stats = learner.getFeedbackStats()
  const latest = learner.getLatestModel()
  const history = learner.getVersionHistory()

  const lines: string[] = [
    'Continuous Learning Pipeline',
    '===========================',
    `  Model versions: ${history.length}`,
    `  Current model: ${latest?.version || 'none'}`,
    `  Feedback entries: ${stats.total}`,
    `  Feedback accuracy: ${(stats.accuracy * 100).toFixed(1)}%`,
    '',
    '  By predicted label:',
  ]

  for (const [label, data] of Object.entries(stats.byPredictedLabel)) {
    lines.push(`    ${label}: ${data.correct}/${data.total} (${(data.correct / data.total * 100).toFixed(1)}%)`)
  }

  if (history.length > 0) {
    lines.push('', '  Version history:')
    for (const v of history.slice(-5)) {
      lines.push(`    ${v.version}: acc=${(v.accuracy * 100).toFixed(1)}% auc=${(v.auc * 100).toFixed(1)}% n=${v.trainedOnExamples}`)
    }
  }

  if (learner.shouldRetrain()) {
    lines.push('', '  ⚠ RETRAIN RECOMMENDED: accuracy drop detected')
  }

  return lines
}

// ── Causal Narrative ────────────────────────────────────────────
export interface CausalEvent {
  timestamp: number
  processName: string
  pid: number
  action: string
  target: string
  severity: 'info' | 'warning' | 'critical'
  confidence: number
}

export interface CausalNarrative {
  title: string
  summary: string
  events: CausalEvent[]
  timeline: string[]
  riskAssessment: string
  keyFindings: string[]
  recommendations: string[]
}

export function generateCausalNarrative(graph: EvidenceGraph): CausalNarrative {
  const teg = buildTemporalEvidenceGraph(graph)
  const bn = buildBayesianNetwork(graph)
  const da = analyzeDominators(graph)

  // Extract key events
  const events: CausalEvent[] = []

  for (const node of graph.nodes) {
    let action = ''
    let severity: 'info' | 'warning' | 'critical' = 'info'

    switch (node.type) {
      case 'SECRET_ACCESSED':
        action = 'accessed secret'
        severity = 'warning'
        break
      case 'SECRET_EXFILTRATED':
        action = 'exfiltrated secret'
        severity = 'critical'
        break
      case 'NETWORK_CONNECT':
        action = `connected to ${node.host || 'unknown'}:${node.port || '?'}`
        severity = 'info'
        break
      case 'NETWORK_UPLOAD':
        action = `uploaded to ${node.host || 'unknown'}`
        severity = 'warning'
        break
      case 'FILE_CREATED':
        action = `created file ${node.filePath || 'unknown'}`
        severity = 'info'
        break
      case 'FILE_READ':
        action = `read file ${node.filePath || 'unknown'}`
        severity = 'info'
        break
      case 'COMPILER_STARTED':
        action = `started compiler ${node.label}`
        severity = 'info'
        break
      case 'CONTRACT_VIOLATED':
        action = 'violated build contract'
        severity = 'critical'
        break
      default:
        action = node.type.toLowerCase().replace(/_/g, ' ')
        if (node.type === 'SCRIPT_EXECUTED' || node.type === 'TOOL_INVOKED') {
          severity = 'warning'
        }
    }

    events.push({
      timestamp: node.timestamp,
      processName: node.processName || node.label,
      pid: node.pid || 0,
      action,
      target: node.filePath || node.host || '',
      severity,
      confidence: node.confidence,
    })
  }

  events.sort((a, b) => a.timestamp - b.timestamp)

  // Generate timeline
  const timeline: string[] = []
  for (const event of events.slice(0, 20)) {
    const sevIcon = event.severity === 'critical' ? '🔴' : event.severity === 'warning' ? '🟡' : '🟢'
    const target = event.target ? ` → ${event.target}` : ''
    timeline.push(`${sevIcon} ${event.processName} [PID ${event.pid}] ${event.action}${target}`)
  }

  // Key findings
  const keyFindings: string[] = []
  const criticalEvents = events.filter(e => e.severity === 'critical')
  const warningEvents = events.filter(e => e.severity === 'warning')

  if (criticalEvents.length > 0) {
    keyFindings.push(`${criticalEvents.length} critical event(s) detected`)
  }
  if (warningEvents.length > 0) {
    keyFindings.push(`${warningEvents.length} warning event(s) detected`)
  }
  if (da.toolchainShiftDetected) {
    keyFindings.push('Toolchain domination shift detected')
  }
  if (teg.criticalPath.causalDelayMs > 10000) {
    keyFindings.push(`Long critical path: ${teg.criticalPath.causalDelayMs}ms`)
  }

  const secretEvents = events.filter(e => e.action.includes('secret'))
  if (secretEvents.length > 0) {
    keyFindings.push(`${secretEvents.length} secret access(es) in build`)
  }

  // Risk assessment
  let riskLevel = 'LOW'
  if (criticalEvents.length > 0) riskLevel = 'CRITICAL'
  else if (warningEvents.length > 2 || da.toolchainShiftDetected) riskLevel = 'HIGH'
  else if (warningEvents.length > 0) riskLevel = 'MEDIUM'

  const riskAssessment = `Overall risk: ${riskLevel}. ${criticalEvents.length} critical, ${warningEvents.length} warning events. Hijack risk: ${(da.hijackRiskScore * 100).toFixed(0)}%.`

  // Recommendations
  const recommendations: string[] = []
  if (criticalEvents.length > 0) {
    recommendations.push('Investigate critical events immediately')
  }
  if (da.toolchainShiftDetected) {
    recommendations.push('Review toolchain for potential hijacking')
  }
  if (secretEvents.length > 0) {
    recommendations.push('Audit secret access patterns')
  }
  if (events.filter(e => e.action.includes('upload') || e.action.includes('connected')).length > 0) {
    recommendations.push('Review network connections for data exfiltration')
  }

  // Summary
  const summary = `Build ${graph.buildId} involving ${graph.nodes.length} events across ${graph.edges.length} relationships. ${riskLevel} risk. ${keyFindings.length} key finding(s).`

  // Title
  const dominantTool = da.dominantProcess
    ? graph.nodes.find(n => n.id === da.dominantProcess)?.label || 'unknown'
    : 'unknown'
  const title = `Build Analysis: ${dominantTool} (${graph.nodes.length} events)`

  return {
    title,
    summary,
    events,
    timeline,
    riskAssessment,
    keyFindings,
    recommendations,
  }
}

export function renderCausalNarrative(narrative: CausalNarrative): string[] {
  const lines: string[] = [
    narrative.title,
    '='.repeat(narrative.title.length),
    '',
    narrative.summary,
    '',
    'Timeline:',
    ...narrative.timeline.map(t => `  ${t}`),
    '',
    'Risk Assessment:',
    `  ${narrative.riskAssessment}`,
    '',
    'Key Findings:',
    ...narrative.keyFindings.map(f => `  • ${f}`),
    '',
    'Recommendations:',
    ...narrative.recommendations.map(r => `  → ${r}`),
  ]

  return lines
}
