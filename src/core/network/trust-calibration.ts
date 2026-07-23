import * as fs from 'fs'
import * as path from 'path'
import { BuildRecord, EvidenceGraph, TrustResult, EvidenceGraphMetrics } from './build-types'
import { EvidenceGraphStats, computeGraphStats, computeAdvancedGraphStats } from './evidence-graph'
import { computeTrust } from './build-trust-engine'
import {
  buildTemporalEvidenceGraph, buildBayesianNetwork, analyzeDominators,
  computeFullGraphMetrics,
} from './temporal-graph'
import { TemporalEvidenceGraph, BayesianNetwork, DominatorAnalysis } from './build-types'

export const CORPUS_SCHEMA_VERSION = 1

// ── Configuration ──────────────────────────────────────────────
let corpusDir: string | null = null

export function setCorpusDir(dir: string): void {
  corpusDir = dir
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true })
  }
}

export function getCorpusDir(): string | null {
  return corpusDir
}

export function corpusPath(ext = 'jsonl'): string {
  const dir = corpusDir || path.join(process.cwd(), '.sentinel', 'corpus')
  if (!corpusDir) setCorpusDir(dir)
  return path.join(dir, `corpus.${ext}`)
}

// ── Feature Vector ─────────────────────────────────────────────
export interface TrustFeatureVector {
  schemaVersion: number
  buildId: string
  command: string
  timestamp: number
  platform: string
  nodeVersion: string
  durationMs: number

  graph: {
    nodeCount: number
    edgeCount: number
    edgeNodeRatio: number
    componentCount: number
    largestComponentRatio: number
    maxDepth: number
    avgFanOut: number
    maxFanOutCount: number
    avgConfidence: number
    confidenceSpread: number
    graphDensity: number
    graphEntropy: number
    isDag: number
    sccCount: number
    idomCount: number
  }

  centrality: {
    avgBetweenness: number
    maxBetweenness: number
    avgCloseness: number
    maxCloseness: number
    rootEccentricity: number
    avgBranchFactor: number
    processTreeDepth: number
  }

  temporal: {
    longestCausalChainMs: number
    criticalPathMs: number
    avgEdgeLatencyMs: number
    maxEdgeLatencyMs: number
    edgeLatencyVariance: number
    temporalSpanMs: number
  }

  bayesian: {
    globalPrior: number
    overallPosterior: number
    spawnedPosterior: number
    accessedPosterior: number
    connectedPosterior: number
    uploadedPosterior: number
    exfiltratedPosterior: number
  }

  dominator: {
    hijackRiskScore: number
    dominantChanged: number
    toolchainShift: number
    dominantIdomCount: number
  }

  signals: {
    processCount: number
    fileOpCount: number
    networkCount: number
    secretCount: number
    compilerCount: number
    anomalyCount: number
    exfilRiskCount: number
    criticalSecretCount: number
    orphanCount: number
    filelessCount: number
    dohCount: number
    namedPipeCount: number
    ldPreloadCount: number
    suspiciousMapsCount: number
    responseFileChanges: number
  }

  paths: {
    secretPathLength: number
    networkPathLength: number
    compilerDiversity: number
    toolchainEntropy: number
    contractViolationRatio: number
    fileReadRatio: number
    secretToProcessRatio: number
    networkToProcessRatio: number
  }

  build: {
    exitCode: number | null
    hermetricScore: number
    reproducibilityScore: number
    observationConfidence: number
    avgInferenceDegradation: number
    avgObservationDegradation: number
    confidenceVariance: number
    totalProcesses: number
    totalHashLinks: number
  }

  label?: 'normal' | 'anomalous' | 'malicious'
  labelSource?: 'auto' | 'manual'
}

export function extractFeatureVector(
  record: BuildRecord,
  graph?: EvidenceGraph,
  label?: 'normal' | 'anomalous' | 'malicious',
): TrustFeatureVector {
  const stats: EvidenceGraphStats | null = graph ? computeGraphStats(graph) : null
  const advanced = graph ? computeAdvancedGraphStats(graph) : null
  const teg: TemporalEvidenceGraph | null = graph ? buildTemporalEvidenceGraph(graph) : null
  const bn: BayesianNetwork | null = graph ? buildBayesianNetwork(graph) : null
  const da: DominatorAnalysis | null = graph ? analyzeDominators(graph) : null
  const fullMetrics: EvidenceGraphMetrics | null = graph
    ? computeFullGraphMetrics(graph, teg || undefined, bn || undefined, da || undefined)
    : null

  const processCount = record.processes.length
  const fileOpCount = record.files.length
  const networkCount = record.network.length
  const secretCount = record.secretFlow?.totalSecrets || 0
  const compilerCount = record.compilerInvocations?.totalInvocations || 0
  const anomalyCount = record.summary?.anomalies?.length || 0
  const exfilRiskCount = record.secretFlow?.exfilRiskCount || 0
  const criticalSecretCount = record.secretFlow?.criticalCount || 0
  const orphanCount = record.orphanProcesses?.length || 0
  const filelessCount = (record as any).filelessExecutions?.length || 0
  const dohCount = (record as any).dohEvents?.length || 0
  const namedPipeCount = record.namedPipes?.length || 0
  const ldPreloadCount = record.processMaps?.filter(m => m.ldPreload).length || 0
  const suspiciousMapsCount = record.processMaps?.filter(m => m.suspiciousRegions.length > 0).length || 0
  const responseFileChanges = (record as any).responseFileChanges?.filter((r: any) => r.changed).length || 0

  const nodeCount = stats?.nodeCount || 0
  const edgeCount = stats?.edgeCount || 0

  // Bayesian posteriors for key relations
  const getRelationPosterior = (relation: string): number => {
    return bn?.relations.find(r => r.relation === relation)?.posteriorGivenEvidence || 0
  }

  return {
    schemaVersion: CORPUS_SCHEMA_VERSION,
    buildId: `${record.command}_${record.startTime}`,
    command: record.command,
    timestamp: Date.now(),
    platform: record.platform || '',
    nodeVersion: record.nodeVersion || '',
    durationMs: record.durationMs,

    graph: {
      nodeCount,
      edgeCount,
      edgeNodeRatio: nodeCount > 0 ? Math.round((edgeCount / nodeCount) * 100) / 100 : 0,
      componentCount: fullMetrics?.componentCount || stats?.componentCount || 0,
      largestComponentRatio: nodeCount > 0
        ? Math.round(((stats?.largestComponentSize || 0) / nodeCount) * 100) / 100
        : 0,
      maxDepth: fullMetrics?.maxDepth || stats?.maxDepth || 0,
      avgFanOut: Math.round((stats?.avgFanOut || 0) * 100) / 100,
      maxFanOutCount: stats?.maxFanOut?.count || 0,
      avgConfidence: stats?.avgConfidence || 0,
      confidenceSpread: stats && stats.maxConfidence > stats.minConfidence
        ? stats.maxConfidence - stats.minConfidence
        : 0,
      graphDensity: fullMetrics?.graphDensity || advanced?.graphDensity || 0,
      graphEntropy: fullMetrics?.graphEntropy || advanced?.graphEntropy || 0,
      isDag: (fullMetrics?.isDag ?? advanced?.isDag) ? 1 : 0,
      sccCount: fullMetrics?.sccCount || advanced?.sccCount || 0,
      idomCount: fullMetrics?.idomCount || (advanced ? Object.entries(advanced.immediateDominators).filter(([, v]) => v !== null).length : 0),
    },

    centrality: {
      avgBetweenness: fullMetrics?.avgBetweenness || 0,
      maxBetweenness: fullMetrics?.maxBetweenness || (advanced ? Math.max(...Object.values(advanced.betweennessCentrality), 0) : 0),
      avgCloseness: fullMetrics?.avgCloseness || 0,
      maxCloseness: fullMetrics?.maxCloseness || (advanced ? Math.max(...Object.values(advanced.closenessCentrality), 0) : 0),
      rootEccentricity: fullMetrics?.rootEccentricity || 0,
      avgBranchFactor: fullMetrics?.avgBranchFactor || 0,
      processTreeDepth: fullMetrics?.processTreeDepth || 0,
    },

    temporal: {
      longestCausalChainMs: fullMetrics?.longestCausalChainMs || teg?.longestCausalChain.totalLatencyMs || 0,
      criticalPathMs: fullMetrics?.criticalPathMs || teg?.criticalPath.causalDelayMs || 0,
      avgEdgeLatencyMs: fullMetrics?.avgEdgeLatencyMs || teg?.avgEdgeLatencyMs || 0,
      maxEdgeLatencyMs: fullMetrics?.maxEdgeLatencyMs || teg?.maxEdgeLatencyMs || 0,
      edgeLatencyVariance: fullMetrics?.edgeLatencyVariance || 0,
      temporalSpanMs: fullMetrics?.temporalSpanMs || 0,
    },

    bayesian: {
      globalPrior: bn?.globalPrior || 0.5,
      overallPosterior: bn?.overallPosterior || 0,
      spawnedPosterior: getRelationPosterior('spawned'),
      accessedPosterior: getRelationPosterior('accessed'),
      connectedPosterior: getRelationPosterior('connected'),
      uploadedPosterior: getRelationPosterior('uploaded'),
      exfiltratedPosterior: getRelationPosterior('exfiltrated'),
    },

    dominator: {
      hijackRiskScore: da?.hijackRiskScore || 0,
      dominantChanged: da?.dominantProcessChanged ? 1 : 0,
      toolchainShift: da?.toolchainShiftDetected ? 1 : 0,
      dominantIdomCount: da ? Object.values(da.currentDominators).filter(v => v !== null).length : 0,
    },

    signals: {
      processCount,
      fileOpCount,
      networkCount,
      secretCount,
      compilerCount,
      anomalyCount,
      exfilRiskCount,
      criticalSecretCount,
      orphanCount,
      filelessCount,
      dohCount,
      namedPipeCount,
      ldPreloadCount,
      suspiciousMapsCount,
      responseFileChanges,
    },

    paths: {
      secretPathLength: fullMetrics?.secretPathLength || 0,
      networkPathLength: fullMetrics?.networkPathLength || 0,
      compilerDiversity: fullMetrics?.compilerDiversity || 0,
      toolchainEntropy: fullMetrics?.toolchainEntropy || 0,
      contractViolationRatio: fullMetrics?.contractViolationRatio || 0,
      fileReadRatio: fullMetrics?.fileReadRatio || 0,
      secretToProcessRatio: fullMetrics?.secretToProcessRatio || 0,
      networkToProcessRatio: fullMetrics?.networkToProcessRatio || 0,
    },

    build: {
      exitCode: record.exitCode,
      hermetricScore: record.hermetricScore || 0,
      reproducibilityScore: record.reproducibilityScore || 0,
      observationConfidence: typeof record.observationConfidence === 'object' && record.observationConfidence !== null
        ? record.observationConfidence.overall
        : (record.observationConfidence as number | undefined) || 0,
      avgInferenceDegradation: fullMetrics?.avgInferenceDegradation || 0,
      avgObservationDegradation: fullMetrics?.avgObservationDegradation || 0,
      confidenceVariance: fullMetrics?.confidenceVariance || 0,
      totalProcesses: record.summary?.totalProcesses || processCount,
      totalHashLinks: record.hashChain?.length || 0,
    },

    label,
    labelSource: label ? 'auto' : undefined,
  }
}

// ── Labeling Pipeline ───────────────────────────────────────────
export function autoLabel(record: BuildRecord): 'normal' | 'anomalous' | 'malicious' | undefined {
  const anomalies = record.summary?.anomalies || []

  const criticalAnomalies = anomalies.filter(a =>
    a.startsWith('[CRITICAL]') || a.toLowerCase().includes('exfil') || a.toLowerCase().includes('injection')
  )
  const highAnomalies = anomalies.filter(a => a.startsWith('[HIGH]'))
  const mediumAnomalies = anomalies.filter(a => a.startsWith('[MEDIUM]'))

  if (criticalAnomalies.length > 0) return 'malicious'
  if (highAnomalies.length >= 3) return 'malicious'
  if ((record.secretFlow?.exfilRiskCount || 0) > 0) return 'malicious'

  if (highAnomalies.length > 0) return 'anomalous'
  if (mediumAnomalies.length >= 3) return 'anomalous'
  if (record.hermetricScore !== undefined && record.hermetricScore < 30) return 'anomalous'
  if ((record.secretFlow?.criticalCount || 0) > 0) return 'anomalous'

  if (record.exitCode === 0 && anomalies.length === 0 && (record.secretFlow?.totalSecrets || 0) === 0) {
    return 'normal'
  }

  return undefined
}

// ── Corpus Persistence ─────────────────────────────────────────
export class CorpusStore {
  private examples: TrustFeatureVector[] = []
  private filePath: string

  constructor(filePath?: string) {
    this.filePath = filePath || corpusPath()
    this.load()
  }

  get path(): string { return this.filePath }

  record(vector: TrustFeatureVector): void {
    this.examples.push({ ...vector })
    this.append(vector)
  }

  getAll(): ReadonlyArray<TrustFeatureVector> {
    return this.examples
  }

  count(): number {
    return this.examples.length
  }

  clear(): void {
    this.examples = []
    if (fs.existsSync(this.filePath)) {
      fs.unlinkSync(this.filePath)
    }
  }

  getLabeled(): TrustFeatureVector[] {
    return this.examples.filter(v => v.label)
  }

  countByLabel(): Record<string, number> {
    const counts: Record<string, number> = { normal: 0, anomalous: 0, malicious: 0, unlabeled: 0 }
    for (const ex of this.examples) {
      counts[ex.label || 'unlabeled']++
    }
    return counts
  }

  // ── persistence ──

  private load(): void {
    if (!fs.existsSync(this.filePath)) return
    const raw = fs.readFileSync(this.filePath, 'utf-8')
    for (const line of raw.split('\n').filter(Boolean)) {
      try {
        const parsed = JSON.parse(line)
        this.examples.push(parsed as TrustFeatureVector)
      } catch {
        // skip corrupt lines
      }
    }
  }

  private append(vector: TrustFeatureVector): void {
    const dir = path.dirname(this.filePath)
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true })
    }
    fs.appendFileSync(this.filePath, JSON.stringify(vector) + '\n', 'utf-8')
  }

  exportToJsonl(targetPath?: string): string {
    const outPath = targetPath || this.filePath.replace(/\.jsonl$/, '_export.jsonl')
    const dir = path.dirname(outPath)
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true })
    }
    const content = this.examples.map(ex => JSON.stringify(ex)).join('\n') + '\n'
    fs.writeFileSync(outPath, content, 'utf-8')
    return outPath
  }

  importFromJsonl(sourcePath: string): number {
    if (!fs.existsSync(sourcePath)) return 0
    let count = 0
    const raw = fs.readFileSync(sourcePath, 'utf-8')
    for (const line of raw.split('\n').filter(Boolean)) {
      try {
        const parsed = JSON.parse(line) as TrustFeatureVector
        this.examples.push(parsed)
        this.append(parsed)
        count++
      } catch {
        // skip corrupt
      }
    }
    return count
  }

  getStatsSummary(): string[] {
    const lines: string[] = [
      'Corpus Store',
      '============',
      `  Path: ${this.filePath}`,
      `  Schema version: ${CORPUS_SCHEMA_VERSION}`,
      `  Total examples: ${this.count()}`,
      '',
      '  By label:',
    ]
    for (const [label, count] of Object.entries(this.countByLabel())) {
      lines.push(`    ${label}: ${count}`)
    }
    if (this.count() > 0) {
      const withAdvanced = this.examples.filter(e => e.graph.graphDensity > 0).length
      lines.push('', `  With advanced graph features: ${withAdvanced}/${this.count()}`)
    }
    return lines
  }
}

let defaultStore: CorpusStore | null = null

export function getDefaultStore(): CorpusStore {
  if (!defaultStore) {
    defaultStore = new CorpusStore()
  }
  return defaultStore
}

// ── Logistic Regression (from scratch) ─────────────────────────
export interface LrConfig {
  learningRate: number
  iterations: number
  lambda: number
}

const DEFAULT_LR_CONFIG: LrConfig = {
  learningRate: 0.01,
  iterations: 1000,
  lambda: 0.01,
}

function sigmoid(z: number): number {
  if (z > 700) return 1
  if (z < -700) return 0
  return 1 / (1 + Math.exp(-z))
}

export function trainLogisticRegression(
  features: number[][],
  labels: number[],
  config: LrConfig = DEFAULT_LR_CONFIG,
): { weights: number[]; intercept: number; lossHistory: number[] } {
  const n = features.length
  const d = features[0].length
  let weights = new Array(d).fill(0)
  let intercept = 0
  const lossHistory: number[] = []

  for (let iter = 0; iter < config.iterations; iter++) {
    const gradW = new Array(d).fill(0)
    let gradB = 0
    let loss = 0

    for (let i = 0; i < n; i++) {
      const z = features[i].reduce((s, x, j) => s + x * weights[j], intercept)
      const p = sigmoid(z)
      const diff = p - labels[i]

      loss += -labels[i] * Math.log(Math.max(p, 1e-15)) - (1 - labels[i]) * Math.log(Math.max(1 - p, 1e-15))

      for (let j = 0; j < d; j++) {
        gradW[j] += diff * features[i][j]
      }
      gradB += diff
    }

    loss = loss / n + (config.lambda / (2 * n)) * weights.reduce((s, w) => s + w * w, 0)
    lossHistory.push(Math.round(loss * 10000) / 10000)

    for (let j = 0; j < d; j++) {
      gradW[j] = (gradW[j] + config.lambda * weights[j]) / n
      weights[j] -= config.learningRate * gradW[j]
    }
    gradB /= n
    intercept -= config.learningRate * gradB
  }

  return { weights, intercept, lossHistory }
}

export function predictLogistic(
  features: number[][],
  weights: number[],
  intercept: number,
  threshold = 0.5,
): { probabilities: number[]; predictions: number[] } {
  const probabilities = features.map(f => {
    const z = f.reduce((s, x, j) => s + x * weights[j], intercept)
    return sigmoid(z)
  })
  const predictions = probabilities.map(p => (p >= threshold ? 1 : 0))
  return { probabilities, predictions }
}

// ── Evaluation Metrics ─────────────────────────────────────────
export interface EvaluationMetrics {
  accuracy: number
  precision: number
  recall: number
  f1: number
  auc: number
  confusionMatrix: { tp: number; fp: number; tn: number; fn: number }
  rocPoints: { fpr: number; tpr: number }[]
  trainedOn: number
}

export function evaluateModel(
  yTrue: number[],
  yPred: number[],
  probabilities: number[],
  trainedOn: number,
): EvaluationMetrics {
  let tp = 0; let fp = 0; let tn = 0; let fn = 0
  for (let i = 0; i < yTrue.length; i++) {
    if (yPred[i] === 1 && yTrue[i] === 1) tp++
    else if (yPred[i] === 1 && yTrue[i] === 0) fp++
    else if (yPred[i] === 0 && yTrue[i] === 0) tn++
    else fn++
  }

  const accuracy = yTrue.length > 0 ? (tp + tn) / yTrue.length : 0
  const precision = tp + fp > 0 ? tp / (tp + fp) : 0
  const recall = tp + fn > 0 ? tp / (tp + fn) : 0
  const f1 = precision + recall > 0 ? 2 * (precision * recall) / (precision + recall) : 0

  // AUC: sort by probability descending
  const paired = yTrue.map((y, i) => ({ y, p: probabilities[i] }))
  paired.sort((a, b) => b.p - a.p)

  const rocPoints: { fpr: number; tpr: number }[] = [{ fpr: 0, tpr: 0 }]
  let tpCount = 0; let fpCount = 0
  const totalPos = yTrue.filter(y => y === 1).length
  const totalNeg = yTrue.filter(y => y === 0).length

  for (const { y } of paired) {
    if (y === 1) tpCount++
    else fpCount++
    rocPoints.push({
      fpr: totalNeg > 0 ? fpCount / totalNeg : 0,
      tpr: totalPos > 0 ? tpCount / totalPos : 0,
    })
  }

  // AUC via trapezoidal rule
  let auc = 0
  for (let i = 1; i < rocPoints.length; i++) {
    auc += (rocPoints[i].fpr - rocPoints[i - 1].fpr) * (rocPoints[i].tpr + rocPoints[i - 1].tpr) / 2
  }

  return {
    accuracy: Math.round(accuracy * 1000) / 1000,
    precision: Math.round(precision * 1000) / 1000,
    recall: Math.round(recall * 1000) / 1000,
    f1: Math.round(f1 * 1000) / 1000,
    auc: Math.round(auc * 1000) / 1000,
    confusionMatrix: { tp, fp, tn, fn },
    rocPoints,
    trainedOn,
  }
}

// ── ML Calibration ──────────────────────────────────────────────
export interface CalibrationResult {
  weights: Record<string, number>
  intercept: number
  featureNames: string[]
  evaluation: EvaluationMetrics | null
  config: LrConfig
}

const FEATURE_NAMES = [
  // Graph features (15)
  'avgConfidence',
  'edgeNodeRatio',
  'maxDepth',
  'componentCount',
  'graphDensity',
  'graphEntropy',
  'isDag',
  'sccCount',
  'idomCount',
  'confidenceSpread',
  'maxFanOutCount',
  'avgFanOut',
  'largestComponentRatio',
  // Centrality features (7)
  'avgBetweenness',
  'maxBetweenness',
  'avgCloseness',
  'maxCloseness',
  'rootEccentricity',
  'avgBranchFactor',
  'processTreeDepth',
  // Temporal features (6)
  'longestCausalChainMs',
  'criticalPathMs',
  'avgEdgeLatencyMs',
  'maxEdgeLatencyMs',
  'edgeLatencyVariance',
  'temporalSpanMs',
  // Bayesian features (7)
  'globalPrior',
  'overallPosterior',
  'spawnedPosterior',
  'accessedPosterior',
  'connectedPosterior',
  'uploadedPosterior',
  'exfiltratedPosterior',
  // Dominator features (4)
  'hijackRiskScore',
  'dominantChanged',
  'toolchainShift',
  'dominantIdomCount',
  // Signal features (15)
  'processCount',
  'fileOpCount',
  'networkCount',
  'secretCount',
  'compilerCount',
  'anomalyCount',
  'exfilRiskCount',
  'criticalSecretCount',
  'orphanCount',
  'filelessCount',
  'dohCount',
  'namedPipeCount',
  'ldPreloadCount',
  'suspiciousMapsCount',
  'responseFileChanges',
  // Path features (8)
  'secretPathLength',
  'networkPathLength',
  'compilerDiversity',
  'toolchainEntropy',
  'contractViolationRatio',
  'fileReadRatio',
  'secretToProcessRatio',
  'networkToProcessRatio',
  // Build features (9)
  'hermetricScore',
  'reproducibilityScore',
  'observationConfidence',
  'avgInferenceDegradation',
  'avgObservationDegradation',
  'confidenceVariance',
  'totalProcesses',
  'totalHashLinks',
  'exitCode',
]

function extractFeatures(v: TrustFeatureVector): number[] {
  const g = v.graph
  const c = v.centrality
  const t = v.temporal
  const bn = v.bayesian
  const d = v.dominator
  const s = v.signals
  const p = v.paths
  const b = v.build
  return [
    // Graph
    g.avgConfidence / 100,
    Math.min(g.edgeNodeRatio, 5) / 5,
    Math.min(g.maxDepth, 20) / 20,
    Math.min(g.componentCount, 10) / 10,
    g.graphDensity,
    g.graphEntropy,
    g.isDag,
    Math.min(g.sccCount, 50) / 50,
    Math.min(g.idomCount, 50) / 50,
    Math.min(g.confidenceSpread, 100) / 100,
    Math.min(g.maxFanOutCount, 20) / 20,
    Math.min(g.avgFanOut, 10) / 10,
    g.largestComponentRatio,
    // Centrality
    Math.min(c.avgBetweenness, 1) ,
    c.maxBetweenness,
    Math.min(c.avgCloseness, 1),
    c.maxCloseness,
    Math.min(c.rootEccentricity, 20) / 20,
    Math.min(c.avgBranchFactor, 10) / 10,
    Math.min(c.processTreeDepth, 20) / 20,
    // Temporal
    Math.min(t.longestCausalChainMs, 60000) / 60000,
    Math.min(t.criticalPathMs, 60000) / 60000,
    Math.min(t.avgEdgeLatencyMs, 30000) / 30000,
    Math.min(t.maxEdgeLatencyMs, 60000) / 60000,
    Math.min(t.edgeLatencyVariance, 1000000) / 1000000,
    Math.min(t.temporalSpanMs, 120000) / 120000,
    // Bayesian
    bn.globalPrior,
    bn.overallPosterior,
    bn.spawnedPosterior,
    bn.accessedPosterior,
    bn.connectedPosterior,
    bn.uploadedPosterior,
    bn.exfiltratedPosterior,
    // Dominator
    d.hijackRiskScore,
    d.dominantChanged,
    d.toolchainShift,
    Math.min(d.dominantIdomCount, 50) / 50,
    // Signals
    Math.min(s.processCount, 100) / 100,
    Math.min(s.fileOpCount, 200) / 200,
    Math.min(s.networkCount, 50) / 50,
    Math.min(s.secretCount, 20) / 20,
    Math.min(s.compilerCount, 20) / 20,
    Math.min(s.anomalyCount, 20) / 20,
    Math.min(s.exfilRiskCount, 10) / 10,
    Math.min(s.criticalSecretCount, 10) / 10,
    Math.min(s.orphanCount, 5) / 5,
    Math.min(s.filelessCount, 5) / 5,
    Math.min(s.dohCount, 5) / 5,
    Math.min(s.namedPipeCount, 5) / 5,
    Math.min(s.ldPreloadCount, 5) / 5,
    Math.min(s.suspiciousMapsCount, 5) / 5,
    Math.min(s.responseFileChanges, 10) / 10,
    // Paths
    Math.min(p.secretPathLength, 20) / 20,
    Math.min(p.networkPathLength, 50) / 50,
    Math.min(p.compilerDiversity, 10) / 10,
    p.toolchainEntropy,
    Math.min(p.contractViolationRatio, 1) ,
    Math.min(p.fileReadRatio, 1) ,
    Math.min(p.secretToProcessRatio, 5) / 5,
    Math.min(p.networkToProcessRatio, 10) / 10,
    // Build
    b.hermetricScore / 100,
    b.reproducibilityScore / 100,
    b.observationConfidence / 100,
    Math.min(b.avgInferenceDegradation, 1) ,
    Math.min(b.avgObservationDegradation, 1) ,
    Math.min(b.confidenceVariance, 1000) / 1000,
    Math.min(b.totalProcesses, 100) / 100,
    Math.min(b.totalHashLinks, 100) / 100,
    b.exitCode === null ? 0.5 : (b.exitCode === 0 ? 0 : 1),
  ]
}

export function calibrateWeights(
  store?: CorpusStore,
  config: LrConfig = DEFAULT_LR_CONFIG,
): CalibrationResult {
  const data = (store || getDefaultStore()).getLabeled()
  const binary = data.filter(v => v.label === 'normal' || v.label === 'malicious')

  if (binary.length < 5) {
    const baselineWeights: Record<string, number> = {}
    for (const [i, name] of FEATURE_NAMES.entries()) {
      const manualWeight = MANUAL_FEATURE_WEIGHTS[name as keyof typeof MANUAL_FEATURE_WEIGHTS]
      baselineWeights[name] = manualWeight?.weight || 0.05
    }

    return {
      weights: baselineWeights,
      intercept: 0,
      featureNames: [...FEATURE_NAMES],
      evaluation: {
        accuracy: 0,
        precision: 0,
        recall: 0,
        f1: 0,
        auc: 0,
        confusionMatrix: { tp: 0, fp: 0, tn: 0, fn: 0 },
        rocPoints: [],
        trainedOn: binary.length,
      },
      config,
    }
  }

  const X = binary.map(v => extractFeatures(v))
  const y = binary.map(v => v.label === 'malicious' ? 1 : 0)

  const { weights, intercept, lossHistory } = trainLogisticRegression(X, y, config)
  const { probabilities, predictions } = predictLogistic(X, weights, intercept)
  const evaluation = evaluateModel(y, predictions, probabilities, binary.length)

  // Also compute on all labeled data for multi-class summary
  const weightMap: Record<string, number> = {}
  for (const [i, name] of FEATURE_NAMES.entries()) {
    weightMap[name] = Math.round(weights[i] * 1000) / 1000
  }

  return {
    weights: weightMap,
    intercept: Math.round(intercept * 1000) / 1000,
    featureNames: [...FEATURE_NAMES],
    evaluation,
    config,
  }
}

// ── Renders ─────────────────────────────────────────────────────
export function renderFeatureVector(vector: TrustFeatureVector): string[] {
  const lines: string[] = [
    `Trust Feature Vector (v${CORPUS_SCHEMA_VERSION})`,
    '====================================',
    `  Build: ${vector.buildId}`,
    `  Label: ${vector.label || 'unlabeled'} [${vector.labelSource || 'none'}]`,
    `  Platform: ${vector.platform} | Node: ${vector.nodeVersion}`,
    `  Duration: ${vector.durationMs}ms`,
    '',
    '  Graph Features:',
  ]

  for (const [key, val] of Object.entries(vector.graph)) {
    lines.push(`    ${key}: ${val}`)
  }

  lines.push('', '  Centrality Features:')
  for (const [key, val] of Object.entries(vector.centrality)) {
    lines.push(`    ${key}: ${val}`)
  }

  lines.push('', '  Temporal Features:')
  for (const [key, val] of Object.entries(vector.temporal)) {
    lines.push(`    ${key}: ${val}`)
  }

  lines.push('', '  Bayesian Features:')
  for (const [key, val] of Object.entries(vector.bayesian)) {
    lines.push(`    ${key}: ${val}`)
  }

  lines.push('', '  Dominator Features:')
  for (const [key, val] of Object.entries(vector.dominator)) {
    lines.push(`    ${key}: ${val}`)
  }

  lines.push('', '  Signal Features:')
  for (const [key, val] of Object.entries(vector.signals)) {
    lines.push(`    ${key}: ${val}`)
  }

  lines.push('', '  Path Features:')
  for (const [key, val] of Object.entries(vector.paths)) {
    lines.push(`    ${key}: ${val}`)
  }

  lines.push('', '  Build Features:')
  for (const [key, val] of Object.entries(vector.build)) {
    lines.push(`    ${key}: ${val}`)
  }

  return lines
}

export function renderCalibrationSummary(store?: CorpusStore): string[] {
  const s = store || getDefaultStore()
  const lines: string[] = [
    'Trust Calibration Summary',
    '=========================',
    `  Corpus path: ${s.path}`,
    `  Schema version: ${CORPUS_SCHEMA_VERSION}`,
    `  Training examples: ${s.count()}`,
    '',
    '  Current weights (manual):',
  ]

  for (const [name, meta] of Object.entries(MANUAL_FEATURE_WEIGHTS)) {
    lines.push(`    ${name}: w=${meta.weight}, max=${meta.maxScore}`)
  }

  if (s.count() > 0) {
    const labeled = s.getLabeled()
    lines.push('', `  Labeled examples: ${labeled.length}/${s.count()}`)
    for (const [label, count] of Object.entries(s.countByLabel())) {
      if (count > 0) lines.push(`    ${label}: ${count}`)
    }
  }

  return lines
}

export function renderEvaluation(evalResult: EvaluationMetrics): string[] {
  const cm = evalResult.confusionMatrix
  const lines: string[] = [
    'Model Evaluation',
    '================',
    `  Trained on: ${evalResult.trainedOn} examples`,
    '',
    '  Confusion Matrix:',
    `                Predicted Malicious  Predicted Benign`,
    `  Actual Malic.        ${String(cm.tp).padStart(3)}               ${String(cm.fn).padStart(3)}`,
    `  Actual Benign        ${String(cm.fp).padStart(3)}               ${String(cm.tn).padStart(3)}`,
    '',
    '  Metrics:',
    `    Accuracy : ${(evalResult.accuracy * 100).toFixed(1)}%`,
    `    Precision: ${(evalResult.precision * 100).toFixed(1)}%`,
    `    Recall   : ${(evalResult.recall * 100).toFixed(1)}%`,
    `    F1 Score : ${(evalResult.f1 * 100).toFixed(1)}%`,
    `    AUC      : ${(evalResult.auc * 100).toFixed(1)}%`,
    '',
    '  ROC curve points:',
  ]
  for (const pt of evalResult.rocPoints.slice(0, 10)) {
    lines.push(`    FPR=${pt.fpr.toFixed(3)}  TPR=${pt.tpr.toFixed(3)}`)
  }
  if (evalResult.rocPoints.length > 10) {
    lines.push(`    ... and ${evalResult.rocPoints.length - 10} more`)
  }
  return lines
}

export function renderCalibrationResult(result: CalibrationResult): string[] {
  const lines: string[] = [
    'ML Calibration Result',
    '=====================',
    `  Features: ${result.featureNames.length}`,
    `  Intercept: ${result.intercept}`,
    `  Config: lr=${result.config.learningRate}, iter=${result.config.iterations}, λ=${result.config.lambda}`,
    '',
    '  Learned weights:',
  ]
  for (const name of result.featureNames) {
    const w = result.weights[name]
    if (w !== undefined) {
      lines.push(`    ${name}: ${w}`)
    }
  }

  if (result.evaluation && result.evaluation.trainedOn > 0) {
    lines.push('', ...renderEvaluation(result.evaluation))
  }
  return lines
}

// ── Manual Weights (fallback) ──────────────────────────────────
export interface WeightedFeature {
  name: string
  value: number
  weight: number
  maxScore: number
}

const MANUAL_FEATURE_WEIGHTS = {
  avgConfidence: { weight: 0.15, maxScore: 100 },
  edgeNodeRatio: { weight: 0.05, maxScore: 5 },
  hermetricScore: { weight: 0.12, maxScore: 100 },
  reproducibilityScore: { weight: 0.08, maxScore: 100 },
  anomalyCount: { weight: 0.12, maxScore: 20 },
  exfilRiskCount: { weight: 0.10, maxScore: 10 },
  criticalSecretCount: { weight: 0.10, maxScore: 10 },
  maxDepth: { weight: 0.05, maxScore: 20 },
  componentCount: { weight: 0.03, maxScore: 10 },
}

export function computeLearnedTrust(record: BuildRecord, graph?: EvidenceGraph): TrustResult {
  const vector = extractFeatureVector(record, graph)
  const baseTrust = computeTrust(record)

  const features: WeightedFeature[] = []

  const addFeature = (name: string, value: number) => {
    const meta = MANUAL_FEATURE_WEIGHTS[name as keyof typeof MANUAL_FEATURE_WEIGHTS]
    if (meta) {
      features.push({ name, value: Math.min(value, meta.maxScore), ...meta })
    }
  }

  addFeature('avgConfidence', vector.graph.avgConfidence)
  addFeature('edgeNodeRatio', vector.graph.edgeNodeRatio)
  addFeature('hermetricScore', vector.build.hermetricScore)
  addFeature('reproducibilityScore', vector.build.reproducibilityScore)
  addFeature('anomalyCount', vector.signals.anomalyCount)
  addFeature('exfilRiskCount', vector.signals.exfilRiskCount)
  addFeature('criticalSecretCount', vector.signals.criticalSecretCount)
  addFeature('maxDepth', vector.graph.maxDepth)
  addFeature('componentCount', vector.graph.componentCount)

  const normalizedScores = features.map(f => {
    const normalized = Math.min(f.value / f.maxScore, 1)
    return { name: f.name, score: Math.round(normalized * 100), weight: f.weight }
  })

  const overallTrust = Math.round(
    normalizedScores.reduce((sum, f) => sum + f.score * f.weight, 0),
  )

  const dimensions = normalizedScores.map(f => ({
    name: f.name,
    score: f.score,
    weight: f.weight,
    evidence: [`${f.name}: ${f.score}/100 (w: ${f.weight})`],
    maxScore: 100,
  }))

  dimensions.push({
    name: 'base_trust',
    score: baseTrust.overallTrust,
    weight: 0.0,
    evidence: [`Original engine trust: ${baseTrust.overallTrust}`],
    maxScore: 100,
  })

  return {
    overallTrust,
    dimensions,
    breakdown: dimensions.flatMap(d => d.evidence),
    inputStability: baseTrust.inputStability,
    toolchainPurity: baseTrust.toolchainPurity,
    buildDeterminism: baseTrust.buildDeterminism,
  }
}
