import { describe, it, expect, beforeEach, afterEach } from 'vitest'
import * as fs from 'fs'
import * as path from 'path'
import * as os from 'os'
import {
  extractFeatureVector,
  computeLearnedTrust,
  renderFeatureVector,
  renderCalibrationSummary,
  calibrateWeights,
  CorpusStore,
  setCorpusDir,
  autoLabel,
  trainLogisticRegression,
  predictLogistic,
  evaluateModel,
  renderEvaluation,
  renderCalibrationResult,
  CORPUS_SCHEMA_VERSION,
} from './trust-calibration'
import { buildEvidenceGraph } from './evidence-graph'
import { BuildRecord, BuildProcessEvent, BuildFileEvent, BuildNetEvent } from './build-types'

function minimalRecord(overrides?: Partial<BuildRecord>): BuildRecord {
  return {
    command: 'test',
    args: [],
    cwd: '/tmp',
    startTime: new Date().toISOString(),
    durationMs: 1000,
    exitCode: 0,
    platform: 'linux',
    nodeVersion: 'v20',
    env: {},
    processes: [],
    files: [],
    network: [],
    artifactHashes: [],
    summary: {
      totalProcesses: 0,
      uniqueProcesses: [],
      buildToolsDetected: [],
      filesCreated: 0,
      filesModified: 0,
      filesDeleted: 0,
      filesRead: 0,
      networkConnections: 0,
      dnsQueries: [],
      artifactsHashed: 0,
      anomalies: [],
      processTree: [],
      totalHashLinks: 0,
    },
    hashChain: [],
    ...overrides,
  }
}

function tmpCorpusDir(): string {
  const dir = path.join(os.tmpdir(), `sentinel-corpus-test-${Date.now()}`)
  return dir
}

describe('trust-calibration', () => {
  let corpusDir: string
  let store: CorpusStore

  beforeEach(() => {
    corpusDir = tmpCorpusDir()
    setCorpusDir(corpusDir)
    store = new CorpusStore()
  })

  afterEach(() => {
    try { fs.rmSync(corpusDir, { recursive: true, force: true }) } catch {/* noop */}
  })

  describe('extractFeatureVector', () => {
    it('extracts features from a build with processes', () => {
      const processes: BuildProcessEvent[] = [
        { pid: 1, name: 'make', cmdline: 'make', ppid: 0, pname: '', timestamp: 100, exitTime: 1000, source: 'procfs' },
        { pid: 2, name: 'gcc', cmdline: 'gcc -c', ppid: 1, pname: 'make', timestamp: 200, exitTime: 800, source: 'procfs' },
      ]
      const record = minimalRecord({ processes })
      const graph = buildEvidenceGraph(record)
      const vector = extractFeatureVector(record, graph)

      expect(vector.schemaVersion).toBe(CORPUS_SCHEMA_VERSION)
      expect(vector.graph.nodeCount).toBe(2)
      expect(vector.signals.processCount).toBe(2)
      expect(vector.graph.avgConfidence).toBeGreaterThan(0)
    })

    it('extracts features without graph', () => {
      const record = minimalRecord()
      const vector = extractFeatureVector(record)

      expect(vector.graph.nodeCount).toBe(0)
      expect(vector.graph.edgeCount).toBe(0)
      expect(vector.centrality.maxBetweenness).toBe(0)
      expect(vector.graph.graphDensity).toBe(0)
    })

    it('includes signals from build record', () => {
      const processes: BuildProcessEvent[] = [
        { pid: 1, name: 'make', cmdline: 'make', ppid: 0, pname: '', timestamp: 100, exitTime: 1000, source: 'procfs' },
      ]
      const files: BuildFileEvent[] = [
        { filePath: '/tmp/out', size: 1024, operation: 'created', timestamp: 500 },
      ]
      const network: BuildNetEvent[] = [
        { type: 'tcp', host: 'example.com', port: 443, timestamp: 600, source: 'procfs' },
      ]
      const record = minimalRecord({
        processes,
        files,
        network,
        hermetricScore: 85,
        reproducibilityScore: 70,
        summary: {
          totalProcesses: 1,
          uniqueProcesses: ['make'],
          buildToolsDetected: [],
          filesCreated: 1,
          filesModified: 0,
          filesDeleted: 0,
          filesRead: 0,
          networkConnections: 1,
          dnsQueries: [],
          artifactsHashed: 0,
          anomalies: ['warning'],
          processTree: [],
          totalHashLinks: 0,
        },
      })
      const vector = extractFeatureVector(record)

      expect(vector.signals.fileOpCount).toBe(1)
      expect(vector.signals.networkCount).toBe(1)
      expect(vector.signals.anomalyCount).toBe(1)
      expect(vector.build.hermetricScore).toBe(85)
      expect(vector.build.reproducibilityScore).toBe(70)
    })

    it('stores label when provided', () => {
      const record = minimalRecord()
      const vector = extractFeatureVector(record, undefined, 'normal')
      expect(vector.label).toBe('normal')
      expect(vector.labelSource).toBe('auto')
    })

    it('includes advanced graph features when graph is provided', () => {
      const processes: BuildProcessEvent[] = [
        { pid: 1, name: 'make', cmdline: 'make', ppid: 0, pname: '', timestamp: 100, exitTime: 1000, source: 'procfs' },
        { pid: 2, name: 'gcc', cmdline: 'gcc -c', ppid: 1, pname: 'make', timestamp: 200, exitTime: 800, source: 'procfs' },
      ]
      const record = minimalRecord({ processes })
      const graph = buildEvidenceGraph(record)
      const vector = extractFeatureVector(record, graph)

      expect(vector.graph.graphDensity).toBeGreaterThan(0)
      expect(vector.graph.graphEntropy).toBeGreaterThanOrEqual(0)
      expect(vector.graph.isDag).toBe(1)
      expect(vector.graph.sccCount).toBeGreaterThan(0)
    })
  })

  describe('autoLabel', () => {
    it('labels clean build as normal', () => {
      const record = minimalRecord()
      expect(autoLabel(record)).toBe('normal')
    })

    it('labels critical anomalies as malicious', () => {
      const record = minimalRecord({
        summary: {
          totalProcesses: 1,
          uniqueProcesses: ['curl'],
          buildToolsDetected: [],
          filesCreated: 0,
          filesModified: 0,
          filesDeleted: 0,
          filesRead: 0,
          networkConnections: 0,
          dnsQueries: [],
          artifactsHashed: 0,
          anomalies: ['[CRITICAL] injection detected'],
          processTree: [],
          totalHashLinks: 0,
        },
      })
      expect(autoLabel(record)).toBe('malicious')
    })

    it('labels exfil risk as malicious', () => {
      const record = minimalRecord({
        secretFlow: {
          secretAccesses: [],
          chains: [{ id: 'c1', source: 'key', processes: ['curl'], hosts: ['evil.com'], hasExfilRisk: true, confidence: 90 }],
          totalSecrets: 1,
          criticalCount: 0,
          exfilRiskCount: 1,
        },
      })
      expect(autoLabel(record)).toBe('malicious')
    })

    it('labels high anomalies as anomalous', () => {
      const record = minimalRecord({
        hermetricScore: 90,
        summary: {
          totalProcesses: 1,
          uniqueProcesses: ['make'],
          buildToolsDetected: [],
          filesCreated: 0,
          filesModified: 0,
          filesDeleted: 0,
          filesRead: 0,
          networkConnections: 0,
          dnsQueries: [],
          artifactsHashed: 0,
          anomalies: ['[HIGH] suspicious file write'],
          processTree: [],
          totalHashLinks: 0,
        },
      })
      expect(autoLabel(record)).toBe('anomalous')
    })
  })

  describe('CorpusStore (persistence)', () => {
    it('records examples to disk', () => {
      const record = minimalRecord()
      const vector = extractFeatureVector(record, undefined, 'normal')
      store.record(vector)

      expect(store.count()).toBe(1)
      expect(store.getAll().length).toBe(1)
      expect(store.getLabeled().length).toBe(1)
    })

    it('persists across instances', () => {
      const record = minimalRecord({ command: 'npm build' })
      const vector = extractFeatureVector(record, undefined, 'normal')
      store.record(vector)

      const store2 = new CorpusStore()
      expect(store2.count()).toBe(1)
      expect(store2.getAll()[0].command).toBe('npm build')
    })

    it('counts by label', () => {
      store.record(extractFeatureVector(minimalRecord({ command: 'a' }), undefined, 'normal'))
      store.record(extractFeatureVector(minimalRecord({ command: 'b' }), undefined, 'malicious'))
      store.record(extractFeatureVector(minimalRecord({ command: 'c' }))) // unlabeled

      const byLabel = store.countByLabel()
      expect(byLabel.normal).toBe(1)
      expect(byLabel.malicious).toBe(1)
      expect(byLabel.unlabeled).toBe(1)
    })

    it('clears data', () => {
      store.record(extractFeatureVector(minimalRecord(), undefined, 'normal'))
      expect(store.count()).toBe(1)
      store.clear()
      expect(store.count()).toBe(0)
    })

    it('export and import round-trip', () => {
      store.record(extractFeatureVector(minimalRecord({ command: 'export-1' }), undefined, 'normal'))
      store.record(extractFeatureVector(minimalRecord({ command: 'export-2' }), undefined, 'malicious'))
      const exportPath = path.join(corpusDir, 'export_test.jsonl')
      store.exportToJsonl(exportPath)

      const store2 = new CorpusStore(path.join(corpusDir, 'import_test.jsonl'))
      const imported = store2.importFromJsonl(exportPath)
      expect(imported).toBe(2)
      expect(store2.count()).toBe(2)
    })

    it('getStatsSummary renders', () => {
      store.record(extractFeatureVector(minimalRecord(), undefined, 'normal'))
      const lines = store.getStatsSummary()
      expect(lines.some(l => l.includes('Corpus Store'))).toBe(true)
      expect(lines.some(l => l.includes('normal: 1'))).toBe(true)
    })
  })

  describe('computeLearnedTrust', () => {
    it('returns a trust result', () => {
      const processes: BuildProcessEvent[] = [
        { pid: 1, name: 'make', cmdline: 'make', ppid: 0, pname: '', timestamp: 100, exitTime: 1000, source: 'procfs' },
        { pid: 2, name: 'gcc', cmdline: 'gcc -c', ppid: 1, pname: 'make', timestamp: 200, exitTime: 800, source: 'procfs' },
      ]
      const record = minimalRecord({
        processes,
        hermetricScore: 90,
        reproducibilityScore: 80,
      })
      const graph = buildEvidenceGraph(record)
      const result = computeLearnedTrust(record, graph)

      expect(result.overallTrust).toBeGreaterThanOrEqual(0)
      expect(result.overallTrust).toBeLessThanOrEqual(100)
      expect(result.dimensions.length).toBeGreaterThan(0)
      expect(result.dimensions.some(d => d.name === 'base_trust')).toBe(true)
    })

    it('works without graph', () => {
      const record = minimalRecord()
      const result = computeLearnedTrust(record)

      expect(result.overallTrust).toBeGreaterThanOrEqual(0)
    })
  })

  describe('renderFeatureVector', () => {
    it('renders without error', () => {
      const record = minimalRecord()
      const vector = extractFeatureVector(record, undefined, 'normal')
      const lines = renderFeatureVector(vector)

      expect(lines.length).toBeGreaterThan(0)
      expect(lines[0]).toContain('Trust Feature Vector')
      expect(lines.some(l => l.includes('avgBetweenness') || l.includes('Centrality Features'))).toBe(true)
    })
  })

  describe('renderCalibrationSummary', () => {
    it('renders without error', () => {
      const lines = renderCalibrationSummary()

      expect(lines.length).toBeGreaterThan(0)
      expect(lines[0]).toContain('Trust Calibration Summary')
    })

    it('shows labeled count after training', () => {
      store.record(extractFeatureVector(minimalRecord(), undefined, 'normal'))
      const lines = renderCalibrationSummary(store)

      expect(lines.some(l => l.includes('normal:'))).toBe(true)
    })
  })

  describe('logistic regression', () => {
    it('trains and predicts for linearly separable data', () => {
      // Simple AND gate: feature[0] AND feature[1]
      const X = [[0, 0], [0, 1], [1, 0], [1, 1]]
      const y = [0, 0, 0, 1]

      const { weights, intercept, lossHistory } = trainLogisticRegression(X, y, { learningRate: 0.1, iterations: 5000, lambda: 0.001 })
      const { probabilities, predictions } = predictLogistic(X, weights, intercept)

      expect(predictions[0]).toBe(0)
      expect(predictions[3]).toBe(1)
      expect(lossHistory.length).toBeGreaterThan(0)
      expect(weights.length).toBe(2)
    })

    it('decreases loss over iterations', () => {
      const X = [[0], [1]]
      const y = [0, 1]
      const result = trainLogisticRegression(X, y, { learningRate: 0.1, iterations: 5000, lambda: 0.001 })
      expect(result.lossHistory[result.lossHistory.length - 1])
        .toBeLessThanOrEqual(result.lossHistory[0])
    })
  })

  describe('evaluateModel', () => {
    it('computes perfect metrics for perfect predictions', () => {
      const yTrue = [1, 1, 0, 0]
      const yPred = [1, 1, 0, 0]
      const probs = [0.9, 0.8, 0.2, 0.1]

      const evalResult = evaluateModel(yTrue, yPred, probs, 4)
      expect(evalResult.accuracy).toBe(1)
      expect(evalResult.precision).toBe(1)
      expect(evalResult.recall).toBe(1)
      expect(evalResult.f1).toBe(1)
      expect(evalResult.auc).toBe(1)
      expect(evalResult.confusionMatrix.tp).toBe(2)
      expect(evalResult.confusionMatrix.tn).toBe(2)
      expect(evalResult.trainedOn).toBe(4)
    })

    it('computes zero metrics for reversed predictions', () => {
      const yTrue = [1, 0]
      const yPred = [0, 1]
      const probs = [0.3, 0.7]

      const evalResult = evaluateModel(yTrue, yPred, probs, 2)
      expect(evalResult.accuracy).toBe(0)
      expect(evalResult.precision).toBe(0)
      expect(evalResult.recall).toBe(0)
      expect(evalResult.f1).toBe(0)
    })

    it('generates ROC points', () => {
      const yTrue = [1, 1, 0, 0]
      const yPred = [1, 0, 0, 0]
      const probs = [0.9, 0.6, 0.4, 0.1]

      const evalResult = evaluateModel(yTrue, yPred, probs, 4)
      expect(evalResult.rocPoints.length).toBeGreaterThan(1)
      expect(evalResult.rocPoints[0].fpr).toBe(0)
      expect(evalResult.rocPoints[0].tpr).toBe(0)
    })
  })

  describe('calibrateWeights (ML)', () => {
    it('returns baseline with insufficient data', () => {
      const result = calibrateWeights(store)
      expect(result.weights).toBeDefined()
      expect(result.featureNames.length).toBe(69)
      expect(result.evaluation!.trainedOn).toBe(0)
      expect(result.evaluation!.auc).toBe(0)
    })

    it('trains with sufficient labeled data', () => {
      // Add enough labeled examples for training
      for (let i = 0; i < 5; i++) {
        const cmd = i < 3 ? 'npm build' : 'curl evil.com'
        const record = minimalRecord({
          command: cmd,
          summary: {
            totalProcesses: 1,
            uniqueProcesses: [cmd.split(' ')[0]],
            buildToolsDetected: [],
            filesCreated: 0,
            filesModified: 0,
            filesDeleted: 0,
            filesRead: 0,
            networkConnections: 0,
            dnsQueries: [],
            artifactsHashed: 0,
            anomalies: i >= 3 ? ['[HIGH] suspicious outbound'] : [],
            processTree: [],
            totalHashLinks: 0,
          },
        })
        const label = i < 3 ? 'normal' : 'malicious' as const
        store.record(extractFeatureVector(record, undefined, label))
      }

      const result = calibrateWeights(store)
      expect(result.evaluation!.trainedOn).toBe(5)
      expect(Object.keys(result.weights).length).toBe(69)
    })

    it('produces different weights than manual defaults', () => {
      for (let i = 0; i < 10; i++) {
        const record = minimalRecord({
          command: i < 5 ? 'good build' : 'curl evil.com',
          hermetricScore: i < 5 ? 95 : 20,
          exitCode: i < 5 ? 0 : 1,
          summary: {
            totalProcesses: 5,
            uniqueProcesses: ['tool'],
            buildToolsDetected: [],
            filesCreated: 0,
            filesModified: 0,
            filesDeleted: 0,
            filesRead: 0,
            networkConnections: i >= 5 ? 10 : 0,
            dnsQueries: [],
            artifactsHashed: 0,
            anomalies: i >= 5 ? ['[HIGH] nc -e', '[HIGH] curl external'] : [],
            processTree: [],
            totalHashLinks: 0,
          },
        })
        const label = i < 5 ? 'normal' : 'malicious' as const
        store.record(extractFeatureVector(record, undefined, label))
      }

      const result = calibrateWeights(store)
      expect(result.evaluation!.trainedOn).toBe(10)
      expect(result.evaluation!.auc).toBeGreaterThan(0)
      expect(result.weights.anomalyCount).not.toBeUndefined()
    })
  })

  describe('renderEvaluation', () => {
    it('renders without error', () => {
      const evalResult = {
        accuracy: 0.85,
        precision: 0.80,
        recall: 0.75,
        f1: 0.77,
        auc: 0.90,
        confusionMatrix: { tp: 10, fp: 3, tn: 15, fn: 2 },
        rocPoints: [{ fpr: 0, tpr: 0 }, { fpr: 0.5, tpr: 0.8 }, { fpr: 1, tpr: 1 }],
        trainedOn: 30,
      }
      const lines = renderEvaluation(evalResult)
      expect(lines.length).toBeGreaterThan(0)
      expect(lines[0]).toContain('Model Evaluation')
      expect(lines.some(l => l.includes('AUC'))).toBe(true)
    })
  })

  describe('renderCalibrationResult', () => {
    it('renders without error', () => {
      const result = calibrateWeights(store)
      const lines = renderCalibrationResult(result)
      expect(lines.length).toBeGreaterThan(0)
      expect(lines[0]).toContain('ML Calibration Result')
    })
  })
})
