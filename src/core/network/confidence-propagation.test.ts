import { describe, it, expect } from 'vitest'
import { propagateGraphConfidence, findConfidencePaths, propagateConfidence, relationDegradation, renderConfidencePaths, renderConfidencePropagation, propagateFromSeed } from './evidence-reliability'
import { EvidenceGraph, EvidenceNode, EvidenceEdge } from './build-types'

describe('confidence-propagation', () => {
  describe('relationDegradation', () => {
    it('returns 0.05 for spawned', () => {
      expect(relationDegradation('spawned')).toBe(0.05)
    })
    it('returns 0.40 for heuristic_association', () => {
      expect(relationDegradation('heuristic_association')).toBe(0.40)
    })
    it('returns 0.30 for unknown relation', () => {
      expect(relationDegradation('unknown' as any)).toBe(0.30)
    })
  })

  describe('propagateConfidence', () => {
    it('returns same confidence for no edges', () => {
      const result = propagateConfidence(100, [])
      expect(result).toBe(100)
    })

    it('reduces confidence across a single edge', () => {
      const edges: EvidenceEdge[] = [
        { from: 'a', to: 'b', relation: 'spawned', confidence: 95, timestamp: 0, degradation: 0.05 },
      ]
      const result = propagateConfidence(100, edges)
      expect(result).toBe(95)
    })

    it('reduces confidence across multiple edges', () => {
      const edges: EvidenceEdge[] = [
        { from: 'a', to: 'b', relation: 'spawned', confidence: 95, timestamp: 0, degradation: 0.05 },
        { from: 'b', to: 'c', relation: 'heuristic_association', confidence: 70, timestamp: 0, degradation: 0.40 },
      ]
      const result = propagateConfidence(100, edges)
      expect(result).toBe(57)
    })

    it('never goes below 0', () => {
      const edges: EvidenceEdge[] = [
        { from: 'a', to: 'b', relation: 'heuristic_association', confidence: 50, timestamp: 0, degradation: 0.99 },
      ]
      const result = propagateConfidence(1, edges)
      expect(result).toBeGreaterThanOrEqual(0)
    })
  })

  describe('propagateGraphConfidence', () => {
    it('propagates from root nodes with no in-edges', () => {
      const graph: EvidenceGraph = {
        buildId: 'test',
        rootPid: 1,
        rootProcess: 'make',
        createdAt: 0,
        schemaVersion: 1,
        nodes: [
          { id: 'n1', type: 'PROCESS_CREATED', label: 'make', timestamp: 100, confidence: 98, observationConfidence: 98, inferenceConfidence: 100, source: 'etw', attributes: {} },
          { id: 'n2', type: 'FILE_CREATED', label: 'out.o', timestamp: 500, confidence: 85, observationConfidence: 85, inferenceConfidence: 100, source: 'procfs', attributes: {} },
        ],
        edges: [
          { from: 'n1', to: 'n2', relation: 'created', confidence: 85, timestamp: 500, degradation: 0.10 },
        ],
      }

      const result = propagateGraphConfidence(graph)
      const n2 = result.nodes.find(n => n.id === 'n2')
      expect(n2).toBeDefined()
      expect(n2!.confidence).toBe(98)
      expect(n2!.observationConfidence).toBe(85)
      expect(n2!.inferenceConfidence).toBeLessThanOrEqual(100)
      expect(n2!.inferenceConfidence).toBeGreaterThan(85)
    })

    it('preserves nodes with no incoming edges', () => {
      const graph: EvidenceGraph = {
        buildId: 'test',
        rootPid: 1,
        rootProcess: 'make',
        createdAt: 0,
        schemaVersion: 1,
        nodes: [
          { id: 'n1', type: 'PROCESS_CREATED', label: 'make', timestamp: 100, confidence: 98, observationConfidence: 98, inferenceConfidence: 100, source: 'etw', attributes: {} },
        ],
        edges: [],
      }

      const result = propagateGraphConfidence(graph)
      const n1 = result.nodes.find(n => n.id === 'n1')
      expect(n1).toBeDefined()
      expect(n1!.confidence).toBe(98)
    })
  })

  describe('findConfidencePaths', () => {
    it('finds direct path between two nodes', () => {
      const graph: EvidenceGraph = {
        buildId: 'test',
        rootPid: 1,
        rootProcess: 'make',
        createdAt: 0,
        schemaVersion: 1,
        nodes: [
          { id: 'n1', type: 'PROCESS_CREATED', label: 'make', timestamp: 100, confidence: 98, observationConfidence: 98, inferenceConfidence: 100, source: 'etw', attributes: {} },
          { id: 'n2', type: 'FILE_CREATED', label: 'out.o', timestamp: 500, confidence: 85, observationConfidence: 85, inferenceConfidence: 100, source: 'procfs', attributes: {} },
        ],
        edges: [
          { from: 'n1', to: 'n2', relation: 'created', confidence: 85, timestamp: 500, degradation: 0.10 },
        ],
      }

      const paths = findConfidencePaths(graph, 'n1', 'n2')
      expect(paths.length).toBeGreaterThanOrEqual(1)
      expect(paths[0].initialConfidence).toBeDefined()
      expect(paths[0].propagatedConfidence).toBeDefined()
    })

    it('returns empty for unreachable nodes', () => {
      const graph: EvidenceGraph = {
        buildId: 'test',
        rootPid: 1,
        rootProcess: 'a',
        createdAt: 0,
        schemaVersion: 1,
        nodes: [
          { id: 'n1', type: 'PROCESS_CREATED', label: 'a', timestamp: 100, confidence: 90, observationConfidence: 90, inferenceConfidence: 100, source: 'procfs', attributes: {} },
          { id: 'n2', type: 'PROCESS_CREATED', label: 'b', timestamp: 200, confidence: 80, observationConfidence: 80, inferenceConfidence: 100, source: 'procfs', attributes: {} },
        ],
        edges: [],
      }

      const paths = findConfidencePaths(graph, 'n1', 'n2')
      expect(paths.length).toBe(0)
    })
  })

  describe('renderConfidencePaths', () => {
    it('renders no-paths message for empty array', () => {
      const lines = renderConfidencePaths([])
      expect(lines).toContain('No confidence paths found')
    })
  })

  describe('renderConfidencePropagation', () => {
    it('renders without error', () => {
      const graph: EvidenceGraph = {
        buildId: 'test',
        rootPid: 1,
        rootProcess: 'make',
        createdAt: 0,
        schemaVersion: 1,
        nodes: [
          { id: 'n1', type: 'PROCESS_CREATED', label: 'make', timestamp: 100, confidence: 98, observationConfidence: 98, inferenceConfidence: 100, source: 'etw', attributes: {} },
        ],
        edges: [],
      }

      const lines = renderConfidencePropagation(graph)
      expect(lines.length).toBeGreaterThan(0)
      expect(lines[0]).toContain('Confidence Propagation')
    })
  })

  describe('propagateFromSeed', () => {
    it('propagates from a seed node through outgoing edges', () => {
      const graph: EvidenceGraph = {
        buildId: 'test',
        rootPid: 1,
        rootProcess: 'make',
        createdAt: 0,
        schemaVersion: 1,
        nodes: [
          { id: 'n1', type: 'PROCESS_CREATED', label: 'make', timestamp: 100, confidence: 98, observationConfidence: 98, inferenceConfidence: 100, source: 'etw', attributes: {} },
          { id: 'n2', type: 'FILE_CREATED', label: 'out.o', timestamp: 500, confidence: 85, observationConfidence: 85, inferenceConfidence: 100, source: 'procfs', attributes: {} },
          { id: 'n3', type: 'NETWORK_CONNECT', label: 'example.com', timestamp: 600, confidence: 80, observationConfidence: 80, inferenceConfidence: 100, source: 'procfs', attributes: {} },
        ],
        edges: [
          { from: 'n1', to: 'n2', relation: 'created', confidence: 85, timestamp: 500, degradation: 0.10 },
          { from: 'n1', to: 'n3', relation: 'connected', confidence: 75, timestamp: 600, degradation: 0.25 },
        ],
      }

      const result = propagateFromSeed(graph, 'n1')
      const n2 = result.nodes.find(n => n.id === 'n2')
      const n3 = result.nodes.find(n => n.id === 'n3')
      expect(n2).toBeDefined()
      expect(n3).toBeDefined()
    })

    it('respects maxDepth', () => {
      const graph: EvidenceGraph = {
        buildId: 'test',
        rootPid: 1,
        rootProcess: 'make',
        createdAt: 0,
        schemaVersion: 1,
        nodes: [
          { id: 'n1', type: 'PROCESS_CREATED', label: 'a', timestamp: 100, confidence: 90, observationConfidence: 90, inferenceConfidence: 100, source: 'procfs', attributes: {} },
          { id: 'n2', type: 'PROCESS_CREATED', label: 'b', timestamp: 200, confidence: 80, observationConfidence: 80, inferenceConfidence: 100, source: 'procfs', attributes: {} },
          { id: 'n3', type: 'FILE_CREATED', label: 'c', timestamp: 300, confidence: 70, observationConfidence: 70, inferenceConfidence: 100, source: 'procfs', attributes: {} },
        ],
        edges: [
          { from: 'n1', to: 'n2', relation: 'spawned', confidence: 95, timestamp: 200, degradation: 0.05 },
          { from: 'n2', to: 'n3', relation: 'created', confidence: 85, timestamp: 300, degradation: 0.10 },
        ],
      }

      const result = propagateFromSeed(graph, 'n1', 1)
      const n3 = result.nodes.find(n => n.id === 'n3')
      expect(n3).toBeDefined()
    })
  })

  describe('cycle handling', () => {
    it('handles cyclic graphs without infinite loop', () => {
      const graph: EvidenceGraph = {
        buildId: 'test',
        rootPid: 1,
        rootProcess: 'make',
        createdAt: 0,
        schemaVersion: 1,
        nodes: [
          { id: 'n1', type: 'PROCESS_CREATED', label: 'a', timestamp: 100, confidence: 90, observationConfidence: 90, inferenceConfidence: 100, source: 'procfs', attributes: {} },
          { id: 'n2', type: 'PROCESS_CREATED', label: 'b', timestamp: 200, confidence: 80, observationConfidence: 80, inferenceConfidence: 100, source: 'procfs', attributes: {} },
          { id: 'n3', type: 'FILE_CREATED', label: 'c', timestamp: 300, confidence: 70, observationConfidence: 70, inferenceConfidence: 100, source: 'procfs', attributes: {} },
        ],
        edges: [
          { from: 'n1', to: 'n2', relation: 'spawned', confidence: 95, timestamp: 200, degradation: 0.05 },
          { from: 'n2', to: 'n3', relation: 'created', confidence: 85, timestamp: 300, degradation: 0.10 },
          { from: 'n3', to: 'n1', relation: 'heuristic_association', confidence: 50, timestamp: 400, degradation: 0.40 },
        ],
      }

      const result = propagateGraphConfidence(graph)
      expect(result.nodes.length).toBe(3)
      for (const node of result.nodes) {
        expect(node.confidence).toBeGreaterThanOrEqual(0)
      }
    })
  })
})
