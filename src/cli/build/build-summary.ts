import * as pc from 'picocolors'
import { BuildRecord, BUILD_TOOLS, DANGEROUS_BUILD_TOOLS } from '../../core/network/build-types'

// ── Trust Score Computation ──────────────────────────────────
export interface TrustBreakdown {
  score: number
  verdict: 'CLEAN' | 'REVIEW' | 'BLOCK'
  deductions: { reason: string; points: number }[]
  additions: { reason: string; points: number }[]
}

export interface Highlight {
  icon: '✓' | '⚠' | '✗'
  text: string
  severity: 'good' | 'warning' | 'bad'
}

export function computeTrustScore(record: BuildRecord): TrustBreakdown {
  let score = 100
  const deductions: { reason: string; points: number }[] = []
  const additions: { reason: string; points: number }[] = []
  const s = record.summary

  // ── Deductions ──

  // Anomalies (each costs points)
  for (const anomaly of s.anomalies) {
    const points = anomaly.includes('exfiltrat') ? 25
      : anomaly.includes('secret') ? 15
      : anomaly.includes('unknown') || anomaly.includes('suspicious') ? 12
      : anomaly.includes('contract') ? 10
      : anomaly.includes('orphan') ? 8
      : anomaly.includes('response file') ? 8
      : anomaly.includes('wrapper') ? 10
      : 5
    score -= points
    deductions.push({ reason: anomaly, points })
  }

  // Build contract violations
  if (record.buildContractViolations && record.buildContractViolations.length > 0) {
    for (const v of record.buildContractViolations) {
      const points = v.severity === 'critical' ? 15 : v.severity === 'warning' ? 10 : 5
      score -= points
      deductions.push({ reason: `Contract violation: ${v.reason}`, points })
    }
  }

  // Secret flow risks
  if (record.secretFlow) {
    const sf = record.secretFlow
    if (sf.exfilRiskCount > 0) {
      const points = Math.min(sf.exfilRiskCount * 12, 25)
      score -= points
      deductions.push({ reason: `${sf.exfilRiskCount} secret exfiltration risk(s)`, points })
    }
    if (sf.secretAccesses.length > 0 && sf.exfilRiskCount === 0) {
      // Secret accessed but no exfiltration — mild concern
      const points = Math.min(sf.secretAccesses.length * 5, 10)
      score -= points
      deductions.push({ reason: `${sf.secretAccesses.length} secret file(s) accessed`, points })
    }
  }

  // Network connections during build (unusual)
  if (s.networkConnections > 3) {
    const points = Math.min((s.networkConnections - 3) * 3, 10)
    score -= points
    deductions.push({ reason: `${s.networkConnections} network connections during build`, points })
  }

  // Unknown processes in process tree
  const knownTools = new Set(s.buildToolsDetected.map(t => t.toLowerCase()))
  const unknownProcesses = s.uniqueProcesses.filter(p => !knownTools.has(p.toLowerCase()) && !BUILD_TOOLS.has(p.toLowerCase()))
  if (unknownProcesses.length > 0) {
    const points = Math.min(unknownProcesses.length * 4, 12)
    score -= points
    deductions.push({ reason: `${unknownProcesses.length} unrecognized process(es): ${unknownProcesses.slice(0, 3).join(', ')}${unknownProcesses.length > 3 ? '...' : ''}`, points })
  }

  // No build tools detected
  if (s.buildToolsDetected.length === 0) {
    score -= 15
    deductions.push({ reason: 'No build tools detected (may not be a build)', points: 15 })
  }

  // Non-zero exit code
  if (record.exitCode !== 0 && record.exitCode !== null) {
    score -= 10
    deductions.push({ reason: `Build exited with code ${record.exitCode}`, points: 10 })
  }

  // Response file changes (potential tampering)
  if (record.responseFileChanges && record.responseFileChanges.length > 0) {
    const changed = record.responseFileChanges.filter(r => r.changed)
    if (changed.length > 0) {
      const points = Math.min(changed.length * 8, 15)
      score -= points
      deductions.push({ reason: `${changed.length} response file(s) modified during build`, points })
    }
  }

  // Orphan processes
  if (record.orphanProcesses && record.orphanProcesses.length > 0) {
    const points = Math.min(record.orphanProcesses.length * 6, 12)
    score -= points
    deductions.push({ reason: `${record.orphanProcesses.length} orphan process(es) detected`, points })
  }

  // ── Additions ──

  // Hermetic build score
  if (record.hermetricScore !== undefined && record.hermetricScore >= 80) {
    const points = Math.round(record.hermetricScore / 20)
    score += points
    additions.push({ reason: `Hermetic build (${record.hermetricScore}/100)`, points })
  }

  // Reproducible build
  if (record.reproducibilityScore !== undefined && record.reproducibilityScore >= 70) {
    const points = Math.round(record.reproducibilityScore / 25)
    score += points
    additions.push({ reason: `Reproducible build (${record.reproducibilityScore}/100)`, points })
  }

  // Known toolchain
  if (s.buildToolsDetected.length > 0 && s.buildToolsDetected.every(t => BUILD_TOOLS.has(t.toLowerCase()))) {
    score += 8
    additions.push({ reason: 'Toolchain matches known build tools', points: 8 })
  }

  // No network activity
  if (s.networkConnections === 0 && s.dnsQueries.length === 0) {
    score += 5
    additions.push({ reason: 'No network activity during build', points: 5 })
  }

  // High observation confidence
  if (record.observationConfidence && record.observationConfidence.overall >= 0.9) {
    score += 3
    additions.push({ reason: 'High observation confidence', points: 3 })
  }

  // Clamp
  score = Math.max(0, Math.min(100, score))

  const verdict: TrustBreakdown['verdict'] = score >= 80 ? 'CLEAN' : score >= 50 ? 'REVIEW' : 'BLOCK'

  return { score, verdict, deductions, additions }
}

export function computeHighlights(record: BuildRecord, trust: TrustBreakdown): Highlight[] {
  const highlights: Highlight[] = []
  const s = record.summary

  // Process count
  highlights.push({
    icon: '✓',
    text: `${s.totalProcesses} process(es) observed`,
    severity: 'good',
  })

  // File activity
  const totalFiles = s.filesCreated + s.filesModified + s.filesDeleted
  if (totalFiles > 0) {
    highlights.push({
      icon: '✓',
      text: `${s.filesCreated} file(s) created, ${s.filesModified} modified, ${s.filesDeleted} deleted`,
      severity: s.filesDeleted > 0 ? 'warning' : 'good',
    })
  }

  // Network
  if (s.networkConnections === 0 && s.dnsQueries.length === 0) {
    highlights.push({ icon: '✓', text: 'No network activity during build', severity: 'good' })
  } else {
    const parts: string[] = []
    if (s.networkConnections > 0) parts.push(`${s.networkConnections} connection(s)`)
    if (s.dnsQueries.length > 0) parts.push(`DNS: ${s.dnsQueries.slice(0, 3).join(', ')}`)
    highlights.push({
      icon: s.networkConnections > 3 ? '✗' : '⚠',
      text: `Network: ${parts.join(', ')}`,
      severity: s.networkConnections > 3 ? 'bad' : 'warning',
    })
  }

  // Secrets
  if (record.secretFlow) {
    const sf = record.secretFlow
    if (sf.exfilRiskCount > 0) {
      highlights.push({
        icon: '✗',
        text: `${sf.exfilRiskCount} secret exfiltration risk(s) detected`,
        severity: 'bad',
      })
    } else if (sf.secretAccesses && sf.secretAccesses.length > 0) {
      highlights.push({
        icon: '⚠',
        text: `${sf.secretAccesses.length} secret file(s) accessed`,
        severity: 'warning',
      })
    } else {
      highlights.push({ icon: '✓', text: 'No secret access detected', severity: 'good' })
    }
  } else {
    highlights.push({ icon: '✓', text: 'No secret access detected', severity: 'good' })
  }

  // Toolchain
  if (s.buildToolsDetected.length > 0) {
    const allKnown = s.buildToolsDetected.every(t => BUILD_TOOLS.has(t.toLowerCase()))
    highlights.push({
      icon: allKnown ? '✓' : '⚠',
      text: allKnown
        ? `Toolchain: ${s.buildToolsDetected.join(', ')}`
        : `Toolchain includes unknown tools: ${s.buildToolsDetected.filter(t => !BUILD_TOOLS.has(t.toLowerCase())).join(', ')}`,
      severity: allKnown ? 'good' : 'warning',
    })
  }

  // Hermetic
  if (record.hermetricScore !== undefined) {
    const score = record.hermetricScore
    highlights.push({
      icon: score >= 80 ? '✓' : score >= 50 ? '⚠' : '✗',
      text: `Hermetic build: ${score}/100`,
      severity: score >= 80 ? 'good' : score >= 50 ? 'warning' : 'bad',
    })
  }

  // Reproducible
  if (record.reproducibilityScore !== undefined) {
    const score = record.reproducibilityScore
    highlights.push({
      icon: score >= 70 ? '✓' : score >= 40 ? '⚠' : '✗',
      text: `Reproducible: ${score}/100`,
      severity: score >= 70 ? 'good' : score >= 40 ? 'warning' : 'bad',
    })
  }

  // Contract violations
  if (record.buildContractViolations && record.buildContractViolations.length > 0) {
    highlights.push({
      icon: '✗',
      text: `${record.buildContractViolations.length} build contract violation(s)`,
      severity: 'bad',
    })
  }

  // Orphan processes
  if (record.orphanProcesses && record.orphanProcesses.length > 0) {
    highlights.push({
      icon: '⚠',
      text: `${record.orphanProcesses.length} orphan process(es) detected`,
      severity: 'warning',
    })
  }

  // Response file changes
  if (record.responseFileChanges) {
    const changed = record.responseFileChanges.filter(r => r.changed)
    if (changed.length > 0) {
      highlights.push({
        icon: '✗',
        text: `${changed.length} response file(s) modified during build`,
        severity: 'bad',
      })
    }
  }

  return highlights
}

export function computeRecommendations(record: BuildRecord, trust: TrustBreakdown): string[] {
  const recs: string[] = []

  if (trust.verdict === 'BLOCK') {
    recs.push('Do not use this build — critical issues detected')
  }

  if (record.secretFlow && record.secretFlow.exfilRiskCount > 0) {
    recs.push('Investigate secret access patterns — potential data exfiltration')
  }

  if (record.buildContractViolations && record.buildContractViolations.length > 0) {
    recs.push('Review build contract violations')
  }

  if (record.orphanProcesses && record.orphanProcesses.length > 0) {
    recs.push('Investigate orphan processes — they may indicate hijacking')
  }

  if (record.responseFileChanges?.some(r => r.changed)) {
    recs.push('Verify response file integrity — files were modified during build')
  }

  const unknownTools = record.summary.buildToolsDetected.filter(t => !BUILD_TOOLS.has(t.toLowerCase()))
  if (unknownTools.length > 0) {
    recs.push(`Review unknown build tools: ${unknownTools.join(', ')}`)
  }

  if (record.summary.networkConnections > 3) {
    recs.push('Review network connections — unusual for a build')
  }

  if (trust.deductions.length === 0 && trust.additions.length > 0) {
    recs.push('No action required — build looks clean')
  }

  return recs
}

// ── Renderers ────────────────────────────────────────────────

function truncate(s: string, n: number): string {
  return s.length > n ? s.substring(0, n) + '...' : s
}

export function renderTrustScore(trust: TrustBreakdown): string {
  const lines: string[] = []
  const scoreColor = trust.score >= 80 ? pc.green : trust.score >= 50 ? pc.yellow : pc.red
  const verdictColor = trust.verdict === 'CLEAN' ? pc.green : trust.verdict === 'REVIEW' ? pc.yellow : pc.red
  const verdictBg = trust.verdict === 'CLEAN' ? pc.bgGreen : trust.verdict === 'REVIEW' ? pc.bgYellow : pc.bgRed

  lines.push('')
  lines.push(pc.cyan(pc.bold('  ═══════════════════════════════════════════════')))
  lines.push(pc.cyan(pc.bold('   SENTINEL BUILD ANALYSIS')))
  lines.push(pc.cyan(pc.bold('  ═══════════════════════════════════════════════')))
  lines.push('')

  // Verdict
  lines.push(pc.bold('  Verdict'))
  lines.push(pc.dim('  ──────────────'))
  lines.push(`  ${verdictBg(pc.white(` ${trust.verdict} `))}`)
  lines.push('')

  // Trust Score
  lines.push(pc.bold('  Trust Score'))
  lines.push(pc.dim('  ──────────────'))
  lines.push(`  ${scoreColor(pc.bold(String(trust.score)))} / 100`)
  lines.push('')

  // Risk level
  const riskLevel = trust.score >= 80 ? 'LOW' : trust.score >= 50 ? 'MEDIUM' : 'HIGH'
  const riskColor = trust.score >= 80 ? pc.green : trust.score >= 50 ? pc.yellow : pc.red
  lines.push(pc.bold('  Risk'))
  lines.push(pc.dim('  ──────────────'))
  lines.push(`  ${riskColor(riskLevel)}`)
  lines.push('')

  return lines.join('\n')
}

export function renderHighlights(highlights: Highlight[]): string {
  const lines: string[] = []

  lines.push(pc.bold('  Highlights'))
  lines.push(pc.dim('  ──────────────'))

  for (const h of highlights) {
    const iconColor = h.severity === 'good' ? pc.green : h.severity === 'warning' ? pc.yellow : pc.red
    lines.push(`  ${iconColor(h.icon)} ${h.text}`)
  }
  lines.push('')

  return lines.join('\n')
}

export function renderRecommendations(recs: string[]): string {
  if (recs.length === 0) return ''

  const lines: string[] = []
  lines.push(pc.bold('  Recommendations'))
  lines.push(pc.dim('  ──────────────'))

  for (const r of recs) {
    lines.push(`  ${pc.dim('→')} ${r}`)
  }
  lines.push('')

  return lines.join('\n')
}

export function renderBuildSummary(record: BuildRecord): string {
  const trust = computeTrustScore(record)
  const highlights = computeHighlights(record, trust)
  const recs = computeRecommendations(record, trust)
  const s = record.summary
  const duration = record.durationMs < 1000
    ? `${record.durationMs}ms`
    : `${(record.durationMs / 1000).toFixed(1)}s`

  const lines: string[] = []
  const scoreColor = trust.score >= 80 ? pc.green : trust.score >= 50 ? pc.yellow : pc.red
  const verdictColor = trust.verdict === 'CLEAN' ? pc.green : trust.verdict === 'REVIEW' ? pc.yellow : pc.red

  // ── Q1: ¿Está limpio? ──────────────────────────────────────
  lines.push('')
  lines.push(pc.cyan(pc.bold('  ═══════════════════════════════════════════════')))
  lines.push(pc.cyan(pc.bold('   SENTINEL BUILD OBSERVATION')))
  lines.push(pc.cyan(pc.bold('  ═══════════════════════════════════════════════')))
  lines.push('')
  lines.push(`  ${verdictColor(pc.bold(trust.verdict.padEnd(8)))} ${scoreColor(pc.bold(String(trust.score)))}/100  ${pc.dim(duration)}`)
  lines.push('')

  // ── Q2: ¿Qué hizo? ─────────────────────────────────────────
  lines.push(pc.bold('  What happened'))
  lines.push(pc.dim('  ──────────────'))
  const tools = s.buildToolsDetected.length > 0 ? s.buildToolsDetected.join(', ') : 'none detected'
  lines.push(`  ${pc.dim('Tools:')}     ${tools}`)
  lines.push(`  ${pc.dim('Processes:')} ${s.totalProcesses} observed`)
  const totalFiles = s.filesCreated + s.filesModified + s.filesDeleted
  if (totalFiles > 0) {
    lines.push(`  ${pc.dim('Files:')}     ${s.filesCreated} created, ${s.filesModified} modified, ${s.filesDeleted} deleted`)
  }
  if (s.networkConnections > 0 || s.dnsQueries.length > 0) {
    const netParts: string[] = []
    if (s.networkConnections > 0) netParts.push(`${s.networkConnections} connection(s)`)
    if (s.dnsQueries.length > 0) netParts.push(`DNS: ${s.dnsQueries.slice(0, 3).join(', ')}`)
    lines.push(`  ${pc.dim('Network:')}   ${netParts.join(', ')}`)
  }
  lines.push('')

  // ── Q3: ¿Qué cambió? (Build Identity) ──────────────────────
  lines.push(pc.bold('  Build Identity'))
  lines.push(pc.dim('  ──────────────'))
  if (record.hermetricScore !== undefined) {
    const hColor = record.hermetricScore >= 80 ? pc.green : record.hermetricScore >= 50 ? pc.yellow : pc.red
    lines.push(`  ${pc.dim('Hermetic:')}      ${hColor(String(record.hermetricScore))}/100`)
  }
  if (record.reproducibilityScore !== undefined) {
    const rColor = record.reproducibilityScore >= 70 ? pc.green : record.reproducibilityScore >= 40 ? pc.yellow : pc.red
    lines.push(`  ${pc.dim('Reproducible:')}  ${rColor(String(record.reproducibilityScore))}/100`)
  }
  if (record.observationConfidence) {
    lines.push(`  ${pc.dim('Confidence:')}    ${record.observationConfidence.overall}`)
  }
  lines.push('')

  // ── Q4: ¿Qué me debe preocupar? ────────────────────────────
  const badHighlights = highlights.filter(h => h.severity === 'bad' || h.severity === 'warning')
  if (badHighlights.length > 0) {
    lines.push(pc.bold('  Risks'))
    lines.push(pc.dim('  ──────────────'))
    for (const h of badHighlights) {
      const iconColor = h.severity === 'bad' ? pc.red : pc.yellow
      lines.push(`  ${iconColor(h.icon)} ${h.text}`)
    }
    lines.push('')
  }

  // ── Q5: ¿Por qué? (score breakdown) ────────────────────────
  if (trust.deductions.length > 0 || trust.additions.length > 0) {
    lines.push(pc.bold('  Why this score'))
    lines.push(pc.dim('  ──────────────'))
    for (const d of trust.deductions) {
      lines.push(`  ${pc.red(`-${d.points}`)}  ${d.reason}`)
    }
    for (const a of trust.additions) {
      lines.push(`  ${pc.green(`+${a.points}`)}  ${a.reason}`)
    }
    lines.push('')
  }

  // ── Q6: ¿Qué hacer ahora? ──────────────────────────────────
  if (recs.length > 0) {
    lines.push(pc.bold('  What to do'))
    lines.push(pc.dim('  ──────────────'))
    for (const r of recs) {
      lines.push(`  ${pc.dim('→')} ${r}`)
    }
    lines.push('')
  }

  // Footer
  if (trust.verdict === 'CLEAN') {
    lines.push(pc.green(pc.bold('  Nothing requires immediate action.')))
  } else if (trust.verdict === 'REVIEW') {
    lines.push(pc.yellow(pc.bold('  Review the findings above before proceeding.')))
  } else {
    lines.push(pc.red(pc.bold('  Do not proceed with this build.')))
  }
  lines.push('')

  return lines.join('\n')
}

export function renderBuildSummaryVerbose(record: BuildRecord): string {
  const base = renderBuildSummary(record)
  const s = record.summary
  const lines: string[] = [base]

  // ── Verbose section ──
  lines.push(pc.cyan(pc.bold('  ═══════════════════════════════════════════════')))
  lines.push(pc.cyan(pc.bold('   TECHNICAL DETAILS')))
  lines.push(pc.cyan(pc.bold('  ═══════════════════════════════════════════════')))
  lines.push('')

  // Build info
  lines.push(pc.bold('  Build'))
  lines.push(`  ${pc.dim('Command:')}  ${pc.white(record.command)} ${record.args.join(' ')}`)
  lines.push(`  ${pc.dim('Exit:')}     ${record.exitCode === 0 ? pc.green(String(record.exitCode)) : pc.red(String(record.exitCode))}`)
  lines.push(`  ${pc.dim('CWD:')}     ${pc.dim(record.cwd)}`)
  lines.push(`  ${pc.dim('Platform:')} ${record.platform} ${record.nodeVersion}`)
  lines.push('')

  // Processes
  lines.push(pc.bold('  Processes'))
  lines.push(pc.dim(`  ${s.totalProcesses} total, ${s.uniqueProcesses.length} unique`))
  if (s.buildToolsDetected.length > 0) {
    lines.push(`  ${pc.dim('Build tools:')} ${pc.green(s.buildToolsDetected.join(', '))}`)
  }
  for (const p of s.processTree) {
    lines.push(`  ${pc.dim('PID')} ${p.pid}: ${pc.white(p.name)} ${pc.dim(truncate(p.cmdline, 80))}`)
  }
  lines.push('')

  // Environment
  if (Object.keys(record.env).length > 0) {
    lines.push(pc.bold('  Environment'))
    for (const [k, v] of Object.entries(record.env)) {
      lines.push(`  ${pc.dim(k)}=${truncate(v, 80)}`)
    }
    lines.push('')
  }

  // Artifacts & Network
  lines.push(pc.bold('  Artifacts & Network'))
  lines.push(`  ${pc.dim('Files created:')}  ${pc.white(String(s.filesCreated))}`)
  lines.push(`  ${pc.dim('Files modified:')} ${pc.white(String(s.filesModified))}`)
  lines.push(`  ${pc.dim('Files deleted:')}  ${s.filesDeleted > 0 ? pc.yellow(String(s.filesDeleted)) : pc.dim('0')}`)
  lines.push(`  ${pc.dim('Artifacts:')}      ${s.artifactsHashed > 0 ? pc.white(String(s.artifactsHashed)) : pc.dim('0')}`)
  lines.push(`  ${pc.dim('Network conns:')}  ${s.networkConnections > 0 ? pc.yellow(String(s.networkConnections)) : pc.dim('0')}`)
  if (s.dnsQueries.length > 0) {
    lines.push(`  ${pc.dim('DNS queries:')}   ${s.dnsQueries.join(', ')}`)
  }
  lines.push('')

  // Artifact Hashes
  if (record.artifactHashes.length > 0) {
    lines.push(pc.bold('  Artifact Hashes'))
    for (const a of record.artifactHashes) {
      lines.push(`  ${pc.dim(a.sha256.substring(0, 16))}  ${pc.white(a.filePath)}`)
    }
    lines.push('')
  }

  // Integrity Chain
  lines.push(pc.bold('  Integrity Chain'))
  lines.push(`  ${pc.dim('Hash links:')} ${pc.white(String(s.totalHashLinks))}`)
  const last = record.hashChain[record.hashChain.length - 1]
  if (last) {
    lines.push(`  ${pc.dim('Last hash:')}  ${pc.dim(last.linkHash)}`)
  }
  lines.push('')

  // Evidence Graph (if present)
  if (record.evidenceGraph && record.evidenceGraph.nodes.length > 0) {
    const evGraph = record.evidenceGraph
    lines.push(pc.cyan(pc.bold('  ─── Evidence Graph ───')))
    lines.push(`  Nodes: ${evGraph.nodes.length}  |  Edges: ${evGraph.edges.length}`)
    const typeCounts: Record<string, number> = {}
    for (const n of evGraph.nodes) typeCounts[n.type] = (typeCounts[n.type] || 0) + 1
    for (const [type, count] of Object.entries(typeCounts).sort((a, b) => b[1] - a[1])) {
      lines.push(`    ${type}: ${count}`)
    }
    lines.push('')
  }

  // Temporal Graph
  if (record.evidenceGraph && record.evidenceGraph.nodes.length > 0) {
    try {
      const { buildTemporalEvidenceGraph, buildBayesianNetwork, analyzeDominators } = require('../../core/network/temporal-graph')
      const teg = buildTemporalEvidenceGraph(record.evidenceGraph)
      const bn = buildBayesianNetwork(record.evidenceGraph)
      const da = analyzeDominators(record.evidenceGraph)

      if (teg.paths.length > 0) {
        lines.push(pc.cyan(pc.bold('  ─── Temporal ───')))
        lines.push(`  Paths: ${teg.paths.length}  |  Avg latency: ${teg.avgEdgeLatencyMs}ms  |  Critical path: ${teg.criticalPath.causalDelayMs}ms`)
        lines.push('')
      }

      if (bn.relations.length > 0) {
        lines.push(pc.cyan(pc.bold('  ─── Bayesian ───')))
        lines.push(`  Global prior: ${bn.globalPrior}  |  Overall posterior: ${bn.overallPosterior}`)
        const sorted = [...bn.relations].sort((a, b) => b.posteriorGivenEvidence - a.posteriorGivenEvidence)
        for (const r of sorted.slice(0, 5)) {
          const delta = r.posteriorGivenEvidence - r.priorP
          lines.push(`    ${r.relation}: posterior=${r.posteriorGivenEvidence} (Δ${delta >= 0 ? '+' : ''}${delta.toFixed(3)})`)
        }
        lines.push('')
      }

      if (da.dominantProcess) {
        lines.push(pc.cyan(pc.bold('  ─── Dominator ───')))
        const domNode = record.evidenceGraph!.nodes.find((n: any) => n.id === da.dominantProcess)
        lines.push(`  Dominant: ${domNode?.label || da.dominantProcess}`)
        lines.push(`  Hijack risk: ${(da.hijackRiskScore * 100).toFixed(1)}%`)
        if (da.toolchainShiftDetected) lines.push(pc.red('  ⚠ Toolchain shift detected'))
        lines.push('')
      }
    } catch {
      // temporal graph modules not available
    }
  }

  // Trust Score Breakdown
  const trust = computeTrustScore(record)
  if (trust.additions.length > 0 || trust.deductions.length > 0) {
    lines.push(pc.bold('  Score Breakdown'))
    for (const a of trust.additions) {
      lines.push(`    ${pc.green('+' + a.points)} ${a.reason}`)
    }
    for (const d of trust.deductions) {
      lines.push(`    ${pc.red('-' + d.points)} ${d.reason}`)
    }
    lines.push('')
  }

  return lines.join('\n')
}

export function renderBuildSummaryJson(record: BuildRecord): string {
  const trust = computeTrustScore(record)
  const highlights = computeHighlights(record, trust)
  const recs = computeRecommendations(record, trust)

  return JSON.stringify({
    verdict: trust.verdict,
    trustScore: trust.score,
    risk: trust.score >= 80 ? 'LOW' : trust.score >= 50 ? 'MEDIUM' : 'HIGH',
    duration: record.durationMs,
    command: `${record.command} ${record.args.join(' ')}`,
    exitCode: record.exitCode,
    summary: {
      processes: record.summary.totalProcesses,
      uniqueProcesses: record.summary.uniqueProcesses.length,
      buildTools: record.summary.buildToolsDetected,
      filesCreated: record.summary.filesCreated,
      filesModified: record.summary.filesModified,
      filesDeleted: record.summary.filesDeleted,
      networkConnections: record.summary.networkConnections,
      dnsQueries: record.summary.dnsQueries,
      anomalies: record.summary.anomalies,
    },
    highlights: highlights.map(h => ({ icon: h.icon, text: h.text, severity: h.severity })),
    recommendations: recs,
    scoreBreakdown: {
      additions: trust.additions,
      deductions: trust.deductions,
    },
    hermeticScore: record.hermetricScore,
    reproducibilityScore: record.reproducibilityScore,
    observationConfidence: record.observationConfidence?.overall,
    evidenceGraph: record.evidenceGraph ? {
      nodes: record.evidenceGraph.nodes.length,
      edges: record.evidenceGraph.edges.length,
    } : null,
  }, null, 2)
}
