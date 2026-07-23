import { BuildRecord, TrustResult, TrustDimension } from './build-types'

const TRUST_DIMENSIONS: { name: string; weight: number; maxScore: number }[] = [
  { name: 'toolchain_identity', weight: 0.18, maxScore: 100 },
  { name: 'input_identity', weight: 0.18, maxScore: 100 },
  { name: 'artifact_integrity', weight: 0.15, maxScore: 100 },
  { name: 'behavior', weight: 0.15, maxScore: 100 },
  { name: 'network', weight: 0.12, maxScore: 100 },
  { name: 'graph', weight: 0.12, maxScore: 100 },
  { name: 'trend', weight: 0.10, maxScore: 100 },
]

export function computeTrust(record: BuildRecord, prevRecord?: BuildRecord): TrustResult {
  const dimensions: TrustDimension[] = []
  const breakdown: string[] = []

  const dimCalculators: Record<string, (rec: BuildRecord, prev?: BuildRecord) => TrustDimension> = {
    toolchain_identity: computeToolchainIdentityTrust,
    input_identity: computeInputIdentityTrust,
    artifact_integrity: computeArtifactIntegrityTrust,
    behavior: computeBehaviorTrust,
    network: computeNetworkTrust,
    graph: computeGraphTrust,
    trend: computeTrendTrust,
  }

  for (const dim of TRUST_DIMENSIONS) {
    const calculator = dimCalculators[dim.name]
    const result = calculator(record, prevRecord)
    dimensions.push(result)
    breakdown.push(...result.evidence)
  }

  const overallTrust = Math.round(
    dimensions.reduce((sum, d) => sum + d.score * d.weight, 0),
  )

  const inputStability = computeInputStabilityMetric(record)
  const toolchainPurity = computeToolchainPurityMetric(record)
  const buildDeterminism = computeBuildDeterminismMetric(record, prevRecord)

  return {
    overallTrust,
    dimensions,
    breakdown,
    inputStability,
    toolchainPurity,
    buildDeterminism,
  }
}

function computeToolchainIdentityTrust(rec: BuildRecord, prev?: BuildRecord): TrustDimension {
  const evidence: string[] = []
  let score = 100

  if (rec.identity?.toolIdentities && rec.identity.toolIdentities.length > 0) {
    evidence.push(`+10 toolchain: ${rec.identity.toolIdentities.length} tools identified`)
    for (const ti of rec.identity.toolIdentities) {
      evidence.push(`  ${ti.name} → ${ti.realPath} (SHA256 ${ti.sha256.substring(0, 12)})`)
    }
  } else {
    score -= 20
    evidence.push('-20 no toolchain identity captured')
  }

  if (prev?.identity?.toolIdentities) {
    const prevShaMap = new Map(prev.identity.toolIdentities.map(t => [t.name, t.sha256]))
    for (const ti of rec.identity?.toolIdentities || []) {
      const prevSha = prevShaMap.get(ti.name)
      if (prevSha && prevSha !== ti.sha256) {
        score -= 15
        evidence.push(`-15 ${ti.name} SHA256 changed: ${prevSha.substring(0, 12)} → ${ti.sha256.substring(0, 12)}`)
      }
    }
  }

  return { name: 'toolchain_identity', score: clamp(score), weight: 0.18, evidence, maxScore: 100 }
}

function computeInputIdentityTrust(rec: BuildRecord, prev?: BuildRecord): TrustDimension {
  const evidence: string[] = []
  let score = 100

  if (rec.inputIdentity) {
    evidence.push(`+15 inputs: ${rec.inputIdentity.totalInputs} build inputs identified`)
    evidence.push(`+5 fingerprint: ${rec.inputIdentity.inputFingerprint.substring(0, 16)}...`)

    if (rec.inputIdentity.changedInputs.length > 0) {
      const modCount = rec.inputIdentity.changedInputs.filter(c => c.changeType === 'modified').length
      const newCount = rec.inputIdentity.changedInputs.filter(c => c.changeType === 'new').length
      const remCount = rec.inputIdentity.changedInputs.filter(c => c.changeType === 'removed').length
      score -= Math.min(modCount * 8 + newCount * 5 + remCount * 5, 40)
      evidence.push(`-${Math.min(modCount * 8 + newCount * 5 + remCount * 5, 40)} ${modCount} modified, ${newCount} new, ${remCount} removed`)
    } else if (prev) {
      evidence.push('+10 inputs identical to baseline')
    }
  } else {
    evidence.push('-10 no input identity captured')
  }

  return { name: 'input_identity', score: clamp(score), weight: 0.18, evidence, maxScore: 100 }
}

function computeArtifactIntegrityTrust(rec: BuildRecord, prev?: BuildRecord): TrustDimension {
  const evidence: string[] = []
  let score = 100

  if (rec.artifactHashes.length > 0) {
    evidence.push(`+15 artifacts: ${rec.artifactHashes.length} artifacts hashed`)

    if (prev?.artifactHashes) {
      const prevShaMap = new Map(prev.artifactHashes.map(a => [a.filePath, a.sha256]))
      let changed = 0
      for (const a of rec.artifactHashes) {
        const prevSha = prevShaMap.get(a.filePath)
        if (prevSha && prevSha !== a.sha256) {
          changed++
          if (changed <= 3) {
            evidence.push(`  ${a.filePath.split(/[/\\]/).pop()}: ${prevSha.substring(0, 12)} → ${a.sha256.substring(0, 12)}`)
          }
        }
      }
      if (changed > 0) {
        score -= Math.min(changed * 10, 40)
        evidence.push(`-${Math.min(changed * 10, 40)} ${changed} artifact${changed > 1 ? 's' : ''} changed`)
      } else {
        evidence.push('+10 artifacts unchanged')
      }
    }
  } else {
    evidence.push('-10 no artifacts hashed')
  }

  return { name: 'artifact_integrity', score: clamp(score), weight: 0.15, evidence, maxScore: 100 }
}

function computeBehaviorTrust(rec: BuildRecord, prev?: BuildRecord): TrustDimension {
  const evidence: string[] = []
  let score = 100

  const anomCount = rec.summary.anomalies.length
  if (anomCount > 0) {
    score -= Math.min(anomCount * 15, 45)
    evidence.push(`-${Math.min(anomCount * 15, 45)} ${anomCount} anomali${anomCount > 1 ? 'es' : ''}: ${rec.summary.anomalies.join('; ')}`)
  } else {
    evidence.push('+10 no behavioral anomalies')
  }

  if (rec.summary.filesCreated + rec.summary.filesModified > 100) {
    evidence.push('+5 high file activity (expected for large build)')
  }

  return { name: 'behavior', score: clamp(score), weight: 0.15, evidence, maxScore: 100 }
}

function computeNetworkTrust(rec: BuildRecord, prev?: BuildRecord): TrustDimension {
  const evidence: string[] = []
  let score = 100

  if (rec.summary.networkConnections === 0) {
    evidence.push('+20 no network connections')
  } else {
    score -= Math.min(rec.summary.networkConnections * 5, 25)
    evidence.push(`-${Math.min(rec.summary.networkConnections * 5, 25)} ${rec.summary.networkConnections} network connection${rec.summary.networkConnections > 1 ? 's' : ''}`)

    const suspicious = rec.network.filter(n =>
      n.type === 'dns' && (n.host.match(/\.(ru|cn|tk|ml|ga)$/) && !n.host.endsWith('.com'))
    )
    if (suspicious.length > 0) {
      score -= 25
      evidence.push(`-25 suspicious destinations: ${[...new Set(suspicious.map(n => n.host))].join(', ')}`)
    }
  }

  return { name: 'network', score: clamp(score), weight: 0.12, evidence, maxScore: 100 }
}

function computeGraphTrust(rec: BuildRecord, prev?: BuildRecord): TrustDimension {
  const evidence: string[] = []
  let score = 100

  if (rec.readFiles && rec.readFiles.length > 0) {
    evidence.push(`+15 provenance: ${rec.readFiles.length} file reads tracked`)
  } else {
    evidence.push('-5 no file read tracking')
  }

  const procCount = rec.summary.uniqueProcesses.length
  if (procCount > 0) {
    evidence.push(`+10 processes: ${procCount} unique processes`)

    const unknownCount = rec.summary.uniqueProcesses.filter(n =>
      !n.match(/^(gcc|g\+\+|clang|ld|make|cmake|ninja|python|node|rustc|cargo|go|javac|curl|wget|git|strip|ar|ranlib|nm|objcopy|readelf|configure)$/)
    ).length
    if (unknownCount > 0) {
      score -= Math.min(unknownCount * 5, 20)
      evidence.push(`-${Math.min(unknownCount * 5, 20)} ${unknownCount} unrecognized process${unknownCount > 1 ? 'es' : ''}`)
    }
  }

  return { name: 'graph', score: clamp(score), weight: 0.12, evidence, maxScore: 100 }
}

function computeTrendTrust(rec: BuildRecord, prev?: BuildRecord): TrustDimension {
  const evidence: string[] = []
  let score = 80

  if (rec.summary.totalHashLinks > 0) {
    evidence.push(`+10 chain integrity: ${rec.summary.totalHashLinks} hash links`)
    score += 10
  }

  if (prev) {
    const durationDiff = Math.abs(rec.durationMs - prev.durationMs)
    const durationChange = prev.durationMs > 0 ? (durationDiff / prev.durationMs) * 100 : 0
    if (durationChange < 10) {
      evidence.push('+10 build duration stable')
      score += 10
    } else if (durationChange > 50) {
      evidence.push(`-10 build duration changed ${Math.round(durationChange)}%`)
      score -= 10
    }
  }

  return { name: 'trend', score: clamp(score), weight: 0.10, evidence, maxScore: 100 }
}

function computeInputStabilityMetric(rec: BuildRecord): number {
  if (!rec.inputIdentity || rec.inputIdentity.inputStability === null) return 100
  return rec.inputIdentity.inputStability
}

function computeToolchainPurityMetric(rec: BuildRecord): number {
  const observed = rec.summary.uniqueProcesses
  const expected = rec.summary.buildToolsDetected
  if (expected.length === 0) return 100
  const expectedSet = new Set(expected)
  const expectedOnly = observed.filter(t => expectedSet.has(t)).length
  return Math.round((expectedOnly / Math.max(expected.length, 1)) * 100)
}

function computeBuildDeterminismMetric(rec: BuildRecord, prev?: BuildRecord): boolean {
  if (!prev) return true
  if (!rec.inputIdentity || !prev.inputIdentity) return true

  const sameInputs = rec.inputIdentity.inputFingerprint === prev.inputIdentity.inputFingerprint
  const sameArtifacts = rec.artifactHashes.length === prev.artifactHashes.length &&
    rec.artifactHashes.every((a, i) => prev.artifactHashes[i]?.sha256 === a.sha256)

  if (sameInputs && !sameArtifacts) return false
  return true
}

function clamp(n: number): number {
  return Math.max(0, Math.min(100, n))
}

export function renderTrustResult(result: TrustResult): string[] {
  const lines: string[] = [
    'Trust Assessment',
    '================',
    `Overall Trust: ${result.overallTrust}/100`,
    `Input Stability: ${result.inputStability}%`,
    `Toolchain Purity: ${result.toolchainPurity}%`,
    `Build Determinism: ${result.buildDeterminism ? 'Yes' : 'No — SAME inputs, DIFFERENT artifacts'}`,
    '',
    'Dimension Breakdown:',
  ]

  for (const dim of result.dimensions) {
    const bar = '█'.repeat(Math.round(dim.score / 10)) + '░'.repeat(10 - Math.round(dim.score / 10))
    lines.push(`  ${dim.name.padEnd(20)} ${String(dim.score).padStart(3)}/100 ${bar}`)
    for (const ev of dim.evidence) {
      lines.push(`    ${ev}`)
    }
  }

  return lines
}
