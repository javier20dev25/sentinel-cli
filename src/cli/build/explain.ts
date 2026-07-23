import * as fs from 'fs'
import * as path from 'path'
import * as os from 'os'
import * as pc from 'picocolors'
import { BuildRecord, ExplainResult } from '../../core/network/build-types'
import { inferBuildGraph } from '../../core/network/build-dna'
import { buildExplainExplanation, toExplainResult } from '../../core/network/build-explain'
import { renderCausalDag } from '../../core/network/build-causal-dag'
import { getCurrentRelease, loadBuildById } from './release'
import { computeTrustScore, computeHighlights, computeRecommendations } from './build-summary'

const BUILDS_DIR = path.join(os.homedir(), '.sentinel', 'builds')

function getLatestBuildId(): string | null {
  if (!fs.existsSync(BUILDS_DIR)) return null
  const files = fs.readdirSync(BUILDS_DIR)
    .filter(f => f.endsWith('.json') && f !== 'releases.json')
    .sort()
    .reverse()
  if (files.length === 0) return null
  return path.basename(files[0], '.json')
}

export function loadLatestBuild(): BuildRecord | null {
  const id = getLatestBuildId()
  if (!id) return null
  return loadBuildById(id)
}

function getBuildKey(buildId: string): string {
  if (!fs.existsSync(BUILDS_DIR)) return buildId
  const files = fs.readdirSync(BUILDS_DIR).filter(f => f.endsWith('.json') && f !== 'releases.json')
  for (const f of files) {
    if (f.includes(buildId) || f.startsWith(buildId)) return path.basename(f, '.json')
  }
  return buildId
}

function getPrevBuildRecord(record: BuildRecord): BuildRecord | null {
  if (!fs.existsSync(BUILDS_DIR)) return null
  const cmdKey = record.command.replace(/[^a-z0-9]/gi, '_') + '_' + record.cwd.replace(/[^a-z0-9]/gi, '_')
  const files = fs.readdirSync(BUILDS_DIR)
    .filter(f => f.endsWith('.json') && f !== 'releases.json' && !f.startsWith(cmdKey))
    .sort()
    .reverse()

  for (const f of files) {
    try {
      const r = JSON.parse(fs.readFileSync(path.join(BUILDS_DIR, f), 'utf8'))
      if (r.command === record.command) return r
    } catch {}
  }
  return null
}

export async function explainBuild(
  buildId?: string,
  vsRelease: boolean = false,
  format: 'human' | 'json' = 'human',
): Promise<{ result: ExplainResult | null; error?: string; output: string }> {
  let record: BuildRecord | null = null
  let compareName = 'rolling baseline (last builds)'

  if (buildId) {
    record = loadBuildById(buildId)
    if (!record) return { result: null, error: `Build ${buildId} not found.`, output: '' }
  } else {
    record = loadLatestBuild()
    if (!record) return { result: null, error: 'No builds available. Run `sentinel build` first.', output: '' }
  }

  let prevRecord: BuildRecord | null = null
  let releaseRecord: BuildRecord | null = null

  if (vsRelease) {
    const rel = getCurrentRelease()
    if (!rel.build || !rel.entry) {
      if (!buildId) record = null
      return { result: null, error: 'No release baseline set. Use `sentinel build mark-release <build-id>` first.', output: '' }
    }
    releaseRecord = rel.build
    compareName = `release: ${rel.entry.tag} (${rel.entry.buildId})`
  } else {
    prevRecord = getPrevBuildRecord(record)
  }

  const graph = inferBuildGraph(record)
  const explanation = buildExplainExplanation(record, graph, prevRecord || undefined, releaseRecord || undefined)

  const buildIdStr = record.startTime || path.basename(getLatestBuildId() || 'unknown')
  const result = toExplainResult(buildIdStr, explanation, compareName)

  if (format === 'json') {
    return { result, output: JSON.stringify(result, null, 2) }
  }

  const bd = explanation.confidenceBreakdown
  const dagLines = renderCausalDag(explanation.causalDag)
  const trust = computeTrustScore(record)
  const highlights = computeHighlights(record, trust)
  const recs = computeRecommendations(record, trust)
  const scoreColor = trust.score >= 80 ? pc.green : trust.score >= 50 ? pc.yellow : pc.red
  const verdictBg = trust.verdict === 'CLEAN' ? pc.bgGreen : trust.verdict === 'REVIEW' ? pc.bgYellow : pc.bgRed

  const lines: string[] = [
    '',
    pc.cyan(pc.bold('  ═══════════════════════════════════════════════')),
    pc.cyan(pc.bold('   WHY THIS SCORE?')),
    pc.cyan(pc.bold('  ═══════════════════════════════════════════════')),
    '',
    `  ${pc.bold('Build:')} ${buildIdStr}`,
    `  ${pc.bold('Compared against:')} ${compareName}`,
    '',
    pc.bold('  Verdict'),
    pc.dim('  ──────────────'),
    `  ${verdictBg(pc.white(` ${trust.verdict} `))}`,
    '',
    pc.bold('  Trust Score'),
    pc.dim('  ──────────────'),
    `  ${scoreColor(pc.bold(String(trust.score)))} / 100`,
    '',
  ]

  // Score breakdown
  if (trust.additions.length > 0 || trust.deductions.length > 0) {
    lines.push(pc.bold('  Score Breakdown'))
    lines.push(pc.dim('  ──────────────'))
    for (const a of trust.additions) {
      lines.push(`    ${pc.green('+' + String(a.points).padStart(2))}  ${a.reason}`)
    }
    for (const d of trust.deductions) {
      lines.push(`    ${pc.red('-' + String(d.points).padStart(2))}  ${d.reason}`)
    }
    lines.push('')
  }

  // Highlights
  lines.push(pc.bold('  Highlights'))
  lines.push(pc.dim('  ──────────────'))
  for (const h of highlights) {
    const iconColor = h.severity === 'good' ? pc.green : h.severity === 'warning' ? pc.yellow : pc.red
    lines.push(`  ${iconColor(h.icon)} ${h.text}`)
  }
  lines.push('')

  // Root cause
  lines.push(pc.bold('  Most Probable Root Cause'))
  lines.push(pc.dim('  ──────────────'))
  lines.push(`  ${explanation.rootCause}`)
  lines.push('')

  // Confidence
  lines.push(pc.bold('  Confidence'))
  lines.push(pc.dim('  ──────────────'))
  lines.push(`  ${explanation.confidenceLabel} (${Math.round(explanation.confidence * 100)}%)`)
  lines.push('')

  // Confidence breakdown
  lines.push(pc.bold('  Confidence Breakdown'))
  lines.push(pc.dim('  ──────────────'))
  lines.push(`  ${pc.dim('Toolchain:')}   ${Math.round(bd.toolchain * 100)}%`)
  lines.push(`  ${pc.dim('Environment:')} ${Math.round(bd.environment * 100)}%`)
  lines.push(`  ${pc.dim('Artifact:')}    ${Math.round(bd.artifact * 100)}%`)
  lines.push(`  ${pc.dim('Network:')}     ${Math.round(bd.network * 100)}%`)
  lines.push(`  ${pc.dim('Graph:')}       ${Math.round(bd.graph * 100)}%`)
  lines.push(`  ${pc.dim('Behavior:')}    ${Math.round(bd.behavior * 100)}%`)
  lines.push(`  ${pc.dim('Signals:')}     ${bd.nSignals} | Diversity: ${bd.diversity} | Severity: +${Math.round(bd.severityBonus * 100)}%`)
  lines.push('')

  // Reasons
  if (explanation.reasons.length > 0) {
    lines.push(pc.bold('  Reasons'))
    lines.push(pc.dim('  ──────────────'))
    for (const r of explanation.reasons) lines.push(`  ${pc.dim('•')} ${r}`)
    lines.push('')
  }

  // Changes
  if (explanation.changes.length > 0) {
    lines.push(pc.bold('  Changes vs Previous'))
    lines.push(pc.dim('  ──────────────'))
    for (const c of explanation.changes) lines.push(`  ${pc.dim('•')} ${c}`)
    lines.push('')
  }

  // Causal DAG
  if (dagLines.length > 0) {
    lines.push(pc.bold('  Causal DAG'))
    lines.push(pc.dim('  ──────────────'))
    lines.push(...dagLines.map(l => `  ${l}`))
    lines.push('')
  }

  // Recommendations
  if (recs.length > 0) {
    lines.push(pc.bold('  Recommendations'))
    lines.push(pc.dim('  ──────────────'))
    for (const r of recs) lines.push(`  ${pc.dim('→')} ${r}`)
    lines.push('')
  }

  return { result, output: lines.join('\n') }
}
