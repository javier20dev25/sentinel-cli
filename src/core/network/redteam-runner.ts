// ── Red Team Campaign Runner ─────────────────────────────────
// Executes attack scenarios, measures detection rates, generates reports
// SENTINEL IS THE PROTAGONIST. Atomic Red Team generates the stimulus.

import { RedTeamAttack, RedTeamCampaign, RedTeamReport, CoverageMatrix, WeakPoint, CampaignStatus } from './redteam-types'
import { ALL_ATTACKS, ATTACK_01_SYSCALL_DIRECT, ATTACK_02_ETW_PATCH, ATTACK_03_FAKE_GCC, ATTACK_04_COMPILER_WRAPPER, ATTACK_05_LD_PRELOAD, ATTACK_06_NAMED_PIPE_EXFIL, ATTACK_07_DNS_EXFIL, ATTACK_08_DLL_INJECTION, ATTACK_09_RESPONSE_FILE, ATTACK_10_LOLBINS, ATTACK_11_TIMING_ATTACK, ATTACK_12_LEARNING_POISON, ATTACK_13_ADVERSARIAL_FEATURES, ATTACK_14_BUILD_FRAGMENTATION, ATTACK_15_SENSOR_CONFUSION, ATTACK_16_NPM_POSTINSTALL, ATTACK_17_GRADLE_INIT_SCRIPT, ATTACK_18_CARGO_BUILD_RS, ATTACK_19_MSBUILD_TASK, ATTACK_20_MAVEN_PLUGIN, ATTACK_21_GIT_HOOKS, ATTACK_22_GIT_CONFIG, ATTACK_23_GIT_SUBMODULE, ATTACK_24_GITHUB_ACTIONS, ATTACK_25_OIDC_FEDERATION, ATTACK_26_COMPOSITE_ACTION } from './redteam-attacks'
import { BuildRecord } from './build-types'

// ── Campaign Definitions (ordered by REAL-WORLD FREQUENCY) ────
// Priority based on how often these attacks occur in real developer workflows
const CAMPAIGNS: RedTeamCampaign[] = [
  // ── PRIORITY 1: Supply Chain (most common in real attacks) ──
  {
    id: 'supply-chain',
    name: 'Supply Chain Attacks',
    description: 'Can malicious package lifecycle scripts execute during build?',
    objective: 'Detect postinstall hooks, init scripts, build.rs, MSBuild Tasks, Maven plugins',
    attacks: [ATTACK_16_NPM_POSTINSTALL, ATTACK_17_GRADLE_INIT_SCRIPT, ATTACK_18_CARGO_BUILD_RS, ATTACK_19_MSBUILD_TASK, ATTACK_20_MAVEN_PLUGIN],
    status: 'pending',
  },
  // ── PRIORITY 2: Identity Evasion (common in supply chain) ──
  {
    id: 'identity-evasion',
    name: 'Identity Evasion',
    description: 'Can it impersonate a legitimate tool?',
    objective: 'Validate that Sentinel identifies tools by hash, not just name',
    attacks: [ATTACK_03_FAKE_GCC, ATTACK_04_COMPILER_WRAPPER],
    status: 'pending',
  },
  // ── PRIORITY 3: Secret Exfiltration (high impact) ──────────
  {
    id: 'secret-exfiltration',
    name: 'Secret Exfiltration',
    description: 'Can it extract secrets without normal sockets?',
    objective: 'Validate that Sentinel detects exfiltration via pipes, DNS, and DoH',
    attacks: [ATTACK_05_LD_PRELOAD, ATTACK_06_NAMED_PIPE_EXFIL, ATTACK_07_DNS_EXFIL],
    status: 'pending',
  },
  // ── PRIORITY 4: Git Attacks (developer workflow) ────────────
  {
    id: 'git-attacks',
    name: 'Git Attacks',
    description: 'Can it detect malicious git hooks and configs?',
    objective: 'Detect pre-commit hooks, config poisoning, submodule attacks',
    attacks: [ATTACK_21_GIT_HOOKS, ATTACK_22_GIT_CONFIG, ATTACK_23_GIT_SUBMODULE],
    status: 'pending',
  },
  // ── PRIORITY 5: CI Attacks (growing threat) ─────────────────
  {
    id: 'ci-attacks',
    name: 'CI/CD Attacks',
    description: 'Can it detect CI/CD pipeline compromise?',
    objective: 'Detect GitHub Actions secret theft, OIDC abuse, composite action poisoning',
    attacks: [ATTACK_24_GITHUB_ACTIONS, ATTACK_25_OIDC_FEDERATION, ATTACK_26_COMPOSITE_ACTION],
    status: 'pending',
  },
  // ── PRIORITY 6: Toolchain Hijack ───────────────────────────
  {
    id: 'toolchain-hijack',
    name: 'Toolchain Hijack',
    description: 'Can it modify the compiler without detection?',
    objective: 'Validate that Sentinel detects DLL injection and response file poisoning',
    attacks: [ATTACK_08_DLL_INJECTION, ATTACK_09_RESPONSE_FILE],
    status: 'pending',
  },
  // ── PRIORITY 7: Graph Poisoning ────────────────────────────
  {
    id: 'graph-poisoning',
    name: 'Graph Poisoning',
    description: 'Can it build a misleading evidence graph?',
    objective: 'Validate that Sentinel handles LOLBins and temp file destruction',
    attacks: [ATTACK_10_LOLBINS, ATTACK_11_TIMING_ATTACK],
    status: 'pending',
  },
  // ── PRIORITY 8: Sensor Evasion (advanced) ──────────────────
  {
    id: 'sensor-evasion',
    name: 'Sensor Evasion',
    description: 'Can a process act without being observed?',
    objective: 'Validate that Sentinel detects processes even when ETW/userland hooks are bypassed',
    attacks: [ATTACK_01_SYSCALL_DIRECT, ATTACK_02_ETW_PATCH],
    status: 'pending',
  },
  // ── PRIORITY 9: Timeline Confusion (advanced) ──────────────
  {
    id: 'timeline-confusion',
    name: 'Timeline Confusion',
    description: 'Can it break temporal correlation?',
    objective: 'Validate that Sentinel correlates events across multiple builds',
    attacks: [ATTACK_14_BUILD_FRAGMENTATION, ATTACK_15_SENSOR_CONFUSION],
    status: 'pending',
  },
  // ── PRIORITY 10: ML Poisoning (future) ─────────────────────
  {
    id: 'ml-poisoning',
    name: 'ML Poisoning',
    description: 'Can it corrupt the learning model?',
    objective: 'Validate that Sentinel resists corpus poisoning and adversarial features',
    attacks: [ATTACK_12_LEARNING_POISON, ATTACK_13_ADVERSARIAL_FEATURES],
    status: 'pending',
  },
]

// ── Detection Rules (what Sentinel should flag) ────────────────
interface DetectionRule {
  id: string
  name: string
  check: (record: BuildRecord, attack: RedTeamAttack) => { detected: boolean; reason: string }
}

const DETECTION_RULES: DetectionRule[] = [
  {
    id: 'DR-001',
    name: 'Unknown tool in PATH',
    check: (record, attack) => {
      const unknownTools = record.summary.buildToolsDetected.filter(
        t => !['npm', 'node', 'tsc', 'esbuild', 'webpack', 'vite', 'rollup', 'gcc', 'g++', 'make', 'cargo', 'rustc', 'go', 'javac', 'mvn', 'gradle'].includes(t.toLowerCase())
      )
      return {
        detected: unknownTools.length > 0,
        reason: unknownTools.length > 0 ? `Unknown tools: ${unknownTools.join(', ')}` : 'All tools known',
      }
    },
  },
  {
    id: 'DR-002',
    name: 'Network without corresponding tool',
    check: (record) => {
      const hasNetwork = record.summary.networkConnections > 0
      const hasKnownNetworkTool = record.summary.buildToolsDetected.some(t =>
        ['npm', 'yarn', 'pnpm', 'curl', 'wget', 'cargo', 'go'].includes(t.toLowerCase())
      )
      return {
        detected: hasNetwork && !hasKnownNetworkTool,
        reason: hasNetwork && !hasKnownNetworkTool ? 'Network activity without known network tool' : 'Network activity consistent with tools',
      }
    },
  },
  {
    id: 'DR-003',
    name: 'Secret access without compiler',
    check: (record) => {
      const hasSecretAccess = (record.secretFlow?.secretAccesses?.length ?? 0) > 0
      const hasCompiler = record.summary.buildToolsDetected.some(t =>
        ['tsc', 'gcc', 'g++', 'javac', 'rustc', 'go', 'cargo'].includes(t.toLowerCase())
      )
      return {
        detected: hasSecretAccess && !hasCompiler,
        reason: hasSecretAccess && !hasCompiler ? 'Secrets accessed without compiler running' : 'Secret access consistent with build',
      }
    },
  },
  {
    id: 'DR-004',
    name: 'Process count anomaly',
    check: (record, attack) => {
      const processCount = record.summary.totalProcesses
      const isAnomalous = processCount > 50 || processCount === 0
      return {
        detected: isAnomalous,
        reason: isAnomalous ? `Process count ${processCount} is outside normal range (1-50)` : 'Process count normal',
      }
    },
  },
  {
    id: 'DR-005',
    name: 'File modification without compiler',
    check: (record) => {
      const filesModified = record.summary.filesModified
      const hasCompiler = record.summary.buildToolsDetected.some(t =>
        ['tsc', 'gcc', 'g++', 'javac', 'rustc', 'go', 'cargo', 'esbuild', 'webpack', 'vite'].includes(t.toLowerCase())
      )
      return {
        detected: filesModified > 0 && !hasCompiler,
        reason: filesModified > 0 && !hasCompiler ? `${filesModified} files modified without compiler` : 'File modifications consistent with build',
      }
    },
  },
  {
    id: 'DR-006',
    name: 'Named pipe anomaly',
    check: (record) => {
      const pipeAnomaly = record.summary.anomalies.find(a => a.includes('named pipe'))
      return {
        detected: !!pipeAnomaly,
        reason: pipeAnomaly || 'No named pipe anomaly',
      }
    },
  },
  {
    id: 'DR-007',
    name: 'Environment change detection',
    check: (record) => {
      const envChanges = record.summary.anomalies.filter(a =>
        a.includes('PATH') || a.includes('LD_PRELOAD') || a.includes('environment')
      )
      return {
        detected: envChanges.length > 0,
        reason: envChanges.length > 0 ? `Environment changes: ${envChanges.join(', ')}` : 'No environment changes',
      }
    },
  },
  {
    id: 'DR-008',
    name: 'Build contract violation',
    check: (record) => {
      const violations = record.buildContractViolations?.length ?? 0
      return {
        detected: violations > 0,
        reason: violations > 0 ? `${violations} contract violation(s)` : 'No violations',
      }
    },
  },
  // ── NEW: Sensor Evasion Detection ──────────────────────────
  {
    id: 'DR-009',
    name: 'ETW provider health monitoring',
    check: (record) => {
      // Detect if ETW providers are being patched or disabled
      const etwAnomalies = record.summary.anomalies.filter(a =>
        a.includes('ETW') || a.includes('EtwEventWrite') || a.includes('provider') || a.includes('VirtualProtect')
      )
      return {
        detected: etwAnomalies.length > 0,
        reason: etwAnomalies.length > 0 ? `ETW anomaly: ${etwAnomalies.join(', ')}` : 'ETW providers healthy',
      }
    },
  },
  {
    id: 'DR-010',
    name: 'Direct syscall detection',
    check: (record) => {
      // Detect processes using ntdll.dll syscalls directly
      const syscallAnomalies = record.summary.anomalies.filter(a =>
        a.includes('syscall') || a.includes('ntdll') || a.includes('NtCreate') || a.includes('NtWrite')
      )
      return {
        detected: syscallAnomalies.length > 0,
        reason: syscallAnomalies.length > 0 ? `Direct syscall: ${syscallAnomalies.join(', ')}` : 'No direct syscalls detected',
      }
    },
  },
  // ── NEW: Identity Validation ───────────────────────────────
  {
    id: 'DR-011',
    name: 'Tool identity validation (hash + path)',
    check: (record) => {
      // Validate tools by hash, not just name
      // Check if any tool has suspicious path priority (e.g., current dir before system)
      const toolAnomalies = record.summary.anomalies.filter(a =>
        a.includes('PATH priority') || a.includes('tool hash') || a.includes('signature') || a.includes('fake')
      )
      return {
        detected: toolAnomalies.length > 0,
        reason: toolAnomalies.length > 0 ? `Tool identity issue: ${toolAnomalies.join(', ')}` : 'Tool identities valid',
      }
    },
  },
  {
    id: 'DR-012',
    name: 'Parent-child chain validation',
    check: (record) => {
      // Validate process parent-child relationships
      // Detect unusual chains (e.g., powershell spawned by compiler)
      const chainAnomalies = record.summary.anomalies.filter(a =>
        a.includes('parent') || a.includes('chain') || a.includes('spawn')
      )
      return {
        detected: chainAnomalies.length > 0,
        reason: chainAnomalies.length > 0 ? `Chain anomaly: ${chainAnomalies.join(', ')}` : 'Parent-child chain valid',
      }
    },
  },
  // ── NEW: Non-Standard Exfiltration ─────────────────────────
  {
    id: 'DR-013',
    name: 'Named pipe exfiltration detection',
    check: (record) => {
      // Detect data exfiltration via named pipes
      const pipeAnomalies = record.summary.anomalies.filter(a =>
        a.includes('named pipe') || a.includes('pipe') || a.includes('IPC')
      )
      // Also check for suspicious pipe names
      const hasPipeActivity = pipeAnomalies.length > 0
      return {
        detected: hasPipeActivity,
        reason: hasPipeActivity ? `Named pipe activity: ${pipeAnomalies.join(', ')}` : 'No named pipe exfiltration',
      }
    },
  },
  {
    id: 'DR-014',
    name: 'DNS exfiltration detection (DoH/DoT)',
    check: (record) => {
      // Detect DNS-based exfiltration
      const dnsAnomalies = record.summary.anomalies.filter(a =>
        a.includes('DoH') || a.includes('DoT') || a.includes('dns-query') || a.includes('base64') || a.includes('TXT query')
      )
      // Check for unusual DNS patterns
      const hasDnsExfil = dnsAnomalies.length > 0 || record.summary.dnsQueries.length > 10
      return {
        detected: hasDnsExfil,
        reason: hasDnsExfil ? `DNS exfil indicator: ${dnsAnomalies.length > 0 ? dnsAnomalies.join(', ') : `${record.summary.dnsQueries.length} DNS queries`}` : 'DNS activity normal',
      }
    },
  },
  {
    id: 'DR-015',
    name: 'Fileless execution detection',
    check: (record) => {
      // Detect fileless execution (memory-only payloads)
      const filelessAnomalies = record.summary.anomalies.filter(a =>
        a.includes('VirtualAlloc') || a.includes('WriteProcessMemory') || a.includes('CreateRemoteThread') || a.includes('fileless') || a.includes('memory')
      )
      return {
        detected: filelessAnomalies.length > 0,
        reason: filelessAnomalies.length > 0 ? `Fileless execution: ${filelessAnomalies.join(', ')}` : 'No fileless execution detected',
      }
    },
  },
]

// ── Runner ────────────────────────────────────────────────────
export function runCampaign(
  campaignId: string,
  records: BuildRecord[]
): RedTeamCampaign {
  const campaign = CAMPAIGNS.find(c => c.id === campaignId)
  if (!campaign) throw new Error(`Campaign ${campaignId} not found`)

  const startTime = Date.now()
  campaign.status = 'running'
  campaign.startedAt = startTime

  // Evaluate each attack against detection rules
  for (const attack of campaign.attacks) {
    const relevantRecords = findRelevantRecords(attack, records)
    const detectionResults = runDetectionRules(relevantRecords, attack)

    attack.detectedIndicators = detectionResults.filter(r => r.detected).map(r => r.ruleName)
    attack.missedIndicators = detectionResults.filter(r => !r.detected).map(r => `${r.ruleName}: ${r.reason}`)

    // Determine outcome
    const detectionRate = detectionResults.filter(r => r.detected).length / detectionResults.length
    if (detectionRate >= 0.8) {
      attack.actualOutcome = 'detected'
    } else if (detectionRate >= 0.3) {
      attack.actualOutcome = 'partial'
    } else {
      attack.actualOutcome = 'missed'
    }
  }

  campaign.status = 'completed'
  campaign.completedAt = Date.now()

  // Calculate campaign metrics
  const detected = campaign.attacks.filter(a => a.actualOutcome === 'detected').length
  campaign.detectionRate = detected / campaign.attacks.length
  campaign.falseNegativeRate = 1 - campaign.detectionRate

  return campaign
}

export function runAllCampaigns(records: BuildRecord[]): RedTeamReport {
  const campaigns: RedTeamCampaign[] = []
  const startTime = Date.now()

  for (const campaignDef of CAMPAIGNS) {
    campaigns.push(runCampaign(campaignDef.id, records))
  }

  // Aggregate results
  const allAttacks = campaigns.flatMap(c => c.attacks)
  const detected = allAttacks.filter(a => a.actualOutcome === 'detected').length
  const missed = allAttacks.filter(a => a.actualOutcome === 'missed').length
  const partial = allAttacks.filter(a => a.actualOutcome === 'partial').length
  const notApplicable = allAttacks.filter(a => a.actualOutcome === 'not_applicable').length

  // Find weak points
  const weakPoints: WeakPoint[] = allAttacks
    .filter(a => a.actualOutcome === 'missed' || a.actualOutcome === 'partial')
    .map(a => ({
      attackId: a.id,
      attackName: a.name,
      campaign: a.campaign,
      severity: a.severity,
      reason: a.missedIndicators?.join('; ') || 'Unknown',
      recommendation: getRecommendation(a),
    }))

  // Generate recommendations
  const recommendations = generateRecommendations(weakPoints)

  return {
    timestamp: new Date().toISOString(),
    totalAttacks: allAttacks.length,
    detected,
    missed,
    partial,
    notApplicable,
    detectionRate: detected / allAttacks.length,
    campaigns,
    weakPoints,
    recommendations,
  }
}

// ── Coverage Matrix ───────────────────────────────────────────
export function computeCoverageMatrix(records: BuildRecord[]): CoverageMatrix {
  const campaigns = CAMPAIGNS.map(c => runCampaign(c.id, records))
  const allAttacks = campaigns.flatMap(c => c.attacks)

  const byCampaign: Record<string, { total: number; covered: number; rate: number }> = {}
  for (const campaign of campaigns) {
    const covered = campaign.attacks.filter(a => a.actualOutcome === 'detected').length
    byCampaign[campaign.id] = {
      total: campaign.attacks.length,
      covered,
      rate: covered / campaign.attacks.length,
    }
  }

  const coveredTechniques = allAttacks.filter(a => a.actualOutcome === 'detected').length
  const gaps = allAttacks
    .filter(a => a.actualOutcome !== 'detected')
    .map(a => ({
      technique: a.name,
      campaign: a.campaign,
      impact: a.severity,
      recommendation: getRecommendation(a),
    }))

  return {
    totalTechniques: allAttacks.length,
    coveredTechniques,
    coverageRate: coveredTechniques / allAttacks.length,
    byCampaign,
    gaps,
  }
}

// ── Helpers ───────────────────────────────────────────────────
function findRelevantRecords(attack: RedTeamAttack, records: BuildRecord[]): BuildRecord[] {
  // Filter records that might be relevant to this attack
  // In a real scenario, this would match by attack signature
  return records.slice(-10) // Use last 10 records for now
}

function runDetectionRules(records: BuildRecord[], attack: RedTeamAttack): Array<{ ruleId: string; ruleName: string; detected: boolean; reason: string }> {
  if (records.length === 0) {
    // No records to test against — attack can't be detected
    return DETECTION_RULES.map(rule => ({
      ruleId: rule.id,
      ruleName: rule.name,
      detected: false,
      reason: 'No build records available for detection',
    }))
  }

  return DETECTION_RULES.map(rule => {
    // Check if any record triggers this rule
    const triggered = records.some(record => {
      const result = rule.check(record, attack)
      return result.detected
    })

    const reasons = records
      .map(record => rule.check(record, attack))
      .filter(r => r.detected)
      .map(r => r.reason)

    return {
      ruleId: rule.id,
      ruleName: rule.name,
      detected: triggered,
      reason: triggered ? reasons[0] : 'Not triggered',
    }
  })
}

function getRecommendation(attack: RedTeamAttack): string {
  const recommendations: Record<string, string> = {
    'ATK-001': 'Implement direct syscall detection via ETW kernel provider or syscall tracing',
    'ATK-002': 'Add ETW provider health monitoring; detect VirtualProtect on EtwEventWrite',
    'ATK-003': 'Validate tools by hash + signature, not just PATH name; monitor PATH priority changes',
    'ATK-004': 'Track compiler invocation chain; detect post-compile file modifications',
    'ATK-005': 'Monitor LD_PRELOAD environment variable; detect shared library injection',
    'ATK-006': 'Track named pipe creation and connections; detect IPC-based exfiltration',
    'ATK-007': 'Monitor DoH/DoT endpoints; detect base64-encoded subdomains in DNS queries',
    'ATK-008': 'Detect CreateRemoteThread + LoadLibrary patterns; monitor DLL loads in build tools',
    'ATK-009': 'Monitor response file integrity; detect modifications between creation and consumption',
    'ATK-010': 'Build behavioral profiles for LOLBins; detect unusual argument patterns',
    'ATK-011': 'Implement file integrity monitoring; detect rapid create-delete patterns',
    'ATK-012': 'Implement anomaly detection on corpus distribution; flag unusual upload patterns',
    'ATK-013': 'Add adversarial robustness testing; implement feature-space anomaly detection',
    'ATK-014': 'Implement cross-build correlation; detect secret flow across multiple builds',
    'ATK-015': 'Implement sensor consistency checks; detect conflicting PID/name reports',
  }
  return recommendations[attack.id] || 'Review attack vector and add detection rule'
}

function generateRecommendations(weakPoints: WeakPoint[]): string[] {
  const recs: string[] = []

  if (weakPoints.some(wp => wp.attackId === 'ATK-001' || wp.attackId === 'ATK-002')) {
    recs.push('CRITICAL: Implement kernel-level syscall tracing to detect ETW bypass attempts')
  }
  if (weakPoints.some(wp => wp.attackId === 'ATK-003' || wp.attackId === 'ATK-004')) {
    recs.push('HIGH: Add tool validation by hash + digital signature, not just executable name')
  }
  if (weakPoints.some(wp => wp.attackId === 'ATK-005' || wp.attackId === 'ATK-006' || wp.attackId === 'ATK-007')) {
    recs.push('HIGH: Expand exfiltration detection beyond TCP sockets to include pipes, DNS, DoH')
  }
  if (weakPoints.some(wp => wp.attackId === 'ATK-008' || wp.attackId === 'ATK-009')) {
    recs.push('HIGH: Implement DLL injection detection and response file integrity monitoring')
  }
  if (weakPoints.some(wp => wp.attackId === 'ATK-010')) {
    recs.push('MEDIUM: Build behavioral profiles for common LOLBins to detect anomalous usage')
  }
  if (weakPoints.some(wp => wp.attackId === 'ATK-011')) {
    recs.push('MEDIUM: Implement file integrity monitoring with rapid create-delete detection')
  }
  if (weakPoints.some(wp => wp.attackId === 'ATK-012' || wp.attackId === 'ATK-013')) {
    recs.push('HIGH: Add corpus anomaly detection and adversarial robustness testing')
  }
  if (weakPoints.some(wp => wp.attackId === 'ATK-014')) {
    recs.push('HIGH: Implement cross-build correlation for multi-stage attacks')
  }
  if (weakPoints.some(wp => wp.attackId === 'ATK-015')) {
    recs.push('CRITICAL: Add sensor consistency validation to detect conflicting reports')
  }

  if (recs.length === 0) {
    recs.push('All attack scenarios detected. Continue monitoring and expand test coverage.')
  }

  return recs
}

// ── Renders ───────────────────────────────────────────────────
export function renderRedTeamReport(report: RedTeamReport): string {
  const lines: string[] = []
  const pc = require('picocolors')

  lines.push('')
  lines.push(pc.cyan(pc.bold('  ═══════════════════════════════════════════════')))
  lines.push(pc.cyan(pc.bold('   RED TEAM REPORT')))
  lines.push(pc.cyan(pc.bold('  ═══════════════════════════════════════════════')))
  lines.push('')
  lines.push(`  ${pc.dim('Timestamp:')} ${report.timestamp}`)
  lines.push('')

  // Summary
  const rateColor = report.detectionRate >= 0.8 ? pc.green : report.detectionRate >= 0.5 ? pc.yellow : pc.red
  lines.push(pc.bold('  Summary'))
  lines.push(pc.dim('  ──────────────'))
  lines.push(`  ${pc.dim('Total attacks:')}    ${report.totalAttacks}`)
  lines.push(`  ${pc.dim('Detected:')}         ${pc.green(String(report.detected))}`)
  lines.push(`  ${pc.dim('Partial:')}          ${pc.yellow(String(report.partial))}`)
  lines.push(`  ${pc.dim('Missed:')}           ${pc.red(String(report.missed))}`)
  lines.push(`  ${pc.dim('Detection rate:')}   ${rateColor(pc.bold((report.detectionRate * 100).toFixed(1) + '%'))}`)
  lines.push('')

  // By campaign
  lines.push(pc.bold('  Campaigns'))
  lines.push(pc.dim('  ──────────────'))
  for (const campaign of report.campaigns) {
    const campaignColor = campaign.detectionRate! >= 0.8 ? pc.green : campaign.detectionRate! >= 0.5 ? pc.yellow : pc.red
    const bar = '█'.repeat(Math.round(campaign.detectionRate! * 20)) + '░'.repeat(20 - Math.round(campaign.detectionRate! * 20))
    lines.push(`  ${campaignColor(bar)} ${(campaign.detectionRate! * 100).toFixed(0)}%  ${campaign.name}`)
    for (const attack of campaign.attacks) {
      const icon = attack.actualOutcome === 'detected' ? pc.green('✓') : attack.actualOutcome === 'partial' ? pc.yellow('⚠') : pc.red('✗')
      lines.push(`    ${icon} ${attack.name}`)
    }
  }
  lines.push('')

  // Weak points
  if (report.weakPoints.length > 0) {
    lines.push(pc.bold(pc.red('  Weak Points')))
    lines.push(pc.dim('  ──────────────'))
    for (const wp of report.weakPoints) {
      const sevColor = wp.severity === 'critical' ? pc.red : wp.severity === 'high' ? pc.yellow : pc.dim
      lines.push(`  ${sevColor(wp.severity.toUpperCase())} ${wp.attackName}`)
      lines.push(`    ${pc.dim(wp.reason)}`)
      lines.push(`    ${pc.cyan(wp.recommendation)}`)
      lines.push('')
    }
  }

  // Recommendations
  lines.push(pc.bold('  Recommendations'))
  lines.push(pc.dim('  ──────────────'))
  for (const rec of report.recommendations) {
    lines.push(`  ${pc.dim('→')} ${rec}`)
  }
  lines.push('')

  return lines.join('\n')
}

export function renderCoverageMatrix(matrix: CoverageMatrix): string {
  const lines: string[] = []
  const pc = require('picocolors')

  lines.push('')
  lines.push(pc.cyan(pc.bold('  ═══════════════════════════════════════════════')))
  lines.push(pc.cyan(pc.bold('   COVERAGE MATRIX')))
  lines.push(pc.cyan(pc.bold('  ═══════════════════════════════════════════════')))
  lines.push('')

  const rateColor = matrix.coverageRate >= 0.8 ? pc.green : matrix.coverageRate >= 0.5 ? pc.yellow : pc.red
  lines.push(`  ${pc.dim('Overall coverage:')} ${rateColor(pc.bold((matrix.coverageRate * 100).toFixed(1) + '%'))} (${matrix.coveredTechniques}/${matrix.totalTechniques})`)
  lines.push('')

  lines.push(pc.bold('  By Campaign'))
  lines.push(pc.dim('  ──────────────'))
  for (const [campaignId, data] of Object.entries(matrix.byCampaign)) {
    const bar = '█'.repeat(Math.round(data.rate * 20)) + '░'.repeat(20 - Math.round(data.rate * 20))
    const color = data.rate >= 0.8 ? pc.green : data.rate >= 0.5 ? pc.yellow : pc.red
    lines.push(`  ${color(bar)} ${(data.rate * 100).toFixed(0)}%  ${campaignId}`)
  }
  lines.push('')

  if (matrix.gaps.length > 0) {
    lines.push(pc.bold(pc.red('  Coverage Gaps')))
    lines.push(pc.dim('  ──────────────'))
    for (const gap of matrix.gaps) {
      const sevColor = gap.impact === 'critical' ? pc.red : gap.impact === 'high' ? pc.yellow : pc.dim
      lines.push(`  ${sevColor(gap.impact.toUpperCase())} ${gap.technique}`)
      lines.push(`    ${pc.cyan(gap.recommendation)}`)
    }
    lines.push('')
  }

  return lines.join('\n')
}
