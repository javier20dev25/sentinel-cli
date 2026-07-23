// ── Atomic Red Team Runner for Sentinel ───────────────────────
// Executes Atomic RT tests and feeds results to Sentinel's Red Team framework

import { AtomicTest, ALL_ATOMIC_TESTS, EXECUTION_ORDER } from './atomic-redteam-map'
import { BuildRecord } from './build-types'
import { runAllCampaigns, renderRedTeamReport, computeCoverageMatrix, renderCoverageMatrix } from './redteam-runner'
import { RedTeamReport, CoverageMatrix } from './redteam-types'
import { execSync } from 'child_process'

export interface AtomicRunResult {
  test: AtomicTest
  executed: boolean
  success: boolean
  output: string
  error?: string
  detectionResult?: {
    detected: boolean
    indicators: string[]
  }
}

export interface AtomicCampaignResult {
  timestamp: string
  totalTests: number
  executed: number
  detected: number
  missed: number
  detectionRate: number
  results: AtomicRunResult[]
  sentinelReport: RedTeamReport
  coverage: CoverageMatrix
}

// ── Execute a single Atomic test ──────────────────────────────
export function executeAtomicTest(
  test: AtomicTest,
  options: {
    dryRun?: boolean
    timeout?: number
  } = {}
): AtomicRunResult {
  const result: AtomicRunResult = {
    test,
    executed: false,
    success: false,
    output: '',
  }

  if (options.dryRun) {
    result.output = `[DRY RUN] Would execute: ${test.command}`
    result.executed = true
    result.success = true
    return result
  }

  try {
    // Execute the Atomic test
    const timeout = options.timeout || 30000
    const output = execSync(test.command, {
      encoding: 'utf8',
      timeout,
      windowsHide: true,
      stdio: ['pipe', 'pipe', 'pipe'],
    })

    result.executed = true
    result.success = true
    result.output = output.trim()
  } catch (err: any) {
    result.executed = true
    result.success = false
    result.error = err.message || 'Unknown error'
    result.output = err.stdout?.toString() || ''
  }

  return result
}

// ── Execute all tests for a campaign ──────────────────────────
export function executeAtomicCampaign(
  campaignAttacks: string[],
  options: {
    dryRun?: boolean
    timeout?: number
  } = {}
): AtomicRunResult[] {
  const tests = ALL_ATOMIC_TESTS.filter(t => campaignAttacks.includes(t.sentinelAttackId))
  return tests.map(test => executeAtomicTest(test, options))
}

// ── Execute all campaigns in priority order ────────────────────
export function executeAllAtomicTests(
  options: {
    dryRun?: boolean
    timeout?: number
    maxPriority?: number
  } = {}
): AtomicCampaignResult {
  const startTime = Date.now()
  const allResults: AtomicRunResult[] = []

  for (const priorityGroup of EXECUTION_ORDER) {
    if (options.maxPriority && priorityGroup.priority > options.maxPriority) {
      continue
    }

    const results = executeAtomicCampaign(priorityGroup.attacks, options)
    allResults.push(...results)
  }

  // Analyze results
  const executed = allResults.filter(r => r.executed).length
  const detected = allResults.filter(r => r.detectionResult?.detected).length
  const missed = allResults.filter(r => !r.detectionResult?.detected).length

  // Feed results to Sentinel's Red Team runner
  // In a real scenario, this would create BuildRecords from the test outputs
  const sentinelReport = runAllCampaigns([])
  const coverage = computeCoverageMatrix([])

  return {
    timestamp: new Date().toISOString(),
    totalTests: allResults.length,
    executed,
    detected,
    missed,
    detectionRate: executed > 0 ? detected / executed : 0,
    results: allResults,
    sentinelReport,
    coverage,
  }
}

// ── Generate integration script ────────────────────────────────
export function generateIntegrationScript(): string {
  const lines: string[] = []

  lines.push('#!/bin/bash')
  lines.push('# Sentinel Red Team Integration Script')
  lines.push('# Run this script in a VM or isolated lab environment')
  lines.push('# DO NOT run on production systems')
  lines.push('')
  lines.push('set -e')
  lines.push('')
  lines.push('# Colors')
  lines.push('RED=\\033[0;31m')
  lines.push('GREEN=\\033[0;32m')
  lines.push('YELLOW=\\033[1;33m')
  lines.push('NC=\\033[0m')
  lines.push('')
  lines.push('echo -e "${RED}════════════════════════════════════════════════${NC}"')
  lines.push('echo -e "${RED}  SENTINEL RED TEAM INTEGRATION${NC}"')
  lines.push('echo -e "${RED}════════════════════════════════════════════════${NC}"')
  lines.push('echo ""')
  lines.push('')
  lines.push('# Prerequisites check')
  lines.push('echo -e "${YELLOW}Checking prerequisites...${NC}"')
  lines.push('command -v sentinel >/dev/null 2>&1 || { echo -e "${RED}sentinel not found. Install first.${NC}"; exit 1; }')
  lines.push('command -v powershell >/dev/null 2>&1 || command -v pwsh >/dev/null 2>&1 || echo -e "${YELLOW}Warning: PowerShell not found. Windows tests will be skipped.${NC}"')
  lines.push('')
  lines.push('# Priority 1: Critical gaps')
  lines.push('echo -e "${YELLOW}═══ Priority 1: Critical Gaps ═══${NC}"')
  lines.push('echo ""')
  lines.push('')
  lines.push('# ATK-001: Direct Syscall')
  lines.push('echo -e "${YELLOW}[ATK-001] Direct Syscall (ETW Bypass)${NC}"')
  lines.push('echo "Expected: Process should be invisible to ETW userland providers"')
  lines.push('echo "Detection: DR-009 (ETW health), DR-010 (syscall detection)"')
  lines.push('echo ""')
  lines.push('')
  lines.push('# ATK-002: ETW Provider Patching')
  lines.push('echo -e "${YELLOW}[ATK-002] ETW Provider Patching${NC}"')
  lines.push('echo "Expected: VirtualProtect on EtwEventWrite should be detected"')
  lines.push('echo "Detection: DR-009 (ETW health monitoring)"')
  lines.push('echo ""')
  lines.push('')
  lines.push('# ATK-005: LD_PRELOAD')
  lines.push('if [[ "$OSTYPE" == "linux-gnu"* ]]; then')
  lines.push('  echo -e "${YELLOW}[ATK-005] LD_PRELOAD Injection${NC}"')
  lines.push('  echo "Expected: LD_PRELOAD environment variable should be detected"')
  lines.push('  echo "Detection: DR-007 (environment change)"')
  lines.push('  echo ""')
  lines.push('fi')
  lines.push('')
  lines.push('# ATK-008: DLL Injection')
  lines.push('if [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "cygwin" ]]; then')
  lines.push('  echo -e "${YELLOW}[ATK-008] DLL Injection${NC}"')
  lines.push('  echo "Expected: CreateRemoteThread + LoadLibrary should be detected"')
  lines.push('  echo "Detection: DR-010 (syscall), DR-011 (tool identity)"')
  lines.push('  echo ""')
  lines.push('fi')
  lines.push('')
  lines.push('# ATK-012: Corpus Poisoning')
  lines.push('echo -e "${YELLOW}[ATK-012] Corpus Poisoning${NC}"')
  lines.push('echo "Submitting 10k builds with subtle network uploads..."')
  lines.push('for i in $(seq 1 10000); do')
  lines.push('  sentinel build observe echo "test_$i" --save 2>/dev/null')
  lines.push('done')
  lines.push('echo ""')
  lines.push('')
  lines.push('# Run Red Team report')
  lines.push('echo -e "${YELLOW}═══ Red Team Report ═══${NC}"')
  lines.push('sentinel redteam')
  lines.push('')
  lines.push('echo -e "${GREEN}════════════════════════════════════════════════${NC}"')
  lines.push('echo -e "${GREEN}  DONE. Review the report above.${NC}"')
  lines.push('echo -e "${GREEN}════════════════════════════════════════════════${NC}"')
  lines.push('')

  return lines.join('\n')
}

// ── Renders ───────────────────────────────────────────────────
export function renderAtomicResult(result: AtomicRunResult): string {
  const pc = require('picocolors')
  const lines: string[] = []

  const icon = result.detectionResult?.detected ? pc.green('✓') : pc.red('✗')
  const status = result.executed ? (result.success ? 'executed' : 'failed') : 'not executed'

  lines.push(`  ${icon} ${result.test.sentinelAttackId}  ${result.test.techniqueName}`)
  lines.push(`    ${pc.dim(result.test.atomicTestName)}`)
  lines.push(`    ${pc.dim('MITRE:')} ${result.test.techniqueId}  ${pc.dim('Platform:')} ${result.test.platform.join(', ')}`)
  lines.push(`    ${pc.dim('Status:')} ${status}`)
  if (result.error) {
    lines.push(`    ${pc.red('Error:')} ${result.error}`)
  }
  if (result.detectionResult) {
    const detIcon = result.detectionResult.detected ? pc.green('DETECTED') : pc.red('MISSED')
    lines.push(`    ${pc.dim('Detection:')} ${detIcon}`)
    if (result.detectionResult.indicators.length > 0) {
      lines.push(`    ${pc.dim('Indicators:')} ${result.detectionResult.indicators.join(', ')}`)
    }
  }
  lines.push('')

  return lines.join('\n')
}

export function renderAtomicCampaignResult(result: AtomicCampaignResult): string {
  const pc = require('picocolors')
  const lines: string[] = []

  lines.push('')
  lines.push(pc.cyan(pc.bold('  ═══════════════════════════════════════════════')))
  lines.push(pc.cyan(pc.bold('   ATOMIC RED TEAM RESULTS')))
  lines.push(pc.cyan(pc.bold('  ═══════════════════════════════════════════════')))
  lines.push('')
  lines.push(`  ${pc.dim('Timestamp:')} ${result.timestamp}`)
  lines.push('')

  const rateColor = result.detectionRate >= 0.8 ? pc.green : result.detectionRate >= 0.5 ? pc.yellow : pc.red
  lines.push(pc.bold('  Summary'))
  lines.push(pc.dim('  ──────────────'))
  lines.push(`  ${pc.dim('Total tests:')}    ${result.totalTests}`)
  lines.push(`  ${pc.dim('Executed:')}       ${result.executed}`)
  lines.push(`  ${pc.dim('Detected:')}       ${pc.green(String(result.detected))}`)
  lines.push(`  ${pc.dim('Missed:')}         ${pc.red(String(result.missed))}`)
  lines.push(`  ${pc.dim('Detection rate:')} ${rateColor(pc.bold((result.detectionRate * 100).toFixed(1) + '%'))}`)
  lines.push('')

  lines.push(pc.bold('  Test Results'))
  lines.push(pc.dim('  ──────────────'))
  for (const r of result.results) {
    lines.push(renderAtomicResult(r))
  }

  // Sentinel report
  lines.push(pc.bold('  Sentinel Red Team Report'))
  lines.push(pc.dim('  ──────────────'))
  lines.push(renderRedTeamReport(result.sentinelReport))

  // Coverage matrix
  lines.push(renderCoverageMatrix(result.coverage))

  return lines.join('\n')
}
