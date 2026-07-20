import * as pc from 'picocolors'
import { BuildRecord, BUILD_TOOLS, DANGEROUS_BUILD_TOOLS } from '../../core/network/build-types'

function dim(s: string): string { return pc.dim(s) }
function green(s: string): string { return pc.green(s) }
function yellow(s: string): string { return pc.yellow(s) }
function red(s: string): string { return pc.red(s) }
function white(s: string): string { return pc.white(s) }
function cyan(s: string): string { return pc.cyan(s) }
function bold(s: string): string { return pc.bold(s) }

export function renderBuildSummary(record: BuildRecord): string {
  const lines: string[] = []
  const s = record.summary
  const exitOk = record.exitCode === 0
  const duration = record.durationMs < 1000
    ? `${record.durationMs}ms`
    : `${(record.durationMs / 1000).toFixed(1)}s`

  lines.push('')
  lines.push(cyan(bold('  Build Flight Recorder')))
  lines.push(dim('  ─────────────────────'))
  lines.push(`  ${dim('Command:')}  ${white(record.command)} ${record.args.join(' ')}`)
  lines.push(`  ${dim('Duration:')} ${exitOk ? green(duration) : red(duration)}`)
  lines.push(`  ${dim('Exit:')}     ${exitOk ? green(String(record.exitCode)) : red(String(record.exitCode))}`)
  lines.push(`  ${dim('CWD:')}     ${dim(record.cwd)}`)
  lines.push(`  ${dim('Platform:')} ${record.platform} ${record.nodeVersion}`)
  lines.push('')

  lines.push(cyan(bold('  Processes')))
  lines.push(dim(`  ${s.totalProcesses} total, ${s.uniqueProcesses.length} unique`))

  if (s.buildToolsDetected.length > 0) {
    lines.push(`  ${dim('Build tools:')} ${green(s.buildToolsDetected.join(', '))}`)
  }

  if (s.anomalies.length > 0) {
    lines.push('')
    lines.push(yellow(bold('  ⚠ Anomalies')))
    for (const a of s.anomalies) {
      lines.push(`  ${yellow('•')} ${a}`)
    }
  }

  lines.push('')
  lines.push(cyan(bold('  Artifacts & Network')))
  lines.push(`  ${dim('Files created:')}  ${white(String(s.filesCreated))}`)
  lines.push(`  ${dim('Files modified:')} ${white(String(s.filesModified))}`)
  lines.push(`  ${dim('Network conns:')}  ${s.networkConnections > 0 ? yellow(String(s.networkConnections)) : dim('0')}`)
  if (s.dnsQueries.length > 0) {
    lines.push(`  ${dim('DNS queries:')}   ${s.dnsQueries.join(', ')}`)
  }

  lines.push('')
  lines.push(cyan(bold('  Integrity Chain')))
  lines.push(`  ${dim('Hash links:')} ${white(String(s.totalHashLinks))}`)
  const last = record.hashChain[record.hashChain.length - 1]
  if (last) {
    lines.push(`  ${dim('Last hash:')}  ${dim(last.linkHash.substring(0, 20))}...`)
  }

  lines.push('')
  if (s.anomalies.length > 0) {
    lines.push(yellow(bold('  Verdict: REVIEW — anomalies detected')))
  } else if (s.buildToolsDetected.length === 0) {
    lines.push(yellow(bold('  Verdict: REVIEW — no build tools detected (maybe not a build?)')))
  } else {
    lines.push(green(bold('  Verdict: CLEAN — no anomalies detected')))
  }
  lines.push('')

  return lines.join('\n')
}
