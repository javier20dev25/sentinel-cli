import { BuildRecord, ArtifactHash } from '../../core/network/build-types'

function fmtSize(bytes: number): string {
  if (bytes === 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(1024))
  return `${(bytes / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0)} ${units[i]}`
}

function elapsed(ms: number): string {
  const s = Math.floor(ms / 1000)
  const m = Math.floor(s / 60)
  return m > 0 ? `${m}m ${s % 60}s` : `${s}s`
}

function indent(lines: string[], level = 0): string[] {
  const pad = '  '.repeat(level)
  return lines.map(l => `${pad}${l}`)
}

function artifactDelta(hashes: ArtifactHash[]): string {
  if (hashes.length === 0) return 'none'
  let total = 0
  for (const a of hashes) total += a.size
  return `${hashes.length} artifacts (${fmtSize(total)})`
}

export function renderBuildProvenance(record: BuildRecord, prevRecord?: BuildRecord): string {
  const s = record.summary
  const lines: string[] = []

  lines.push('')
  lines.push('='.repeat(60))
  lines.push('  BUILD PROVENANCE REPORT')
  lines.push('='.repeat(60))
  lines.push('')

  lines.push(`  Build #${record.startTime.replace(/[^0-9]/g, '').substring(0, 14)}`)
  lines.push(`  Command:   ${record.command} ${record.args.join(' ')}`)
  lines.push(`  Started:   ${record.startTime}`)
  lines.push(`  Duration:  ${elapsed(record.durationMs)}`)
  lines.push(`  Exit code: ${record.exitCode}`)
  lines.push(`  Platform:  ${record.platform} ${record.nodeVersion}`)
  lines.push(`  CWD:       ${record.cwd}`)
  lines.push('')

  lines.push('  ── Environment ──')
  const envEntries = Object.entries(record.env)
  if (envEntries.length > 0) {
    for (const [k, v] of envEntries) lines.push(`    ${k}=${v}`)
  } else {
    lines.push('    (none captured)')
  }
  lines.push('')

  lines.push('  ── Toolchain ──')
  if (s.buildToolsDetected.length > 0) {
    for (const t of s.buildToolsDetected) lines.push(`    ${t}`)
  } else {
    lines.push('    (none detected)')
  }
  lines.push('')

  if (s.anomalies.length > 0) {
    lines.push('  ── Anomalies ──')
    for (const a of s.anomalies) lines.push(`    [WARN] ${a}`)
    lines.push('')
  }

  lines.push('  ── Process Tree ──')
  function printTree(pid: number, depth: number, rec: BuildRecord) {
    for (const p of rec.summary.processTree) {
      if (p.pid === pid) {
        lines.push(`    ${'  '.repeat(depth)}${p.name} (pid ${p.pid}) ${p.cmdline ? '— ' + p.cmdline : ''}`)
        for (const c of p.children) printTree(c.pid, depth + 1, rec)
      }
    }
  }
  if (s.processTree.length > 0) {
    printTree(s.processTree[0].pid, 0, record)
  } else {
    lines.push('    (no processes captured)')
  }
  lines.push('')

  lines.push('  ── Artifacts ──')
  if (record.artifactHashes.length > 0) {
    for (const a of record.artifactHashes) {
      const fp = a.filePath.length > 80 ? '...' + a.filePath.substring(a.filePath.length - 80) : a.filePath
      lines.push(`    ${a.sha256.substring(0, 12)}  ${fmtSize(a.size).padStart(8)}  ${fp}`)
    }
    lines.push(`    ${artifactDelta(record.artifactHashes)}`)
  } else {
    lines.push('    (none)')
  }
  lines.push('')

  lines.push('  ── File Changes ──')
  lines.push(`    Created:  ${s.filesCreated}`)
  lines.push(`    Modified: ${s.filesModified}`)
  lines.push(`    Deleted:  ${s.filesDeleted}`)
  if (s.filesCreated + s.filesModified + s.filesDeleted > 0) {
    const created = record.files.filter(f => f.operation === 'created').slice(0, 10)
    for (const f of created) lines.push(`      + ${pathRelative(f.filePath, record.cwd)} (${fmtSize(f.size)})`)
    const modded = record.files.filter(f => f.operation === 'modified').slice(0, 10)
    for (const f of modded) lines.push(`      ~ ${pathRelative(f.filePath, record.cwd)} (${fmtSize(f.size)})`)
    const deleted = record.files.filter(f => f.operation === 'deleted').slice(0, 10)
    for (const f of deleted) lines.push(`      - ${pathRelative(f.filePath, record.cwd)}`)
  }
  lines.push('')

  lines.push('  ── Network ──')
  if (record.network.length > 0) {
    for (const n of record.network) {
      if (n.type === 'dns') lines.push(`    DNS  ${n.host}`)
      else lines.push(`    TCP  ${n.host}:${n.port}`)
    }
  } else {
    lines.push('    (no connections)')
  }
  lines.push('')

  if (prevRecord) {
    lines.push('  ── Diff vs Previous Build ──')
    const ps = prevRecord.summary
    if (s.totalProcesses !== ps.totalProcesses) lines.push(`    Processes: ${ps.totalProcesses} → ${s.totalProcesses}`)
    if (s.filesCreated !== ps.filesCreated) lines.push(`    Files created: ${ps.filesCreated} → ${s.filesCreated}`)
    if (s.filesModified !== ps.filesModified) lines.push(`    Files modified: ${ps.filesModified} → ${s.filesModified}`)
    if (s.artifactsHashed !== ps.artifactsHashed) lines.push(`    Artifacts: ${ps.artifactsHashed} → ${s.artifactsHashed}`)
    if (record.artifactHashes.length > 0 || prevRecord.artifactHashes.length > 0) {
      const prevSet = new Set(prevRecord.artifactHashes.map(a => a.sha256))
      const currSet = new Set(record.artifactHashes.map(a => a.sha256))
      const newHashes = record.artifactHashes.filter(a => !prevSet.has(a.sha256))
      const removedHashes = prevRecord.artifactHashes.filter(a => !currSet.has(a.sha256))
      if (newHashes.length > 0) lines.push(`    New artifacts: ${newHashes.length}`)
      if (removedHashes.length > 0) lines.push(`    Removed artifacts: ${removedHashes.length}`)
      for (const a of newHashes) {
        lines.push(`      + ${a.sha256.substring(0, 12)}  ${pathRelative(a.filePath, record.cwd)}`)
      }
      for (const a of removedHashes) {
        lines.push(`      - ${a.sha256.substring(0, 12)}  ${pathRelative(a.filePath, prevRecord.cwd)}`)
      }
    }
    if (s.anomalies.length > 0 && ps.anomalies.length === 0) lines.push('    New anomalies: yes')
    lines.push('')
  }

  lines.push('  ── Integrity ──')
  lines.push(`    Hash chain links: ${s.totalHashLinks}`)
  const last = record.hashChain[record.hashChain.length - 1]
  if (last) lines.push(`    Terminal hash:     ${last.linkHash}`)

  const verdict = s.anomalies.length > 0 ? 'REVIEW' : 'CLEAN'
  lines.push('')
  lines.push(`  Verdict: ${verdict}`)
  lines.push('='.repeat(60))
  lines.push('')

  return lines.join('\n')
}

function pathRelative(fp: string, cwd: string): string {
  if (fp.startsWith(cwd)) return fp.substring(cwd.length + 1).replace(/\\/g, '/')
  return fp
}
