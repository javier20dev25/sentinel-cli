import * as fs from 'fs'
import * as path from 'path'
import { LiteScanner, LiteFinding } from '../core/lite/lite_scanner'
import { calculateAgencyScore, AgencyScoreResult } from '../core/agency_score'
import pc from 'picocolors'

function walkDir(dir: string): string[] {
  const files: string[] = []
  const entries = fs.readdirSync(dir, { withFileTypes: true })
  for (const entry of entries) {
    const fullPath = path.join(dir, entry.name)
    if (entry.isDirectory()) {
      files.push(...walkDir(fullPath))
    } else {
      files.push(fullPath)
    }
  }
  return files
}

function colorForScore(score: number): (s: string) => string {
  if (score >= 70) return pc.red
  if (score >= 30) return pc.yellow
  return pc.green
}

function colorForVerdict(verdict: string): (s: string) => string {
  if (verdict === 'BLOCK') return pc.red
  if (verdict === 'REVIEW') return pc.yellow
  return pc.green
}

function renderScoreBar(score: number): string {
  const filled = Math.round(score / 10)
  const empty = 10 - filled
  const color = colorForScore(score)
  return color('█'.repeat(filled)) + pc.dim('░'.repeat(empty))
}

export function renderExplain(result: AgencyScoreResult, filePaths: string[]): string {
  const lines: string[] = []
  const scoreColor = colorForScore(result.agencyScore)
  const verdictColor = colorForVerdict(result.verdict)

  lines.push('')
  lines.push(pc.white(pc.bold('  ═══════════════════════════════════════════════')))
  lines.push(pc.white(pc.bold('   WHY BLOCK? — SENTINEL EXPLAIN')))
  lines.push(pc.white(pc.bold('  ═══════════════════════════════════════════════')))
  lines.push('')

  lines.push(`  ${pc.bold('Files scanned:')} ${pc.cyan(String(filePaths.length))}`)
  lines.push(`  ${pc.bold('Total findings:')} ${pc.cyan(String(result.totalFindings))}` +
    (result.criticalCount > 0 ? `  ${pc.red(`${result.criticalCount} critical`)}` : '') +
    (result.highCount > 0 ? `  ${pc.yellow(`${result.highCount} high`)}` : ''))
  lines.push('')

  lines.push(`  ${pc.bold('Agency Score')}`)
  lines.push(`    ${pc.bold(scoreColor(String(result.agencyScore)))}/100  ${renderScoreBar(result.agencyScore)}`)
  lines.push(`    ${pc.bold('Blast Radius:')} ${scoreColor(result.blastRadius)}`)
  lines.push(`    ${pc.bold('Verdict:')} ${verdictColor(pc.bold(result.verdict))}  ${result.verdict === 'BLOCK' ? pc.dim('(threshold: 70)') : result.verdict === 'REVIEW' ? pc.dim('(threshold: 30)') : ''}`)
  lines.push('')

  if (result.drivers.length > 0) {
    lines.push(pc.white(pc.bold('  Drivers (ranked by contribution):')))
    lines.push('')
    for (const driver of result.drivers) {
      const contribColor = driver.contribution >= 70 ? pc.red : driver.contribution >= 30 ? pc.yellow : pc.white
      const location = driver.file ? pc.dim(`${driver.file}:${driver.line}`) : ''
      lines.push(`    ${contribColor(String(driver.contribution).padStart(3))}  ${pc.cyan(driver.subcode.padEnd(12))}  ${pc.white(driver.title.padEnd(40))}  ${location}`)
    }
    lines.push('')
  }

  if (result.correlations.length > 0) {
    lines.push(pc.white(pc.bold('  Correlations (cross-pattern signals):')))
    lines.push('')
    for (const corr of result.correlations) {
      lines.push(`    ${pc.magenta(String(corr.bonus).padStart(3))}  ${pc.dim(corr.description)}`)
      if (corr.involved.length > 0) {
        lines.push(`         ${pc.dim('→')} ${pc.dim(corr.involved.join(', '))}`)
      }
    }
    lines.push('')
  }

  if (result.recommendation && result.recommendation !== 'No action required') {
    lines.push(pc.white(pc.bold('  Recommendation:')))
    lines.push('')
    const steps = result.recommendation.split('; ')
    for (const step of steps) {
      lines.push(`    ${pc.cyan('▸')} ${step}`)
    }
    lines.push('')
  }

  return lines.join('\n')
}

export function explainFiles(targetPaths: string[]): { result: AgencyScoreResult; files: string[] } {
  const scanner = new LiteScanner()
  const allFindings: LiteFinding[] = []
  const scannedFiles: string[] = []

  for (const target of targetPaths) {
    const absPath = path.resolve(target)
    if (!fs.existsSync(absPath)) {
      console.error(pc.red(`  Error: path not found: ${target}`))
      continue
    }

    const filesToScan = fs.statSync(absPath).isDirectory() ? walkDir(absPath) : [absPath]

    for (const file of filesToScan) {
      try {
        const content = fs.readFileSync(file, 'utf8')
        const relPath = path.relative(process.cwd(), file)
        const result = scanner.scanFileContent(relPath, content)
        allFindings.push(...result.findings)
        scannedFiles.push(relPath)
      } catch {
        // skip binary files
      }
    }
  }

  const result = calculateAgencyScore(allFindings)
  return { result, files: scannedFiles }
}
