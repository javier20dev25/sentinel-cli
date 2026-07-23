import * as path from 'path'
import * as fs from 'fs'
import * as os from 'os'
import {
  BuildRecord,
  BuildContractEntry,
  BuildContractViolation,
  ProcessIntent,
} from './build-types'
import { classifyIntent } from './build-intent'

const CONTRACT_DIR = path.join(os.homedir(), '.sentinel', 'builds', 'contracts')

function contractPath(command: string, cwd: string): string {
  const safe = `${command}_${cwd.replace(/[^a-zA-Z0-9]/g, '_')}`
  return path.join(CONTRACT_DIR, `${safe}.json`)
}

export function loadContract(command: string, cwd: string): BuildContractEntry[] {
  try {
    const cp = contractPath(command, cwd)
    if (!fs.existsSync(cp)) return []
    return JSON.parse(fs.readFileSync(cp, 'utf-8'))
  } catch { return [] }
}

export function saveContract(command: string, cwd: string, entries: BuildContractEntry[]): void {
  try {
    fs.mkdirSync(CONTRACT_DIR, { recursive: true })
    fs.writeFileSync(contractPath(command, cwd), JSON.stringify(entries, null, 2), 'utf-8')
  } catch {}
}

export function updateContract(
  record: BuildRecord,
  existingContract: BuildContractEntry[],
  threshold = 5,
): { contract: BuildContractEntry[]; violations: BuildContractViolation[] } {
  const contract = [...existingContract]
  const violations: BuildContractViolation[] = []
  const now = Date.now()
  const contractTools = new Set(contract.map(e => e.tool))

  const seen = new Map<string, number>()

  for (const p of record.processes) {
    const tool = p.name
    const count = (seen.get(tool) || 0) + 1
    seen.set(tool, count)

    const existing = contract.find(e => e.tool === tool)
    if (existing) {
      existing.lastSeen = now
      existing.count += count
    } else {
      contract.push({
        tool,
        firstSeen: now,
        lastSeen: now,
        count,
        intent: classifyIntent(tool, p.cmdline),
      })
    }

    if (!contractTools.has(tool) && contract.length > threshold) {
      violations.push({
        tool,
        intent: classifyIntent(tool, p.cmdline),
        reason: `Tool "${tool}" was never seen in the first ${threshold} builds for this project`,
        severity: 'warning',
      })
    }
  }

  for (const entry of contract) {
    const inThisBuild = seen.has(entry.tool)
    if (entry.count >= threshold && !inThisBuild) {
      violations.push({
        tool: entry.tool,
        intent: entry.intent,
        reason: `Tool "${entry.tool}" (seen ${entry.count} times historically) is missing from this build`,
        severity: 'info',
      })
    }
  }

  const downloaders = ['curl', 'wget', 'fetch']
  for (const tool of downloaders) {
    if (seen.has(tool)) {
      const existing = contract.find(e => e.tool === tool)
      if (existing && existing.count < threshold) {
        violations.push({
          tool,
          intent: 'download',
          reason: `Network download tool "${tool}" detected early in project history (seen ${existing.count}x before threshold ${threshold})`,
          severity: 'critical',
        })
      }
    }
  }

  contract.sort((a, b) => b.count - a.count)

  return { contract, violations }
}

export function renderContractViolations(violations: BuildContractViolation[]): string[] {
  if (violations.length === 0) return ['No contract violations']

  const lines: string[] = ['Build Contract Violations', '=======================']
  for (const v of violations) {
    const icon = v.severity === 'critical' ? '!' : v.severity === 'warning' ? '~' : '·'
    lines.push(`  ${icon} [${v.severity.toUpperCase()}] ${v.reason}`)
  }
  return lines
}
