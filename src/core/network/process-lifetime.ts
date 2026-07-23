import { BuildProcessEvent } from './build-types'

export interface ProcessLifetime {
  pid: number
  name: string
  startTime: number
  exitTime: number | null
  durationMs: number | null
}

export interface EphemeralCluster {
  thresholdMs: number
  label: string
  processes: BuildProcessEvent[]
  count: number
}

export function trackProcessExits(
  currentPids: Set<number>,
  previousPids: Set<number>,
  processes: Map<number, BuildProcessEvent>,
): BuildProcessEvent[] {
  const exited: BuildProcessEvent[] = []
  const now = Date.now()

  for (const pid of previousPids) {
    if (!currentPids.has(pid)) {
      const proc = processes.get(pid)
      if (proc) {
        proc.exitTime = now
        exited.push(proc)
      }
    }
  }

  return exited
}

export function computeProcessLifetimes(
  processes: BuildProcessEvent[],
): ProcessLifetime[] {
  return processes.map(p => ({
    pid: p.pid,
    name: p.name,
    startTime: p.startTime || p.timestamp,
    exitTime: p.exitTime || null,
    durationMs: p.exitTime ? (p.exitTime - (p.startTime || p.timestamp)) : null,
  }))
}

export function findEphemeralProcesses(
  processes: BuildProcessEvent[],
  thresholdMs = 100,
): BuildProcessEvent[] {
  return processes.filter(p => {
    const exitTime = p.exitTime
    if (!exitTime) return false
    const start = p.startTime || p.timestamp
    const duration = exitTime - start
    return duration >= 0 && duration < thresholdMs
  })
}

export function classifyEphemeralProcesses(
  processes: BuildProcessEvent[],
): EphemeralCluster[] {
  const clusters: EphemeralCluster[] = [
    { thresholdMs: 25, label: '<25ms (ptrace/evasion risk)', processes: [], count: 0 },
    { thresholdMs: 50, label: '<50ms (race window)', processes: [], count: 0 },
    { thresholdMs: 100, label: '<100ms (ephemeral)', processes: [], count: 0 },
  ]

  for (const cluster of clusters) {
    cluster.processes = findEphemeralProcesses(processes, cluster.thresholdMs)
    cluster.count = cluster.processes.length
  }

  return clusters
}

export function findSubThresholdProcesses(
  processes: BuildProcessEvent[],
  thresholdsMs: number[] = [25, 50, 100],
): Map<number, BuildProcessEvent[]> {
  const map = new Map<number, BuildProcessEvent[]>()
  for (const t of thresholdsMs) {
    const found = findEphemeralProcesses(processes, t)
    if (found.length > 0) map.set(t, found)
  }
  return map
}

export function renderLifetimeSummary(processes: BuildProcessEvent[]): string[] {
  const lines: string[] = ['Process Lifetime Summary', '=======================']
  const clusters = classifyEphemeralProcesses(processes)
  const ephemeral = findEphemeralProcesses(processes)

  const withDuration = processes
    .filter(p => p.exitTime)
    .map(p => ({
      name: p.name,
      pid: p.pid,
      durationMs: p.exitTime! - (p.startTime || p.timestamp),
    }))
    .sort((a, b) => a.durationMs - b.durationMs)

  if (withDuration.length > 0) {
    const avg = withDuration.reduce((s, p) => s + p.durationMs, 0) / withDuration.length
    const max = withDuration[withDuration.length - 1]
    lines.push(`  Total tracked: ${withDuration.length}`)
    lines.push(`  Average lifetime: ${Math.round(avg)}ms`)
    lines.push(`  Max lifetime: ${max.name} (${max.durationMs}ms)`)
  }

  for (const cluster of clusters) {
    if (cluster.count > 0) {
      lines.push('')
      lines.push(`  ⚠ ${cluster.label}: ${cluster.count}`)
      for (const e of cluster.processes.slice(0, 10)) {
        const dur = (e.exitTime || 0) - (e.startTime || e.timestamp)
        lines.push(`    ${e.name} (PID ${e.pid}): ${dur}ms`)
      }
    }
  }

  return lines
}
