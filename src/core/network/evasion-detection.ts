import * as fs from 'fs'
import * as path from 'path'
import * as os from 'os'
import { execFileSync } from 'child_process'
import {
  BuildProcessEvent,
  BuildNetEvent,
  OrphanProcessInfo,
  NamedPipeEvent,
  MemoryRegion,
  ProcessMaps,
  EvidenceSource,
  RecordOptions,
} from './build-types'

const KNOWN_DOH_PROVIDERS = [
  'dns.cloudflare.com', 'cloudflare-dns.com',
  'dns.google', 'dns.google.com',
  'dns.quad9.net', 'dns9.quad9.net',
  'dns.opendns.com', 'dns.family.opendns.com',
  'dns.mullvad.net',
  'dns.adguard.com', 'dns.adguard-dns.com',
  'doh.cleanbrowsing.org',
  'doh.dns.sb',
  'dns.nextdns.io',
  'doh.crypto.sx',
  'odvr.nic.cz',
]

const PIPE_INDICATORS = [
  /\\pipe\\/i,
  /\/run\//,
  /\/tmp\/.*fifo/,
  /\/var\/run\//,
]

export function detectOrphanProcesses(
  processes: BuildProcessEvent[],
): OrphanProcessInfo[] {
  const pids = new Set(processes.map(p => p.pid))

  const orphans: OrphanProcessInfo[] = []
  for (const proc of processes) {
    if (proc.ppid === 0 || proc.ppid === proc.pid) continue
    if (!pids.has(proc.ppid)) {
      orphans.push({
        pid: proc.pid,
        name: proc.name,
        cmdline: proc.cmdline,
        ppid: proc.ppid,
        pname: proc.pname || 'unknown',
        reason: 'Parent PID not in build process set (possible ptrace injection)',
        timestamp: proc.timestamp,
      })
    }
  }
  return orphans
}

export function detectNamedPipes(
  processes: BuildProcessEvent[],
  cwd: string,
): NamedPipeEvent[] {
  const pipes: NamedPipeEvent[] = []
  try {
    if (process.platform === 'win32') {
      const out = execFileSync('powershell', [
        '-NoProfile', '-Command',
        'Get-ChildItem -Path "\\\\.\\pipe\\" -ErrorAction SilentlyContinue | Select-Object Name | ConvertTo-Json -Compress',
      ], { timeout: 3000, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] })
      if (out.trim()) {
        const data = JSON.parse(out.trim())
        const arr: any[] = Array.isArray(data) ? data : [data]
        for (const p of arr) {
          if (p && p.Name) {
            pipes.push({
              pipePath: `\\\\.\\pipe\\${p.Name}`,
              pid: 0,
              processName: 'unknown',
              operation: 'read',
              timestamp: Date.now(),
            })
          }
        }
      }
    } else {
      const fifoDir = '/tmp'
      const entries = fs.readdirSync(fifoDir)
      for (const entry of entries) {
        const fp = path.join(fifoDir, entry)
        try {
          const stat = fs.statSync(fp)
          if (stat.isFIFO()) {
            pipes.push({
              pipePath: fp,
              pid: 0,
              processName: 'unknown',
              operation: 'read',
              timestamp: Date.now(),
            })
          }
        } catch {}
      }
    }
  } catch {}
  return pipes
}

export function detectDnsOverHttps(
  netEvents: BuildNetEvent[],
): BuildNetEvent[] {
  const dohEvents: BuildNetEvent[] = []
  for (const event of netEvents) {
    if (event.type === 'tcp') {
      const isDoH = KNOWN_DOH_PROVIDERS.some(doh => event.host.includes(doh))
      if (isDoH) {
        dohEvents.push({
          ...event,
        })
      }
    }
  }
  return dohEvents
}

export function captureProcessMaps(
  processes: BuildProcessEvent[],
): ProcessMaps[] {
  const results: ProcessMaps[] = []
  if (process.platform === 'win32') return results

  for (const proc of processes.slice(0, 50)) {
    try {
      const mapsPath = `/proc/${proc.pid}/maps`
      if (!fs.existsSync(mapsPath)) continue

      const content = fs.readFileSync(mapsPath, 'utf-8')
      const lines = content.split('\n').filter(Boolean)
      const regions: MemoryRegion[] = []
      const suspiciousRegions: string[] = []

      let ldPreload: string | null = null
      try {
        const envPath = `/proc/${proc.pid}/environ`
        if (fs.existsSync(envPath)) {
          const env = fs.readFileSync(envPath, 'utf-8')
          const match = env.match(/LD_PRELOAD=([^\0]+)/)
          if (match) ldPreload = match[1]
        }
      } catch {}

      for (const line of lines) {
        const parts = line.trim().split(/\s+/)
        if (parts.length < 5) continue
        const [range, perms, offset, dev, inode, ...rest] = parts
        const [start, end] = range.split('-')
        const memPath = rest.join(' ') || ''

        regions.push({
          start,
          end,
          permissions: perms,
          path: memPath,
          inode: parseInt(inode) || 0,
        })

        if (perms.includes('rwx') && memPath === '') {
          suspiciousRegions.push(`rwx anonymous ${start}-${end}`)
        }
        if (perms.includes('wx') && memPath === '') {
          suspiciousRegions.push(`wx anonymous ${start}-${end}`)
        }
        if (memPath.includes('/memfd:') || memPath.includes('/delayed_free')) {
          suspiciousRegions.push(`memfd region: ${memPath}`)
        }
        if (memPath.includes('(deleted)')) {
          suspiciousRegions.push(`deleted file mapping: ${memPath}`)
        }
      }

      results.push({
        pid: proc.pid,
        processName: proc.name,
        regions,
        ldPreload,
        suspiciousRegions,
        timestamp: Date.now(),
      })
    } catch {}
  }
  return results
}

export function detectEphemeralProcesses(
  processes: BuildProcessEvent[],
  thresholdsMs: number[] = [25, 50, 100],
): Record<string, BuildProcessEvent[]> {
  const result: Record<string, BuildProcessEvent[]> = {}
  for (const threshold of thresholdsMs) {
    const key = `under_${threshold}ms`
    result[key] = processes.filter(p => {
      const exitTime = p.exitTime
      if (!exitTime) return false
      const start = p.startTime || p.timestamp
      const duration = exitTime - start
      return duration >= 0 && duration < threshold
    })
  }
  return result
}

export function inferEvidenceSource(
  platform: string,
  options?: RecordOptions,
): EvidenceSource {
  if (options?.observeOnly) return 'procfs'
  if (platform === 'win32') {
    try {
      execFileSync('wevtutil', ['ep'], { stdio: 'pipe', timeout: 2000 })
      return 'etw'
    } catch {
      return 'cim_query'
    }
  }
  if (platform === 'linux') {
    if (fs.existsSync('/sys/kernel/security/apparmor')) return 'ebpf'
    return 'procfs'
  }
  return 'polling'
}

export function detectFilelessExecution(
  processes: BuildProcessEvent[],
): BuildProcessEvent[] {
  return processes.filter(p => {
    const cmdline = p.cmdline || ''
    if (/\/dev\/fd\/\d+|pipe:\[\d+\]|socket:\[\d+\]/.test(cmdline)) return true
    if (cmdline.startsWith('-') && cmdline.length > 3) return true
    if (p.name === 'sh' && cmdline.includes('/dev/stdin')) return true
    return false
  })
}
