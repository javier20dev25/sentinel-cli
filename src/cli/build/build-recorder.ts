import * as fs from 'fs'
import * as path from 'path'
import * as os from 'os'
import * as crypto from 'crypto'
import { spawn, ChildProcess } from 'child_process'
import {
  BuildRecord, BuildProcessEvent, BuildFileEvent, BuildNetEvent,
  BuildChainLink, BuildSummary, ProcessNode,
  BUILD_TOOLS, DANGEROUS_BUILD_TOOLS,
} from '../../core/network/build-types'

const POLL_PROCESS_MS = 100
const POLL_FILE_MS = 2000

interface ProcessEntry {
  pid: number
  name: string
  cmdline: string
  ppid: number
  pname: string
}

function getProcessList(): ProcessEntry[] {
  try {
    if (process.platform === 'win32') {
      const out = require('child_process').execFileSync('powershell', [
        '-NoProfile', '-Command',
        'Get-CimInstance Win32_Process | Select-Object ProcessId,Name,CommandLine,ParentProcessId | ConvertTo-Json -Compress',
      ], { timeout: 3000, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] })
      const data = JSON.parse(out.trim())
      const arr: any[] = Array.isArray(data) ? data : [data]
      return arr.filter((p: any) => p && p.ProcessId).map((p: any) => ({
        pid: p.ProcessId,
        name: (p.Name || '').toLowerCase(),
        cmdline: (p.CommandLine || p.Name || ''),
        ppid: p.ParentProcessId ?? 0,
        pname: '',
      }))
    } else {
      const out = require('child_process').execFileSync('ps', ['-eo', 'pid,comm,args,ppid', '--no-headers'], { timeout: 3000, encoding: 'utf8', stdio: ['pipe', 'pipe', 'pipe'] })
      return out.trim().split('\n').filter(Boolean).map((line: string) => {
        const [pid, comm, ...rest] = line.trim().split(/\s+/)
        const args = rest.join(' ')
        return { pid: parseInt(pid), name: (comm || '').toLowerCase(), cmdline: args, ppid: 0, pname: '' }
      })
    }
  } catch { return [] }
}

function buildToolName(name: string): string {
  for (const tool of BUILD_TOOLS) {
    if (tool.endsWith('*')) {
      if (name.startsWith(tool.slice(0, -1))) return tool.slice(0, -1)
    }
    if (name === tool) return tool
  }
  return ''
}

export function recordBuild(command: string, args: string[], cwd: string, timeoutMs = 300_000): Promise<BuildRecord> {
  return new Promise((resolve, reject) => {
    const startTime = Date.now()
    const startTimeIso = new Date().toISOString()

    const processes: BuildProcessEvent[] = []
    const files: BuildFileEvent[] = []
    const network: BuildNetEvent[] = []
    const knownPids = new Set<number>()
    const hashChain: BuildChainLink[] = []
    let processInterval: NodeJS.Timeout | null = null
    let fileInterval: NodeJS.Timeout | null = null
    let child: ChildProcess | null = null

    function addHashLink(eventType: string, fingerprint: string) {
      const previousHash = hashChain.length > 0 ? hashChain[hashChain.length - 1].linkHash : crypto.createHash('sha256').update('genesis').digest('hex')
      const linkData = `${eventType}|${fingerprint}|${previousHash}`
      const linkHash = crypto.createHash('sha256').update(linkData).digest('hex')
      hashChain.push({ index: hashChain.length, timestamp: Date.now(), eventType, eventFingerprint: fingerprint, previousHash, linkHash })
    }

    function detectBuildToolName(proc: ProcessEntry): string {
      const base = path.basename(proc.cmdline.split(' ')[0]).toLowerCase().replace(/\.exe$/, '')
      return buildToolName(base) || buildToolName(proc.name)
    }

    function pollProcesses() {
      const list = getProcessList()
      const currentPids = new Set<number>()
      for (const entry of list) {
        currentPids.add(entry.pid)
        if (!knownPids.has(entry.pid)) {
          knownPids.add(entry.pid)
          const ev: BuildProcessEvent = {
            pid: entry.pid, name: entry.name, cmdline: entry.cmdline.substring(0, 200),
            ppid: entry.ppid, pname: entry.pname, timestamp: Date.now(),
          }
          processes.push(ev)
          addHashLink('process_start', `${entry.pid}:${entry.name}`)
        }
      }
    }

    function pollFiles() {
      const seen = new Set<string>()
      const scanDir = (dir: string) => {
        try {
          const entries = fs.readdirSync(dir, { withFileTypes: true })
          for (const entry of entries) {
            const fullPath = path.join(dir, entry.name)
            try {
              if (entry.isDirectory()) {
                if (!entry.name.startsWith('.') && entry.name !== 'node_modules') {
                  scanDir(fullPath)
                }
              } else {
                if (seen.has(fullPath)) continue
                seen.add(fullPath)
                const stat = fs.statSync(fullPath)
                const age = Date.now() - stat.birthtimeMs
                files.push({
                  filePath: fullPath,
                  size: stat.size,
                  operation: age < 5000 ? 'created' : 'modified',
                  timestamp: Date.now(),
                })
                addHashLink('file_change', `${entry.name}:${stat.size}`)
              }
            } catch { }
          }
        } catch { }
      }
      try { scanDir(cwd) } catch { }
    }

    pollProcesses()
    processInterval = setInterval(pollProcesses, POLL_PROCESS_MS)
    fileInterval = setInterval(pollFiles, POLL_FILE_MS)

    child = spawn(command, args, {
      cwd,
      stdio: ['pipe', 'pipe', 'pipe'],
      shell: process.platform === 'win32',
    })

    const stdoutChunks: Buffer[] = []
    const stderrChunks: Buffer[] = []

    child.stdout?.on('data', (chunk: Buffer) => stdoutChunks.push(chunk))
    child.stderr?.on('data', (chunk: Buffer) => stderrChunks.push(chunk))

    const timer = setTimeout(() => {
      child?.kill('SIGTERM')
    }, timeoutMs)

    child.on('close', (exitCode) => {
      clearTimeout(timer)
      if (processInterval) clearInterval(processInterval)
      if (fileInterval) clearInterval(fileInterval)

      const durationMs = Date.now() - startTime
      const allPids = processes.map(p => p.pid)
      const pidToName = new Map(processes.map(p => [p.pid, p.name]))

      const roots = new Set<number>()
      for (const p of processes) {
        if (!allPids.includes(p.ppid) || p.ppid === p.pid) roots.add(p.pid)
      }

      function buildTree(pid: number): ProcessNode {
        const p = processes.find(x => x.pid === pid)
        if (!p) return { name: '?', pid, ppid: 0, cmdline: '', children: [] }
        return {
          name: p.name, pid: p.pid, ppid: p.ppid, cmdline: p.cmdline,
          children: processes.filter(c => c.ppid === pid && c.pid !== pid).map(c => buildTree(c.pid)),
        }
      }

      const processTree = Array.from(roots).map(r => buildTree(r))

      const uniqueNames = [...new Set(processes.map(p => p.name))]
      const buildToolsDetected = uniqueNames.filter(n => buildToolName(n))
      const anomalies: string[] = []

      const dangerousSeen = processes.filter(p => [...DANGEROUS_BUILD_TOOLS].some(t => p.name.includes(t) || p.cmdline.includes(t)))
      if (dangerousSeen.length > 0) {
        anomalies.push(`Suspicious process${dangerousSeen.length > 1 ? 'es' : ''}: ${[...new Set(dangerousSeen.map(p => p.name))].join(', ')}`)
      }

      const unknown = uniqueNames.filter(n => !BUILD_TOOLS.has(n) && !DANGEROUS_BUILD_TOOLS.has(n) && !n.startsWith('gcc-') && !n.startsWith('g++-') && !['conhost.exe', 'powershell', 'cmd.exe'].includes(n))
      if (unknown.length > 0) {
        anomalies.push(`Unknown processes: ${unknown.join(', ')}`)
      }

      const summary: BuildSummary = {
        totalProcesses: processes.length,
        uniqueProcesses: uniqueNames,
        buildToolsDetected,
        filesCreated: files.filter(f => f.operation === 'created').length,
        filesModified: files.filter(f => f.operation === 'modified').length,
        networkConnections: network.length,
        dnsQueries: [...new Set(network.filter(n => n.type === 'dns').map(n => n.host))],
        anomalies,
        processTree,
        totalHashLinks: hashChain.length,
      }

      const record: BuildRecord = {
        command, args, cwd: path.resolve(cwd),
        startTime: startTimeIso, durationMs, exitCode,
        platform: os.platform(), nodeVersion: process.version,
        processes, files, network, summary, hashChain,
      }

      resolve(record)
    })

    child.on('error', (err) => {
      clearTimeout(timer)
      if (processInterval) clearInterval(processInterval)
      if (fileInterval) clearInterval(fileInterval)
      reject(err)
    })
  })
}
